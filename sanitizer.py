import base64
import json
import logging
import datetime
import httplib2
import time
import os
import functions_framework

import google.auth
from google.auth.transport.requests import Request
from google.auth import iam
from google.oauth2 import service_account
from googleapiclient.discovery import build
from google_auth_httplib2 import AuthorizedHttp
from google.cloud import bigquery
from google.cloud import pubsub_v1

# ==========================================
# CONFIGURATION
# ==========================================
PROJECT_ID = 'your-gcp-project-id'
BQ_TABLE_ID = f'{PROJECT_ID}.compliance_dataset.drive_audit_log'
SCOPES = ['https://www.googleapis.com/auth/drive']

# Target MIME types
TARGET_MIME_TYPES = [
    'application/vnd.google-apps.document',
    'application/vnd.google-apps.spreadsheet',
    'application/vnd.google-apps.presentation',
    'application/vnd.google-apps.form',
    'application/vnd.google-apps.kix',
    'application/vnd.google-apps.ritz',
    'application/pdf',
    'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
    'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
    'image/jpeg',
    'image/png'
]

# ==========================================
# GLOBAL CACHING & SECRETS
# ==========================================
bq_client = bigquery.Client(project=PROJECT_ID)
publisher = pubsub_v1.PublisherClient()
# Defaults to your topic name if the environment variable isn't set
topic_path = publisher.topic_path(PROJECT_ID, os.environ.get('PUBSUB_TOPIC', 'workspace-sanitizer-topic'))

# Global cache for the ADC Signer
SIGNER = None
SIGNER_EMAIL = None

def get_signer():
    """Lazily initializes the IAM Signer. Retries if it failed on a previous cold start."""
    global SIGNER, SIGNER_EMAIL
    if SIGNER is None:
        try:
            adc_creds, _ = google.auth.default(scopes=['https://www.googleapis.com/auth/iam'])
            request = Request()
            adc_creds.refresh(request)
            SIGNER_EMAIL = adc_creds.service_account_email
            SIGNER = iam.Signer(request, adc_creds, SIGNER_EMAIL)
        except Exception as e:
            raise RuntimeError(f"ADC setup failed: {e}")
    return SIGNER, SIGNER_EMAIL

def stream_to_bigquery(log_entries):
    """Streams data using Legacy Streaming to completely bypass the 1,500 daily Load Job limit."""
    if not log_entries:
        return
        
    # Reverting to insert_rows_json. It has NO daily quota limits. 
    errors = bq_client.insert_rows_json(BQ_TABLE_ID, log_entries)
    
    if errors:
        logging.error(f"CRITICAL: BigQuery Streaming Failed. Errors: {errors}")
        # We maintain the hard exception to guarantee Pub/Sub retries the message on failure
        raise RuntimeError(f"BigQuery Telemetry Loss Prevented by forcing Pub/Sub retry. Errors: {errors}")


@functions_framework.cloud_event
def process_sanitization_target(cloud_event):
    """Triggered by Pub/Sub. Scans a specific user's Drive."""
    
    # 1. Start the 9-minute stopwatch immediately
    start_time = time.time()
    TIME_LIMIT = 540  # 9 minutes (540 seconds)
    
    pubsub_message = base64.b64decode(cloud_event.data["message"]["data"]).decode("utf-8")
    payload = json.loads(pubsub_message)
    
    target_user = payload.get("target_user")
    
    # FIX: Fast-fail to guard against malformed tickets missing a target user
    if not target_user:
        logging.error("Missing target_user in Pub/Sub payload. Aborting.")
        return
        
    organizational_unit = payload.get("organizational_unit", "UNKNOWN_OU")
    dry_run = payload.get("dry_run", True)
    
    # 2. Check if this is a resumed job with a bookmark
    page_token = payload.get("page_token", None)
    
    logging.info(f"Initiating scan for: {target_user} | OU: {organizational_unit} | Dry Run: {dry_run} | Resuming: {bool(page_token)}")
    
    # FIX: Lazily get or initialize the Signer
    current_signer, current_signer_email = get_signer()
    
    dwd_creds = service_account.Credentials(
        signer=current_signer,
        service_account_email=current_signer_email,
        token_uri="https://oauth2.googleapis.com/token",
        subject=target_user,
        scopes=SCOPES
    )
    
    # Set a 60-second timeout to prevent the httplib2 infinite hang bug
    http = httplib2.Http(timeout=60)
    authed_http = AuthorizedHttp(dwd_creds, http=http)
    drive_service = build('drive', 'v3', http=authed_http, cache_discovery=False)
    
    mime_query = " or ".join([f"mimeType='{m}'" for m in TARGET_MIME_TYPES])
    
    # Added 'and trashed = false' to ignore Vault Ghost Files.
    query = f"({mime_query}) and 'me' in owners and trashed = false"
    
    telemetry_batch = []
    total_processed = 0
    
    while True:
        # 3. The Safety Valve: Check if we are approaching the 10-minute Pub/Sub limit
        if time.time() - start_time > TIME_LIMIT:
            logging.info(f"Approaching 10-minute limit for {target_user}. Pausing and sending bookmark to Pub/Sub.")
            
            resume_payload = {
                "target_user": target_user,
                "organizational_unit": organizational_unit,
                "dry_run": dry_run,
                "page_token": page_token
            }
            
            # Added .result() to strictly await the Future, preventing silent drops.
            publisher.publish(topic_path, json.dumps(resume_payload).encode("utf-8")).result()
            
            # Return successfully so Pub/Sub deletes the CURRENT ticket, preventing a retry storm
            logging.info(f"Graceful exit. Handoff complete for {target_user}.")
            return
            
        try:
            results = drive_service.files().list(
                q=query,
                spaces='drive',
                corpora='user',
                fields="nextPageToken, files(id, name, mimeType, createdTime, modifiedTime, quotaBytesUsed, shared, driveId, permissions(role,type,emailAddress,domain))",
                pageSize=100,  # Safely respecting the 9-minute checkpoint
                pageToken=page_token
            ).execute()
            
            for f in results.get('files', []):
                
                action = "DRY_RUN_SKIPPED"
                if not dry_run:
                    try:
                        time.sleep(0.1)  # Speed bump to protect against Google Drive 403 API Rate Limits
                        drive_service.files().update(fileId=f.get('id'), body={'trashed': True}, supportsAllDrives=True).execute()
                        action = "TRASHED"
                    except Exception as del_error:
                        logging.error(f"Granular Trash Failed for {f.get('id')} ({target_user}): {del_error}")
                        action = "ACTION_FAILED"
                
                created_time = f.get('createdTime')
                modified_time = f.get('modifiedTime')
                file_size_bytes = int(f.get('quotaBytesUsed', 0))
                is_shared = f.get('shared', False)
                drive_type = "Shared Drive" if f.get('driveId') else "My Drive"

                shared_emails = []
                if is_shared:
                    for p in f.get('permissions', []):
                        if p.get('role') != 'owner': 
                            if 'emailAddress' in p:
                                shared_emails.append(p.get('emailAddress'))
                            elif p.get('type') == 'domain':
                                shared_emails.append(f"DOMAIN WIDE: {p.get('domain')}")
                            elif p.get('type') == 'anyone':
                                shared_emails.append("ANYONE WITH LINK - CRITICAL RISK")
                
                shared_with_string = ", ".join(shared_emails) if shared_emails else None

                telemetry_batch.append({
                    "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                    "target_user": target_user,
                    "organizational_unit": organizational_unit,
                    "file_id": f.get('id'),
                    "file_name": f.get('name'),
                    "mime_type": f.get('mimeType'),
                    "action_taken": action,
                    "created_time": created_time,
                    "modified_time": modified_time,
                    "file_size_bytes": file_size_bytes,
                    "is_shared": is_shared,
                    "drive_type": drive_type,
                    "shared_with_emails": shared_with_string
                })
            
            stream_to_bigquery(telemetry_batch)
            total_processed += len(telemetry_batch)
            telemetry_batch.clear()
            
            page_token = results.get('nextPageToken')
            if not page_token:
                break
                
        except Exception: 
            # Preserve exact stack traces in Cloud Logging
            logging.exception(f"FATAL Error scanning {target_user} at page token {page_token}")
            raise
            
    logging.info(f"Successfully processed {total_processed} files for {target_user}.")
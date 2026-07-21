import json
import logging
import httplib2
import functions_framework

import google.auth
from google.auth.transport.requests import Request
from google.auth import iam
from google.oauth2 import service_account
from googleapiclient.discovery import build
from google_auth_httplib2 import AuthorizedHttp
from google.cloud import pubsub_v1

# ==========================================
# CONFIGURATION
# ==========================================
PROJECT_ID = 'your-gcp-project-id'
TOPIC_ID = 'sanitization-target-queue'
WORKSPACE_ADMIN_EMAIL = 'admin@your-domain.com'

# The Strict Whitelist - The script is mathematically blind to any OU not on this list.
TARGET_OUS = [
    '/EMEA/Region-A/1. Agents',
    '/EMEA/Region-A/3. Supervisors',
    '/EMEA/Region-B/1. Agents',
    '/EMEA/Region-B/3. Supervisors',
    '/EMEA/Call Center/1. Agents',
    '/EMEA/Call Center/3. Supervisors'
]

SCOPES = [
    'https://www.googleapis.com/auth/admin.directory.user.readonly'
]

# ==========================================
# GLOBAL CACHING & SECRETS
# ==========================================
publisher = pubsub_v1.PublisherClient()
topic_path = publisher.topic_path(PROJECT_ID, TOPIC_ID)

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


def get_target_users(target_ou, directory_service):
    """Fetches user emails explicitly matching the whitelist and pairs them with their OU."""
    users = []
    page_token = None
    
    while True:
        # Explicit viewType added to ensure orgUnitPath query works correctly
        results = directory_service.users().list(
            customer='my_customer',
            query=f"orgUnitPath='{target_ou}'",
            projection='basic',
            fields="nextPageToken, users(primaryEmail, orgUnitPath)", 
            viewType='admin_view', 
            pageToken=page_token
        ).execute()
        
        for user in results.get('users', []):
            # Programmatic Strict Whitelist for Sub-OU Leakage Prevention
            if user.get('orgUnitPath') == target_ou:
                users.append({
                    "email": user['primaryEmail'],
                    "ou": target_ou
                })
            
        page_token = results.get('nextPageToken')
        if not page_token:
            break
            
    return users

@functions_framework.http
def trigger_discovery(request):
    """HTTP Cloud Function entry point."""
    logging.info("Waking up Discoverer Function [LIVE DELETION MODE]...")
    
    # Lazily get or initialize the Signer
    current_signer, current_signer_email = get_signer()
    
    # Secretless Domain-Wide Delegation (Matching the Sanitizer)
    dwd_creds = service_account.Credentials(
        signer=current_signer,
        service_account_email=current_signer_email,
        token_uri="https://oauth2.googleapis.com/token",
        subject=WORKSPACE_ADMIN_EMAIL,
        scopes=SCOPES
    )
    
    # Set a 60-second timeout to prevent the httplib2 infinite hang bug
    http = httplib2.Http(timeout=60)
    authed_http = AuthorizedHttp(dwd_creds, http=http)
    directory_service = build('admin', 'directory_v1', http=authed_http, cache_discovery=False)
    
    all_user_mappings = []
    
    # 1. Discover Users
    for ou in TARGET_OUS:
        logging.info(f"Scanning OU: {ou}")
        all_user_mappings.extend(get_target_users(ou, directory_service))
        
    # Deduplicate users while preserving the dictionary structure
    unique_users = {user["email"]: user for user in all_user_mappings}.values()
    
    if not unique_users:
        return "No users found in target OUs. Execution terminated.", 200

    # 2. Publish to Pub/Sub Queue
    publish_count = 0
    publish_futures = [] # Array to hold our async futures
    
    for user_data in unique_users:
        payload = {
            "target_user": user_data["email"],
            "organizational_unit": user_data["ou"],
            "dry_run": False  # <--- LIVE DELETION MODE ACTIVATED
        }
        
        data_bytes = json.dumps(payload).encode("utf-8")
        
        # Capture the future object to prevent Serverless background thread death
        future = publisher.publish(topic_path, data=data_bytes)
        publish_futures.append(future)
        publish_count += 1
        
    # Block the container from terminating until ALL network requests are confirmed
    for future in publish_futures:
        future.result()
        
    summary_msg = f"LIVE DELETION Discovery complete. Guaranteed delivery of {publish_count} approved targets for telemetry scanning."
    logging.info(summary_msg)
    return summary_msg, 200
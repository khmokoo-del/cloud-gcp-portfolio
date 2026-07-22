import os
import json
import functions_framework
import httplib2
from google_auth_httplib2 import AuthorizedHttp
from google.auth import default
from google.auth import impersonated_credentials
from googleapiclient.discovery import build
from google.cloud import pubsub_v1
from google.api_core.exceptions import DeadlineExceeded, RetryError

# ==============================================================================
# GLOBAL INITIALIZATION (Warm Start Optimization)
# ==============================================================================
PROJECT_ID = os.environ.get('GCP_PROJECT_ID')
TOPIC_ID = os.environ.get('PUBSUB_TOPIC_ID', 'dlp-event-queue')
SUB_ID = os.environ.get('PUBSUB_SUB_ID', 'dlp-event-processor')
SERVICE_ACCOUNT = os.environ.get('SERVICE_ACCOUNT_EMAIL')
SHEET_ID = os.environ.get('SPREADSHEET_ID')
WEBHOOK_SECRET = os.environ.get('WEBHOOK_SECRET')
CRON_SECRET = os.environ.get('CRON_SECRET')
WORKSPACE_ADMIN_EMAIL = os.environ.get('WORKSPACE_ADMIN_EMAIL', 'dlp-automation@your-domain.com')

# Initialize Pub/Sub clients globally.
publisher = pubsub_v1.PublisherClient()
subscriber = pubsub_v1.SubscriberClient()
topic_path = publisher.topic_path(PROJECT_ID, TOPIC_ID) if PROJECT_ID else None
subscription_path = subscriber.subscription_path(PROJECT_ID, SUB_ID) if PROJECT_ID else None

# Initialize Application Default Credentials (ADC)
try:
    base_creds, _ = default()
except Exception as e:
    base_creds = None
    print(f"ADC Initialization Warning: {e}")

# ==============================================================================
# ROUTER: Directs traffic based on URL path
# ==============================================================================
@functions_framework.http
def dlp_controller(request):
    if request.path == '/webhook':
        return ingest_webhook(request)
    elif request.path == '/process':
        return process_queue(request)
    else:
        return ('Not Found', 404)

# ==============================================================================
# COMPONENT A: THE INGESTOR (Thundering Herd Absorber)
# ==============================================================================
def ingest_webhook(request):
    """Absorbs agent webhooks and instantly queues them in Pub/Sub."""
    if not WEBHOOK_SECRET or not PROJECT_ID or not TOPIC_ID:
        print("CRITICAL: Missing environment variables for Ingestor.")
        return ('Internal Server Error', 500)

    auth_header = request.headers.get('Authorization')
    if auth_header != WEBHOOK_SECRET:
        return ('Unauthorized', 401)

    request_json = request.get_json(silent=True)
    if not request_json or 'events' not in request_json:
        return ('Bad Request', 400)

    events = request_json.get('events', [])
    if not events:
        return ('OK', 200)

    try:
        futures = []
        # Publish each event individually to Pub/Sub for atomic tracking
        for ev in events:
            message_data = json.dumps(ev).encode('utf-8')
            # publisher.publish is asynchronous and returns a Future
            futures.append(publisher.publish(topic_path, data=message_data))
        
        # Await all futures. If we return before this finishes, GCP throttles 
        # the CPU to 0 and data is lost.
        for f in futures:
            f.result()
            
        return ('Queued', 200)
    except Exception as e:
        print(f"Pub/Sub Publish Error: {str(e)}")
        return ('Internal Server Error', 500)

# ==============================================================================
# COMPONENT B: THE PROCESSOR (Synchronous Batch Writer)
# ==============================================================================
def process_queue(request):
    """Pulls messages from Pub/Sub, impersonates User, and Batch Appends to Sheets."""
    # Strict validation: ensures CRON_SECRET exists to prevent "Bearer None" exploit
    if not CRON_SECRET or not all([PROJECT_ID, SUB_ID, SERVICE_ACCOUNT, SHEET_ID, base_creds]):
        print("CRITICAL: Missing environment variables or base credentials for Processor.")
        return ('Internal Server Error', 500)

    auth_header = request.headers.get('Authorization')
    if auth_header != f"Bearer {CRON_SECRET}":
        return ('Unauthorized', 401)

    try:
        # Pull up to 1000 queued events from the Queue. 
        # We set a timeout so it doesn't hang indefinitely if the queue is empty.
        try:
            response = subscriber.pull(
                request={"subscription": subscription_path, "max_messages": 1000},
                timeout=15.0
            )
        except (DeadlineExceeded, RetryError):
            return ('No messages to process', 200)
        
        if not response.received_messages:
            return ('No messages to process', 200)

        values = []
        ack_ids = []

        # Parse messages
        for received_message in response.received_messages:
            try:
                ev = json.loads(received_message.message.data.decode('utf-8'))
                hw = ev.get('hardware', {})
                if isinstance(hw, str):
                    try: hw = json.loads(hw)
                    except: hw = {}

                values.append([
                    ev.get('timestamp', 'UNKNOWN'),
                    ev.get('hostname', 'UNKNOWN'),
                    ev.get('local_user', 'UNKNOWN'),
                    ev.get('jc_id', 'UNKNOWN'),
                    ev.get('type', 'UNKNOWN'),
                    hw.get('vendor', 'N/A'),
                    hw.get('model', 'N/A'),
                    hw.get('serial', 'N/A'),
                    ev.get('file_path', 'N/A'),
                    ev.get('os_audit', 'N/A')
                ])
                ack_ids.append(received_message.ack_id)
            except Exception as e:
                print(f"Message Parse Error: {e}")
                # Acknowledge corrupted messages so they don't permanently poison the queue
                ack_ids.append(received_message.ack_id)

        if not values:
            subscriber.acknowledge(request={"subscription": subscription_path, "ack_ids": ack_ids})
            return ('Processed empty payload', 200)

        # ==============================================================================
        # PLATINUM AUTHENTICATION: ADC + IAM Credentials (Zero Static Keys)
        # ==============================================================================
        delegated_creds = impersonated_credentials.Credentials(
            source_credentials=base_creds,
            target_principal=SERVICE_ACCOUNT,
            target_scopes=['https://www.googleapis.com/auth/spreadsheets'],
            subject=WORKSPACE_ADMIN_EMAIL
        )
        
        # Explicitly set the timeout on the httplib2 transport to prevent the per-request crash
        http_client = httplib2.Http(timeout=60)
        authed_http = AuthorizedHttp(credentials=delegated_creds, http=http_client)
        
        # Pass the pre-configured http client instead of raw credentials
        service = build('sheets', 'v4', http=authed_http)
        
        # ==============================================================================

        # SINGLE BATCH APPEND: valueInputOption='RAW' prevents Spreadsheet Injection 
        # and API crashes when handling arbitrary hardware serials/paths.
        body = {'values': values}
        service.spreadsheets().values().append(
            spreadsheetId=SHEET_ID, 
            range='Audit Events!A:A',
            valueInputOption='RAW', 
            body=body
        ).execute()

        # ONLY acknowledge (delete) messages from Pub/Sub AFTER a successful Sheet write.
        # If the Sheets API crashes, the messages stay in PubSub to be retried next minute.
        subscriber.acknowledge(request={"subscription": subscription_path, "ack_ids": ack_ids})
        
        return (f'Successfully processed {len(values)} events', 200)

    except Exception as e:
        print(f"Processor Error: {str(e)}")
        # Do NOT acknowledge messages. They safely return to the queue.
        return ('Internal Server Error', 500)
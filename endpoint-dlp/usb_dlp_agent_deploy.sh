#!/bin/bash
# ==================================================================
# ENTERPRISE USB DEVICE CONTROL & AUDIT LOGGING AGENT
# Architecture: Local Device Monitor + Asynchronous Cloud Sync
# Features: Hardware Hashing, Active User Tracking, Auditd File Checks
# Compliance: ISO 27001 Access Control and Logging
# ==================================================================

set -euo pipefail
export JC_WEBHOOK_SECRET={{JC_WEBHOOK_SECRET}}

# --- STANDARD LOGGING UTILITY ---
log() {
    local level=$1
    shift
    echo -e "$(date '+%Y-%m-%d %H:%M:%S') [${level}] $*"
}
log_info()  { log "INFO"  "$@"; }
log_error() { log "ERROR" "$@" >&2; }

# --- ERROR HANDLING & CLEANUP ---
cleanup() {
    local exit_code=$?
    if [ $exit_code -ne 0 ]; then
        log_error "Deployment failed. (Exit code: ${exit_code})"
    else
        log_info "✅ Enterprise USB Control deployed successfully."
    fi
    systemctl daemon-reload 2>/dev/null || true 
    exit "${exit_code}"
}
trap cleanup EXIT

log_info "Starting deployment process..."

# --- PREREQUISITE CHECKS ---
if [ "$EUID" -ne 0 ]; then
    log_error "This script requires root privileges."
    exit 1
fi

if [ -z "${JC_WEBHOOK_SECRET:-}" ]; then
    log_error "CRITICAL: JC_WEBHOOK_SECRET environment variable is missing."
    exit 1
fi

log_info "Updating package lists and installing dependencies..."
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq

for pkg in python3-venv sqlite3 jq auditd; do
    if ! dpkg -s "$pkg" >/dev/null 2>&1; then
        log_info "Installing missing package: $pkg"
        apt-get install -y -qq "$pkg"
    fi
done

# --- 1. DIRECTORY CREATION & PERMISSIONS ---
log_info "Creating secure directories and assigning permissions..."
mkdir -p /opt/jc-dlp /var/lib/jc-dlp /etc/jc-dlp
chmod 700 /opt/jc-dlp /var/lib/jc-dlp
chmod 755 /etc/jc-dlp

echo "$JC_WEBHOOK_SECRET" > /etc/jc-dlp/webhook.secret
chmod 400 /etc/jc-dlp/webhook.secret

touch /var/lib/jc-dlp/audit_checkpoint /var/lib/jc-dlp/tamper_checkpoint
chmod 600 /var/lib/jc-dlp/audit_checkpoint /var/lib/jc-dlp/tamper_checkpoint

# --- 2. PYTHON ENVIRONMENT & EVENT DATABASE ---
log_info "Creating Python virtual environment and initializing event database..."
if [ ! -d "/opt/jc-dlp/.venv" ]; then
    python3 -m venv /opt/jc-dlp/.venv
fi
# Force unconditional dependency check to prevent phantom venv crashes
/opt/jc-dlp/.venv/bin/pip install requests --quiet

DB_PATH="/var/lib/jc-dlp/audit_events.db"
/opt/jc-dlp/.venv/bin/python3 <<EOF
import sqlite3
conn = sqlite3.connect('$DB_PATH')
conn.execute('PRAGMA journal_mode=WAL;')
conn.execute('PRAGMA synchronous=NORMAL;')
conn.execute('''CREATE TABLE IF NOT EXISTS usb_events 
    (event_id INTEGER PRIMARY KEY AUTOINCREMENT, 
     timestamp DATETIME DEFAULT CURRENT_TIMESTAMP, 
     hostname TEXT, local_user TEXT, jc_id TEXT, type TEXT, 
     hardware TEXT, file_path TEXT, os_audit TEXT)''')
conn.close()
EOF
chmod 600 "$DB_PATH"; chown root:root "$DB_PATH"

# --- 3. HARDWARE MONITORING SCRIPT ---
log_info "Creating hardware monitoring script..."
cat << 'EOF' > /opt/jc-dlp/usb_monitor.py
import sys, sqlite3, json, os, subprocess, hashlib

def get_jc_id():
    try: return json.load(open('/opt/jc/jcagent.conf')).get('systemKey', 'UNKNOWN_JC_ID')
    except: return "UNKNOWN_JC_ID"

def get_active_user():
    try:
        res = subprocess.run(['loginctl', 'list-sessions', '--no-legend'], capture_output=True, text=True)
        for line in res.stdout.splitlines():
            parts = line.split()
            if len(parts) >= 3 and parts[2] != 'gdm':
                session_id = parts[0]
                remote_check = subprocess.run(['loginctl', 'show-session', session_id, '-p', 'Remote', '--value'], capture_output=True, text=True)
                if remote_check.stdout.strip() == 'no':
                    return parts[2]
    except: pass
    return "UNKNOWN_USER"

def query_hw(kernel_name):
    meta = {"serial": "N/A", "vendor": "N/A", "model": "N/A", "class": "N/A"}
    if not kernel_name or kernel_name == "AUDIT": return meta
    syspath = f"/sys/bus/usb/devices/{kernel_name.split(':')[0]}"
    try:
        if os.path.exists(syspath + "/manufacturer"):
            with open(syspath + "/manufacturer") as f: meta["vendor"] = f.read().strip()
        if os.path.exists(syspath + "/product"):
            with open(syspath + "/product") as f: meta["model"] = f.read().strip()
        if os.path.exists(syspath + "/bDeviceClass"):
            with open(syspath + "/bDeviceClass") as f: meta["class"] = f.read().strip()
        if os.path.exists(syspath + "/serial"):
            with open(syspath + "/serial") as f: 
                raw_serial = f.read().strip()
                meta["serial"] = hashlib.sha256(raw_serial.encode('utf-8')).hexdigest()
    except: pass
    return meta

def classify_device(interface_sysfs_path):
    """Determines if a blocked device is a real threat or a benign peripheral.
    
    ALWAYS returns EVENT_BLOCKED for:
      - Apple devices (iPhones, iPads) via vendor ID 05ac
      - MTP/Imaging devices (Android phones) via interface class 06
      - Pure storage devices (USB flash drives) via interface counting
    
    Returns COMPOSITE_BLOCKED only for:
      - Peripherals where HID interfaces outnumber storage (barcode scanners)
    """
    try:
        parent_device_path = os.path.dirname(interface_sysfs_path)
        
        # GATE 1: Apple vendor ID = iPhone/iPad. ALWAYS a violation.
        vendor_file = os.path.join(parent_device_path, 'idVendor')
        if os.path.exists(vendor_file):
            with open(vendor_file, 'r') as f:
                if f.read().strip().lower() == '05ac':
                    return "EVENT_BLOCKED"
        
        # GATE 2: If the blocked interface is MTP/Imaging (06) = Android phone. ALWAYS a violation.
        blocked_class_file = os.path.join(interface_sysfs_path, 'bInterfaceClass')
        if os.path.exists(blocked_class_file):
            with open(blocked_class_file, 'r') as f:
                if f.read().strip() == '06':
                    return "EVENT_BLOCKED"
        
        # GATE 3: For storage (08) interfaces, count siblings to distinguish
        # barcode scanners (HID-primary) from USB flash drives (storage-primary)
        dangerous_classes = {'08', '06'}
        benign_classes = {'03', '07'}
        dangerous_count = 0
        benign_count = 0
        
        for sibling in os.listdir(parent_device_path):
            sibling_path = os.path.join(parent_device_path, sibling)
            if os.path.isdir(sibling_path) and ':' in sibling:
                class_file = os.path.join(sibling_path, 'bInterfaceClass')
                if os.path.exists(class_file):
                    with open(class_file, 'r') as f:
                        iface_class = f.read().strip()
                        if iface_class in dangerous_classes:
                            dangerous_count += 1
                        elif iface_class in benign_classes:
                            benign_count += 1
        
        # Barcode scanner: 2-3 HID + 1 storage = benign(3) > dangerous(1) = COMPOSITE
        # USB flash drive: 0 HID + 1 storage = benign(0) NOT > dangerous(1) = BLOCKED
        # Android storage: 0-1 HID + 1 storage + ADB(ff) = benign NOT > dangerous = BLOCKED
        if benign_count > dangerous_count:
            return "COMPOSITE_BLOCKED"
        
        return "EVENT_BLOCKED"
        
    except Exception:
        # Fail SECURE: if sysfs is unreadable, treat as a real threat
        return "EVENT_BLOCKED"

if __name__ == "__main__" and len(sys.argv) > 1:
    sysfs_path = sys.argv[1]
    
    if sysfs_path != "AUDIT":
        if os.path.isabs(sysfs_path):
            k_name = os.path.basename(sysfs_path)
            ev_type = classify_device(sysfs_path)
        else:
            k_name = sysfs_path
            ev_type = "EVENT_BLOCKED"
            
        hardware_meta = json.dumps(query_hw(k_name))
        audit_msg = "Composite peripheral storage disabled" if ev_type == "COMPOSITE_BLOCKED" else "Device connection blocked by policy"
    else:
        ev_type = "SYSTEM_AUDIT"
        hardware_meta = "{}"
        audit_msg = "Audit check completed"
        k_name = "AUDIT"
        
    payload = (os.uname()[1], get_active_user(), get_jc_id(), ev_type, hardware_meta, "N/A", audit_msg)
    
    conn = sqlite3.connect("/var/lib/jc-dlp/audit_events.db", timeout=30.0)
    # Enforce a 5-second busy timeout to prevent 'database is locked' errors during concurrent syncs
    conn.execute("PRAGMA busy_timeout=5000")
    conn.execute("INSERT INTO usb_events (hostname, local_user, jc_id, type, hardware, file_path, os_audit) VALUES (?,?,?,?,?,?,?)", payload)
    conn.commit()
    conn.close()

    # REAL-TIME SYNC: Force immediate cloud sync for ALL blocked events
    if ev_type in ("EVENT_BLOCKED", "COMPOSITE_BLOCKED"):
        subprocess.run(["systemctl", "start", "--no-block", "jc-dlp-sync.service"])
EOF
chmod +x /opt/jc-dlp/usb_monitor.py

# --- 4. SYSTEMD UNIT FOR HARDWARE MONITORING ---
log_info "Creating systemd unit files for hardware monitoring..."
cat << 'EOF' > /etc/systemd/system/jc-dlp-monitor@.service
[Unit]
Description=Enterprise USB Monitoring Service (%I)
After=local-fs.target

[Service]
Type=oneshot
ExecStart=/opt/jc-dlp/.venv/bin/python3 /opt/jc-dlp/usb_monitor.py "%I"
User=root
EOF

# --- 5. UDEV RULES CONFIGURATION ---
log_info "Configuring udev rules for device identification..."
cat << 'EOF' > /etc/udev/rules.d/99-endpoint-dlp.rules
# Block Storage (08) interfaces natively
ACTION=="add", SUBSYSTEM=="usb", ENV{DEVTYPE}=="usb_interface", ATTR{bInterfaceClass}=="08", ATTR{authorized}="0", RUN+="/bin/sh -c '/bin/systemctl start --no-block jc-dlp-monitor@$$(/usr/bin/systemd-escape -p /sys$devpath).service'"

# Block Imaging/MTP (06) interfaces natively
ACTION=="add", SUBSYSTEM=="usb", ENV{DEVTYPE}=="usb_interface", ATTR{bInterfaceClass}=="06", ATTR{authorized}="0", RUN+="/bin/sh -c '/bin/systemctl start --no-block jc-dlp-monitor@$$(/usr/bin/systemd-escape -p /sys$devpath).service'"

# Block Apple iOS devices via specific hardware descriptors
ACTION=="add", SUBSYSTEM=="usb", ENV{DEVTYPE}=="usb_interface", ATTRS{idVendor}=="05ac", ATTR{bInterfaceClass}=="ff", ATTR{authorized}="0", RUN+="/bin/sh -c '/bin/systemctl start --no-block jc-dlp-monitor@$$(/usr/bin/systemd-escape -p /sys$devpath).service'"
EOF

# --- 6. AUDITD FILE MONITORING ---
log_info "Configuring auditd file monitoring..."
echo "-w /media/ -p w -k enterprise_usb_write" > /etc/audit/rules.d/endpoint_dlp.rules
echo "-w /run/media/ -p w -k enterprise_usb_write" >> /etc/audit/rules.d/endpoint_dlp.rules
echo "-w /mnt/ -p w -k enterprise_usb_write" >> /etc/audit/rules.d/endpoint_dlp.rules
echo "-w /etc/udev/rules.d/ -p wa -k system_tamper_audit" >> /etc/audit/rules.d/endpoint_dlp.rules
echo "-w /opt/jc-dlp/ -p wa -k system_tamper_audit" >> /etc/audit/rules.d/endpoint_dlp.rules
value_load=$(augenrules --load 2>&1 || true)

cat << 'EOF' > /opt/jc-dlp/audit_watcher.py
import subprocess, sqlite3, os, csv, io, sys
sys.path.append('/opt/jc-dlp')
from usb_monitor import get_jc_id, get_active_user

def run_ausearch(key, checkpoint_file, ev_type, msg):
    if not os.path.exists(checkpoint_file): open(checkpoint_file, 'a').close()
    cmd = ["ausearch", "-k", key, "--checkpoint", checkpoint_file, "--format", "csv"]
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=30.0)
        
        if res.returncode in [10, 11, 12]:
            fallback_cmd = ["ausearch", "-k", key, "--start", "checkpoint", "--checkpoint", checkpoint_file, "--format", "csv"]
            res = subprocess.run(fallback_cmd, capture_output=True, text=True, timeout=30.0)
            if res.returncode != 0:
                return 
            
        if not res.stdout.strip() or "no matches" in res.stdout.lower(): return
        
        reader = csv.reader(io.StringIO(res.stdout))
        headers = next(reader, None)
        if not headers: return
        
        for row in reader:
            row_dict = dict(zip(headers, row))
            file_path = row_dict.get("OBJ_PRIME", "") or row_dict.get("OBJ_SEC", "") or row_dict.get("NAME", "UNKNOWN")
            
            if not file_path.startswith("/") and key == "enterprise_usb_write":
                for val in row_dict.values():
                    if isinstance(val, str) and val.startswith("/"):
                        file_path = val
                        break
                        
            user = get_active_user() if key == "enterprise_usb_write" else "SYSTEM_ADMIN"
            
            if file_path:
                conn = sqlite3.connect("/var/lib/jc-dlp/audit_events.db", timeout=30.0)
                conn.execute("PRAGMA busy_timeout=5000")
                conn.execute("INSERT INTO usb_events (hostname, local_user, jc_id, type, hardware, file_path, os_audit) VALUES (?,?,?,?,?,?,?)",
                             (os.uname()[1], user, get_jc_id(), ev_type, "{}", file_path, msg))
                conn.commit()
                conn.close()
    except Exception: pass

if __name__ == "__main__":
    run_ausearch("enterprise_usb_write", "/var/lib/jc-dlp/audit_checkpoint", "UNAUTHORIZED_WRITE", "Write attempt to external media")
    run_ausearch("system_tamper_audit", "/var/lib/jc-dlp/tamper_checkpoint", "POLICY_MODIFIED", "System configuration files modified")
EOF

# --- 7. SYSTEM HEALTH CHECK ---
log_info "Creating system health check scripts..."
cat << 'EOF' > /opt/jc-dlp/health_check.py
import sqlite3, os, subprocess, sys
sys.path.append('/opt/jc-dlp')
from usb_monitor import get_jc_id

def check_health():
    healthy = True
    audit_msg = []
    
    if not os.path.exists("/etc/udev/rules.d/99-endpoint-dlp.rules"):
        healthy = False
        audit_msg.append("Missing udev rules")
        
    if not os.path.exists("/etc/modprobe.d/disable-mmc.conf"):
        healthy = False
        audit_msg.append("Missing module blacklist")
        
    usbmuxd_check = subprocess.run(['systemctl', 'is-enabled', 'usbmuxd'], capture_output=True, text=True).stdout.strip()
    if usbmuxd_check != 'masked':
        healthy = False
        audit_msg.append("usbmuxd service is active")
        
    status_type = "HEALTH_PASS" if healthy else "HEALTH_FAIL"
    msg = "All configurations active" if healthy else " | ".join(audit_msg)
    
    conn = sqlite3.connect("/var/lib/jc-dlp/audit_events.db", timeout=10.0)
    conn.execute("PRAGMA busy_timeout=5000")
    payload = (os.uname()[1], "SYSTEM_PROCESS", get_jc_id(), status_type, "{}", "N/A", msg)
    conn.execute("INSERT INTO usb_events (hostname, local_user, jc_id, type, hardware, file_path, os_audit) VALUES (?,?,?,?,?,?,?)", payload)
    conn.commit()
    conn.close()

if __name__ == "__main__":
    check_health()
EOF

# --- 8. CLOUD SYNCHRONIZATION SCRIPT ---
log_info "Creating cloud synchronization script..."
cat << 'EOF' > /opt/jc-dlp/log_sync.py
import sqlite3, json, requests, os

DB_PATH = "/var/lib/jc-dlp/audit_events.db"
# Replaced with generic secure endpoint
WEBHOOK_URL = "https://your-cloud-run-endpoint.run.app/webhook"

try:
    with open('/etc/jc-dlp/webhook.secret', 'r') as f:
        WEBHOOK_SECRET = f.read().strip()
except: WEBHOOK_SECRET = ""

def sync():
    if not os.path.exists(DB_PATH) or not WEBHOOK_SECRET: return
    db = sqlite3.connect(DB_PATH, timeout=10.0)
    rows = db.execute("SELECT event_id, timestamp, hostname, local_user, jc_id, type, hardware, file_path, os_audit FROM usb_events").fetchall()
    if not rows: return db.close()

    events, sent_ids = [], []
    for r in rows:
        # Fallback to prevent crash on legacy non-JSON test data
        try:
            hw_meta = json.loads(r[6])
        except Exception:
            hw_meta = {}

        events.append({
            "timestamp": r[1], "hostname": r[2], "local_user": r[3], "jc_id": r[4],
            "type": r[5], "hardware": hw_meta, "file_path": r[7], "os_audit": r[8]
        })
        sent_ids.append(r[0])

    try:
        res = requests.post(WEBHOOK_URL, json={"events": events}, headers={"Authorization": WEBHOOK_SECRET}, timeout=10)
        if res.status_code == 200:
            db.executemany("DELETE FROM usb_events WHERE event_id = ?", [(i,) for i in sent_ids])
            db.commit()
    except: pass
    finally: db.close()

if __name__ == "__main__": sync()
EOF

# --- 9. SYSTEMD TIMERS FOR BACKGROUND EXECUTION ---
log_info "Configuring systemd timers for background execution..."
cat << 'EOF' > /etc/systemd/system/jc-dlp-sync.service
[Unit]
Description=Enterprise Event Log Sync Service
[Service]
Type=oneshot
ExecStart=/opt/jc-dlp/.venv/bin/python3 /opt/jc-dlp/audit_watcher.py
ExecStart=/opt/jc-dlp/.venv/bin/python3 /opt/jc-dlp/log_sync.py
EOF

cat << 'EOF' > /etc/systemd/system/jc-dlp-sync.timer
[Unit]
Description=Timer for Enterprise Log Sync
[Timer]
OnBootSec=2min
OnUnitActiveSec=2min
RandomizedDelaySec=120
[Install]
WantedBy=timers.target
EOF

cat << 'EOF' > /etc/systemd/system/jc-dlp-health.service
[Unit]
Description=Enterprise System Health Check Service
[Service]
Type=oneshot
ExecStart=/opt/jc-dlp/.venv/bin/python3 /opt/jc-dlp/health_check.py
EOF

cat << 'EOF' > /etc/systemd/system/jc-dlp-health.timer
[Unit]
Description=Timer for Enterprise Health Check
[Timer]
OnCalendar=*-*-* 00/4:00:00
Persistent=true
RandomizedDelaySec=1800
[Install]
WantedBy=timers.target
EOF

# --- 10. DISABLING UNAUTHORIZED MODULES ---
log_info "Disabling unauthorized device modules and services..."
systemctl stop usbmuxd 2>/dev/null || true
systemctl mask usbmuxd 2>/dev/null || true

cat << 'EOF' > /etc/modprobe.d/disable-mmc.conf
install mmc_block /bin/true
install sdhci /bin/true
blacklist mmc_block
blacklist sdhci
EOF

# --- 11. START SERVICES ---
log_info "Reloading configurations and starting background services..."
udevadm control --reload-rules
systemctl daemon-reload
systemctl enable --now jc-dlp-sync.timer
systemctl enable --now jc-dlp-health.timer

# Force an initial audit log entry
/opt/jc-dlp/.venv/bin/python3 /opt/jc-dlp/usb_monitor.py "AUDIT"
systemctl start jc-dlp-sync.service
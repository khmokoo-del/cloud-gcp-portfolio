#!/bin/bash
# ==================================================================
# ENTERPRISE EPHEMERAL WORKSPACE SANITIZATION & LOGGING
# Trigger: JumpCloud Command (On User Login)
# Execution: Background priority (nice/ionice) to prevent GUI freeze
# Logging: Dumps to local SQLite spooler for asynchronous cloud sync
# Compliance: ISO 27001 Data Sanitization and Audit Logging
# ==================================================================

# Enforce strict error handling
set -euo pipefail

# Fallback matrix for unconfigured XDG environments
FALLBACK_DIRS=("Downloads" "Documents" "Desktop" "Pictures" "Videos" "Music" "Templates" "Public")

# Grab JumpCloud ID once for the machine
JC_ID=$(grep -o '"systemKey":"[^"]*"' /opt/jc/jcagent.conf 2>/dev/null | cut -d'"' -f4 || echo "UNKNOWN_JC_ID")
HOSTNAME=$(hostname)

# 1. Isolate interactive human users based on UID (1000+), excluding 'nobody'
getent passwd | awk -F: '$3 >= 1000 && $1 != "nobody" {print $1 ":" $6}' | while IFS=: read -r user_name user_home; do

    # 2. Validate that the home directory exists and is explicitly NOT a symbolic link
    if [ -d "$user_home" ] && [ ! -L "$user_home" ]; then
        
        TARGET_PATHS=()
        XDG_CONFIG="$user_home/.config/user-dirs.dirs"

        # 3. Attempt secure passive parsing of the XDG config for localized paths
        if [ -f "$XDG_CONFIG" ] && [ -r "$XDG_CONFIG" ]; then
            while IFS= read -r parsed_path; do
                if [ -n "$parsed_path" ]; then
                    TARGET_PATHS+=("$user_home/$parsed_path")
                fi
            done < <(awk -F'=' '/^XDG_[A-Z]+_DIR=/ { 
                        gsub(/"/, "", $2); 
                        if ($2 ~ /^\$HOME\//) { 
                            sub(/^\$HOME\//, "", $2); 
                            print $2 
                        } 
                     }' "$XDG_CONFIG")
        fi

        # 4. Implement fallback logic if XDG parsing yielded zero results
        if [ ${#TARGET_PATHS[@]} -eq 0 ]; then
            for fallback in "${FALLBACK_DIRS[@]}"; do
                TARGET_PATHS+=("$user_home/$fallback")
            done
        fi

        # Explicitly append the hidden Linux Recycle Bin to the target list
        TARGET_PATHS+=("$user_home/.local/share/Trash")

        # AGGREGATION TRACKERS: Initialize counters outside the loop
        TOTAL_DELETED=0
        CLEARED_DIRS=""

        # 5. Iterate through the compiled target paths and execute sanitization
        for target in "${TARGET_PATHS[@]}"; do
            
            # Defensive check: Ensure target is a directory, not a symlink (TOCTOU protection)
            if [ -d "$target" ] && [ ! -L "$target" ]; then
                
                # Delete items and count exactly how many were deleted in one pass
                # nice -n 19 / ionice -c 3 enforces lowest CPU and idle I/O priority
                # '|| true' guarantees safe fallback under pipefail without multi-line integer crashes
                # Using -printf '.' | wc -c completely prevents overcounting on files with newlines in names
                deleted_count=$(nice -n 19 ionice -c 3 find "$target" -mindepth 1 -xdev -delete -printf '.' 2>/dev/null | wc -c || true)
                
                # Add to the tally instead of logging immediately
                if [ "$deleted_count" -gt 0 ]; then
                    TOTAL_DELETED=$((TOTAL_DELETED + deleted_count))
                    # Extract just the base folder name for a clean log entry
                    base_dir=$(basename "$target")
                    CLEARED_DIRS="${CLEARED_DIRS}${base_dir}, "
                fi
            fi
        done

        # 6. SINGLE LOG EXECUTION: Only log to the cloud if we actually deleted something
        if [ "$TOTAL_DELETED" -gt 0 ]; then
            # Native bash string truncation (No 'sed' fork needed)
            CLEARED_DIRS="${CLEARED_DIRS%, }"
            
            FILE_PATH="$user_home/[$CLEARED_DIRS]"
            AUDIT_MSG="Sanitized $TOTAL_DELETED items across active directories"
            
            # PRE-ESCAPE variables to prevent SQL syntax crashes from single quotes (e.g., O'Connor)
            SQL_HOST="${HOSTNAME//\'/''}"
            SQL_USER="${user_name//\'/''}"
            SQL_PATH="${FILE_PATH//\'/''}"
            SQL_MSG="${AUDIT_MSG//\'/''}"
            
            # Insert the single summary directly into the existing DLP Database
            sqlite3 /var/lib/jc-dlp/audit_events.db "PRAGMA busy_timeout=5000; INSERT INTO usb_events (hostname, local_user, jc_id, type, hardware, file_path, os_audit) VALUES ('$SQL_HOST', '$SQL_USER', '$JC_ID', 'DATA_SANITIZATION', '{}', '$SQL_PATH', '$SQL_MSG');"
            
            # Force an immediate push to the Google Sheet asynchronously
            systemctl start --no-block jc-dlp-sync.service 2>/dev/null || true
        fi

    fi
done

echo "Data sanitization executed successfully."
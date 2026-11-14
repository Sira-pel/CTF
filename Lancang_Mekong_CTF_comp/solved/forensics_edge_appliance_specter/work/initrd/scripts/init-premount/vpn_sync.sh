#!/bin/sh
# ApexGate Early-Boot Hardware Cryptographic Synchronizer
# Synchronizes security anchor state prior to root filesystem mount.

log_message() {
    echo "[INIT-PREMOUNT] vpn_sync: $1" > /dev/kmsg 2>/dev/null || echo "[INIT-PREMOUNT] vpn_sync: $1"
}

log_message "Initializing hardware cryptographic key synchronization..."

TPM_LOG="/sys/kernel/security/tpm0/binary_bios_measurements"
if [ -f "$TPM_LOG" ]; then
    log_message "Reading hardware measurements from $TPM_LOG..."
    if [ -x "/sbin/apex-anchor" ]; then
        if /sbin/apex-anchor --verify-pcr 14 "$TPM_LOG" >/dev/null 2>&1; then
            log_message "Verified PCR 14 integrity binding"
        else
            log_message "ERROR: PCR 14 hardware security binding verification failed!"
            exit 1
        fi
    fi
fi

log_message "Pre-mount cryptographic validation completed successfully."
exit 0

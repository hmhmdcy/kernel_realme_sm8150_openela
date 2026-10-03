#!/system/bin/sh
MODDIR=${0%/*}
# Retry once later if early-init had not mounted pstore yet.
/system/bin/sh "$MODDIR/collect.sh" boot >/dev/null 2>&1
attempt=0
while [ "$(getprop sys.boot_completed)" != 1 ] && [ "$attempt" -lt 60 ]; do
    sleep 2
    attempt=$((attempt + 1))
done
/system/bin/sh "$MODDIR/collect.sh" snapshot >/dev/null 2>&1

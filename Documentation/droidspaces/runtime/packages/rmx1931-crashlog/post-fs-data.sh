#!/system/bin/sh
# Do not hold KernelSU's post-fs-data boot stage while reading logs.
MODDIR=${0%/*}
/system/bin/sh "$MODDIR/collect.sh" boot >/dev/null 2>&1 &

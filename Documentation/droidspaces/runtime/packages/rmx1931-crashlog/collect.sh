#!/system/bin/sh
# Normal-boot user space only. Preserve pstore entries; do not trigger a panic.
set -eu
umask 077
[ "$(id -u)" = 0 ] || exit 1
case "$(getprop ro.product.device)" in RMX1931|RMX1931CN) ;; *) exit 1 ;; esac
mode=${1:-boot}
case "$mode" in boot|snapshot) ;; *) exit 2 ;; esac
boot_id=$(cat /proc/sys/kernel/random/boot_id)
case "$boot_id" in ''|*[!a-f0-9-]*) exit 1 ;; esac
[ "${#boot_id}" = 36 ] || exit 1
base=/data/adb/rmx1931-crashlog
for parent in /data /data/adb "$base"; do
    [ ! -L "$parent" ] || exit 1
done
mkdir -p "$base"
chmod 700 "$base"
lock="$base/.lock-$boot_id"
if ! mkdir "$lock" 2>/dev/null; then
    echo 'Another collection is running (or an interrupted collection needs inspection)' >&2
    exit 3
fi
trap 'rmdir "$lock"' EXIT
dest="$base/boot-$boot_id"
if [ "$mode" = boot ] && [ -f "$dest/complete" ]; then exit 0; fi
if [ "$mode" = snapshot ]; then
    dest="$base/snapshot-$boot_id-$$"
fi
[ ! -e "$dest" ] && [ ! -L "$dest" ] || exit 1
mkdir "$dest"
# Android's early boot clock can be 1970. Order owned archives by a persistent
# sequence rather than wall-clock mtimes; collections in this boot are locked.
latest=0
for ordering in "$base"/boot-*/order.txt "$base"/snapshot-*/order.txt; do
    [ -f "$ordering" ] && [ ! -L "$ordering" ] || continue
    number=$(cat "$ordering")
    case "$number" in ''|*[!0-9]*) exit 1 ;; esac
    [ "${#number}" -le 9 ] || exit 1
    [ "$number" -le "$latest" ] || latest=$number
done
[ "$latest" -lt 999999999 ] || exit 1
printf '%s\n' "$((latest + 1))" > "$dest/order.txt"
errors=0
{
    printf 'boot_id=%s\ncollection=%s\n' "$boot_id" "$mode"
    printf 'utc='; date -u '+%Y-%m-%dT%H:%M:%SZ'
    printf 'uptime_seconds='; cut -d ' ' -f 1 /proc/uptime
    printf 'kernel='; uname -r
    printf 'selinux='; getenforce
} > "$dest/metadata.txt"
cat /proc/cmdline > "$dest/cmdline.txt"
cat /proc/modules > "$dest/modules.txt"
cat /proc/config.gz > "$dest/config.gz" || errors=$((errors + 1))
timeout 15 dmesg > "$dest/dmesg.txt" 2> "$dest/dmesg.stderr" || errors=$((errors + 1))
grep ' /sys/fs/pstore pstore ' /proc/mounts > "$dest/pstore-mount.txt" || errors=$((errors + 1))
count=0
if [ -s "$dest/pstore-mount.txt" ]; then
    for entry in /sys/fs/pstore/*; do
        [ -f "$entry" ] && [ ! -L "$entry" ] || continue
        name=${entry##*/}
        case "$name" in *[!a-zA-Z0-9_.-]*|.*) continue ;; esac
        if timeout 10 cat "$entry" > "$dest/pstore-$name"; then
            count=$((count + 1))
        else
            errors=$((errors + 1))
        fi
    done
fi
printf 'pstore_records=%s\ncollection_errors=%s\n' "$count" "$errors" > "$dest/status.txt"
(
    cd "$dest"
    for file in *; do
        [ -f "$file" ] && [ ! -L "$file" ] || continue
        [ "$file" != SHA256SUMS ] || continue
        sha256sum "$file"
    done
) > "$dest/SHA256SUMS"
if [ "$errors" -eq 0 ]; then
    printf 'complete\n' > "$dest/complete"
else
    # Preserve failures for inspection; allow the later boot hook to retry.
    mv "$dest" "$dest-incomplete-$$"
    exit 1
fi
# Keep the newest ten complete boot records and two snapshots. A boot UUID,
# fixed base and a strict file whitelist bound deletion to our own archives.
prune() {
    kind=$1
    keep=$2
    seen=0
    for directory in $(
        rank=999999999
        for item in $(ls -dt "$base"/"$kind"-* 2>/dev/null); do
            order=0
            if [ -f "$item/order.txt" ] && [ ! -L "$item/order.txt" ]; then
                order=$(cat "$item/order.txt")
                case "$order" in ''|*[!0-9]*) continue ;; esac
                [ "${#order}" -le 9 ] || continue
            fi
            printf '%09d %09d %s\n' "$order" "$rank" "$item"
            rank=$((rank - 1))
        done | sort -r | cut -d ' ' -f 3-
    ); do
        name=${directory##*/}
        case "$name" in *[!a-z0-9-]*) continue ;; esac
        [ -d "$directory" ] && [ ! -L "$directory" ] && [ -f "$directory/complete" ] || continue
        seen=$((seen + 1))
        [ "$seen" -gt "$keep" ] || continue
        safe=1
        for file in "$directory"/* "$directory"/.[!.]*; do
            [ -e "$file" ] || continue
            [ ! -L "$file" ] && [ -f "$file" ] || { safe=0; break; }
            case "${file##*/}" in order.txt|metadata.txt|cmdline.txt|modules.txt|config.gz|dmesg.txt|dmesg.stderr|pstore-mount.txt|status.txt|SHA256SUMS|complete|pstore-*) ;; *) safe=0; break ;; esac
        done
        [ "$safe" -eq 1 ] || continue
        for file in "$directory"/*; do rm -f "$file"; done
        rmdir "$directory"
    done
}
prune boot 10
prune snapshot 2
echo "CRASHLOG_ARCHIVED $dest"

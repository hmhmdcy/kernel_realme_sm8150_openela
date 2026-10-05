#!/system/bin/sh
# Exercise Settings foreground/background profiles without changing settings.
set -eu
test "$(getprop sys.boot_completed)" = 1
test "$(getenforce)" = Enforcing
kernel=$(uname -r)
boot=$(cat /proc/sys/kernel/random/boot_id)
case "$kernel" in *-ext-h2cp4) ;; *) exit 2 ;; esac
printf 'IDENTITY|%s|%s\n' "$kernel" "$boot"
hal=$(pidof android.hardware.power-service.lineage-libperfmgr)
test -n "$hal"
printf 'POWER_HAL|%s\n' "$hal"
work=$(mktemp -d /data/local/tmp/rmx1931-android-profiles-XXXXXXXX)
sampler=
cleanup() {
    if test -n "$sampler"; then kill "$sampler" 2>/dev/null || true; wait "$sampler" 2>/dev/null || true; fi
    input keyevent KEYCODE_HOME || true
    rm -f "$work/boost" "$work/launch"
    rmdir "$work"
}
trap cleanup EXIT
snapshot() {
    phase=$1
    pid=$(pidof com.android.settings | awk '{print $1}')
    test -n "$pid"
    printf 'PHASE|%s|%s\n' "$phase" "$pid"
    cat "/proc/$pid/cgroup"
    grep '^Cpus_allowed_list:' "/proc/$pid/status"
    for task in /proc/$pid/task/*; do
        if test -r "$task/cgroup" && test -r "$task/status"; then
            groups=$(tr '\n' ';' < "$task/cgroup")
            allowed=$(sed -n 's/^Cpus_allowed_list:[[:space:]]*//p' "$task/status")
            printf 'THREAD|%s|%s|%s\n' "${task##*/}" "$allowed" "$groups"
        fi
    done
    if dumpsys activity activities | grep -q 'topResumedActivity=.*com.android.settings'; then
        printf 'SETTINGS_TOP_RESUMED|yes\n'
    else
        printf 'SETTINGS_TOP_RESUMED|no\n'
    fi
}
input keyevent KEYCODE_HOME
sleep 1
(
    i=0
    while test "$i" -lt 300; do
        cat /dev/stune/top-app/schedtune.boost
        sleep .01
        i=$((i+1))
    done
) > "$work/boost" &
sampler=$!
am start -W -a android.settings.DISPLAY_SETTINGS > "$work/launch"
cat "$work/launch"
snapshot foreground
input keyevent KEYCODE_HOME
sleep 3
snapshot background
am start -W -a android.settings.DISPLAY_SETTINGS > "$work/launch"
cat "$work/launch"
snapshot relaunch
wait "$sampler"
sampler=
printf 'BOOST_HISTOGRAM_BEGIN\n'
sort -n "$work/boost" | uniq -c
printf 'BOOST_HISTOGRAM_END\n'
test "$(pidof android.hardware.power-service.lineage-libperfmgr)" = "$hal"
test "$(uname -r)" = "$kernel"
test "$(cat /proc/sys/kernel/random/boot_id)" = "$boot"
test "$(getenforce)" = Enforcing
printf 'ANDROID_PROFILE_PROBE_COMPLETED\n'

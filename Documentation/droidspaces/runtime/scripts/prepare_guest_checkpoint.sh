#!/bin/sh
# Expose only guest PID/IPC namespace checkpoint IDs through its RO proc/sys.
set -eu
test -f /etc/droidspaces
test "$(cat /proc/1/comm)" = systemd
test "$(readlink /proc/self/ns/pid)" = "$(readlink /proc/1/ns/pid)"
test "$(readlink /proc/self/ns/ipc)" = "$(readlink /proc/1/ns/ipc)"
case ",$(findmnt -n -o OPTIONS -T /proc/sys)," in *,ro,*) ;; *) exit 1 ;; esac
for name in ns_last_pid sem_next_id msg_next_id shm_next_id; do
    source=/run/droidspaces/proc/sys/kernel/$name
    target=/proc/sys/kernel/$name
    test "$(findmnt -n -o FSTYPE -T "$source")" = proc
    test "$(findmnt -n -o FSTYPE -T "$target")" = proc
    test "$(stat -Lc '%d:%i' "$source")" = "$(stat -Lc '%d:%i' "$target")"
    if ! mountpoint -q "$target"; then mount --bind "$source" "$target"; fi
    mount -o remount,bind,rw "$target"
    case ",$(findmnt -n -o OPTIONS -T "$target")," in *,rw,*) ;; *) exit 1 ;; esac
done
case ",$(findmnt -n -o OPTIONS -T /proc/sys)," in *,ro,*) ;; *) exit 1 ;; esac
printf 'GUEST_PID_IPC_NAMESPACE_CHECKPOINT_SYSCTLS_READY\n'

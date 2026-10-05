#!/bin/sh
# Called only through privileged_guest.py; the existing guest remains filtered.
set -eu
test -f /etc/droidspaces
test "$(id -u)" = 0
test "$(sed -n 's/^Seccomp:[[:space:]]*//p' /proc/self/status)" = 0
action=${1:?checkpoint or restore}
container=${2:?existing rootful runc container name or id}
archive=${3:-}
case "$action" in checkpoint|restore) ;; *) exit 2 ;; esac
case "$container" in ''|*[!a-zA-Z0-9_.-]*|-*) exit 2 ;; esac
if test -n "$archive"; then
    test "$action" = checkpoint
    python3 - "$archive" <<'PY'
import os,re,sys
from pathlib import Path
path=Path(sys.argv[1])
assert re.fullmatch('/var/tmp/rmx1931-checkpoint-[a-zA-Z0-9]+/checkpoint.tar',str(path))
assert path.parent.is_dir() and not path.parent.is_symlink() and not path.exists()
assert path.parent.stat().st_uid==0
PY
fi
python3 - "$container" "$action" <<'PY'
import json,subprocess,sys
target,action=sys.argv[1:]
record=json.loads(subprocess.check_output(['podman','inspect',target]))[0]
assert record['OCIRuntime']=='runc', 'Create the container with podman --runtime=runc; crun in this guest has no CRIU support'
assert record['State']['Running']==(action=='checkpoint'), 'Container state does not match requested action'
assert not record['State'].get('Paused',False), 'Paused containers are outside this recovery entry'
print(json.dumps({'container_id':record['Id'],'runtime':record['OCIRuntime'],'action':action}),flush=True)
PY
case "$action" in
    checkpoint)
        if test -n "$archive"; then exec podman container checkpoint --keep --compress=none --export "$archive" "$container"; fi
        exec podman container checkpoint --keep "$container" ;;
    restore) exec podman container restore --keep "$container" ;;
esac

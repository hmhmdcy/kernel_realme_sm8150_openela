#!/bin/sh
# Stop only the ping-verified policy server in this guest, using its pidfd.
set -eu
test -f /etc/droidspaces
test "$(id -u)" = 0
python3 - <<'PY'
import os,signal,sys,time
from pathlib import Path
sys.path.insert(0,'/usr/local/libexec')
from rmx1931_resource_policy import send_request,SOCKET
health=send_request({'action':'ping'})
assert health['boot_id']==Path('/proc/sys/kernel/random/boot_id').read_text().strip()
assert health['pid_namespace']==os.readlink('/proc/self/ns/pid')
fd=os.pidfd_open(health['pid'])
try:signal.pidfd_send_signal(fd,signal.SIGTERM)
finally:os.close(fd)
for _ in range(50):
    if not SOCKET.exists():break
    time.sleep(.1)
else:raise RuntimeError('Policy server did not stop; inspect current state')
print('VERIFIED_RESOURCE_POLICY_SERVER_STOP_PASS',flush=True)
PY

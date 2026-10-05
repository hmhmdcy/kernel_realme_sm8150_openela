#!/bin/sh
# Initial bounded runtime proof before the complete lifecycle/pressure probe.
set -eu
test -f /etc/droidspaces
test "$(id -u)" = 0
runtime=${1:-crun}
case "$runtime" in crun|runc) ;; *) exit 2 ;; esac
python3 - "$runtime" <<'PY'
import json,subprocess,sys,uuid
runtime=sys.argv[1]
token='rmx1931-policy-smoke-'+uuid.uuid4().hex[:8]
def run(argv,check=True):
    r=subprocess.run(argv,capture_output=True,text=True,timeout=30)
    if check and r.returncode:raise RuntimeError(json.dumps({'argv':argv,'rc':r.returncode,'stdout':r.stdout,'stderr':r.stderr}))
    return r.stdout.strip()
for mode,launcher in [('rootful',['podman']),('rootless',['podman-rootless'])]:
    name=token+'-'+mode;profile=False
    try:
        run(['rmx1931-policy','set',name,'--mode',mode,'--cpus','.5','--memory-mib','64','--pids','32','--read-bps','2097152','--write-bps','2097152','--oom-group']);profile=True
        output=run(launcher+['run','--runtime='+runtime,'--rm','--name',name,'--network=none','--annotation','io.rmx1931.resource-policy='+name,'localhost/rmx1931-probe:1','/bin/sh','-c','cat /proc/self/cgroup; cat /sys/fs/cgroup/memory.max /sys/fs/cgroup/pids.max /sys/fs/cgroup/io.max /sys/fs/cgroup/memory.oom.group; sed -n "s/^Seccomp:[[:space:]]*//p" /proc/self/status'])
        print(json.dumps({'mode':mode,'runtime':runtime,'first_payload_output':output}),flush=True)
        # The payload cgroup namespace correctly renders its own group as /.
        # CPU placement/pressure are verified from the operator view separately.
        assert '67108864\n32\n' in output and 'rbps=2097152 wbps=2097152' in output and output.endswith('1\n2'),output
    finally:
        run(launcher+['rm','-f','--time','0',name],check=False)
        if profile:run(['rmx1931-policy','remove',name])
print('POLICY_FIRST_PAYLOAD_ROOTFUL_ROOTLESS_SMOKE_PASS',flush=True)
PY

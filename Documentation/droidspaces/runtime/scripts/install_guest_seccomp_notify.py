#!/usr/bin/env python3
"""Install the byte-identical foreground broker after real OCI acceptance."""
import argparse
import datetime as dt
import hashlib
import json
from pathlib import Path
import re
import shlex
import subprocess
from device_runtime import device, guest_info, read_identity, read_root, ROOT

def sha(p): return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--label',required=True)
    args=parser.parse_args()
    assert re.fullmatch(r'[a-zA-Z0-9_-]+',args.label)
    report_path=ROOT/'artifacts/droidspaces/runtime'/(args.label+'.json')
    assert not report_path.exists()
    adb=device()
    identity=read_identity(adb)
    boot_path=ROOT/'artifacts/droidspaces/extensions-harden4-seccomp-notify-boot-result.json'
    boot=json.loads(boot_path.read_text(encoding='utf-8'))
    assert identity=={k:boot[k] for k in ('kernel','boot_id')}
    assert boot['running_config_matches'] and boot['selinux']=='Enforcing'
    proof_path=ROOT/'artifacts/droidspaces/runtime/seccomp-notify-crun3-h4sn-20261004.json'
    proof=json.loads(proof_path.read_text(encoding='utf-8'))
    assert proof['returncode']==0 and proof['end_identity']==identity
    assert 'SECCOMP_NOTIFY_CRUN_BROKER_PASS' in proof['stdout']
    source=ROOT/'scripts/rmx1931_seccomp_notify.py'
    content=source.read_bytes().replace(b'\r\n',b'\n')
    digest=hashlib.sha256(content).hexdigest()
    rows=[json.loads(line) for line in proof['stdout'].splitlines() if line.startswith('{')]
    assert len([r for r in rows if r.get('broker_sha256')==digest])==2
    pid=guest_info(adb)['pid']
    target='/proc/'+str(pid)+'/root/usr/local/bin/rmx1931-seccomp-notify'
    normalized=ROOT/'tools/droidspaces/rmx1931-seccomp-notify.py'
    normalized.write_bytes(content)
    remote='/data/local/tmp/rmx1931-seccomp-notify.py'
    subprocess.run(adb+['push',str(normalized),remote],capture_output=True,check=True)
    command=('set -e; test -f /proc/'+str(pid)+'/root/etc/droidspaces; '
      'test ! -L '+target+'; test ! -L /proc/'+str(pid)+'/root/usr/local/bin; '
      'if test -e '+target+'; then test "$(sha256sum '+target+' | cut -d " " -f 1)" = '+digest+'; '
      'else test "$(sha256sum '+remote+' | cut -d " " -f 1)" = '+digest+'; '
      'cp '+remote+' '+target+'; chown 0:0 '+target+'; chmod 755 '+target+'; fi; sha256sum '+target)
    report={'observed_at':dt.datetime.now(dt.timezone.utc).isoformat(),**identity,
      'guest_pid':pid,'source_sha256':digest,'real_oci_acceptance_sha256':sha(proof_path),
      'boot_verification_sha256':sha(boot_path),'installed_path':'/usr/local/bin/rmx1931-seccomp-notify',
      'completed':False}
    try:
        installed=subprocess.run(adb+['exec-out','su','-c',command],capture_output=True,timeout=25)
        assert installed.returncode==0,installed.stderr.decode(errors='replace')
        checksum=installed.stdout.decode().split()
        if not checksum:
            checksum=read_root(adb,'sha256sum '+target).decode().split()
        assert checksum and checksum[0]==digest
        report['end_identity']=read_identity(adb)
        report['completed']=report['end_identity']==identity
    finally:
        report_path.write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
        print(json.dumps(report,indent=2),flush=True)
    assert report['completed']
if __name__=='__main__':main()

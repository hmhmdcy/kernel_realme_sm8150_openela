#!/usr/bin/env python3
"""Prove operator checkpoint/restore of a container created by the ordinary guest."""
import argparse
import datetime as dt
import hashlib
import json
import re
import subprocess
import sys
import time
from device_runtime import ROOT, device, guest_info, read_identity, read_root


def main():
    p=argparse.ArgumentParser()
    p.add_argument('--label',required=True)
    args=p.parse_args()
    assert re.fullmatch(r'[a-zA-Z0-9_-]+',args.label)
    directory=ROOT/'artifacts/droidspaces/runtime'
    report_path=directory/(args.label+'.json')
    assert not report_path.exists()
    adb=device();identity=read_identity(adb);pid=guest_info(adb)['pid']
    guest_root='/proc/'+str(pid)+'/root'
    fixture_label=args.label+'-ordinary-fixture'
    logs=directory/(args.label+'-driver-stdout.txt');errors=directory/(args.label+'-driver-stderr.txt')
    assert not logs.exists() and not errors.exists()
    report={'observed_at':dt.datetime.now(dt.timezone.utc).isoformat(),**identity,
            'ordinary_guest_filters_changed':False,'actions':[],'passed':False}
    command=[sys.executable,str(ROOT/'scripts/device_runtime.py'),'run-file',
             '--script',str(ROOT/'scripts/probe_podman_checkpoint.sh'),
             '--script-arg','external-operator','--script-arg',args.label,
             '--guest-service','--timeout','220','--label',fixture_label]
    with logs.open('wb') as out,errors.open('wb') as err:
        child=subprocess.Popen(command,stdout=out,stderr=err)
    try:
        for action in ('checkpoint','restore'):
            relative='/tmp/rmx1931-tests/checkpoint-control-'+args.label+'.'+action+'.json'
            path=guest_root+relative
            deadline=time.monotonic()+110
            request=None
            while time.monotonic()<deadline:
                raw=read_root(adb,'if test -f '+path+'; then cat '+path+'; fi')
                if raw:
                    try:request=json.loads(raw);break
                    except json.JSONDecodeError:pass
                if child.poll() is not None:
                    raise RuntimeError('Ordinary fixture exited before '+action+'; inspect its durable report')
                time.sleep(.5)
            assert request is not None,'Missing operator request'
            assert request['action']==action and re.fullmatch('[0-9a-f]{64}',request['container_id'])
            assert re.fullmatch('rmx1931-checkpoint-[a-z0-9]+',request['container_name'])
            assert re.fullmatch('/var/tmp/rmx1931-checkpoint-[a-zA-Z0-9]+',request['base'])
            assert guest_info(adb)['pid']==pid and read_identity(adb)==identity
            action_label=args.label+'-operator-'+action
            argv=[sys.executable,str(ROOT/'scripts/privileged_guest.py'),
                  '--script',str(ROOT/'scripts/control_podman_checkpoint.sh'),
                  '--script-arg',action,'--script-arg',request['container_id'],
                  '--label',action_label,'--timeout','70']
            if action=='checkpoint':
                assert request['export']==request['base']+'/checkpoint.tar'
                argv+=['--script-arg',request['export']]
            subprocess.run(argv,check=True,stdout=subprocess.DEVNULL)
            evidence=directory/(action_label+'.json')
            report['actions'].append({'request':request,'evidence':evidence.relative_to(ROOT).as_posix(),
                                      'sha256':hashlib.sha256(evidence.read_bytes()).hexdigest()})
            done=path.removesuffix('.json')+'.done'
            result=subprocess.run(adb+['exec-out','su','-c','test ! -e '+done+'; printf "done\\n" > '+done],capture_output=True,timeout=15)
            assert result.returncode==0
        assert child.wait(timeout=70)==0,'Fixture verification or cleanup failed'
        fixture=directory/(fixture_label+'.json');record=json.loads(fixture.read_text())
        assert record['returncode']==0 and record['boot_id']==identity['boot_id'] and record['end_identity']==identity
        for marker in ('OCI_CONTAINER_PROCESS_TREE_CHECKPOINT_STOP_PASS',
                       'OCI_CONTAINER_TREE_MEMORY_SOCKET_OVERLAY_VOLUME_RESTORE_PASS',
                       'PODMAN_CHECKPOINT_FIXTURE_CLEANUP_PASS'):
            assert marker in record['stdout']
        report['fixture_evidence']={'path':fixture.relative_to(ROOT).as_posix(),'sha256':hashlib.sha256(fixture.read_bytes()).hexdigest()}
        report['passed']=True
    except Exception as error:
        report['error']=str(error)
        # Do not replay a possibly committed checkpoint. The bounded ordinary
        # fixture times out and cleans its own uniquely named container/volume.
        try:child.wait(timeout=120)
        except subprocess.TimeoutExpired:report['fixture_still_pending']=True
        raise
    finally:
        report['end_identity']=read_identity(adb)
        if report['end_identity']!=identity:report['passed']=False
        report_path.write_text(json.dumps(report,indent=2)+'\n')
        print(json.dumps(report,indent=2),flush=True)
    assert report['passed']


if __name__=='__main__':
    main()

#!/usr/bin/env python3
"""Explicitly authorized real SysRq panic, with separate trigger and post-boot verification."""
import argparse
import datetime as dt
import hashlib
import json
from pathlib import Path
import re
import subprocess
import uuid
from device_runtime import device, read_identity, read_root, ROOT


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('phase',choices=['trigger','recover','verify'])
    parser.add_argument('--label',required=True)
    parser.add_argument('--authorization')
    args=parser.parse_args()
    assert re.fullmatch('[a-zA-Z0-9_-]+',args.label)
    directory=ROOT/'artifacts/droidspaces/crashlog'/args.label
    path=directory/'panic.json'
    if args.phase=='recover':
        record=json.loads(path.read_text())
        executable=str(ROOT/'tools/platform-tools/adb.exe')
        rows=[row.split() for row in subprocess.check_output([executable,'devices'],text=True).splitlines()[1:] if row.strip()]
        assert len(rows)==1 and rows[0][1]=='recovery'
        assert hashlib.sha256(rows[0][0].encode()).hexdigest()==record['transport_id_sha256']
        adb=[executable,'-s',rows[0][0]]
        def recovery_read(command):
            return subprocess.check_output(adb+['exec-out','sh','-c',command],timeout=20)
        assert recovery_read('getprop ro.product.device').strip() in (b'RMX1931',b'RMX1931CN')
        assert recovery_read('id -u').strip()==b'0'
        retained=[]
        dest=directory/'recovery-pstore'
        assert not dest.exists()
        dest.mkdir()
        for name in recovery_read('ls -1 /sys/fs/pstore').decode().splitlines():
            assert re.fullmatch('[a-zA-Z0-9_.-]+',name)
            data=recovery_read('cat /sys/fs/pstore/'+name)
            (dest/name).write_bytes(data)
            retained.append({'name':name,'sha256':hashlib.sha256(data).hexdigest(),'bytes':len(data),
                             'marker_present':record['marker'].encode() in data,
                             'panic_present':b'Kernel panic - not syncing: sysrq triggered crash' in data})
        record.update(recovery_kernel=recovery_read('uname -r').decode().strip(),recovery_records=retained,
                      recovery_boot_observed=True)
        path.write_text(json.dumps(record,indent=2)+'\n')
        assert any(item['panic_present'] for item in retained),'Preserve recovery and inspect missing panic before reboot'
        subprocess.run(adb+['reboot'],check=True,timeout=15)
        print('RECOVERY_PSTORE_PRESERVED_ANDROID_REBOOT_SENT',flush=True)
        return
    adb=device(); identity=read_identity(adb)
    if args.phase=='trigger':
        assert args.authorization and not path.exists()
        assert read_root(adb,'getenforce').strip()==b'Enforcing'
        assert read_root(adb,'getprop sys.boot_completed').strip()==b'1'
        assert read_root(adb,'cat /proc/sys/kernel/panic').strip()==b'5'
        assert not read_root(adb,'grep /mnt/Droidspaces/rmx1931-podman /proc/mounts || true').strip()
        read_root(adb,'test -w /proc/sysrq-trigger; test -c /dev/pmsg0; test -d /sys/fs/pstore')
        marker='RMX1931_CONTROLLED_PANIC_'+uuid.uuid4().hex
        record={'requested_at':dt.datetime.now(dt.timezone.utc).isoformat(),**identity,
                'boot_sha256':read_root(adb,'sha256sum /dev/block/by-name/boot').decode().split()[0],
                'authorization':args.authorization,'marker':marker,'reset_path':'actual SysRq c panic',
                'transport_id_sha256':hashlib.sha256(adb[-1].encode()).hexdigest(),
                'trigger_attempted':False,'retention_passed':False}
        directory.mkdir(parents=True)
        path.write_text(json.dumps(record,indent=2)+'\n')
        # OEM printk silently discards prefixed user writes. An unprefixed message
        # reaches the real ring buffer; confirm it before committing to a panic.
        marked=subprocess.run(adb+['exec-out','su','-c',"printf '%s\\n' '"+marker+"' > /dev/kmsg; printf '%s\\n' '"+marker+"' > /dev/pmsg0"],capture_output=True,timeout=15)
        assert marked.returncode==0
        assert marker.encode() in read_root(adb,'dmesg | grep -F '+marker)
        record['marker_verified_before_trigger']=True
        # Once trigger_attempted is durable, never automatically replay this operation.
        record['trigger_attempted']=True
        path.write_text(json.dumps(record,indent=2)+'\n')
        command='sync; printf c > /proc/sysrq-trigger'
        try:
            output=subprocess.run(adb+['exec-out','su','-c',command],capture_output=True,timeout=10)
            record.update(trigger_returncode=output.returncode,trigger_stdout=output.stdout.decode(errors='replace'),
                          trigger_stderr=output.stderr.decode(errors='replace'))
        except subprocess.TimeoutExpired:
            record['trigger_transport_timed_out']=True
        path.write_text(json.dumps(record,indent=2)+'\n')
        print(json.dumps(record,indent=2),flush=True)
    else:
        record=json.loads(path.read_text())
        assert record['trigger_attempted'] and identity['boot_id']!=record['boot_id']
        assert identity['kernel']==record['kernel']
        assert read_root(adb,'getprop sys.boot_completed').strip()==b'1'
        assert read_root(adb,'getenforce').strip()==b'Enforcing'
        assert read_root(adb,'sha256sum /dev/block/by-name/boot').decode().split()[0]==record['boot_sha256']
        observed=[]; panic_found=False; marker_found=False
        sources=['/sys/fs/pstore','/data/adb/rmx1931-crashlog/boot-'+identity['boot_id']]
        for source in sources:
            files=read_root(adb,'if test -d '+source+'; then ls -1 '+source+'; fi').decode().splitlines()
            for name in files:
                if not re.fullmatch('[a-zA-Z0-9_.-]+',name):continue
                if source=='/sys/fs/pstore' or name.startswith('pstore-'):
                    data=read_root(adb,'cat '+source+'/'+name)
                    dest=directory/('live-' if source=='/sys/fs/pstore' else 'archived-')
                    dest.mkdir(exist_ok=True)
                    (dest/name).write_bytes(data)
                    text=data.decode(errors='replace')
                    contains_marker=record['marker'] in text
                    contains_panic='Kernel panic - not syncing: sysrq triggered crash' in text
                    marker_found|=contains_marker; panic_found|=contains_panic
                    observed.append({'source':source+'/'+name,'sha256':hashlib.sha256(data).hexdigest(),
                                     'bytes':len(data),'marker_present':contains_marker,'panic_present':contains_panic})
        archived_panic=any(item['panic_present'] and '/data/adb/' in item['source'] for item in observed)
        archived_marker=any(item['marker_present'] and '/data/adb/' in item['source'] for item in observed)
        record.update(verified_at=dt.datetime.now(dt.timezone.utc).isoformat(),end_identity=identity,
                      retained_records=observed,actual_panic_present=panic_found,
                      unique_marker_present=marker_found,boot_collector_archived_panic=archived_panic,
                      boot_collector_archived_marker=archived_marker,
                      retention_passed=panic_found and marker_found and archived_panic and archived_marker)
        path.write_text(json.dumps(record,indent=2)+'\n')
        print(json.dumps(record,indent=2),flush=True)
        assert record['retention_passed'],'Actual panic/unique marker/automatic archive evidence incomplete'


if __name__=='__main__':main()

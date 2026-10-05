#!/usr/bin/env python3
"""One explicit final regression round on the current dualio boot, with durable logs."""
import datetime as dt
import argparse
import json
from pathlib import Path
import subprocess
import sys
from device_runtime import ROOT,device,read_identity

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--with-wifi', action='store_true', help='Opt in to Wi-Fi toggle/reconnect regression')
    args = parser.parse_args()
    label='postpanic20261004'
    directory=ROOT/'artifacts/droidspaces/runtime'/('final-driver-'+label)
    assert not directory.exists(),'Inspect existing driver and services; do not replay the round'
    directory.mkdir()
    identity=read_identity(device())
    assert identity['kernel'].endswith('ext-dualio')
    commands=[('v1-io','probe_io_throttling.py','--label','extensions-dualio-'+label+'-io'),
              ('cumulative','check_kernel_extension_runtime.py','--stage','dualio','--run-label',label),
              ('cpu','probe_container_cpu_quota.py','--label','container-cpu-'+label),
              ('lxc-bpf','device_runtime.py','run-file','--script',str(ROOT/'scripts/probe_lxc_device_policy.sh'),
               '--script-arg','lxc-start-bpf','--guest-service','--timeout','100','--label','lxc-bpf-'+label),
              ('bind','device_runtime.py','run-file','--script',str(ROOT/'scripts/probe_bind_propagation.sh'),
               '--guest-service','--timeout','150','--label','bind-propagation-'+label),
              ('native-io','device_runtime.py','run-file','--script',str(ROOT/'scripts/probe_guest_io_max.sh'),
               '--guest-service','--timeout','180','--label','native-io-'+label),
              ('io-writeback','device_runtime.py','run-file','--script',str(ROOT/'scripts/probe_io_hierarchy_writeback.sh'),
               '--guest-service','--timeout','100','--label','io-hierarchy-writeback-'+label),
              ('checkpoint-management','probe_checkpoint_management.py','--label','checkpoint-management-'+label),
              ('wireguard-external','probe_external_wireguard.py','--label','externalwg-'+label),
              ('bbr-cubic','probe_external_tcp.py','--label','bbr-cubic-battery-'+label,'--battery-discharge'),
              ('acceptance','record_extension_acceptance.py','--stage','dualio','--run-label',label)]
    if args.with_wifi:
        commands.insert(2, ('wifi','probe_lowrisk_wifi.py','--label','extensions-dualio-'+label+'-wifi'))
        commands[-1] += ('--with-wifi',)
    report={'started_at':dt.datetime.now(dt.timezone.utc).isoformat(),**identity,'steps':[],'passed':False}
    try:
        for name,script,*arguments in commands:
            assert read_identity(device())==identity,'Boot changed; inspect before repeating'
            print('FINAL_STEP_START '+name,flush=True)
            with (directory/(name+'.stdout')).open('wb') as out,(directory/(name+'.stderr')).open('wb') as err:
                code=subprocess.run([sys.executable,str(ROOT/'scripts'/script),*arguments],stdout=out,stderr=err).returncode
            report['steps'].append({'name':name,'returncode':code})
            (directory/'driver.json').write_text(json.dumps(report,indent=2)+'\n')
            assert code==0,'Inspect '+str(directory/(name+'.stderr'))+' and existing remote task before retry'
            print('FINAL_STEP_PASS '+name,flush=True)
        assert read_identity(device())==identity
        report['passed']=True
    finally:
        report['ended_at']=dt.datetime.now(dt.timezone.utc).isoformat()
        (directory/'driver.json').write_text(json.dumps(report,indent=2)+'\n')
    print('FINAL_DUALIO_REGRESSION_PASS',flush=True)

if __name__=='__main__':main()

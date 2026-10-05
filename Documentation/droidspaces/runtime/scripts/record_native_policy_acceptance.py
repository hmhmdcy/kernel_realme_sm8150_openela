#!/usr/bin/env python3
"""Seal actual native policy lifecycle evidence without accepting all of stage 3."""
import datetime as dt
import argparse
import hashlib
import json
import re
import shlex
from pathlib import Path
from device_runtime import ROOT,DS,NAME,device,guest_info,read_identity,read_root
from record_resource_policy_acceptance import fixture

RUNTIME=ROOT/'artifacts/droidspaces/runtime'
PHASES={
 'prepare':('native-policy-lifecycle-prepare-h2cp-20261004','probe_resource_policy_lifecycle.sh','RESOURCE_POLICY_PREPARE_PASS'),
 'admission':('native-policy-admission-h2cp-20261004','probe_resource_policy_admission.sh','RESOURCE_POLICY_ADMISSION_PASS_KERNEL_OOM_LOG_REQUIRED'),
 'outage-stop':('native-policy-server-outage-stop-h2cp-20261004','stop_guest_resource_policy.sh','VERIFIED_RESOURCE_POLICY_SERVER_STOP_PASS'),
 'outage':('native-policy-outage-h2cp-20261004','probe_resource_policy_lifecycle.sh','RESOURCE_POLICY_OUTAGE_PASS'),
 'resume':('native-policy-after-outage-h2cp-20261004','probe_resource_policy_lifecycle.sh','RESOURCE_POLICY_VERIFY_PASS'),
 'stop':('native-policy-guest-restart-workloads-stopped-h2cp-20261004','probe_resource_policy_lifecycle.sh','RESOURCE_POLICY_STOP_PASS'),
 'guest-resume':('native-policy-after-guest-restart-h2cp-20261004','probe_resource_policy_lifecycle.sh','RESOURCE_POLICY_VERIFY_PASS'),
 'crun':('native-policy-smoke-crun-h2cp-20261004','probe_resource_policy_smoke.sh','POLICY_FIRST_PAYLOAD_ROOTFUL_ROOTLESS_SMOKE_PASS'),
 'runc':('native-policy-smoke-runc-h2cp-20261004','probe_resource_policy_smoke.sh','POLICY_FIRST_PAYLOAD_ROOTFUL_ROOTLESS_SMOKE_PASS'),
 'cleanup':('native-policy-lifecycle-cleanup-h2cp-20261004','probe_resource_policy_lifecycle.sh','RESOURCE_POLICY_CLEANUP_PASS')}
def read(p):return json.loads(p.read_text(encoding='utf-8'))
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()

def main():
 parser=argparse.ArgumentParser(description=__doc__)
 parser.add_argument('--kernel-suffix',choices=('h2cp','h2cp2','h2cp3','h2cp4'),default='h2cp')
 args=parser.parse_args();suffix=args.kernel_suffix
 phases={k:(label.replace('-h2cp-','-'+suffix+'-'),source,marker) for k,(label,source,marker) in PHASES.items()}
 destination=ROOT/('artifacts/droidspaces/native-policy-'+suffix+'-acceptance.json');assert not destination.exists()
 adb=device();identity=read_identity(adb)
 assert identity['kernel']=='4.14.356-openela-rc1-perf-droidspaces-lr2-ksu3-ext-'+suffix
 evidence={}
 for phase,(label,source,marker) in phases.items():
  path=RUNTIME/(label+'.json');r=read(path)
  assert r['returncode']==0 and marker in r['stdout'],phase
  assert r['end_identity']==identity and all(r[k]==v for k,v in identity.items()),phase
  assert r['script_source_sha256']==hashlib.sha256((ROOT/'scripts'/source).read_bytes().replace(b'\r\n',b'\n')).hexdigest()
  evidence[phase]={'path':'runtime/'+path.name,'sha256':sha(path),'source_sha256':r['script_source_sha256']}
 complete=fixture(read(RUNTIME/(phases['cleanup'][0]+'.json'))['stdout'])
 assert complete['cpu_backend']=='v2' and all(complete.get(k) for k in ('passed','prepare_passed','admission_passed','outage_passed','cleanup_passed'))
 assert not complete['cleanup_errors']
 before_path=RUNTIME/('native-policy-guest-before-'+suffix+'-20261004.json');after_path=RUNTIME/('native-policy-guest-after-'+suffix+'-20261004.json')
 before,after=read(before_path),read(after_path)
 assert before['passed'] and after['passed'] and after['guest_restart_proven'] and after['previous_sha256']==sha(before_path)
 assert before['registry_sha256']==after['registry_sha256'] and before['containers']==after['containers']
 assert before['guest_pid_namespace']!=after['guest_pid_namespace']
 assert [r['pid_namespace'] for r in complete['resume_passes']]==[before['guest_pid_namespace'],after['guest_pid_namespace']]
 log_path=RUNTIME/('native-policy-oom-log-bound-'+suffix+'-20261004.json');log=read(log_path)
 assert log['returncode']==0 and log['exact_container_oom_domains_verified'] and log['end_identity']==identity
 assert log['stdout'].splitlines()[:2]==[identity['kernel'],identity['boot_id']]
 for row in complete['modes']:
  assert row['initial_cid']!=row['recreated_cid']
  assert {'create','stop-start','recreate','resume','unmanaged'}<={r['phase'] for r in row['measurements']}
  for measurement in row['measurements']:
   assert measurement['cpu']['seccomp']==2 and all(io['seccomp']==2 for io in measurement['io'])
   if measurement['neighbor']:
    assert measurement['used_cores']>2 and all(io['seconds']<2 for io in measurement['io'])
   else:
    assert .3<measurement['used_cores']<.75 and all(2.8<io['seconds']<12 for io in measurement['io'])
    assert measurement['pids']['errno']==11 and 8<=measurement['pids']['children']<32
  for snap in row['snapshots']:
   assert snap['cpu_backend']=='v2' and snap['legacy_cpu_group']=='/' and snap['first_payload']['seccomp']==2
   assert snap['first_payload']['cpu_max']==('max 100000' if snap['neighbor'] else '50000 100000')
  domain='/libpod-'+row['admission']['oom_container_id']+'.scope/container'
  assert any(domain in l and 'killed as a result of limit of' in l for l in log['stdout'].splitlines())
  assert any(domain in l and 'are going to be killed due to memory.oom.group set' in l for l in log['stdout'].splitlines())
  assert row['admission']['oom_exec_exit']==137
  assert {e['case'] for e in row['admission']['negative']}=={'unknown','wrong-user'}
  assert row['admission']['profile_change_exit']==row['admission']['profile_remove_exit']==row['admission']['rootless_admin_exit']==125
  assert all(row['outage'][k]!=0 for k in ('exec_exit','start_exit','create_exit')) and 'policy service unavailable' in row['outage']['diagnostic']
 for path in (before_path,after_path,log_path):evidence[path.stem]={'path':'runtime/'+path.name,'sha256':sha(path)}
 init=guest_info(adb)['pid'];assert init==after['guest_pid'];root=f'/proc/{init}/root'
 assert read_root(adb,'getenforce').strip()==b'Enforcing'
 assert re.search(r'^Seccomp:\s+2$',read_root(adb,'cat '+root+'/proc/1/status').decode(),re.M)
 assert not json.loads(read_root(adb,'cat '+root+'/etc/rmx1931/resource-policies.json'))['profiles']
 assert not read_root(adb,'find '+root+'/var/lib/rmx1931-policy/containers -mindepth 1 -maxdepth 1 -type f').strip()
 for launcher in ('podman','podman-rootless'):
  assert not read_root(adb,shlex.join([DS,'--name='+NAME,'run',launcher,'ps','-aq'])).strip()
 health=json.loads(read_root(adb,shlex.join([DS,'--name='+NAME,'run','rmx1931-policy','ping'])))
 assert health['cpu_backend']=='v2' and health['boot_id']==identity['boot_id'] and health['pid_namespace']==after['guest_pid_namespace']
 fatal=read_root(adb,"dmesg | grep -E 'Kernel panic - not syncing|Oops:|BUG:|Unable to handle kernel|soft lockup' || true").decode();assert not fatal,fatal
 assert read_identity(adb)==identity
 result={'observed_at':dt.datetime.now(dt.timezone.utc).isoformat(),**identity,'passed':True,
  'scope':'native V2 CPU/IO/memory/pids persistent policy lifecycle regression only',
  'complete_native_cpu_cpuset_stage_accepted':False,'cpu_backend':'v2','evidence':evidence,
  'guest_restart_before':before['guest_pid_namespace'],'guest_restart_after':after['guest_pid_namespace'],
  'registry_persisted_sha256':after['registry_sha256'],'modes':complete['modes'],
  'cleanup_passed':True,'normal_guest_seccomp':2,'selinux':'Enforcing','fatal_kernel_log':False,
  'remaining_stage3':(['Joint stage 3 acceptance is recorded separately'] if suffix=='h2cp4' else
    ['Podman native weight regression','rootless cpuset fix validation','V1/V2 coexistence','CPU quota/threaded hierarchy and Android performance policy regression'])}
 destination.write_text(json.dumps(result,indent=2,ensure_ascii=False)+'\n',encoding='utf-8')
 print(json.dumps({'passed':True,'scope':result['scope'],'evidence_reports':len(evidence),'complete_stage3':False},ensure_ascii=False))

if __name__=='__main__':main()

#!/usr/bin/env python3
"""Seal stage 5 from same-boot native, actual OCI broker and regression proofs."""
import datetime as dt
import hashlib
import json
import re
from device_runtime import ROOT,device,guest_info,read_identity,read_root
from record_binfmt_acceptance import rows

ART=ROOT/'artifacts/droidspaces'
STAGE='harden4-seccomp-notify'
def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def read(path):return json.loads(path.read_text(encoding='utf-8'))
def main():
    target=ART/'seccomp-notify-stage5-acceptance.json'
    assert not target.exists()
    boot_path=ART/('extensions-'+STAGE+'-boot-result.json')
    boot=read(boot_path)
    identity={k:boot[k] for k in ('kernel','boot_id')}
    assert identity['kernel'].endswith('-ext-h4sn') and boot['running_config_matches']
    audit_path=ART/('kernel-ext-'+STAGE)/'audit.json'
    audit=read(audit_path)
    predecessor=ART/'binfmt-stage4-acceptance.json'
    assert read(predecessor)['complete_stage_4_accepted']
    assert audit['build_audit_passed'] and audit['source']['stage4_acceptance_sha256']==sha(predecessor)
    assert not audit['export_crc']['missing'] and not audit['export_crc']['changed']
    evidence={}
    def proof(name,label,source,marker):
        p=ART/'runtime'/(label+'.json')
        data=read(p)
        assert all(data[k]==v for k,v in identity.items()) and data['end_identity']==identity,label
        assert data['returncode']==0 and marker in data['stdout'] and not data.get('cleanup_errors'),label
        digest=hashlib.sha256((ROOT/source).read_bytes().replace(b'\r\n',b'\n')).hexdigest()
        assert data['script_source_sha256']==digest,label
        evidence[name]={'path':p.relative_to(ART).as_posix(),'sha256':sha(p),
                        'source_path':source,'source_sha256':digest}
        return data
    selected=proof('upstream-selftests','seccomp-notify-upstream-h4sn-20261004',
                   'scripts/probe_seccomp_notify_selftests.sh','SECCOMP_NOTIFY_UPSTREAM_SELFTESTS_PASS')
    assert len(re.findall(r'^ok \d+ global\.',selected['stdout'],re.M))==25
    assert not re.search(r'^not ok|# SKIP',selected['stdout'],re.M)
    assert 'total=25 failures=0 skips_rejected=1' in selected['stdout']
    assert selected['guest_filters_changed'] is False
    broker_sha=hashlib.sha256((ROOT/'scripts/rmx1931_seccomp_notify.py').read_bytes().replace(b'\r\n',b'\n')).hexdigest()
    crun=proof('crun-broker','seccomp-notify-crun3-h4sn-20261004',
       'references/runtime-probes/seccomp-notify-crun-attempt3-20261004/probe_seccomp_notify_crun.sh',
       'SECCOMP_NOTIFY_CRUN_BROKER_PASS')
    crun_rows=rows(crun['stdout'])
    assert len([r for r in crun_rows if r.get('broker_sha256')==broker_sha])==2
    cases=[r for r in crun_rows if 'case' in r]
    assert {(r['uid'],r['case']) for r in cases}=={(u,c) for u in (0,1000) for c in ('normal','closed','deadline')}
    for case in cases:
        assert case['crun_rc']==case['broker_rc']==0 and not case['broker_stderr']
        payload=json.loads(case['payload'])
        assert payload['seccomp']==2
        events=case['events']
        accepted=next(e for e in events if e['event']=='listener_accepted')
        assert accepted['peer_uid']==case['uid'] and accepted['target_starttime'].isdigit()
        if case['case']=='normal':
            assert {e['decision'] for e in events if e['event']=='request_answered'}=={'emulate','deny','continue','addfd'}
            assert sum(e['event']=='listener_rejected' for e in events)==2
            assert any(e['event']=='listener_hup' for e in events)
            assert payload['emulated']==777 and payload['denied']==-1 and payload['denied_errno']==1
            assert payload['continued_pid']==1 and payload['read_bytes']==18 and payload['cloexec']==1
        else:
            expected='listener_closed_on_request' if case['case']=='closed' else 'deadline_closed_listener'
            assert any(e['event']==expected for e in events)
            assert payload['result']==-1 and payload['errno']==38
    binding=proof('installed-broker-target-binding','seccomp-notify-target-binding-h4sn-20261004',
                  'scripts/probe_seccomp_notify_crun.sh','SECCOMP_NOTIFY_CRUN_TARGET_BINDING_PASS')
    bound=[r for r in rows(binding['stdout']) if 'case' in r]
    assert {r['uid'] for r in bound}=={0,1000} and len(bound)==2
    for case in bound:
        assert case['crun_rc']==case['broker_rc']==0 and case['case']=='target-change'
        payload=json.loads(case['payload'])
        assert payload['child_denied']==1 and payload['parent_result']==777 and payload['seccomp']==2
        accepted=next(e for e in case['events'] if e['event']=='listener_accepted')
        answered=[e for e in case['events'] if e['event']=='request_answered']
        assert len(answered)==2 and answered[0]['target_pid']!=accepted['target_pid'] and answered[0]['decision']=='deny'
        assert answered[1]['target_pid']==accepted['target_pid'] and answered[1]['decision']=='emulate'
    proof('filter-preservation','seccomp-notify-filter-preservation-h4sn-20261004',
          'scripts/probe_container_seccomp_setresuid.sh','CONTAINER_SECCOMP_SETRESUID_PASS')
    native=proof('native-cpu-cpuset','seccomp-notify-native-cpu-h4sn-20261004',
                 'scripts/probe_native_cpu_podman.sh','NATIVE_CPU_PODMAN_PASS')
    assert next(r for r in rows(native['stdout']) if 'modes' in r)['passed']
    cross=proof('crossarch','seccomp-notify-crossarch-pinned-h4sn-20261004',
                'scripts/probe_binfmt_crossarch_podman_pinned.sh','BINFMT_CROSSARCH_PODMAN_PASS')
    summary=next(r for r in rows(cross['stdout']) if r.get('entry_mode')=='helper')
    assert summary['passed'] and summary['entry_seccomp']==summary['ordinary_guest_seccomp']==2
    assert summary['namespace_fds_pinned'] and len({m['user_namespace'] for m in summary['modes']})==2
    assert summary['global_registration_sha256_before']==summary['global_registration_sha256_after']
    assert {m['mode'] for m in summary['modes']}=={'rootful','rootless'}
    for mode in summary['modes']:
        assert mode['passed'] and not mode['cleanup_errors'] and mode['local_revocation_returncode']!=0
        for arch,case in mode['cases'].items():
            assert arch in ('amd64','arm64')
            for kind in ('build_payload','run_payload','nonroot_payload','runc_payload'):
                row=case[kind]
                assert row['architecture']==arch and row['seccomp']==2 and row['build_marker']
                assert row['uid']==row['gid']==(1000 if kind=='nonroot_payload' else 0)
    for runtime in ('crun','runc'):
        proof('policy-'+runtime,'seccomp-notify-policy-'+runtime+'-h4sn-20261004',
              'scripts/probe_resource_policy_smoke.sh','POLICY_FIRST_PAYLOAD_ROOTFUL_ROOTLESS_SMOKE_PASS')
    cpu=proof('policy-cpu','seccomp-notify-policy-cpu-h4sn-20261004',
              'scripts/probe_resource_policy_cpu_backend.sh','POLICY_CPU_BACKEND_PRESSURE_PASS')
    assert next(r for r in rows(cpu['stdout']) if 'modes' in r)['passed']
    installed_path=ART/'runtime/seccomp-notify-broker-install-h4sn-20261004.json'
    installed=read(installed_path)
    assert installed['completed'] and installed['end_identity']==identity and installed['source_sha256']==broker_sha
    assert installed['real_oci_acceptance_sha256']==evidence['crun-broker']['sha256']
    evidence['broker-installation']={'path':installed_path.relative_to(ART).as_posix(),'sha256':sha(installed_path)}
    adb=device()
    assert read_identity(adb)==identity
    assert read_root(adb,'getenforce').strip()==b'Enforcing'
    assert read_root(adb,'getprop sys.boot_completed').strip()==b'1'
    assert b'uid=0(root)' in read_root(adb,'id')
    ksu=read_root(adb,'/data/adb/ksud debug info').decode()
    assert 'version: 33304' in ksu and 'uapi_version: 4' in ksu
    assert read_root(adb,'cat /sys/devices/system/cpu/online').strip()==b'0-7'
    assert read_root(adb,'zcat /proc/config.gz')==(ART/('kernel-ext-'+STAGE)/'resolved.config').read_bytes()
    assert read_root(adb,'sha256sum /dev/block/by-name/boot').decode().split()[0]==boot['boot_sha256']
    pid=guest_info(adb)['pid'];root='/proc/'+str(pid)+'/root'
    status=read_root(adb,'cat /proc/'+str(pid)+'/status').decode()
    assert re.search(r'^Seccomp:\s+2$',status,re.M)
    assert read_root(adb,'sha256sum '+root+'/usr/local/bin/rmx1931-seccomp-notify').decode().split()[0]==broker_sha
    assert not json.loads(read_root(adb,'cat '+root+'/etc/rmx1931/resource-policies.json'))['profiles']
    leftovers=read_root(adb,'find '+root+'/var/lib/rmx1931-policy/containers -name "*.json"; '
      'find '+root+'/var/tmp -maxdepth 1 -type d \\( -name "rmx1931-notify-*" -o -name "rmx1931-crossarch-*" \\); '
      'find /sys/fs/cgroup/droidspaces/rmx1931-podman -maxdepth 1 -type d -name "privileged-seccomp-notify*"; '
      'printf "SECCOMP_CLEANUP_READ_COMPLETE\\n"').decode()
    assert leftovers.strip()=='SECCOMP_CLEANUP_READ_COMPLETE',leftovers
    log=read_root(adb,'printf "SECCOMP_LOG_BEGIN\\n"; dmesg; printf "SECCOMP_LOG_END\\n"').decode()
    assert log.startswith('SECCOMP_LOG_BEGIN\n') and log.rstrip().endswith('SECCOMP_LOG_END')
    assert not re.search(r'Kernel panic - not syncing|Oops:|BUG:|Unable to handle kernel|soft lockup',log)
    assert read_identity(adb)==identity
    receipt={'observed_at':dt.datetime.now(dt.timezone.utc).isoformat(),**identity,'stage':STAGE,
     'passed':True,'complete_stage_5_accepted':True,'boot_sha256':boot['boot_sha256'],
     'build_audit_sha256':sha(audit_path),'boot_verification_sha256':sha(boot_path),
     'predecessor_stage4_acceptance_sha256':sha(predecessor),'evidence':evidence,
     'upstream_tests':{'passed':25,'failed':0,'skipped':0},'actual_oci_modes':['rootful','rootless'],
     'guest_pid':pid,'normal_guest_seccomp':2,'selinux':'Enforcing','ksu_version':33304,
     'cpu_online':'0-7','cleanup_passed':True,'fatal_kernel_log':False,
     'scope':'Seccomp notification core and FD/lifetime ABI; actual filtered crun broker and target binding; affected Podman/crossarch/resources',
     'limitations':['ARM64 single-process foreground example broker; four pointer-free demonstration syscalls',
                    'Explicit OCI notify profile only; ordinary seccomp profile retained',
                    'ADDFD_SEND and WAIT_KILLABLE_RECV not included'],
     'remaining_functional_stages':[6]}
    target.write_text(json.dumps(receipt,indent=2)+'\n',encoding='utf-8')
    runtime={**boot,'runtime_passed':True,'stage5_acceptance_sha256':sha(target),
             'boot_verification_sha256':sha(boot_path),'scope':receipt['scope']}
    output=ART/('extensions-'+STAGE+'-runtime-result.json')
    assert not output.exists()
    output.write_text(json.dumps(runtime,indent=2)+'\n',encoding='utf-8')
    print(json.dumps({'complete_stage_5_accepted':True,'receipt_sha256':sha(target),'evidence_reports':len(evidence)}))
if __name__=='__main__':main()

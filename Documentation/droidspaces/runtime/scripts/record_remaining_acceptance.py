#!/usr/bin/env python3
"""Accept the complete extended matrix only from current-boot functional evidence."""
import datetime as dt
import gzip
import hashlib
import json
from pathlib import Path
import shlex
import statistics
import subprocess
from device_runtime import ROOT, DS, NAME, device, guest_info, read_identity, read_root

ART=ROOT/'artifacts/droidspaces'
LABEL='postpanic20261004'
BOOT='fe5edbce96623c20c51f5cf83d08d302298004e71540ae8b7771df6c8d866bac'

def read(path):return json.loads(path.read_text(encoding='utf-8'))
def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()

def main():
    adb=device();identity=read_identity(adb)
    assert identity['kernel']=='4.14.356-openela-rc1-perf-droidspaces-lr2-ksu3-ext-dualio'
    evidence={}
    def proof(name,relative,markers=(),script=None,boot_bound=True):
        path=ART/relative;record=read(path)
        assert path.resolve().is_relative_to(ART.resolve())
        if boot_bound:
            assert record['kernel']==identity['kernel'] and record['boot_id']==identity['boot_id'],name
            if 'end_identity' in record:assert record['end_identity']==identity,name
        if 'returncode' in record:assert record['returncode']==0,name
        if 'passed' in record:assert record['passed'],name
        if 'cleanup_errors' in record:assert not record['cleanup_errors'],name
        for marker in markers:assert marker in record['stdout'],(name,marker)
        if script:
            assert record['script_source_sha256']==hashlib.sha256((ROOT/'scripts'/script).read_bytes().replace(b'\r\n',b'\n')).hexdigest(),name
        evidence[name]={'path':path.relative_to(ROOT).as_posix(),'sha256':sha(path)}
        return record
    regression=proof('cumulative','extensions-dualio-'+LABEL+'-acceptance.json')
    assert regression['runtime_passed'] and len(regression['probe_evidence'])==19
    assert regression['official_capabilities_passed']==27 and regression['boot_sha256']==BOOT
    for item in regression['probe_evidence'].values():
        assert sha(ROOT/item['path'])==item['sha256']
    cpu=proof('cpu','runtime/container-cpu-'+LABEL+'.json')
    assert {row['mode'] for row in cpu['containers']}=={'rootful','rootless'}
    cpu_summary=[]
    for row in cpu['containers']:
        assert row['passed'] and row['throttled_periods']>0
        assert row['baseline']['cpu_ratio']>2 and .35<row['limited']['cpu_ratio']<.7 and row['restored']['cpu_ratio']>2
        assert all(row[phase]['seccomp']==2 for phase in ('baseline','limited','restored'))
        assert all(row[phase]['completed'] and row[phase]['payload_unfrozen'] and row[phase]['end_identity']==identity for phase in ('quota_entry','release_entry'))
        assert row['quota_entry']['android_processes_moved'] is False
        assert row['cleanup']=='CONTAINER_CPU_FIXTURE_CLEANUP_PASS'
        cpu_summary.append({key:row[key] for key in ('mode','baseline','limited','restored','throttled_periods')})
    native=proof('native-io','runtime/native-io-'+LABEL+'.json',
                 ['GUEST_ROOTFUL_ROOTLESS_NATIVE_IO_MAX_READ_WRITE_PASS'],'probe_guest_io_max.sh')
    io=json.JSONDecoder().raw_decode(native['stdout'][native['stdout'].index('{'):])[0]
    assert io['passed'] and not io['cleanup_errors'] and io['fixture_bytes']==16777216 and io['limit_bps']==2097152
    assert {row['mode'] for row in io['modes']}=={'guest','rootful','rootless'}
    io_summary=[]
    for row in io['modes']:
        assert row['passed'] and len(row['measurements'])==6
        for measurement in row['measurements']:
            assert measurement['device']==io['major_minor'] and measurement['bytes']==16777216
            assert measurement['seccomp']==2 and measurement['accounted_bytes']>=16777216
        for operation in ('read','write'):
            points={m['phase']:m['seconds'] for m in row['measurements'] if m['operation']==operation}
            assert points['limited']>=6 and points['limited']>2*points['baseline'] and points['restored']<points['limited']/2
            io_summary.append({'mode':row['mode'],'operation':operation,**points})
        if row['mode']=='rootless':assert row['rootless_self_service_io_max']
    writeback=proof('io-hierarchy-writeback','runtime/io-hierarchy-writeback-'+LABEL+'.json',
                    ['V2_IO_PARENT_SIBLING_BUFFERED_WRITEBACK_ENFORCEMENT_PASS'],'probe_io_hierarchy_writeback.sh')
    wb=json.JSONDecoder().raw_decode(writeback['stdout'])[0]
    assert wb['passed'] and not wb['cleanup_errors'] and wb['disable_selection_rejected_errno']==22
    wb_times={m['phase']:m['seconds'] for m in wb['measurements']}
    assert wb_times['buffered-write-parent-limit']>=6 and wb_times['direct-read-parent-limit']>=6
    assert wb_times['unlimited-sibling-read']<wb_times['direct-read-parent-limit']/2
    proof('lxc-bpf','runtime/lxc-bpf-'+LABEL+'.json',
          ['LXC_DEVICE_POLICY_ALLOW_PASS','LXC_DEVICE_POLICY_DENY_PASS','LXC_DEVICE_BPF_ALLOW_DENY_ALIAS_CLEANUP_PASS'],
          'probe_lxc_device_policy.sh')
    proof('bind-propagation','runtime/bind-propagation-'+LABEL+'.json',
          ['BIND_'+mode+'_'+policy+'_HOST_TO_CONTAINER_AND_UNMOUNT_PASS' for mode in ('rootful','rootless') for policy in ('rslave','rprivate')]+
          ['BIND_rootful_READ_ONLY_ENFORCEMENT_PASS','BIND_rootless_READ_ONLY_ENFORCEMENT_PASS',
           'BIND_ROOTFUL_RSHARED_BIDIRECTIONAL_PASS','BIND_PROPAGATION_CLEANUP_PASS'],'probe_bind_propagation.sh')
    checkpoint=proof('checkpoint-management','runtime/checkpoint-management-'+LABEL+'.json')
    assert checkpoint['ordinary_guest_filters_changed'] is False
    fixture=checkpoint['fixture_evidence'];assert sha(ROOT/fixture['path'])==fixture['sha256']
    ordinary=read(ROOT/fixture['path']);assert ordinary['returncode']==0 and ordinary['end_identity']==identity
    assert all(marker in ordinary['stdout'] for marker in ('OCI_CONTAINER_PROCESS_TREE_CHECKPOINT_STOP_PASS',
        'OCI_CONTAINER_TREE_MEMORY_SOCKET_OVERLAY_VOLUME_RESTORE_PASS','PODMAN_CHECKPOINT_FIXTURE_CLEANUP_PASS'))
    for item in checkpoint['actions']:
        path=ROOT/item['evidence'];assert sha(path)==item['sha256']
        operator=read(path);assert operator['returncode']==0 and operator['guest_filters_changed'] is False
        assert operator['end_identity']==identity and not operator['cleanup_errors']
    def successful(prefix):
        paths=sorted((ART/'runtime').glob(prefix+'*.json'),key=lambda p:p.stat().st_mtime,reverse=True)
        for path in paths:
            record=read(path)
            if record.get('passed') and record.get('boot_id')==identity['boot_id'] and record.get('end_identity')==identity:
                return path.relative_to(ART).as_posix()
        raise RuntimeError('No successful current-boot evidence: '+prefix)
    wg=proof('wireguard-external',successful('externalwg-'+LABEL))
    assert wg['renewed_handshake']>wg['initial_handshake']
    assert '0% packet loss' in wg['recovery_ping'] and '100% packet loss' in wg['wrong_key_rejected']
    network=proof('bbr-cubic-battery',successful('bbr-cubic-battery-'+LABEL))
    assert network['energy_measurement_valid'] and network['charging_input_restored']
    assert len(network['trials'])==6 and all(sum(t['algorithm']==a for t in network['trials'])==3 for a in ('cubic','bbr'))
    network_summary={}
    for algorithm in ('cubic','bbr'):
        trials=[row for row in network['trials'] if row['algorithm']==algorithm]
        network_summary[algorithm]={key:[row[key] for row in trials] for key in
            ('megabits_per_second','rtt_microseconds_mean','sender_cpu_seconds','measured_battery_mwh_per_gib')}
    panic=proof('panic','crashlog/controlled-panic-dualio20261004/panic.json',boot_bound=False)
    assert panic['retention_passed'] and panic['end_identity']==identity and panic['kernel']==identity['kernel'] and panic['boot_sha256']==BOOT
    copies=panic['recovery_records']+[r for r in panic['retained_records'] if r['panic_present']]
    assert len(copies)==3 and all(row['panic_present'] and row['marker_present'] for row in copies)
    assert len({row['sha256'] for row in copies})==1
    audit=read(ART/'kernel-ext-dualio/audit.json');sync=read(ART/'dualio-local-source-sync.json')
    assert audit['build_audit_passed'] and sync['passed'] and len(sync['verified_source_sha256'])==32
    for name,digest in sync['verified_source_sha256'].items():assert sha(ROOT/'worktrees/rmx1931-ksunext3'/name)==digest
    assert hashlib.sha256(gzip.decompress(read_root(adb,'cat /proc/config.gz'))).hexdigest()==audit['resolved_config_sha256']
    assert read_root(adb,'sha256sum /dev/block/by-name/boot').decode().split()[0]==BOOT
    assert read_root(adb,'getenforce').strip()==b'Enforcing' and read_root(adb,'getprop sys.boot_completed').strip()==b'1'
    assert read_root(adb,'cat /sys/class/power_supply/battery/input_suspend').strip()==b'0'
    assert read_root(adb,'cat /proc/sys/net/ipv4/tcp_congestion_control').strip()==b'cubic'
    assert read_root(adb,'cat /dev/blkio/blkio.weight; cat /dev/blkio/background/blkio.weight').split()==[b'1000',b'200']
    assert not read_root(adb,"find /dev/cpuctl -maxdepth 1 -type d -name 'rmx1931-container-*'").strip()
    pid=guest_info(adb)['pid']
    command='cd /var/tmp; test -z "$(podman ps -aq)"; test -z "$(podman-rootless ps -aq)"; test -z "$(find /run/rmx1931-cpu -mindepth 1 -maxdepth 1)"; echo FINAL_GUEST_CLEANUP_PASS'
    assert b'FINAL_GUEST_CLEANUP_PASS' in read_root(adb,shlex.join([DS,'--name='+NAME,'run','/bin/sh','-ec',command]))
    guest_status=read_root(adb,'cat /proc/'+str(pid)+'/status').decode()
    assert any(line.startswith('Seccomp:') and line.split()[1]=='2' for line in guest_status.splitlines())
    dmesg=read_root(adb,'dmesg')
    fatal=[line for line in dmesg.decode(errors='replace').splitlines() if any(word in line for word in ('BUG:','Oops:','Kernel panic -','Unknown symbol','disagrees about version'))]
    assert not fatal,fatal[:3]
    assert read_identity(adb)==identity
    report={'accepted_at':dt.datetime.now(dt.timezone.utc).isoformat(),**identity,
            'goal_scope':'Previously unfinished kernel and container functional matrix',
            'passed':True,'boot_sha256':BOOT,'selinux':'Enforcing','ordinary_guest_seccomp':2,
            'cumulative_probes_passed':19,'official_capabilities_passed':27,'evidence':evidence,
            'cpu':cpu_summary,'native_io':io_summary,'io_writeback':wb_times,
            'wireguard_megabits_per_second':{key:wg[key]['end']['sum_received']['bits_per_second']/1e6 for key in
                ('computer_to_phone','phone_to_computer')},'bbr_cubic':network_summary,
            'battery_measurement_scope':network['energy_scope'],
            'panic_bytes':copies[0]['bytes'],'panic_sha256':copies[0]['sha256'],
            'source_sync_sha256':sha(ART/'dualio-local-source-sync.json'),
            'kernel_audit_sha256':sha(ART/'kernel-ext-dualio/audit.json'),
            'current_dmesg_sha256':hashlib.sha256(dmesg).hexdigest(),
            'kernel_fatal_errors_observed':[],'temporary_workloads_and_cpu_mounts_cleaned':True,
            'limitations':['CPU quota uses an Android-root V1 leaf operator and managed OCI runtime; native V2 cpu.max is unavailable',
                           'Whole-container restore requires the separate Android-root entry and runc/CRIU; ordinary guest remains filtered',
                           'Personal optional dual IO fork changes module ABI; io.low is unsupported',
                           'BBR throughput and net battery measurements apply only to the recorded Wi-Fi workload',
                           'Individual camera/sensor/IMS hardware certification and cross-device container migration are outside this acceptance'],
            'publication_performed':False}
    target=ART/'remaining-acceptance-20261004.json';assert not target.exists()
    target.write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
    public={key:value for key,value in report.items() if key not in ('boot_id','evidence')}
    public['evidence_sha256']={key:item['sha256'] for key,item in evidence.items()}
    public['private_device_logs_included']=False
    (ROOT/'worktrees/rmx1931-ksunext3/Documentation/droidspaces/remaining-acceptance-20261004.json').write_text(
        json.dumps(public,indent=2)+'\n',encoding='utf-8')
    print(json.dumps({'passed':True,'probes':19,'capabilities':27,'extended_evidence':len(evidence),'boot_sha256':BOOT}))

if __name__=='__main__':main()

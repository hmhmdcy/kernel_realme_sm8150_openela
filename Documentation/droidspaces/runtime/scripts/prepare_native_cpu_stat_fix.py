#!/usr/bin/env python3
"""Prepare and audit an immutable repair of native CPU split accounting."""
import argparse
import difflib
import hashlib
import json
from pathlib import Path
from audit_lowrisk_kernel import config, symbols

ROOT=Path(__file__).resolve().parents[1]
ART=ROOT/'artifacts/droidspaces'
BASE=ART/'kernel-ext-harden2-cpuset-decay'
DEST=ART/'kernel-ext-harden2-cpuset-stats'
UPSTREAM=ROOT/'references/native-cpuset-upstream/rstat-linux-v4.19.c'
UPSTREAM_SHA='6592872b8301a81571978e34f1d614dd9de756047228267fc01ad1292ea7d25d'
UPSTREAM_HEADER=ROOT/'references/native-cpuset-upstream/cputime-header-linux-v4.19.h'
UPSTREAM_HEADER_SHA='1ca5179c205259321ebb89b1c413d829a1852445b12db9530039c5411c05f748'
UPSTREAM_CPUTIME=ROOT/'references/native-cpuset-upstream/cputime-linux-v4.19.c'
UPSTREAM_CPUTIME_SHA='32acd1ee5b17ac8480e9ff42cfdaf2862e15a86026345612ad1642e0fa3fd8a6'
RELEASE='4.14.356-openela-rc1-perf-droidspaces-lr2-ksu3-ext-h2cp4'
FAILURE='runtime/native-cpu-stat-settled-semantics-h2cp3-20261004.json'

def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def read(path):return json.loads(path.read_text(encoding='utf-8'))
def save(path,data):path.write_text(json.dumps(data,indent=2)+'\n',encoding='utf-8')

def replace_once(text,old,new):
    assert text.count(old)==1,old
    return text.replace(old,new)

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--prepare',action='store_true');p.add_argument('--source',type=Path)
    p.add_argument('--after-build',action='store_true');args=p.parse_args()
    prior=read(BASE/'audit.json');assert prior['build_audit_passed']
    assert sha(BASE/'Image.gz-dtb')==prior['kernel_sha256'] and sha(UPSTREAM)==UPSTREAM_SHA
    assert sha(UPSTREAM_HEADER)==UPSTREAM_HEADER_SHA
    assert sha(UPSTREAM_CPUTIME)==UPSTREAM_CPUTIME_SHA
    failure=read(ART/FAILURE)
    assert failure['returncode']==1 and failure['kernel'].endswith('-ext-h2cp3')
    assert failure['end_identity']=={'kernel':failure['kernel'],'boot_id':failure['boot_id']}
    assert 'NATIVE_CPU_STAT_CONSISTENCY_FAILED' in failure['stdout']
    assert sha(ROOT/'scripts/probe_native_cpu_stat_consistency.sh')==failure['script_source_sha256']
    before_source=Path(prior['source']['source'])
    assert all(sha(before_source/n)==h for n,h in prior['cumulative_source_sha256'].items())
    changes={}
    name='include/linux/sched/cputime.h';original=(before_source/name).read_text()
    old='extern void thread_group_cputime_adjusted(struct task_struct *p, u64 *ut, u64 *st);'
    changed=replace_once(original,old,old+'\nextern void cputime_adjust(struct task_cputime *curr, struct prev_cputime *prev,\n\t\t\t   u64 *ut, u64 *st);')
    changes[name]=(original,changed)
    name='kernel/sched/cputime.c';original=(before_source/name).read_text()
    changed=replace_once(original,'static void cputime_adjust(struct task_cputime *curr,',
        'void cputime_adjust(struct task_cputime *curr,')
    upstream=UPSTREAM_CPUTIME.read_text()
    start=upstream.index('void cputime_adjust(struct task_cputime *curr,')
    end=upstream.index('\n}\n',start)+3
    native_adjust=upstream[start:end]
    assert '*ut = curr->utime;' in native_adjust and '*st = curr->stime;' in native_adjust
    native_anchor='\n#else /* !CONFIG_VIRT_CPU_ACCOUNTING_NATIVE */'
    changed=replace_once(changed,native_anchor,'\n'+native_adjust+'\n'+native_anchor)
    changes[name]=(original,changed)
    name='kernel/sched/sched.h';original=(before_source/name).read_text()
    changed=replace_once(original,'\tstruct rmx_cpu_time __percpu *rmx_cputime;',
        '\tstruct rmx_cpu_time __percpu *rmx_cputime;\n\tstruct prev_cputime rmx_prev_cputime;')
    changes[name]=(original,changed)
    name='kernel/sched/rmx_cpu_v2.h';original=(before_source/name).read_text()
    changed=replace_once(original,'static struct cgroup_subsys_state *',
        '#include <linux/sched/cputime.h>\n\n/* Serialize read snapshots, as upstream rstat does before cputime_adjust. */\nstatic DEFINE_MUTEX(rmx_cpu_stat_lock);\n\nstatic struct cgroup_subsys_state *')
    changed=replace_once(changed,'\treturn &tg->css;',
        '\tprev_cputime_init(&tg->rmx_prev_cputime);\n\treturn &tg->css;')
    changed=replace_once(changed,'\tstruct cfs_bandwidth *bandwidth = &tg->cfs_bandwidth;',
        '\tstruct cfs_bandwidth *bandwidth = &tg->cfs_bandwidth;\n\tstruct task_cputime cputime;')
    changed=replace_once(changed,'\tfor_each_possible_cpu(cpu) {\n\t\tstruct rmx_cpu_time *time',
        '\tmutex_lock(&rmx_cpu_stat_lock);\n\tfor_each_possible_cpu(cpu) {\n\t\tstruct rmx_cpu_time *time')
    changed=replace_once(changed,'\tseq_printf(sf, "usage_usec %llu\\nuser_usec %llu\\nsystem_usec %llu\\n"',
        '\tcputime.utime = user;\n\tcputime.stime = system;\n\tcputime.sum_exec_runtime = usage;\n\tcputime_adjust(&cputime, &tg->rmx_prev_cputime, &user, &system);\n\tmutex_unlock(&rmx_cpu_stat_lock);\n\tseq_printf(sf, "usage_usec %llu\\nuser_usec %llu\\nsystem_usec %llu\\n"')
    changes[name]=(original,changed)
    patch=''.join(''.join(difflib.unified_diff(old.splitlines(True),new.splitlines(True),fromfile='a/'+name,tofile='b/'+name)) for name,(old,new) in changes.items())
    patch_path=ROOT/'patches/rmx1931-native-cpu-stat-adjust.patch'
    if args.prepare:
        assert args.source is not None
        source=args.source.resolve();assert source!=before_source.resolve() and source.is_dir()
        for name,(old,new) in changes.items():
            actual=(source/name).read_text();assert actual in (old,new)
            if actual==old:(source/name).write_text(new)
        if patch_path.exists():assert patch_path.read_text(encoding='utf-8')==patch
        else:patch_path.write_text(patch,encoding='utf-8')
        DEST.mkdir(parents=True,exist_ok=True)
        record={'stage':'harden2-cpuset-stats','repairs_stage':'harden2-cpuset-decay','source':str(source),
            'base_source':str(before_source),'predecessor_audit_sha256':sha(BASE/'audit.json'),
            'upstream_reference':'Linux v4.19 kernel/cgroup/rstat.c cgroup_base_stat_cputime_show',
            'upstream_source_sha256':UPSTREAM_SHA,'upstream_url':'https://raw.githubusercontent.com/torvalds/linux/v4.19/kernel/cgroup/rstat.c',
            'upstream_header_sha256':UPSTREAM_HEADER_SHA,'upstream_header_url':'https://raw.githubusercontent.com/torvalds/linux/v4.19/include/linux/sched/cputime.h',
            'upstream_cputime_sha256':UPSTREAM_CPUTIME_SHA,'upstream_cputime_url':'https://raw.githubusercontent.com/torvalds/linux/v4.19/kernel/sched/cputime.c',
            'adaptation':'Native controller reader uses serialized snapshots, per-task-group prev_cputime and existing cputime_adjust; accounting writers and scheduling limits unchanged',
            'failure_path':FAILURE,'failure_sha256':sha(ART/FAILURE),'patch_sha256':sha(patch_path),
            'modified_sources':{name:{'before_sha256':sha(before_source/name),'after_sha256':sha(source/name)} for name in changes}}
        destination=DEST/'source.json'
        if destination.exists():assert read(destination)==record
        else:save(destination,record)
        print('NATIVE_CPU_STAT_REPAIR_SOURCE_READY');return
    record=read(DEST/'source.json');source=Path(record['source'])
    assert record['predecessor_audit_sha256']==sha(BASE/'audit.json') and sha(patch_path)==record['patch_sha256']
    assert record['failure_sha256']==sha(ART/FAILURE)
    hashes={**prior['cumulative_source_sha256'],**{n:r['after_sha256'] for n,r in record['modified_sources'].items()}}
    assert all(sha(source/n)==h for n,h in hashes.items())
    assert config(BASE/'resolved.config')==config(DEST/'resolved.config')
    assert sha(source/'kernel/sched/walt.c')==prior['walt_source_sha256']
    assert sha(source/'kernel/cgroup/cgroup.c')==prior['generic_cgroup_core_sha256']
    result={'stage':'harden2-cpuset-stats','repairs_stage':'harden2-cpuset-decay','source':record,
        'cumulative_stages':prior['cumulative_stages']+['harden2-cpuset-stats'],
        'cumulative_source_sha256':hashes,'verified_source_files':len(hashes),'config_changes':{},
        'walt_source_sha256':prior['walt_source_sha256'],'generic_cgroup_core_sha256':prior['generic_cgroup_core_sha256'],
        'generic_cgroup_core_unchanged_from_harden1':True,'build_audit_passed':False,
        'runtime_acceptance':'pending','android_v1_cpu_cpuset_retained':True}
    if args.after_build:
        assert (DEST/'kernel.release').read_text().strip()==RELEASE
        baseline=symbols(ART/'kernel-ext-harden1/Module.symvers');current=symbols(DEST/'Module.symvers')
        missing=sorted(baseline.keys()-current.keys());assert not missing
        changed_crcs=sorted(n for n in baseline.keys()&current.keys() if baseline[n]!=current[n])
        linked={l.split()[-1] for l in (DEST/'System.map').read_text().splitlines() if l.split()}
        assert set(prior['linked_symbols'])|{'cputime_adjust'}<=linked
        result.update(build_audit_passed=True,export_crc={'missing':missing,'changed':changed_crcs},
            existing_export_crc_preserved=not changed_crcs,linked_symbols=sorted(set(prior['linked_symbols'])|{'cputime_adjust'}))
        result.update({k:sha(DEST/f) for k,f in [('kernel_sha256','Image.gz-dtb'),('resolved_config_sha256','resolved.config'),('module_symvers_sha256','Module.symvers'),('system_map_sha256','System.map')]})
    save(DEST/'audit.json',result)
    print(json.dumps({'build_audit_passed':result['build_audit_passed'],'verified_source_files':len(hashes),'kernel_sha256':result.get('kernel_sha256'),'runtime_acceptance':'pending'}))

if __name__=='__main__':main()

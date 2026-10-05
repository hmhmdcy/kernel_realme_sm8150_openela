#!/usr/bin/env python3
"""Build-audit an immutable h2cp repair of missing CFS load decay after a sleeping-task cpuset migration."""
import argparse
import difflib
import hashlib
import json
from pathlib import Path
from audit_lowrisk_kernel import config,symbols

ROOT=Path(__file__).resolve().parents[1]
ART=ROOT/'artifacts/droidspaces'
BASE=ART/'kernel-ext-harden2-cpuset-fix'
DEST=ART/'kernel-ext-harden2-cpuset-decay'
COMMIT='0258bdfaff5bd13c4d2383150b7097aecd6b6d82'
UPSTREAM=ROOT/'references/native-cpuset-upstream'/f'{COMMIT}.patch'
UPSTREAM_SHA='149dd6ed3b86989039221426cf7787167551979d37687df07db128571fc1cfbe'
RELEASE='4.14.356-openela-rc1-perf-droidspaces-lr2-ksu3-ext-h2cp3'

def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def read(path):return json.loads(path.read_text(encoding='utf-8'))
def save(path,data):path.write_text(json.dumps(data,indent=2)+'\n',encoding='utf-8')

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--prepare',action='store_true');p.add_argument('--source',type=Path)
    p.add_argument('--after-build',action='store_true');args=p.parse_args()
    prior=read(BASE/'audit.json');assert prior['build_audit_passed']
    assert sha(BASE/'Image.gz-dtb')==prior['kernel_sha256']
    assert sha(UPSTREAM)==UPSTREAM_SHA
    failure=read(ART/'runtime/native-cpu-podman-h2cp2-20261004.json')
    assert failure['returncode']==1 and failure['kernel'].endswith('-ext-h2cp2')
    assert failure['end_identity']=={'kernel':failure['kernel'],'boot_id':failure['boot_id']}
    assert 'weight-competition' in failure['stdout']
    before_source=Path(prior['source']['source'])
    assert all(sha(before_source/n)==h for n,h in prior['cumulative_source_sha256'].items())
    name='kernel/sched/fair.c';original=(before_source/name).read_text()
    old='static void propagate_entity_cfs_rq(struct sched_entity *se)\n{\n\tstruct cfs_rq *cfs_rq;\n\n\t/* Start to propagate at parent */\n\tse = se->parent;\n\n\tfor_each_sched_entity(se) {\n\t\tcfs_rq = cfs_rq_of(se);\n\n\t\tif (cfs_rq_throttled(cfs_rq))\n\t\t\tbreak;\n\n\t\tupdate_load_avg(se, UPDATE_TG);\n\t}\n}'
    new='static void propagate_entity_cfs_rq(struct sched_entity *se)\n{\n\tstruct cfs_rq *cfs_rq;\n\n\t/* Decay removed load even when a sleeping task never enqueues here. */\n\tlist_add_leaf_cfs_rq(cfs_rq_of(se));\n\n\t/* Start to propagate at parent */\n\tse = se->parent;\n\n\tfor_each_sched_entity(se) {\n\t\tcfs_rq = cfs_rq_of(se);\n\n\t\tif (!cfs_rq_throttled(cfs_rq)) {\n\t\t\tupdate_load_avg(se, UPDATE_TG);\n\t\t\tlist_add_leaf_cfs_rq(cfs_rq);\n\t\t\tcontinue;\n\t\t}\n\n\t\t/* 4.14 has a void list helper; use its branch-complete invariant. */\n\t\tlist_add_leaf_cfs_rq(cfs_rq);\n\t\tif (rq_of(cfs_rq)->tmp_alone_branch ==\n\t\t    &rq_of(cfs_rq)->leaf_cfs_rq_list)\n\t\t\tbreak;\n\t}\n}'
    assert original.count(old)==1
    changed=original.replace(old,new)
    patch=''.join(difflib.unified_diff(original.splitlines(True),changed.splitlines(True),fromfile='a/'+name,tofile='b/'+name))
    patch_path=ROOT/'patches/rmx1931-cfs-sleeping-load-decay-fix.patch'
    if args.prepare:
        assert args.source is not None
        source=args.source.resolve();assert source!=before_source.resolve() and source.is_dir()
        actual=(source/name).read_text();assert actual in (original,changed)
        if actual==original:(source/name).write_text(changed)
        if patch_path.exists():assert patch_path.read_text(encoding='utf-8')==patch
        else:patch_path.write_text(patch,encoding='utf-8')
        DEST.mkdir(parents=True,exist_ok=True)
        record={'stage':'harden2-cpuset-decay','repairs_stage':'harden2-cpuset-fix','source':str(source),
            'base_source':str(before_source),'predecessor_audit_sha256':sha(BASE/'audit.json'),
            'upstream_commit':COMMIT,'upstream_patch_sha256':UPSTREAM_SHA,
            'upstream_url':'https://github.com/torvalds/linux/commit/'+COMMIT,
            'adaptation':'Backport sleeping-task leaf-list registration; older update_load_avg signature and void list helper use the equivalent branch-complete invariant',
            'patch_sha256':sha(patch_path),'modified_sources':{name:{'before_sha256':sha(before_source/name),'after_sha256':sha(source/name)}}}
        destination=DEST/'source.json'
        if destination.exists():assert read(destination)==record
        else:save(destination,record)
        print('NATIVE_CPUSET_REPAIR_SOURCE_READY');return
    record=read(DEST/'source.json');source=Path(record['source'])
    assert record['predecessor_audit_sha256']==sha(BASE/'audit.json') and sha(patch_path)==record['patch_sha256']
    hashes={**prior['cumulative_source_sha256'],name:record['modified_sources'][name]['after_sha256']}
    assert all(sha(source/n)==h for n,h in hashes.items())
    assert config(BASE/'resolved.config')==config(DEST/'resolved.config')
    assert sha(source/'kernel/sched/walt.c')==prior['walt_source_sha256']
    assert sha(source/'kernel/cgroup/cgroup.c')==prior['generic_cgroup_core_sha256']
    result={'stage':'harden2-cpuset-decay','repairs_stage':'harden2-cpuset-fix','source':record,
        'cumulative_stages':prior['cumulative_stages']+['harden2-cpuset-decay'],
        'cumulative_source_sha256':hashes,'verified_source_files':len(hashes),
        'config_changes':{},'walt_source_sha256':prior['walt_source_sha256'],
        'generic_cgroup_core_sha256':prior['generic_cgroup_core_sha256'],
        'generic_cgroup_core_unchanged_from_harden1':True,'build_audit_passed':False,
        'runtime_acceptance':'pending','android_v1_cpu_cpuset_retained':True}
    if args.after_build:
        assert (DEST/'kernel.release').read_text().strip()==RELEASE
        baseline=symbols(ART/'kernel-ext-harden1/Module.symvers');current=symbols(DEST/'Module.symvers')
        missing=sorted(baseline.keys()-current.keys());assert not missing
        changed_crcs=sorted(n for n in baseline.keys()&current.keys() if baseline[n]!=current[n])
        linked={l.split()[-1] for l in (DEST/'System.map').read_text().splitlines() if l.split()}
        assert set(prior['linked_symbols'])<=linked
        result.update(build_audit_passed=True,export_crc={'missing':missing,'changed':changed_crcs},
            existing_export_crc_preserved=not changed_crcs,linked_symbols=prior['linked_symbols'])
        result.update({k:sha(DEST/f) for k,f in [('kernel_sha256','Image.gz-dtb'),('resolved_config_sha256','resolved.config'),('module_symvers_sha256','Module.symvers'),('system_map_sha256','System.map')]})
    save(DEST/'audit.json',result)
    print(json.dumps({'build_audit_passed':result['build_audit_passed'],'verified_source_files':len(hashes),'kernel_sha256':result.get('kernel_sha256'),'runtime_acceptance':'pending'}))

if __name__=='__main__':main()

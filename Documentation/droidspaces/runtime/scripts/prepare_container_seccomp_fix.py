#!/usr/bin/env python3
"""Keep KernelSU Android setuid handling outside container namespaces."""
import argparse,difflib,hashlib,json
from pathlib import Path
from audit_lowrisk_kernel import config,symbols
ROOT=Path(__file__).resolve().parents[1];ART=ROOT/'artifacts/droidspaces'
BASE=ART/'kernel-ext-harden3-binfmt';DEST=ART/'kernel-ext-harden3-binfmt-fix'
FAILURE=ART/'runtime/binfmt-seccomp-setresuid-baseline-h3bm-20261004.json'
NAME='KernelSU-Next/kernel/hook/setuid_hook.c'
RELEASE='4.14.356-openela-rc1-perf-droidspaces-lr2-ksu3-ext-h3bm2'
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def read(p):return json.loads(p.read_text(encoding='utf-8'))
def save(p,d):p.write_text(json.dumps(d,indent=2)+'\n',encoding='utf-8')
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--prepare',action='store_true');p.add_argument('--source',type=Path);p.add_argument('--after-build',action='store_true');args=p.parse_args()
 prior=read(BASE/'audit.json');failure=read(FAILURE)
 assert prior['build_audit_passed'] and failure['returncode']==1 and failure['kernel'].endswith('-ext-h3bm')
 assert failure['end_identity']=={'kernel':failure['kernel'],'boot_id':failure['boot_id']}
 assert 'BINFMT_SECCOMP_PRESERVATION_FAILED' in failure['stdout']
 assert sha(ROOT/'scripts/probe_container_seccomp_setresuid.sh')==failure['script_source_sha256']
 before=Path(prior['source']['source']);assert all(sha(before/n)==h for n,h in prior['cumulative_source_sha256'].items())
 old=(before/NAME).read_text();new=old.replace('#include <linux/uidgid.h>','#include <linux/uidgid.h>\n#include <linux/user_namespace.h>\n#include <linux/pid_namespace.h>')
 assert new!=old and old.count('#include <linux/uidgid.h>')==1
 anchor='int ksu_handle_setresuid(uid_t old_uid, uid_t new_uid)\n{';assert new.count(anchor)==1
 new=new.replace(anchor,anchor+'''
    /* Android UID allowlists must not clear OCI filters or inject manager
     * handles in a container whose UID numbers overlap with Android's.
     * Explicit host su/root-profile handling remains unchanged.
     */
    if (current_user_ns() != &init_user_ns ||
        task_active_pid_ns(current) != &init_pid_ns)
        return 0;
''')
 patch=''.join(difflib.unified_diff(old.splitlines(True),new.splitlines(True),fromfile='a/'+NAME,tofile='b/'+NAME));patch_path=ROOT/'patches/rmx1931-ksu-container-seccomp-preserve.patch'
 if args.prepare:
  assert args.source and args.source.is_dir() and args.source.resolve()!=before.resolve()
  actual=(args.source/NAME).read_text();assert actual in (old,new)
  if actual==old:(args.source/NAME).write_text(new)
  if patch_path.exists():assert patch_path.read_text(encoding='utf-8')==patch
  else:patch_path.write_text(patch,encoding='utf-8')
  DEST.mkdir(parents=True,exist_ok=True)
  record={'stage':'harden3-binfmt-fix','repairs_stage':'harden3-binfmt','source':str(args.source.resolve()),'base_source':str(before),
   'predecessor_audit_sha256':sha(BASE/'audit.json'),'failure_path':FAILURE.relative_to(ART).as_posix(),'failure_sha256':sha(FAILURE),
   'adaptation':'KernelSU setresuid UID-based Android handling is limited to initial user and PID namespaces; preserves real OCI seccomp denials and avoids cross-namespace manager UID collisions',
   'patch_sha256':sha(patch_path),'modified_sources':{NAME:{'before_sha256':sha(before/NAME),'after_sha256':sha(args.source/NAME)}}}
  dest=DEST/'source.json'
  if dest.exists():assert read(dest)==record
  else:save(dest,record)
  print('CONTAINER_SECCOMP_FIX_SOURCE_READY');return
 record=read(DEST/'source.json');source=Path(record['source'])
 assert record['predecessor_audit_sha256']==sha(BASE/'audit.json') and record['failure_sha256']==sha(FAILURE) and record['patch_sha256']==sha(patch_path)
 hashes={**prior['cumulative_source_sha256'],**{n:r['after_sha256'] for n,r in record['modified_sources'].items()}}
 assert all(sha(source/n)==h for n,h in hashes.items()) and config(BASE/'resolved.config')==config(DEST/'resolved.config')
 assert sha(source/'kernel/sched/walt.c')==prior['walt_source_sha256'] and sha(source/'kernel/cgroup/cgroup.c')==prior['generic_cgroup_core_sha256']
 result={'stage':'harden3-binfmt-fix','repairs_stage':'harden3-binfmt','source':record,'cumulative_stages':prior['cumulative_stages']+['harden3-binfmt-fix'],
  'cumulative_source_sha256':hashes,'verified_source_files':len(hashes),'config_changes':{},'walt_source_sha256':prior['walt_source_sha256'],
  'generic_cgroup_core_sha256':prior['generic_cgroup_core_sha256'],'generic_cgroup_core_unchanged_from_harden1':True,'build_audit_passed':False,'runtime_acceptance':'pending','android_v1_cpu_cpuset_retained':True}
 if args.after_build:
  assert (DEST/'kernel.release').read_text().strip()==RELEASE
  previous=symbols(BASE/'Module.symvers');current=symbols(DEST/'Module.symvers');missing=sorted(previous.keys()-current.keys());assert not missing
  changed=sorted(n for n in previous.keys()&current.keys() if previous[n]!=current[n])
  linked={l.split()[-1] for l in (DEST/'System.map').read_text().splitlines() if l.split()};assert set(prior['linked_symbols'])<=linked
  result.update(build_audit_passed=True,export_crc={'missing':missing,'changed':changed},existing_export_crc_preserved=not changed,linked_symbols=prior['linked_symbols'])
  result.update({k:sha(DEST/f) for k,f in [('kernel_sha256','Image.gz-dtb'),('resolved_config_sha256','resolved.config'),('module_symvers_sha256','Module.symvers'),('system_map_sha256','System.map')]})
 save(DEST/'audit.json',result);print(json.dumps({'build_audit_passed':result['build_audit_passed'],'verified_source_files':len(hashes),'kernel_sha256':result.get('kernel_sha256')}))
if __name__=='__main__':main()

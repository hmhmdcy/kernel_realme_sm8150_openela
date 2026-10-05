#!/usr/bin/env python3
"""Publish stage 4 source/evidence without rewriting accepted stage 1-3 locks."""
import hashlib,json,re,shutil
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];ART=ROOT/'artifacts/droidspaces'
PUBLIC=ROOT/'worktrees/rmx1931-ksunext3/Documentation/droidspaces'
TARGET=PUBLIC/'runtime/candidates/h3bm'
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def read(p):return json.loads(p.read_text(encoding='utf-8'))
def copy(p,target):target.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(p,target);assert sha(p)==sha(target)
def main():
 frozen={p:sha(p) for p in PUBLIC.glob('source-lock*.json')}
 predecessor=ART/'native-cpu-cpuset-stage3-h2cp4-acceptance.json';assert read(predecessor)['complete_stage_3_accepted']
 evidence={};sources={};candidates={}
 for path in sorted((ART/'runtime').glob('binfmt-*.json')):
  if not any(s in path.stem for s in ('h2cp4','h3bm')):continue
  value=read(path)
  if value.get('end_identity'):assert value['end_identity']=={k:value[k] for k in ('kernel','boot_id')}
  target=TARGET/'evidence/runtime'/path.name;copy(path,target)
  evidence[path.name]={'path':target.relative_to(PUBLIC).as_posix(),'sha256':sha(path),'returncode':value.get('returncode'),
   'kernel':value.get('kernel'),'boot_id':value.get('boot_id'),'source_sha256':value.get('script_source_sha256')}
 for stage in ('harden3-binfmt','harden3-binfmt-fix'):
  directory=ART/('kernel-ext-'+stage)
  if not (directory/'source.json').exists():continue
  for name in ('source.json','audit.json','resolved.config','kernel.release'):
   p=directory/name
   if p.exists():copy(p,TARGET/'evidence'/directory.name/name)
  audit=read(directory/'audit.json') if (directory/'audit.json').exists() else {}
  candidates[stage]={'source_sha256':sha(directory/'source.json'),'build_audit_passed':audit.get('build_audit_passed',False),
   'kernel_sha256':audit.get('kernel_sha256'),'runtime_passed':False}
  if audit.get('build_audit_passed'):
   assert sha(directory/'Image.gz-dtb')==audit['kernel_sha256']
   for name in ('configure.log','build.log','Module.symvers','System.map'):copy(directory/name,TARGET/'evidence'/directory.name/name)
  for suffix in ('deployment','preflight','boot-result','acceptance','runtime-result'):
   p=ART/f'extensions-{stage}-{suffix}.json'
   if p.exists():copy(p,TARGET/'evidence'/p.name);candidates[stage][suffix+'_sha256']=sha(p)
  for name in (f'kernel-ext-{stage}-dtb-comparison.json',f'boot-images/ext-{stage}-candidate-check.json'):
   p=ART/name
   if p.exists():copy(p,TARGET/'evidence'/name)
 for name in ('prepare_binfmt_namespace.py','build_kernel_binfmt_namespace.sh','prepare_container_seccomp_fix.py','build_kernel_container_seccomp_fix.sh',
   'probe_binfmt_namespace_baseline.sh','probe_binfmt_namespace_isolation.sh','probe_binfmt_crossarch_podman.sh','probe_binfmt_stack_guard.sh',
   'probe_container_seccomp_setresuid.sh','probe_binfmt_filtered_mount.sh','prepare_crossarch_fixture.sh','privileged_guest.py','device_runtime.py','deploy_kernel_extensions.py',
   'rmx1931_binfmt.py','install_guest_binfmt.py','record_binfmt_acceptance.py','cleanup_owned_crossarch_fixture.sh',
   'probe_native_cpu_podman.sh','probe_resource_policy_smoke.sh','probe_resource_policy_cpu_backend.sh','probe_resource_policy_lifecycle.sh',
   'start_podman_guest.py','delegate_guest_cgroup_v2.py','install_guest_resource_policy.py','install_guest_podman_oom_wrapper.sh','seal_binfmt_progress.py'):
  p=ROOT/'scripts'/name;copy(p,TARGET/'scripts'/name);sources[name]=sha(p)
 for name in ('rmx1931-binfmt-user-namespace.patch','rmx1931-ksu-container-seccomp-preserve.patch'):
  p=ROOT/'patches'/name;copy(p,TARGET/'patches'/name);sources[name]=sha(p)
 for directory in [ROOT/'references/binfmt-ns-upstream',ROOT/'references/runtime-probes/binfmt-crossarch',
   *sorted((ROOT/'references/runtime-probes').glob('binfmt-crossarch-attempt*-20261004'))]:
  for p in directory.iterdir():
   if p.is_file():copy(p,TARGET/'source-versions'/directory.name/p.name)
 for p in (ART/'binfmt-crossarch-fixture').iterdir():
  if p.is_file():copy(p,TARGET/'source-versions/binfmt-crossarch-fixture'/p.name)
 acceptance=ART/'binfmt-stage4-acceptance.json';complete=acceptance.exists() and read(acceptance).get('complete_stage_4_accepted') is True
 if complete:
  value=read(acceptance);assert value['passed']
  for entry in value['evidence'].values():assert sha(ART/entry['path'])==entry['sha256']
  copy(acceptance,TARGET/'evidence'/acceptance.name)
  candidates[value['stage']]['runtime_passed']=True
 progress={'stage':4,'complete_stage_4_accepted':complete,'predecessor_stage3_acceptance_sha256':sha(predecessor),
  'candidates':candidates,'evidence':evidence,'current_script_source_sha256':sources,
  'ordinary_guest_filter_required':2,'scope':'binfmt user namespace isolation; actual cross-architecture RUN/build/exec; KernelSU setuid filter preservation',
  'remaining_functional_stages':([5,6] if complete else [4,5,6])}
 (ART/'binfmt-stage4-progress.json').write_text(json.dumps(progress,indent=2)+'\n',encoding='utf-8')
 copy(ART/'binfmt-stage4-progress.json',TARGET/'progress.json')
 mapping={'test-policy.md':'TEST-POLICY.md','hardening1-validation.md':'HARDENING1-VALIDATION.md','resource-policy-validation.md':'RESOURCE-POLICY-VALIDATION.md',
  'virtualization-feasibility.md':'VIRTUALIZATION-FEASIBILITY.md','android16-cgroup-v2-migration.md':'ANDROID16-CGROUP-V2-MIGRATION.md',
  'container-hardening-plan.md':'CONTAINER-HARDENING-PLAN.md','binfmt-namespace-validation.md':'BINFMT-NAMESPACE-VALIDATION.md','binfmt-usage.md':'BINFMT-USAGE.md'}
 rendered=[]
 for name in ('binfmt-namespace-validation.md','container-hardening-plan.md','binfmt-usage.md'):
  t=(ROOT/'docs'/name).read_text(encoding='utf-8')
  t=t.replace('../artifacts/droidspaces/', 'runtime/candidates/h3bm/evidence/' if name.startswith('binfmt') else '')
  for a,b in mapping.items():t=t.replace('('+a,'('+b)
  (PUBLIC/mapping[name]).write_text(t,encoding='utf-8')
  rendered.append((name,t))
 for name,t in rendered:
  for url in re.findall(r'\]\(([^)]+)\)',t):
   if '://' in url or url.startswith('#'):continue
   assert (PUBLIC/url.split('#',1)[0]).exists(),(name,url)
 assert all(sha(p)==h for p,h in frozen.items()),'Accepted root source locks changed'
 print(json.dumps({'complete_stage_4_accepted':complete,'evidence_reports':len(evidence),'candidate_scripts':len(sources)}))
if __name__=='__main__':main()

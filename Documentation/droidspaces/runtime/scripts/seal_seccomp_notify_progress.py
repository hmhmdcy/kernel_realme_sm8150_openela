#!/usr/bin/env python3
"""Publish the accepted stage 5 snapshot while retaining older source locks."""
import hashlib,json,re,shutil
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];ART=ROOT/'artifacts/droidspaces'
PUBLIC=ROOT/'worktrees/rmx1931-ksunext3/Documentation/droidspaces'
TARGET=PUBLIC/'runtime/candidates/h4sn'
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def read(p):return json.loads(p.read_text(encoding='utf-8'))
def copy(p,t):t.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(p,t);assert sha(p)==sha(t)
def main():
    frozen={p:sha(p) for p in PUBLIC.glob('source-lock*.json')}
    prior_snapshots={p:sha(p) for candidate in ('h2cp','h3bm') for p in (PUBLIC/'runtime/candidates'/candidate).rglob('*') if p.is_file()}
    receipt_path=ART/'seccomp-notify-stage5-acceptance.json';receipt=read(receipt_path)
    assert receipt['complete_stage_5_accepted'] and receipt['passed']
    assert receipt['predecessor_stage4_acceptance_sha256']==sha(ART/'binfmt-stage4-acceptance.json')
    evidence={};sources={}
    for name,entry in receipt['evidence'].items():
        p=ART/entry['path'];assert sha(p)==entry['sha256']
        copy(p,TARGET/'evidence'/entry['path'])
        evidence[name]=entry
        if entry.get('source_path'):
            source=ROOT/entry['source_path']
            assert hashlib.sha256(source.read_bytes().replace(b'\r\n',b'\n')).hexdigest()==entry['source_sha256']
            copy(source,TARGET/'bound-sources'/entry['source_path'])
    for p in sorted((ART/'runtime').glob('seccomp-notify-*.json')):
        copy(p,TARGET/'evidence/runtime'/p.name)
    stage='harden4-seccomp-notify';directory=ART/('kernel-ext-'+stage)
    for p in directory.rglob('*'):
        if p.is_file() and p.name!='Image.gz-dtb':copy(p,TARGET/'evidence'/directory.name/p.relative_to(directory))
    for suffix in ('preflight','deployment','boot-result','runtime-result'):
        p=ART/f'extensions-{stage}-{suffix}.json';copy(p,TARGET/'evidence'/p.name)
    for name in ('seccomp-notify-stage5-acceptance.json','binfmt-stage4-acceptance.json',
                 'kernel-ext-harden4-seccomp-notify-dtb-comparison.json','boot-images/ext-harden4-seccomp-notify-candidate-check.json'):
        p=ART/name;copy(p,TARGET/'evidence'/name)
    for name in ('prepare_seccomp_notify.py','build_kernel_seccomp_notify.sh','archive_unbuilt_seccomp_notify.py',
        'prepare_seccomp_notify_selftests.py','probe_seccomp_notify_selftests.sh','prepare_seccomp_notify_oci_probe.py',
        'probe_seccomp_notify_crun.sh','probe_seccomp_notification_baseline.sh','rmx1931_seccomp_notify.py',
        'install_guest_seccomp_notify.py','record_seccomp_notify_acceptance.py','seal_seccomp_notify_progress.py',
        'device_runtime.py','privileged_guest.py','deploy_kernel_extensions.py','prepare_boot_candidate.py',
        'inspect_kernel_dtb.py','start_podman_guest.py','delegate_guest_cgroup_v2.py','install_guest_resource_policy.py',
        'install_guest_podman_oom_wrapper.sh','probe_binfmt_crossarch_podman_pinned.sh'):
        p=ROOT/'scripts'/name;copy(p,TARGET/'scripts'/name);sources[name]=sha(p)
    patch=ROOT/'patches/rmx1931-seccomp-user-notification.patch';copy(patch,TARGET/'patches'/patch.name);sources[patch.name]=sha(patch)
    for directory in [ROOT/'references/seccomp-notify-upstream',ROOT/'references/seccomp-notify-selftests',
        *sorted((ROOT/'references/runtime-probes').glob('seccomp-notify-*'))]:
        for p in directory.rglob('*'):
            if p.is_file():copy(p,TARGET/'source-versions'/directory.name/p.relative_to(directory))
    progress={'stage':5,'complete_stage_5_accepted':True,'kernel':receipt['kernel'],'boot_id':receipt['boot_id'],
        'acceptance_sha256':sha(receipt_path),'evidence':evidence,'current_script_source_sha256':sources,
        'remaining_functional_stages':[6],'ordinary_guest_filter_required':2}
    p=ART/'seccomp-notify-stage5-progress.json';p.write_text(json.dumps(progress,indent=2)+'\n',encoding='utf-8');copy(p,TARGET/'progress.json')
    mapping={'container-hardening-plan.md':'CONTAINER-HARDENING-PLAN.md','seccomp-notify-validation.md':'SECCOMP-NOTIFY-VALIDATION.md',
        'hardening1-validation.md':'HARDENING1-VALIDATION.md','resource-policy-validation.md':'RESOURCE-POLICY-VALIDATION.md',
        'binfmt-namespace-validation.md':'BINFMT-NAMESPACE-VALIDATION.md'}
    rendered=[]
    for name in ('seccomp-notify-validation.md','container-hardening-plan.md'):
        text=(ROOT/'docs'/name).read_text(encoding='utf-8')
        text=text.replace('../artifacts/droidspaces/','runtime/candidates/h4sn/evidence/' if name.startswith('seccomp') else '')
        for a,b in mapping.items():text=text.replace('('+a,'('+b)
        (PUBLIC/mapping[name]).write_text(text,encoding='utf-8');rendered.append((name,text))
    for name,text in rendered:
        for url in re.findall(r'\]\(([^)]+)\)',text):
            if '://' not in url and not url.startswith('#'):assert (PUBLIC/url.split('#',1)[0]).exists(),(name,url)
    assert all(sha(p)==h for p,h in {**frozen,**prior_snapshots}.items()),'Prior accepted snapshots changed'
    print(json.dumps({'complete_stage_5_accepted':True,'evidence_reports':len(evidence),'scripts_and_patches':len(sources),'earlier_snapshots_preserved':True}))
if __name__=='__main__':main()

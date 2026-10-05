#!/usr/bin/env python3
"""Verify compiled sources and synchronize only this iteration into the local checkout."""
import datetime as dt
import difflib
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
from check_kernel_extensions_syntax import NAMES

ROOT = Path(__file__).resolve().parents[1]
ART = ROOT / 'artifacts/droidspaces'
TREE = ROOT / 'worktrees/rmx1931-ksunext3'
DOC = TREE / 'Documentation/droidspaces'

def read(path):
    return json.loads(path.read_text(encoding='utf-8'))

def sha(data):
    return hashlib.sha256(data).hexdigest()

def linux_file(path):
    return subprocess.check_output(['wsl','-u','root','--exec','cat',path],timeout=30)

def write_json(path,data):
    path.write_text(json.dumps(data,indent=2)+'\n',encoding='utf-8')

def main():
    source=read(ART/'kernel-ext-dualio/source.json')
    audit=read(ART/'kernel-ext-dualio/audit.json')
    resources=read(ART/'kernel-ext-resources/source.json')
    assert audit['build_audit_passed']
    old_lock=read(DOC/'source-lock.json')
    hashes=dict(old_lock['modified_source_sha256'])
    hashes.update({k:v['after_sha256'] for k,v in source['modified_sources'].items()})
    checked={}
    # Full tree comparison catches extra, missing and unrecorded changes.
    comparison=subprocess.run(['wsl','-u','root','--exec','diff','-qr','--exclude=.git',
                               source['base_source'],source['source']],capture_output=True,timeout=180)
    assert comparison.returncode==1 and not comparison.stderr,comparison.stderr
    changed=[]
    for line in comparison.stdout.decode().splitlines():
        match=re.fullmatch(r'Files '+re.escape(source['base_source'])+r'/(.+) and '+
                           re.escape(source['source'])+r'/\1 differ',line)
        assert match,line
        changed.append(match[1])
    assert set(changed)==set(source['modified_sources'])
    for name,expected in hashes.items():
        data=linux_file(source['source']+'/'+name)
        assert sha(data)==expected,name
        destination=TREE/name
        if name in source['modified_sources']:
            allowed={source['modified_sources'][name]['before_sha256'],expected}
            if name=='init/Kconfig':allowed.add(resources['modified_sources'][name]['before_sha256'])
            previous=destination.read_bytes() if destination.exists() else subprocess.check_output(
                ['git','-C',str(TREE),'show','HEAD:'+name],timeout=30)
            assert sha(previous) in allowed,'Unexpected local source changes: '+name
            destination.parent.mkdir(parents=True,exist_ok=True)
            destination.write_bytes(data)
        assert sha(destination.read_bytes())==expected,name
        checked[name]=expected
    before=linux_file(source['base_source'].replace('src-ext-resources','src-ext-network')+'/init/Kconfig')
    after=linux_file(source['base_source']+'/init/Kconfig')
    assert sha(before)==resources['modified_sources']['init/Kconfig']['before_sha256']
    assert sha(after)==resources['modified_sources']['init/Kconfig']['after_sha256']
    resource_patch=''.join(difflib.unified_diff(before.decode().splitlines(True),after.decode().splitlines(True),
                                              fromfile='a/init/Kconfig',tofile='b/init/Kconfig')).encode()
    (ROOT/'patches/rmx1931-walt-cfs-bandwidth.patch').write_bytes(resource_patch)
    config=(ART/'kernel-ext-dualio/resolved.config').read_bytes()
    assert sha(config)==audit['resolved_config_sha256']
    (TREE/'arch/arm64/configs/rmx1931_droidspaces_defconfig').write_bytes(config)
    builder=DOC/'build-ksunext.sh'
    text=builder.read_text().replace('-ksu3-ext-io','-ksu3-ext-dualio')
    builder.write_text(text,encoding='utf-8',newline='\n')
    for name in ('rmx1931-walt-cfs-bandwidth.patch','rmx1931-opt-in-dual-blkio.patch'):
        shutil.copyfile(ROOT/'patches'/name,DOC/name)
    helpers={}
    for name in sorted(set(NAMES)|{'sync_dualio_source.py','record_remaining_acceptance.py'}):
        path=ROOT/'scripts'/name
        if not path.exists():continue
        destination=DOC/'runtime/scripts'/name
        shutil.copyfile(path,destination)
        helpers[name]=sha(path.read_bytes())
    history=DOC/'source-lock-ext-io.json'
    if not history.exists():shutil.copyfile(DOC/'source-lock.json',history)
    lock=dict(old_lock)
    lock.update(tested_kernel_release='4.14.356-openela-rc1-perf-droidspaces-lr2-ksu3-ext-dualio',
                tested_boot_sha256='fe5edbce96623c20c51f5cf83d08d302298004e71540ae8b7771df6c8d866bac',
                kernel_sha256=audit['kernel_sha256'],resolved_config_sha256=audit['resolved_config_sha256'],
                modified_source_sha256=checked,runtime_helpers_sha256=helpers,
                source_iteration='local, uncommitted; published HEAD remains 933a65a',
                previous_extension_lock='source-lock-ext-io.json',
                changed_export_crcs_vs_resources=len(audit['export_crc']['changed']),
                personal_dual_controller_abi=True,external_modules_require_rebuild=True,
                runtime_acceptance='remaining-acceptance-20261004.json',
                iteration_patches_sha256={name:sha((ROOT/'patches'/name).read_bytes()) for name in
                    ('rmx1931-walt-cfs-bandwidth.patch','rmx1931-opt-in-dual-blkio.patch')})
    # The old comparison count applies to its ext-io predecessor, not this new ABI.
    lock['historical_changed_export_crcs_vs_ksunext3']=lock.pop('changed_export_crcs_vs_ksunext3',1033)
    write_json(DOC/'source-lock.json',lock)
    workspace_lock=read(ROOT/'ksunext.sources.lock.json')
    workspace_lock['latest_local_iteration']={k:lock[k] for k in
        ('tested_kernel_release','tested_boot_sha256','kernel_sha256','resolved_config_sha256',
         'modified_source_sha256','iteration_patches_sha256','external_modules_require_rebuild')}
    write_json(ROOT/'ksunext.sources.lock.json',workspace_lock)
    report={'observed_at':dt.datetime.now(dt.timezone.utc).isoformat(),
            'passed':True,'compiled_tree':source['source'],'local_tree':str(TREE),
            'full_tree_comparison_changed_files':sorted(changed),
            'full_tree_comparison_sha256':sha(comparison.stdout),
            'verified_source_sha256':checked,'resolved_config_sha256':sha(config),
            'publication_performed':False,'previous_local_changes_preserved':True}
    write_json(ART/'dualio-local-source-sync.json',report)
    print(json.dumps({'passed':True,'verified_sources':len(checked),'changed_files':len(changed),
                      'publication_performed':False}))

if __name__=='__main__':main()

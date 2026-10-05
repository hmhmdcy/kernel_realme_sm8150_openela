#!/usr/bin/env python3
"""Reproduce real scheduler export CRCs and compare their reachable type roots."""
import datetime as dt
import hashlib
import json
from pathlib import Path
import shlex
import subprocess

ROOT = Path(__file__).resolve().parents[1]
ART = ROOT / 'artifacts/droidspaces'
DEST = ART / 'kernel-ext-android16-group-psi-reclaim-fix'
BASE = Path('/var/tmp/rmx1931-ksunext-cd739c788023')
target = DEST / 'abi-change'
target.mkdir(exist_ok=True)
report_path = target / 'type-analysis.json'
assert not report_path.exists(), 'ABI analysis evidence is immutable'
audit = json.loads((DEST / 'audit.json').read_text())
assert not audit['build_audit_passed'] and not audit['export_crc']['missing']
(target / 'build-audit-before-review.json').write_bytes((DEST / 'audit.json').read_bytes())
definitions = {}
crc_reports = {}
core_sources = {}
for label, stage in (('before', 'android16-group-psi'), ('after', 'android16-group-psi-reclaim-fix')):
    source = BASE / ('src-ext-' + stage)
    out = BASE / ('out-ext-' + stage)
    core_sources[label] = hashlib.sha256((source / 'kernel/sched/core.c').read_bytes()).hexdigest()
    command = (out / 'kernel/sched/.core.o.cmd').read_text().splitlines()[0].split(':=', 1)[1]
    original = shlex.split(command)
    args = []
    skip = False
    for arg in original:
        if skip:
            skip = False
            continue
        if arg == '-o':
            skip = True
            continue
        if arg == '-c' or arg.startswith('-Wp,-MD,'):
            continue
        args.append(arg)
    args[0] = str(BASE / 'clang/bin/clang')
    args += ['-E', '-D__GENKSYMS__']
    preprocessed = target / (label + '-core.i')
    with preprocessed.open('wb') as stream:
        result = subprocess.run(args, cwd=out, stdout=stream, stderr=subprocess.PIPE, timeout=60)
    (target / (label + '-preprocess-stderr.txt')).write_bytes(result.stderr)
    assert result.returncode == 0, result.stderr.decode(errors='replace')
    types = target / (label + '-types.txt')
    with preprocessed.open('rb') as stream:
        result = subprocess.run([str(out / 'scripts/genksyms/genksyms'), '-T', str(types)],
                                stdin=stream, capture_output=True, cwd=out, timeout=60)
    assert result.returncode == 0, result.stderr.decode(errors='replace')
    (target / (label + '-core.ver')).write_bytes(result.stdout)
    (target / (label + '-genksyms-stderr.txt')).write_bytes(result.stderr)
    definitions[label] = {line.split()[0]: line for line in types.read_text().splitlines() if line.split()}
    import re
    reproduced = dict(re.findall(r'__crc_(\w+)\s*=\s*(0x[0-9a-f]+)', result.stdout.decode()))
    existing = {line.split()[1]: line.split()[0] for line in (out / 'Module.symvers').read_text().splitlines() if line.split()}
    assert reproduced and all(existing[name] == crc for name, crc in reproduced.items())
    crc_reports[label] = reproduced
assert core_sources['before'] == core_sources['after']
old, new = definitions['before'], definitions['after']
changed = {name: {'before': old[name], 'after': new[name]} for name in old.keys() & new.keys() if old[name] != new[name]}
added = sorted(new.keys() - old.keys())
removed = sorted(old.keys() - new.keys())
report = {'observed_at': dt.datetime.now(dt.timezone.utc).isoformat(),
    'core_source_byte_identical': True, 'core_source_sha256': core_sources['after'],
    'reproduced_crcs_match_actual_builds': True, 'reproduced_exports': crc_reports,
    'changed_reachable_type_definitions': changed, 'added_type_definitions': added, 'removed_type_definitions': removed,
    'candidate_changed_exports': len(audit['export_crc']['changed']),
    'candidate_missing_exports': len(audit['export_crc']['missing']),
    'candidate_module_layout_crc': audit['export_crc']['details'].get('module_layout'),
    'original_failed_build_audit_sha256': hashlib.sha256((target / 'build-audit-before-review.json').read_bytes()).hexdigest(),
    'interpretation': 'Compiler/genksyms output from actual unchanged core.c and each build context; type changes explain recursive CRC propagation. This does not establish compatibility with old external modules.'}
report_path.write_text(json.dumps(report, indent=2) + '\n')
print(json.dumps({'reproduced_core_exports': len(crc_reports['after']), 'changed_type_roots': list(changed),
                  'added_types': added, 'removed_types': removed, 'changed_export_count': report['candidate_changed_exports']}))

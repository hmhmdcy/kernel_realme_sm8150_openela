#!/usr/bin/env python3
"""Bind reviewed type propagation to the standing human ABI authorization."""
from audit_group_psi_reclaim_fix import ART, DEST, STAGE, crc_digest, read, save, sha

audit = read(DEST / 'audit.json')
analysis_path = DEST / 'abi-change/type-analysis.json'
analysis = read(analysis_path)
authorization = read(ART / 'authorized-native-cpu-repair.json')
assert authorization['authorization'] == '我现在授权你刷入；请根据建议顺序补强功能，确保所有功能能够正常使用。延续此前同项目内核部署与 ABI 变更授权。'
assert authorization['source'] == 'standing human deployment and ABI authorization in this conversation'
assert not audit['build_audit_passed'] and not audit['export_crc']['missing']
assert len(audit['export_crc']['changed']) == analysis['candidate_changed_exports'] == 3916
assert analysis['core_source_byte_identical'] and analysis['reproduced_crcs_match_actual_builds']
assert analysis['changed_reachable_type_definitions'] == {'E#NR_PSI_TASK_COUNTS': {'before': 'E#NR_PSI_TASK_COUNTS 3 ', 'after': 'E#NR_PSI_TASK_COUNTS 4 '}}
assert not analysis['added_type_definitions'] and not analysis['removed_type_definitions']
assert len(analysis['reproduced_exports']['before']) == len(analysis['reproduced_exports']['after']) == 23
assert analysis['candidate_module_layout_crc'] == audit['export_crc']['details']['module_layout']
assert analysis['original_failed_build_audit_sha256'] == sha(DEST / 'abi-change/build-audit-before-review.json')
assert 'MODPOST 0 modules' in (DEST / 'build.log').read_text()
path = DEST / 'abi-change/review.json'
assert not path.exists(), 'ABI review is immutable'
save(path, {'allowed': True, 'stage': STAGE, 'external_module_compatibility': False,
    'required_deployment_condition': 'no loaded or available external .ko modules',
    'changed_export_count': 3916, 'export_crc_sha256': crc_digest(audit['export_crc']),
    **{key: audit[key] for key in ('kernel_sha256', 'module_symvers_sha256', 'resolved_config_sha256')},
    'source_record_sha256': sha(DEST / 'source.json'), 'type_analysis_sha256': sha(analysis_path),
    'human_authorization_sha256': sha(ART / 'authorized-native-cpu-repair.json'),
    'original_failed_build_audit_sha256': analysis['original_failed_build_audit_sha256'],
    'reason': 'NR_PSI_TASK_COUNTS 3->4 changes the PSI per-CPU array type reachable through kernel structs. Actual unchanged scheduler source reproduced 23 CRCs; its only changed reachable type root is that count. All 12219 exports remain; 3916 CRCs including module_layout change. All configured drivers are built in, with MODPOST 0 modules. Never claim old modules remain compatible.'})
print('GROUP_PSI_ABI_CHANGE_REVIEW_RECORDED; physical module checks remain deployment gates')

#!/usr/bin/env python3
"""Verify deployment refusal paths without connecting or writing to a phone."""
import sys
import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
import deploy_kernel_extensions as deploy


class RefusalTests(unittest.TestCase):
    def test_binfmt_requires_sealed_joint_stage3_acceptance(self):
        # Use the real sealed predecessor; no transport, mock candidate only.
        receipt = deploy.read(deploy.ART / 'extensions-harden2-cpuset-stats-runtime-result.json')
        data = (None, {'candidate_sha256': receipt['boot_sha256']}, None, receipt['kernel'])
        with patch.object(deploy, 'candidate', return_value=data):
            self.assertEqual(deploy.predecessor('harden3-binfmt'), (receipt['kernel'], receipt['boot_sha256']))
        original = deploy.read
        for field, value in [('runtime_passed', False), ('boot_id', 'other-boot'), ('acceptance_sha256', '0'*64)]:
            def changed(path):
                data = original(path)
                if path.name == 'extensions-harden2-cpuset-stats-runtime-result.json': data = {**data, field:value}
                return data
            with self.subTest(field=field), patch.object(deploy, 'candidate', return_value=(None, {'candidate_sha256':receipt['boot_sha256']}, None, receipt['kernel'])), patch.object(deploy, 'read', side_effect=changed):
                with self.assertRaisesRegex(RuntimeError, 'joint runtime acceptance'):
                    deploy.predecessor('harden3-binfmt')
        digest = deploy.sha
        def changed_evidence(path):
            return '0'*64 if path.name == 'native-statistics-h2cp4-acceptance.json' else digest(path)
        with patch.object(deploy, 'candidate', return_value=data), patch.object(deploy, 'sha', side_effect=changed_evidence):
            with self.assertRaisesRegex(RuntimeError, 'joint evidence changed'):
                deploy.predecessor('harden3-binfmt')

    def test_binfmt_deployment_still_requires_abi_authorization(self):
        self.reject_before_device(['flash-reboot', '--stage', 'harden3-binfmt', '--authorization', 'fixture only'], compatible=False, text='ABI-change authorization')

    def reject_before_device(self, arguments, compatible=True, text='authorization'):
        data = (Path('unused.img'), {'candidate_sha256': '1' * 64},
                {'existing_export_crc_preserved': compatible}, 'unused-release')
        with patch.object(deploy, 'candidate', return_value=data), \
             patch.object(deploy, 'device', side_effect=AssertionError('Device access was not authorized')), \
             patch.object(sys, 'argv', ['deploy'] + arguments):
            with self.assertRaisesRegex(RuntimeError, text):
                deploy.main()

    def test_reboot_needs_recorded_authorization(self):
        self.reject_before_device(['reboot-bootloader', '--stage', 'utilities'])

    def test_flash_needs_recorded_authorization(self):
        self.reject_before_device(['flash-reboot', '--stage', 'utilities'])

    def test_io_needs_separate_abi_authorization(self):
        self.reject_before_device(['reboot-bootloader', '--stage', 'io', '--authorization', 'test only'],
                                  compatible=False, text='ABI-change authorization')

    def test_native_cpu_cpuset_reboot_needs_authorization(self):
        self.reject_before_device(['reboot-bootloader', '--stage', 'harden2-cpuset'], compatible=False)

    def test_native_cpu_cpuset_flash_needs_abi_authorization(self):
        self.reject_before_device(['flash-reboot', '--stage', 'harden2-cpuset', '--authorization', 'test only'],
                                  compatible=False, text='ABI-change authorization')

    def test_unexpected_abi_change_is_rejected_even_for_preflight(self):
        self.reject_before_device(['preflight', '--stage', 'utilities'], compatible=False,
                                  text='Unreviewed external module ABI change')

    def test_predecessor_requires_actual_runtime_acceptance(self):
        data = (None, {'candidate_sha256': '1' * 64}, None, 'expected')
        for acceptance in ({'runtime_passed': False},
                           {'runtime_passed': True, 'boot_sha256': '2' * 64, 'kernel': 'expected'}):
            with self.subTest(acceptance=acceptance), \
                 patch.object(deploy, 'candidate', return_value=data), \
                 patch.object(deploy, 'read', return_value=acceptance):
                with self.assertRaisesRegex(RuntimeError, 'matching runtime acceptance'):
                    deploy.predecessor('bbr')

    def test_modified_image_is_rejected(self):
        with patch.object(deploy, 'sha', return_value='0' * 64):
            with self.assertRaisesRegex(RuntimeError, 'Candidate boot changed'):
                deploy.candidate('utilities')

    def test_same_stage_repair_requires_real_matching_failure(self):
        data=(None,{'candidate_sha256':'1'*64},None,'expected')
        boot={'running_config_matches':True,'kernel':'expected','boot_sha256':'1'*64}
        failure={'returncode':1,'kernel':'expected','boot_id':'fixture-boot',
                 'end_identity':{'kernel':'expected','boot_id':'fixture-boot'},'stdout':'weight-competition failed'}
        for stage in ('harden2-cpuset-fix', 'harden2-cpuset-decay', 'harden2-cpuset-stats', 'harden3-binfmt-fix'):
            failure['stdout'] = deploy.REPAIR_FAILURE_MARKERS.get(stage, 'weight-competition') + ' failed'
            with self.subTest(stage=stage), patch.object(deploy,'candidate',return_value=data), \
                 patch.object(deploy,'read',side_effect=[boot,failure]) as reads:
                self.assertEqual(deploy.predecessor(stage),('expected','1'*64))
                self.assertEqual(reads.call_args_list[1].args[0], deploy.ART / deploy.REPAIR_FAILURES[stage])
            for bad in ({**failure,'returncode':0},{**failure,'kernel':'other'}, {**failure,'stdout':'different failure'},
                        {**failure,'end_identity':{'kernel':'expected','boot_id':'different'}}):
                with self.subTest(stage=stage,bad=bad),patch.object(deploy,'candidate',return_value=data), \
                     patch.object(deploy,'read',side_effect=[boot,bad]):
                    with self.assertRaisesRegex(RuntimeError,'matching real failure'):
                        deploy.predecessor(stage)

    def test_decay_repair_needs_deploy_and_abi_authorization(self):
        for stage in ('harden2-cpuset-decay', 'harden2-cpuset-stats'):
            self.reject_before_device(['reboot-bootloader', '--stage', stage], compatible=False)
            self.reject_before_device(['flash-reboot', '--stage', stage, '--authorization', 'test only'],
                                      compatible=False, text='ABI-change authorization')

    def test_failed_send_records_failure_without_reboot(self):
        report={'preflight_passed':True,'bootloader_reboot_sent':True,'flashed':False,
                'candidate_sha256':'1'*64,'transport_id_sha256':hashlib.sha256(b'fixture-device').hexdigest()}
        data=(Path('fixture.img'),{'candidate_sha256':'1'*64},
              {'existing_export_crc_preserved':False},'fixture-release')
        answers=['fixture-device fastboot','product: msmnile','unlocked: yes',
                 'partition-size:boot: 0x6000000',RuntimeError("Sending 'boot' FAILED (995)")]
        with patch.object(deploy,'candidate',return_value=data), \
             patch.object(deploy,'read',return_value=report), \
             patch.object(deploy,'run',side_effect=answers) as commands, \
             patch.object(deploy,'save') as save, \
             patch.object(sys,'argv',['deploy','flash-reboot','--stage','harden2-cpuset',
                                      '--authorization','fixture only','--allow-abi-change']):
            with self.assertRaisesRegex(RuntimeError,'Sending'):
                deploy.main()
            self.assertFalse(report['flashed'])
            self.assertFalse(report['boot_write_confirmed'])
            self.assertIn('FAILED',report['last_flash_error'])
            save.assert_called_once()
            self.assertFalse(any('reboot' in call.args[0] for call in commands.call_args_list))

    def test_failed_resume_requires_same_boot_and_device(self):
        observed={'stage':'harden2-cpuset','candidate_sha256':'1'*64,'kernel':'predecessor',
                  'boot_sha256':'2'*64,'transport_id_sha256':'3'*64}
        old={**observed,'phase':'flash failed; inspect device before retry','flashed':False,
             'boot_write_confirmed':False,'preflight_passed':True,'bootloader_reboot_sent':True,
             'last_flash_error':'send failed'}
        for key in ('candidate_sha256','boot_sha256','transport_id_sha256'):
            with self.subTest(key=key), patch.object(deploy,'read',return_value={**old,key:'different'}):
                with self.assertRaisesRegex(RuntimeError,'cannot resume'):
                    deploy.archive_failed_deployment(Path('unused.json'),observed)

    def test_pinned_serial_flashes_without_enumeration_or_getvar(self):
        report={'preflight_passed':True,'bootloader_reboot_sent':True,'flashed':False,
                'candidate_sha256':'1'*64,'transport_id_sha256':hashlib.sha256(b'fixture-device').hexdigest()}
        data=(Path('fixture.img'),{'candidate_sha256':'1'*64},
              {'existing_export_crc_preserved':False},'fixture-release')
        with patch.object(deploy,'candidate',return_value=data), \
             patch.object(deploy,'read',return_value=report), \
             patch.object(deploy,'run',side_effect=["Sending 'boot' OKAY\nWriting 'boot' OKAY",'reboot OKAY']) as commands, \
             patch.object(deploy,'save'), \
             patch.object(sys,'argv',['deploy','flash-reboot','--stage','harden2-cpuset',
                 '--authorization','fixture only','--allow-abi-change','--fastboot-serial','fixture-device']):
            deploy.main()
        self.assertEqual(len(commands.call_args_list),2)
        self.assertEqual(commands.call_args_list[0].args[0][-5:],['-s','fixture-device','flash','boot','fixture.img'])
        self.assertEqual(commands.call_args_list[1].args[0][-3:],['-s','fixture-device','reboot'])
        self.assertTrue(report['boot_write_confirmed'])

    def test_pinned_serial_mismatch_rejected_before_transport(self):
        report={'preflight_passed':True,'bootloader_reboot_sent':True,'flashed':False,
                'candidate_sha256':'1'*64,'transport_id_sha256':hashlib.sha256(b'fixture-device').hexdigest()}
        data=(Path('fixture.img'),{'candidate_sha256':'1'*64},
              {'existing_export_crc_preserved':False},'fixture-release')
        with patch.object(deploy,'candidate',return_value=data), \
             patch.object(deploy,'read',return_value=report), \
             patch.object(deploy,'run',side_effect=AssertionError('No transport request should occur')), \
             patch.object(sys,'argv',['deploy','flash-reboot','--stage','harden2-cpuset',
                 '--authorization','fixture only','--allow-abi-change','--fastboot-serial','wrong-device']):
            with self.assertRaisesRegex(RuntimeError,'differs from checked'):
                deploy.main()

    def test_failed_resume_preserves_original_record(self):
        observed={'stage':'harden2-cpuset','candidate_sha256':'1'*64,'kernel':'predecessor',
                  'boot_sha256':'2'*64,'transport_id_sha256':'3'*64}
        old={**observed,'phase':'flash failed; inspect device before retry','flashed':False,
             'boot_write_confirmed':False,'preflight_passed':True,'bootloader_reboot_sent':True,
             'last_flash_error':'send failed'}
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);art=root/'artifacts';art.mkdir();record=art/'deployment.json'
            record.write_text(json.dumps(old));before=record.read_bytes()
            with patch.object(deploy,'ROOT',root),patch.object(deploy,'ART',art):
                history=deploy.archive_failed_deployment(record,observed)
            self.assertEqual((root/history[-1]).read_bytes(),before)
            self.assertEqual(record.read_bytes(),before)


if __name__ == '__main__':
    unittest.main()

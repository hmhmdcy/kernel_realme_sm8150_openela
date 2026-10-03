#!/usr/bin/env python3
"""Verify deployment refusal paths without connecting or writing to a phone."""
import sys
import unittest
from pathlib import Path
from unittest.mock import patch
import deploy_kernel_extensions as deploy


class RefusalTests(unittest.TestCase):
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


if __name__ == '__main__':
    unittest.main()

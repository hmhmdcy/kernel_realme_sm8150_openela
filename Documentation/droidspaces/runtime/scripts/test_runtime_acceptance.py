#!/usr/bin/env python3
"""Regression tests for stale evidence and app-started guest identity refusal."""
import unittest
import json
import sys
import tempfile
import subprocess
import shlex
import shutil
from pathlib import Path
from unittest.mock import patch
import device_runtime
from check_kernel_extension_runtime import current_probe
from delegate_guest_cgroup_v2 import monitor_launch, BASE, CONFIG, NAME
from probe_lowrisk_wifi import packet_loss
import accept_phone
from record_extension_acceptance import wifi_evidence


class EvidenceTests(unittest.TestCase):
    def test_default_entry_cannot_start_cumulative_suite_or_query_usb(self):
        with patch.object(accept_phone, 'device') as device, \
             patch.object(accept_phone.subprocess, 'run') as runner, \
             patch.object(sys, 'argv', ['accept', '--stage', 'dualio']):
            with self.assertRaises(SystemExit) as result:
                accept_phone.main()
            self.assertEqual(result.exception.code, 2)
            device.assert_not_called()
            runner.assert_not_called()

    def test_current_dualio_stage_runs_actual_io_before_suite(self):
        with tempfile.TemporaryDirectory() as temporary, \
             patch.object(accept_phone, 'ART', Path(temporary)), \
             patch.object(accept_phone, 'device', return_value=['unused']), \
             patch.object(accept_phone, 'read_identity', return_value={'kernel':
                 '4.14.356-openela-rc1-perf-droidspaces-lr2-ksu3-ext-dualio'}), \
             patch.object(accept_phone.subprocess, 'run') as runner, \
             patch.object(sys, 'argv', ['accept', '--full', '--run-label', 'fresh']):
            accept_phone.main()
            calls=[item.args[0] for item in runner.call_args_list]
            self.assertEqual(Path(calls[1][1]).name, 'probe_io_throttling.py')
            self.assertIn('extensions-dualio-fresh-io', calls[1])
            self.assertIn('dualio', calls[2])
            self.assertNotIn('probe_lowrisk_wifi.py', [Path(call[1]).name for call in calls])
            self.assertNotIn('--with-wifi', calls[-1])

    def test_wifi_probe_and_evidence_check_require_explicit_opt_in(self):
        with tempfile.TemporaryDirectory() as temporary, \
             patch.object(accept_phone, 'ART', Path(temporary)), \
             patch.object(accept_phone.subprocess, 'run') as runner, \
             patch.object(sys, 'argv', ['accept', '--full', '--stage', 'dualio', '--run-label', 'fresh', '--with-wifi']):
            accept_phone.main()
            calls = [item.args[0] for item in runner.call_args_list]
            self.assertEqual(Path(calls[-2][1]).name, 'probe_lowrisk_wifi.py')
            self.assertIn('extensions-dualio-fresh-wifi', calls[-2])
            self.assertIn('--with-wifi', calls[-1])

    def test_skipped_wifi_needs_no_evidence_and_is_not_reported_as_passed(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'missing-wifi.json'
            self.assertEqual(wifi_evidence(path, {}, None),
                             {'requested': False, 'passed': None, 'evidence_sha256': None})

    def test_opt_in_wifi_requires_fresh_current_boot_zero_loss_evidence(self):
        identity = {'kernel': 'same-release', 'boot_id': 'current-boot'}
        timestamp = '2026-10-04T00:00:00+00:00'
        record = {**identity, 'observed_at': timestamp, 'packet_loss_percent': 0, 'passed': True}
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'wifi.json'
            path.write_text(json.dumps(record))
            self.assertTrue(wifi_evidence(path, identity, timestamp, requested=True)['passed'])
            for changed in ({'boot_id': 'older-boot'}, {'kernel': 'other-release'},
                            {'packet_loss_percent': 33}, {'passed': False},
                            {'observed_at': '2026-10-03T23:59:59+00:00'}):
                with self.subTest(changed=changed):
                    path.write_text(json.dumps({**record, **changed}))
                    with self.assertRaisesRegex(RuntimeError, 'Wi-Fi regression is incomplete'):
                        wifi_evidence(path, identity, timestamp, requested=True)

    def test_unknown_current_kernel_refuses_before_preparing_guest(self):
        with patch.object(accept_phone, 'device', return_value=['unused']), \
             patch.object(accept_phone, 'read_identity', return_value={'kernel':'unknown'}), \
             patch.object(accept_phone.subprocess, 'run') as runner, \
             patch.object(sys, 'argv', ['accept', '--full']):
            with self.assertRaisesRegex(RuntimeError, 'recognized extension'):
                accept_phone.main()
            runner.assert_not_called()

    def test_completed_or_previous_boot_service_cannot_be_relabelled(self):
        identity = {'kernel': 'same-release', 'boot_id': 'current-boot'}
        for previous in ({'returncode': 0, **identity},
                         {'returncode': 124, **identity, 'boot_id': 'older-boot'}):
            with self.subTest(previous=previous), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                report = root / 'artifacts/droidspaces/runtime/existing.json'
                report.parent.mkdir(parents=True)
                report.write_text(json.dumps(previous))
                with patch.object(device_runtime, 'ROOT', root), \
                     patch.object(device_runtime, 'device', return_value=['unused']), \
                     patch.object(device_runtime, 'read_identity', return_value=identity), \
                     patch.object(device_runtime, 'collect_service', side_effect=AssertionError('Must refuse collection')), \
                     patch.object(sys, 'argv', ['runtime', 'collect-service', '--label', 'existing']):
                    with self.assertRaisesRegex(RuntimeError, 'pending service'):
                        device_runtime.main()
                self.assertEqual(json.loads(report.read_text()), previous)

    def test_existing_probe_is_refused_before_connecting(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            report = root / 'artifacts/droidspaces/runtime/existing.json'
            report.parent.mkdir(parents=True)
            report.write_text(json.dumps({'returncode': 1, 'stdout': 'original failure'}))
            with patch.object(device_runtime, 'ROOT', root), \
                 patch.object(device_runtime, 'device', side_effect=AssertionError('Must refuse before ADB')), \
                 patch.object(sys, 'argv', ['runtime', 'run', '--label', 'existing', '--command', 'true']):
                with self.assertRaisesRegex(RuntimeError, 'overwrite'):
                    device_runtime.main()
            self.assertEqual(json.loads(report.read_text())['stdout'], 'original failure')

    def test_success_is_bound_to_current_boot(self):
        identity = {'kernel': 'same-release', 'boot_id': 'current-boot'}
        record = {'returncode': 0, **identity, 'end_identity': identity}
        self.assertTrue(current_probe(record, identity))
        for changed in ({'boot_id': 'older-boot'}, {'boot_id': None},
                        {'kernel': 'other-release'}, {'returncode': 77}, {'end_identity': None},
                        {'end_identity': {**identity, 'boot_id': 'rebooted'}}):
            with self.subTest(changed=changed):
                self.assertFalse(current_probe({**record, **changed}, identity))


class MonitorTests(unittest.TestCase):
    def setUp(self):
        self.app = ['droidspaces', '--config=' + CONFIG, 'start']
        self.config = 'name=' + NAME + '\nrootfs_path=' + BASE + '/rootfs.img\nforce_cgroupv1=0\n'
        self.direct = ['droidspaces', '--name=' + NAME, '--rootfs-img=' + BASE + '/rootfs.img', '--net=nat', 'start']

    def test_accepts_pinned_app_and_direct_launch_shapes(self):
        self.assertEqual(monitor_launch(self.app, self.config), 'app-config')
        self.assertEqual(monitor_launch(self.direct), 'direct')

    def test_rejects_other_or_ambiguous_container_identity(self):
        cases = [(self.app, None),
                 (self.app, self.config.replace(NAME, 'other-guest', 1)),
                 (self.app, self.config.replace('rootfs.img', 'other.img')),
                 (self.app, self.config + 'name=other\n'),
                 (self.app, self.config.replace('force_cgroupv1=0', 'force_cgroupv1=1')),
                 (['droidspaces', '--config=/other/container.config', 'start'], self.config),
                 (self.direct[:-1] + ['--name=other', 'start'], None),
                 (self.direct[:-1] + ['--config=' + CONFIG, 'start'], self.config)]
        for arguments, config in cases:
            with self.subTest(arguments=arguments, config=config):
                with self.assertRaises(RuntimeError):
                    monitor_launch(arguments, config)


class WifiTests(unittest.TestCase):
    def test_requires_three_received_and_zero_loss(self):
        for output in ('3 packets transmitted, 3 received, 0% packet loss',
                       '3 packets transmitted, 3 packets received, 0.0% packet loss'):
            self.assertEqual(packet_loss(output), 0)
        for output in ('3 packets transmitted, 2 received, 33% packet loss',
                       '3 packets transmitted, 2 received, 0% packet loss',
                       '1 packets transmitted, 1 received, 0% packet loss',
                       'gateway returned success with no statistics'):
            with self.subTest(output=output):
                with self.assertRaises(RuntimeError):
                    packet_loss(output)


class CleanupTests(unittest.TestCase):
    def test_name_collision_never_removes_existing_container_or_volume(self):
        shell = Path('C:/Program Files/Git/bin/sh.exe')
        executable = str(shell) if shell.exists() else shutil.which('sh')
        if not executable:
            self.skipTest('POSIX shell is unavailable')
        script = (Path(__file__).parent / 'probe_podman_functional.sh').read_text()
        with tempfile.TemporaryDirectory() as temporary:
            marker = Path(temporary) / 'guest-marker'
            marker.touch()
            script = script.replace('test -f /etc/droidspaces', 'test -f ' + shlex.quote(marker.as_posix()))
            for collision in ('container', 'volume'):
                stub = '''
id() { printf '0\\n'; }
podman() {
    if [ "$1" = ps ]; then
        if [ "$collision" = container ]; then printf 'rmx1931-acceptance-rootful\\n'; fi
        return 0
    fi
    if [ "$1" = volume ] && [ "$2" = ls ]; then
        if [ "$collision" = volume ]; then printf 'rmx1931-acceptance-rootful\\n'; fi
        return 0
    fi
    printf 'UNEXPECTED_MUTATION %s\\n' "$*"
    return 1
}
set -- rootful
'''
                result = subprocess.run([executable], input='collision=' + collision + '\n' + stub + script,
                                        capture_output=True, text=True, timeout=10)
                with self.subTest(collision=collision):
                    self.assertNotEqual(result.returncode, 0)
                    self.assertNotIn('UNEXPECTED_MUTATION', result.stdout + result.stderr)


if __name__ == '__main__':
    unittest.main()

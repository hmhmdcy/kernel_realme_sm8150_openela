#!/usr/bin/env python3
"""Offline failure-boundary tests; actual lifecycle proof is a device probe."""
import copy
import unittest
from pathlib import Path
import rmx1931_resource_policy as policy


class PolicyTests(unittest.TestCase):
    def setUp(self):
        self.profile = {'uid': 1000, 'cpu_quota_us': 50000, 'memory_bytes': 67108864,
                        'pids': 32, 'read_bps': 2097152, 'write_bps': 2097152, 'oom_group': True}

    def test_unknown_and_unbounded_fields_are_rejected(self):
        for field, value in [('uid', 1001), ('pids', True), ('pids', -1), ('memory_bytes', 0),
                             ('cpu_quota_us', 900000), ('read_bps', 0), ('oom_group', 1), ('extra', 'value')]:
            with self.subTest(field=field, value=value):
                profile = dict(self.profile, **{field: value})
                with self.assertRaises(policy.PolicyError):
                    policy.validate_registry({'version': 1, 'profiles': {'small': profile}})

    def test_scopes_and_traversal_are_rejected(self):
        cid = 'a' * 64
        self.assertEqual(policy.expected_config(1000, cid), Path('/home/podmantest/.local/share/containers/storage/overlay-containers') / cid / 'userdata/config.json')
        for uid, bad in [(1001, cid), (1000, '../' + cid), (1000, 'b' * 63)]:
            with self.assertRaises(policy.PolicyError):
                policy.expected_config(uid, bad)

    def test_optional_high_threshold_preserves_old_profiles_and_rejects_bad_limits(self):
        policy.validate_registry({'version': 1, 'profiles': {'old': self.profile}})
        high = dict(self.profile, memory_high_bytes=32 * 1024**2)
        policy.validate_registry({'version': 1, 'profiles': {'new': high}})
        for value in (True, 0, 15 * 1024**2, self.profile['memory_bytes'], 96 * 1024**2):
            with self.subTest(value=value), self.assertRaises(policy.PolicyError):
                policy.validate_registry({'version': 1, 'profiles': {'bad': dict(self.profile, memory_high_bytes=value)}})

    def test_high_threshold_wins_over_raw_knob_without_changing_hard_limit_or_security(self):
        high = dict(self.profile, memory_high_bytes=32 * 1024**2)
        config = {'linux': {'resources': {'unified': {'memory.high': 'max', 'unrelated': 'kept'}},
                           'seccomp': {'defaultAction': 'SCMP_ACT_ERRNO'}}}
        result = policy.apply_resources(config, high, (7, 312), cpu_backend='v2')
        self.assertEqual(result['linux']['resources']['unified']['memory.high'], '33554432')
        self.assertEqual(result['linux']['resources']['memory']['limit'], 67108864)
        self.assertEqual(result['linux']['resources']['unified']['unrelated'], 'kept')
        self.assertEqual(result['linux']['seccomp'], {'defaultAction': 'SCMP_ACT_ERRNO'})

    def test_resource_update_preserves_other_devices_and_security(self):
        config = {'linux': {'resources': {'devices': [{'allow': False}],
                  'blockIO': {'throttleReadBpsDevice': [{'major': 8, 'minor': 0, 'rate': 123456}]},
                  'unified': {'other': 'kept'}}, 'seccomp': {'defaultAction': 'SCMP_ACT_ERRNO'}}}
        original = copy.deepcopy(config)
        result = policy.apply_resources(config, self.profile, (7, 312))
        self.assertEqual(result['linux']['seccomp'], original['linux']['seccomp'])
        self.assertEqual(result['linux']['resources']['devices'], original['linux']['resources']['devices'])
        self.assertEqual(result['linux']['resources']['blockIO']['throttleReadBpsDevice'][0], {'major': 8, 'minor': 0, 'rate': 123456})
        self.assertEqual(result['linux']['resources']['memory']['limit'], 67108864)
        self.assertNotIn('cpu', result['linux']['resources'])

    def test_ambiguous_container_identity_is_rejected(self):
        with self.assertRaises(policy.PolicyError):
            policy.parse_runtime(['create', 'a' * 64, 'b' * 64])
        self.assertIsNone(policy.parse_runtime(['--version']))

    def test_native_cpu_policy_overrides_conflicting_raw_quota(self):
        config = {'linux': {'resources': {'cpu': {'quota': 400000, 'period': 50000, 'cpus': '2-3'},
                                         'unified': {'cpu.max': '800000 100000', 'other': 'kept'}}}}
        result = policy.apply_resources(config, self.profile, (7, 312), cpu_backend='v2')
        self.assertEqual(result['linux']['resources']['cpu'], {'quota': 50000, 'period': 100000, 'cpus': '2-3'})
        self.assertNotIn('cpu.max', result['linux']['resources']['unified'])
        self.assertEqual(result['linux']['resources']['unified']['other'], 'kept')
        with self.assertRaises(policy.PolicyError):
            policy.apply_resources(config, self.profile, (7, 312), cpu_backend='unknown')

    def test_native_policy_rejects_a_legacy_cpu_override(self):
        policy.require_native_cpu_peer('0::/container\n2:cpu:/\n3:cpuset:/background\n')
        policy.require_native_cpu_peer('0::/container\n')
        for legacy in ('cpu', 'cpu,cpuacct', 'cpu_legacy'):
            with self.subTest(legacy=legacy), self.assertRaises(policy.PolicyError):
                policy.require_native_cpu_peer('2:' + legacy + ':/rmx1931-policy-old\n0::/container\n')
        with self.assertRaises(policy.PolicyError):
            policy.require_native_cpu_peer('invalid-line')

    def test_root_file_ownership_in_user_namespace(self):
        self.assertEqual(policy.visible_root_uid('0 0 4294967295\n', 65534), 0)
        self.assertEqual(policy.visible_root_uid('0 1000 1\n1 100000 65536\n', 65534), 65534)


if __name__ == '__main__':
    unittest.main()

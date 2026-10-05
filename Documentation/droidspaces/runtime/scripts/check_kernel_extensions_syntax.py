#!/usr/bin/env python3
"""Check extension Python, shell and Python heredoc bodies without running probes."""
import ast
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess

ROOT = Path(__file__).resolve().parents[1]
NAMES = ('audit_kernel_extensions.py', 'build_kernel_extensions.sh', 'prepare_kernel_extensions.py',
         'prepare_boot_candidate.py', 'inspect_kernel_dtb.py', 'crashlog.py', 'test_crashlog.py',
         'probe_kernel_extensions.sh', 'probe_extension_erofs.sh', 'probe_extension_lxc.sh',
         'probe_io_throttling.py', 'prepare_extension_tools.sh', 'prepare_extension_guest.sh',
         'build_extension_criu.sh', 'export_extension_criu.py', 'deploy_kernel_extensions.py',
         'record_kernel_extensions.py', 'device_runtime.py', 'start_podman_guest.py',
         'test_deploy_kernel_extensions.py', 'check_kernel_extensions_syntax.py')
NAMES += ('check_kernel_extension_runtime.py', 'record_extension_acceptance.py',
          'reboot_extension_retention.py', 'install_guest_podman_oom_wrapper.sh', 'probe_lowrisk_wifi.py',
          'prepare_guest_checkpoint.sh', 'probe_checkpoint_privileged.py')
NAMES += ('accept_phone.py', 'test_runtime_acceptance.py', 'delegate_guest_cgroup_v2.py',
          'probe_podman_functional.sh', 'probe_podman_memory_enforcement.sh')
NAMES += ('audit_kernel_dualio.py', 'build_kernel_dualio.sh', 'prepare_dual_blkio.py',
          'probe_checkpoint_management.py', 'control_podman_checkpoint.sh',
          'probe_podman_checkpoint.sh', 'privileged_guest.py',
          'set_container_cpu_quota.py', 'probe_container_cpu_quota.py',
          'probe_container_cpu_fixture.sh', 'install_guest_cpu_runtime.sh',
          'prepare_guest_cpu_mounts.sh', 'probe_guest_io_max.sh',
          'probe_io_hierarchy_writeback.sh', 'probe_lxc_device_policy.sh',
          'install_lxc_bpf_launcher.sh', 'probe_bind_propagation.sh',
          'probe_external_tcp.py', 'probe_external_tcp_server.sh',
          'probe_external_wireguard.py', 'probe_external_wireguard_guest.sh',
          'probe_panic_retention.py')
NAMES += ('audit_kernel_resources.py', 'build_kernel_resources.sh',
          'record_remaining_acceptance.py', 'sync_dualio_source.py', 'run_dualio_final.py')
NAMES += ('prepare_kernel_hardening.py', 'audit_kernel_hardening.py', 'build_kernel_hardening.sh',
          'probe_container_lifecycle.sh', 'sync_hardening_source.py', 'record_hardening_acceptance.py')
NAMES += ('rmx1931_resource_policy.py', 'oci_resource_entry.py', 'install_guest_resource_policy.py',
          'test_resource_policy.py', 'probe_policy_oci_layout.sh', 'probe_resource_policy_smoke.sh')
NAMES += ('probe_resource_policy_lifecycle.sh', 'probe_resource_policy_admission.sh')
NAMES += ('stop_guest_resource_policy.sh',)
NAMES += ('record_resource_policy_restart.py',)
NAMES += ('record_resource_policy_acceptance.py',)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--shell-directory', type=Path, help='Explicit directory containing sh/bash (Git for Windows or Linux tools)')
    args = parser.parse_args()
    records = {}
    heredocs = children = 0
    def python(text, label):
        nonlocal children
        tree = ast.parse(text, filename=label)
        for node in ast.walk(tree):
            if (isinstance(node, ast.Constant) and isinstance(node.value, str) and
                    '\n' in node.value and node.value.lstrip().startswith(('import ', 'from '))):
                ast.parse(node.value, filename=label + ':embedded-child')
                children += 1
    paths = [ROOT / 'scripts' / name for name in NAMES]
    paths += sorted((ROOT / 'packages/rmx1931-crashlog').glob('*.sh'))
    for path in paths:
        content = path.read_bytes()
        text = content.decode().replace('\r\n', '\n')
        if path.suffix == '.py':
            python(text, path.name)
        else:
            shell = 'bash' if text.startswith('#!/usr/bin/env bash') else 'sh'
            executable = str(args.shell_directory / (shell + ('.exe' if os.name == 'nt' else ''))) if args.shell_directory else (shutil.which(shell) or shell)
            subprocess.run([executable, '-n'], input=text.encode(), capture_output=True, check=True)
            for match in re.finditer(r"<<['\"](PY|PYTHON)['\"]\n(.*?)\n\1(?:\n|$)", text, re.S):
                python(match[2], path.name + ':heredoc')
                heredocs += 1
        records[path.relative_to(ROOT).as_posix()] = hashlib.sha256(content).hexdigest()
    report = {'passed': True, 'files': records, 'python_heredocs': heredocs,
              'embedded_python_children': children, 'probes_executed': False}
    (ROOT / 'artifacts/droidspaces/extensions-syntax.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({k: v for k, v in report.items() if k != 'files'}))


if __name__ == '__main__':
    main()

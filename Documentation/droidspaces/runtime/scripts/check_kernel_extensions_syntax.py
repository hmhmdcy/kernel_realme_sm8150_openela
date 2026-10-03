#!/usr/bin/env python3
"""Check extension Python, shell and Python heredoc bodies without running probes."""
import ast
import hashlib
import json
from pathlib import Path
import re
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


def main():
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
            subprocess.run([shell, '-n'], input=text.encode(), capture_output=True, check=True)
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

#!/usr/bin/python3
"""Reviewed OCI entry: persistent policies and legacy manual CPU inheritance."""
import os
import re
import sys
from rmx1931_resource_policy import runtime_entry

runtime = os.path.basename(sys.argv[0]).removeprefix('rmx1931-oci-')
if runtime not in ('crun', 'runc') or not os.path.isfile('/etc/droidspaces'):
    raise SystemExit('Invalid isolated guest OCI entry')
try:
    managed = runtime_entry(sys.argv[1:])
    if not managed:
        for cid in [arg for arg in sys.argv[1:] if re.fullmatch('[0-9a-f]{64}', arg)]:
            procs = '/run/rmx1931-cpu/' + cid + '/cgroup.procs'
            if os.path.isfile(procs):
                with open(procs, 'w') as stream:
                    stream.write(str(os.getpid()) + '\n')
except Exception as error:
    print('RMX1931_RESOURCE_POLICY_ERROR: ' + str(error), file=sys.stderr)
    raise SystemExit(125)
os.execv('/usr/bin/' + runtime, [runtime, *sys.argv[1:]])

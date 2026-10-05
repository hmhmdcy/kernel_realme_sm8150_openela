#!/usr/bin/env python3
"""Export an audited adaptation of cb0e52b for the actual 4.14 PSI baseline.

Does not edit a WSL tree, build a kernel or deploy. Preserve the baseline and
all acceptance failures; a separate build/ABI audit and real retest are required.
"""
import datetime as dt
import difflib
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REF = ROOT / 'references/group-psi-upstream'
ART = ROOT / 'artifacts/droidspaces'
COMMIT = 'cb0e52b7748737b2cf6481fdd9b920ce7e1ebbdf'


def sha(data):
    return hashlib.sha256(data).hexdigest()


def replace_one(text, old, new):
    assert text.count(old) == 1, 'Unexpected source context: ' + repr(old)
    return text.replace(old, new, 1)


def main():
    lock = json.loads((REF / 'source-lock.json').read_text())
    assert lock['upstream_commit'] == COMMIT
    upstream = (REF / (COMMIT + '.patch')).read_bytes()
    assert sha(upstream) == lock['patch_sha256'] == '9fd02aa518ad3cbdeb90431610720d37fc27d3a5f9afd9a532a409ddae1c140a'
    destination = ART / 'kernel-ext-android16-group-psi-reclaim-fix'
    report_path = destination / 'preparation.json'
    assert not report_path.exists(), 'Prepared snapshot is immutable; inspect it before iterating'
    names = ('include/linux/psi_types.h', 'kernel/sched/psi.c', 'kernel/sched/stats.h')
    before = {}
    after = {}
    for name in names:
        data = (REF / 'baseline-a16ps' / name).read_bytes()
        assert sha(data) == lock['baseline_sha256'][name]
        before[name] = data.decode()
        after[name] = data.decode()

    name = 'include/linux/psi_types.h'
    after[name] = replace_one(after[name], '\tNR_PSI_TASK_COUNTS = 3,',
        '\t/* Reclaimers are runnable, but are not productive memory tasks. */\n'
        '\tNR_MEMSTALL_RUNNING,\n\tNR_PSI_TASK_COUNTS = 4,')
    after[name] = replace_one(after[name], '#define TSK_RUNNING\t(1 << NR_RUNNING)',
        '#define TSK_RUNNING\t(1 << NR_RUNNING)\n#define TSK_MEMSTALL_RUNNING\t(1 << NR_MEMSTALL_RUNNING)')

    name = 'kernel/sched/stats.h'
    after[name] = replace_one(after[name],
        '\tif (!wakeup || p->sched_psi_wake_requeue) {',
        '\tif (p->flags & PF_MEMSTALL)\n\t\tset |= TSK_MEMSTALL_RUNNING;\n\n'
        '\tif (!wakeup || p->sched_psi_wake_requeue) {')
    # This older scheduler clears runnable state in psi_dequeue, rather
    # than deferring sleep handling to psi_task_switch like the upstream tree.
    after[name] = replace_one(after[name], '\tif (!sleep) {\n\t\tif (p->flags & PF_MEMSTALL)',
        '\tif (p->flags & PF_MEMSTALL)\n\t\tclear |= TSK_MEMSTALL_RUNNING;\n\n'
        '\tif (!sleep) {\n\t\tif (p->flags & PF_MEMSTALL)')

    name = 'kernel/sched/psi.c'
    after[name] = replace_one(after[name], '\t\treturn tasks[NR_MEMSTALL] && !tasks[NR_RUNNING];',
        '\t\treturn tasks[NR_MEMSTALL] &&\n\t\t\ttasks[NR_RUNNING] == tasks[NR_MEMSTALL_RUNNING];')
    after[name] = replace_one(after[name], 'tasks=[%u %u %u] clear=', 'tasks=[%u %u %u %u] clear=')
    after[name] = replace_one(after[name], '\t\t\t\t\tclear, set);',
        '\t\t\t\t\tgroupc->tasks[3], clear, set);')
    after[name] = replace_one(after[name], 'psi_task_change(current, 0, TSK_MEMSTALL);',
        'psi_task_change(current, 0, TSK_MEMSTALL | TSK_MEMSTALL_RUNNING);')
    after[name] = replace_one(after[name], 'psi_task_change(current, TSK_MEMSTALL, 0);',
        'psi_task_change(current, TSK_MEMSTALL | TSK_MEMSTALL_RUNNING, 0);')
    # The local cgroup mover reconstructs flags, so it must transfer the
    # new runnable-memstall state too. Sleep-persistent memstall stays separate.
    after[name] = replace_one(after[name],
        '\tif (task->flags & PF_MEMSTALL)\n\t\ttask_flags |= TSK_MEMSTALL;',
        '\tif (task->flags & PF_MEMSTALL) {\n\t\ttask_flags |= TSK_MEMSTALL;\n'
        '\t\tif (task_flags & TSK_RUNNING)\n\t\t\ttask_flags |= TSK_MEMSTALL_RUNNING;\n\t}')
    after[name] = replace_one(after[name],
        ' *\tFULL = nr_delayed_tasks != 0 && nr_running_tasks == 0',
        ' *\tFULL = nr_delayed_tasks != 0 && nr_productive_tasks == 0\n *\n'
        ' * For IO, productive means running. For memory, a runnable reclaimer\n'
        ' * remains stalled, so only a running non-reclaimer is productive.')
    after[name] = replace_one(after[name],
        ' *\t   FULL = (threads - min(nr_running_tasks, threads)) / threads',
        ' *\t   FULL = (threads - min(nr_productive_tasks, threads)) / threads')
    after[name] = replace_one(after[name],
        ' *\t   tFULL[cpu] = time(nr_delayed_tasks[cpu] && !nr_running_tasks[cpu])',
        ' *\t   tFULL[cpu] = time(nr_delayed_tasks[cpu] && !nr_productive_tasks[cpu])')

    patch = '# Backport of upstream ' + COMMIT + '\n'
    patch += '# Adapted to PF_MEMSTALL, local psi_dequeue and cgroup_move_task.\n'
    patch += '# CPU PSI state definitions and legacy tick sampling are retained.\n'
    modified = {}
    for name in names:
        assert after[name] != before[name]
        target = destination / 'modified-sources' / name
        target.parent.mkdir(parents=True, exist_ok=True)
        data = after[name].encode()
        target.write_bytes(data)
        modified[name] = sha(data)
        patch += f'diff --git a/{name} b/{name}\n'
        patch += ''.join(difflib.unified_diff(before[name].splitlines(True), after[name].splitlines(True),
                                            fromfile='a/' + name, tofile='b/' + name))
    patch_path = ROOT / 'patches/rmx1931-psi-reclaim-full.patch'
    assert not patch_path.exists()
    patch_path.write_bytes(patch.encode())
    report = {'observed_at': dt.datetime.now(dt.timezone.utc).isoformat(),
        'stage': 'android16-group-psi-reclaim-fix', 'planned_release_suffix': 'a16pf',
        'upstream_commit': COMMIT, 'upstream_patch_sha256': sha(upstream),
        'baseline_sha256': {name: lock['baseline_sha256'][name] for name in names},
        'modified_sources': modified, 'adaptation_patch_sha256': sha(patch.encode()),
        'source_lock_sha256': sha((REF / 'source-lock.json').read_bytes()),
        'full_trigger_failure': 'runtime/psi-policy-full-diagnostic-a16ps-20261005.json',
        'status': 'source adaptation prepared; build, export CRC audit, deployment and runtime acceptance pending',
        'built': False, 'deployed': False, 'runtime_accepted': False,
        'adaptation': ['Retain existing PF_MEMSTALL storage and nested section semantics.',
            'Track runnable memstall in enqueue and clear it on every dequeue, including sleep.',
            'Transfer the new state in the local cgroup_move_task flag reconstruction.',
            'Keep original CPU PSI definition, timer sampling, WALT and generic cgroup core.']}
    report_path.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({'prepared': True, 'changed_sources': len(modified), 'patch_sha256': report['adaptation_patch_sha256']}))


if __name__ == '__main__':
    main()

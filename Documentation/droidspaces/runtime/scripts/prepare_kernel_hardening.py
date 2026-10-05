#!/usr/bin/env python3
"""Backport group OOM and race-safe cgroup.kill onto the accepted dualio tree."""
import argparse
import difflib
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
UPSTREAM = ROOT / 'references/container-hardening-upstream'
COMMITS = {
    '661ee6280931548f7b3b887ad26a157474ae5ac4': '266db7a0967bf6042851544b80beee4c8197068cc2e29084a73bad2f48eaa6cb',
    'b69bb476dee99d564d65d418e9a20acca6f32c3f': 'cb384981fa12e314b0a4e252f8e766888e555d5c51504c12c277bbea33cfd98c',
    '3d8b38eb81cac81395f6a823f6bf401b327268e6': 'bfc6b99f98fd231648faba1061dd18ee83333d28fd0ecaec90412a537d3736f1',
    '5989ad7b5ede38d605c588981f634c08252abfc3': '107289a173880bfd2457ff28ed5afa5fd108b93c129c4392b57224febeac550e',
    '48fe267c503ec22014ba4e83d002b07caad034d0': 'ac8ce8f0743d2d1acd7fbafca500782f77ab5e3ba30857ddb1cc6a2390197af0',
    '74183a956dec832723b411ed8497f58d1fc84fec': 'add9e1aede491bd3ddd9f1cec9e286d00c1f32331b33bf6b3d3ce23d19783e28',
}


def sha(data):
    return hashlib.sha256(data).hexdigest()


def upstream_function(commit, path, declaration):
    patch = UPSTREAM / (commit + '.patch')
    assert sha(patch.read_bytes()) == COMMITS[commit], 'Upstream patch changed'
    active = False
    added = []
    for line in patch.read_text(encoding='utf-8').splitlines():
        if line.startswith('diff --git '):
            active = line == 'diff --git a/' + path + ' b/' + path
        elif active and line.startswith('+') and not line.startswith('+++'):
            added.append(line[1:])
    text = '\n'.join(added) + '\n'
    start = text.index(declaration)
    end = text.index('\n}\n', start) + 3
    return text[start:end]


def transform(name, text):
    def replace(old, new):
        nonlocal text
        assert text.count(old) == 1, (name, old[:90], text.count(old))
        text = text.replace(old, new)

    if name == 'include/linux/cgroup-defs.h':
        replace('\tint nr_threaded_children;\t/* # of live threaded child cgroups */\n',
                '\tint nr_threaded_children;\t/* # of live threaded child cgroups */\n\n'
                '\t/* cgroup.kill sequence, protected by css_set_lock. */\n\tunsigned int kill_seq;\n')
    elif name == 'include/linux/sched.h':
        replace('\tstruct css_set __rcu\t\t*cgroups;\n',
                '\tstruct css_set __rcu\t\t*cgroups;\n'
                '\t/* Old fork API has no kernel_clone_args; cache before siglock. */\n'
                '\tunsigned int\t\t\tcgroup_kill_seq;\n')
    elif name == 'kernel/cgroup/cgroup.c':
        commit = '661ee6280931548f7b3b887ad26a157474ae5ac4'
        functions = '\n'.join(upstream_function(commit, name, signature) for signature in (
            'static void __cgroup_kill(', 'static void cgroup_kill(', 'static ssize_t cgroup_kill_write('))
        functions = functions.replace('set_bit(CGRP_KILL, &cgrp->flags);', 'cgrp->kill_seq++;')
        functions = functions.replace('\n\tspin_lock_irq(&css_set_lock);\n\tclear_bit(CGRP_KILL, &cgrp->flags);\n\tspin_unlock_irq(&css_set_lock);', '')
        replace('static int cgroup_file_open(struct kernfs_open_file *of)\n',
                functions + '\nstatic int cgroup_file_open(struct kernfs_open_file *of)\n')
        replace('\t\t.write = cgroup_freeze_write,\n\t},',
                '\t\t.write = cgroup_freeze_write,\n\t},\n\t{\n'
                '\t\t.name = "cgroup.kill",\n\t\t.flags = CFTYPE_NOT_ON_ROOT,\n'
                '\t\t.write = cgroup_kill_write,\n\t},')
        replace('int cgroup_can_fork(struct task_struct *child)\n{\n\tstruct cgroup_subsys *ss;\n\tint i, j, ret;\n',
                'int cgroup_can_fork(struct task_struct *child)\n{\n\tstruct cgroup_subsys *ss;\n\tint i, j, ret;\n\n'
                '\t/* Adapt b69bb476dee9 to the pre-kernel_clone_args fork API. */\n'
                '\tspin_lock_irq(&css_set_lock);\n'
                '\tchild->cgroup_kill_seq = task_css_set(current)->dfl_cgrp->kill_seq;\n'
                '\tspin_unlock_irq(&css_set_lock);\n')
        replace('void cgroup_post_fork(struct task_struct *child)\n{\n\tstruct cgroup_subsys *ss;\n\tint i;\n',
                'void cgroup_post_fork(struct task_struct *child)\n{\n\tstruct cgroup_subsys *ss;\n'
                '\tbool kill = false;\n\tint i;\n')
        start = text.index('void cgroup_post_fork(')
        end = text.index('\n/**\n * cgroup_exit', start)
        body = text[start:end]
        assert body.count('\t\tcset = task_css_set(current);') == 1
        body = body.replace('\t\tcset = task_css_set(current);',
                '\t\tcset = task_css_set(current);\n'
                '\t\tkill = !(child->flags & PF_KTHREAD) &&\n'
                '\t\t\tchild->cgroup_kill_seq != cset->dfl_cgrp->kill_seq;')
        assert body.endswith('} while_each_subsys_mask();\n}\n')
        body = body[:-2] + '\n\tif (unlikely(kill))\n'
        body += '\t\tdo_send_sig_info(SIGKILL, SEND_SIG_FORCED, child, true);\n}\n'
        text = text[:start] + body + text[end:]
    elif name == 'include/linux/memcontrol.h':
        replace('\tbool use_hierarchy;\n', '\tbool use_hierarchy;\n\n\t/* V2 workload integrity policy; disabled by default. */\n\tbool oom_group;\n')
        replace('bool mem_cgroup_oom_synchronize(bool wait);\n',
                'bool mem_cgroup_oom_synchronize(bool wait);\n'
                'struct mem_cgroup *mem_cgroup_get_oom_group(struct task_struct *victim,\n'
                '\t\t\t\t\t    struct mem_cgroup *oom_domain);\n'
                'void mem_cgroup_print_oom_group(struct mem_cgroup *memcg);\n')
        replace('static inline bool mem_cgroup_oom_synchronize(bool wait)\n{\n\treturn false;\n}\n',
                'static inline bool mem_cgroup_oom_synchronize(bool wait)\n{\n\treturn false;\n}\n\n'
                'static inline struct mem_cgroup *mem_cgroup_get_oom_group(\n'
                '\tstruct task_struct *victim, struct mem_cgroup *oom_domain)\n{\n\treturn NULL;\n}\n\n'
                'static inline void mem_cgroup_print_oom_group(struct mem_cgroup *memcg)\n{\n}\n')
    elif name == 'mm/memcontrol.c':
        commit = '3d8b38eb81cac81395f6a823f6bf401b327268e6'
        getter = upstream_function(commit, name, 'struct mem_cgroup *mem_cgroup_get_oom_group(')
        getter = getter.replace('\tif (memcg == root_mem_cgroup)\n\t\tgoto out;',
                '\tif (memcg == root_mem_cgroup)\n\t\tgoto out;\n\n'
                '\t/* 48fe267c503e: never extend a memcg OOM beyond its domain. */\n'
                '\tif (unlikely(!mem_cgroup_is_descendant(memcg, oom_domain)))\n\t\tgoto out;')
        getter = getter.replace('if (memcg->oom_group)', 'if (READ_ONCE(memcg->oom_group))')
        functions = getter + '\n' + upstream_function(commit, name, 'void mem_cgroup_print_oom_group(')
        replace('/**\n * lock_page_memcg - lock a page->mem_cgroup binding', functions + '\n/**\n * lock_page_memcg - lock a page->mem_cgroup binding')
        knobs = '\n'.join(upstream_function(commit, name, signature) for signature in (
            'static int memory_oom_group_show(', 'static ssize_t memory_oom_group_write('))
        knobs = knobs.replace('memcg->oom_group);', 'READ_ONCE(memcg->oom_group));')
        knobs = knobs.replace('memcg->oom_group = oom_group;', 'WRITE_ONCE(memcg->oom_group, oom_group);')
        replace('static struct cftype memory_files[] = {', knobs + '\nstatic struct cftype memory_files[] = {')
        replace('\t\t.seq_show = memory_stat_show,\n\t},',
                '\t\t.seq_show = memory_stat_show,\n\t},\n\t{\n'
                '\t\t.name = "oom.group",\n\t\t.flags = CFTYPE_NOT_ON_ROOT | CFTYPE_NS_DELEGATABLE,\n'
                '\t\t.seq_show = memory_oom_group_show,\n\t\t.write = memory_oom_group_write,\n\t},')
        replace('static void mem_cgroup_css_reset(struct cgroup_subsys_state *css)\n{\n'
                '\tstruct mem_cgroup *memcg = mem_cgroup_from_css(css);\n',
                'static void mem_cgroup_css_reset(struct cgroup_subsys_state *css)\n{\n'
                '\tstruct mem_cgroup *memcg = mem_cgroup_from_css(css);\n\n'
                '\t/* 74183a956dec: reset hidden memory css policy too. */\n'
                '\tWRITE_ONCE(memcg->oom_group, false);\n')
    elif name == 'mm/oom_kill.c':
        start = text.index('static void oom_kill_process(struct oom_control *oc, const char *message)')
        end = text.index('\n#undef K', start)
        original = text[start:end]
        split = original.index('\tp = find_lock_task_mm(victim);')
        helper = ('static void __oom_kill_process(struct task_struct *victim)\n{\n'
                  '\tstruct task_struct *p;\n\tstruct mm_struct *mm;\n\tbool can_oom_reap = true;\n\n'
                  + original[split:])
        selector = original[:split].replace('\tstruct mm_struct *mm;', '\tstruct mem_cgroup *oom_group;')
        selector = selector.replace('\tbool can_oom_reap = true;\n', '')
        selector += ('\toom_group = mem_cgroup_get_oom_group(victim, oc->memcg);\n'
                     '\t__oom_kill_process(victim);\n\n'
                     '\tif (oom_group) {\n\t\tmem_cgroup_print_oom_group(oom_group);\n'
                     '\t\tmem_cgroup_scan_tasks(oom_group, oom_kill_memcg_member, NULL);\n'
                     '#ifdef CONFIG_MEMCG\n\t\tcss_put(&oom_group->css);\n#endif\n\t}\n}\n')
        member = upstream_function('3d8b38eb81cac81395f6a823f6bf401b327268e6', name, 'static int oom_kill_memcg_member(')
        text = text[:start] + helper + '\n' + member + '\n' + selector + text[end:]
    else:
        raise ValueError(name)
    return text


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--base', type=Path, required=True)
    parser.add_argument('--source', type=Path, required=True)
    args = parser.parse_args()
    baseline = json.loads((ROOT / 'tools/hardening-baseline/lock.json').read_text())
    for commit, expected in COMMITS.items():
        assert sha((UPSTREAM / (commit + '.patch')).read_bytes()) == expected
    changes = {}
    outputs = {}
    patch = []
    for name, expected in baseline.items():
        before = (args.base / name).read_bytes()
        assert sha(before) == expected, 'Baseline differs: ' + name
        text = before.decode()
        after = transform(name, text).encode()
        path = args.source / name
        if path.exists():
            assert sha(path.read_bytes()) in {expected, sha(after)}, 'Unreviewed target edit: ' + name
        outputs[path] = after
        changes[name] = {'before_sha256': expected, 'after_sha256': sha(after)}
        patch.extend(difflib.unified_diff(text.splitlines(True), after.decode().splitlines(True),
                                          fromfile='a/' + name, tofile='b/' + name))
    for path, content in outputs.items():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
    destination = ROOT / 'artifacts/droidspaces/kernel-ext-harden1'
    destination.mkdir(parents=True, exist_ok=True)
    patch_text = ''.join(patch)
    (ROOT / 'patches/container-lifecycle-4.14.patch').write_text(patch_text, encoding='utf-8', newline='\n')
    (destination / 'source.json').write_text(json.dumps({'source': str(args.source), 'base_source': str(args.base),
        'modified_sources': changes, 'upstream_patches_sha256': COMMITS, 'patch_sha256': sha(patch_text.encode()),
        'adaptations': ['Cache kill sequence in task_struct because old fork API has no kernel_clone_args',
                        'Preserve existing OOM child-selection reference fix and old group-signal API',
                        'Use css_put for selected OOM group because old tree lacks mem_cgroup_put',
                        'Keep memory controller disabled configuration compilable']}, indent=2) + '\n')
    print(json.dumps({'source_prepared': True, 'modified_files': len(changes), 'patch_sha256': sha(patch_text.encode())}))


if __name__ == '__main__':
    main()

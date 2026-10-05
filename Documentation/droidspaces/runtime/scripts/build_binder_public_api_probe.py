#!/usr/bin/env python3
"""Compile the public API 36 callback fixture with locked SDK and D8 inputs."""
import hashlib
import json
from pathlib import Path
import subprocess
from device_runtime import ROOT


def sha(path): return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    tools = ROOT / 'tools/downloads/android16-binder-api'
    lock = json.loads((tools / 'source-lock.json').read_text(encoding='utf-8'))
    for name in ('android.jar', 'r8.jar'): assert sha(tools / name) == lock[name]['sha256']
    output = ROOT / 'artifacts/droidspaces/binder-public-api-fixture'
    output.mkdir(parents=True, exist_ok=True)
    source = ROOT / 'references/runtime-probes/binder-freeze/RmxBinderFreezeApi.java'
    def wsl(path): return '/mnt/' + path.drive[0].lower() + str(path)[2:].replace('\\','/')
    program = '''import pathlib, subprocess, sys
out, source, sdk, r8 = map(pathlib.Path, sys.argv[1:])
classes = out / 'classes'; classes.mkdir(exist_ok=True)
subprocess.run(['javac','--release','8','-cp',str(sdk),'-d',str(classes),str(source)],check=True)
subprocess.run(['java','-cp',str(r8),'com.android.tools.r8.D8','--min-api','36','--lib',str(sdk),'--output',str(out),*[str(p) for p in sorted(classes.glob('*.class'))]],check=True)
print(subprocess.check_output(['javac','-version'],stderr=subprocess.STDOUT).decode().strip())
print(subprocess.check_output(['java','-cp',str(r8),'com.android.tools.r8.D8','--version'],stderr=subprocess.STDOUT).decode().strip())
'''
    result = subprocess.run(['wsl.exe','-d','Ubuntu','--','python3','-c',program,
                             wsl(output),wsl(source),wsl(tools/'android.jar'),wsl(tools/'r8.jar')],capture_output=True)
    record={'source_sha256':sha(source),'tools_source_lock_sha256':sha(tools/'source-lock.json'),
            'returncode':result.returncode,'stdout':result.stdout.decode(errors='replace'),'stderr':result.stderr.decode(errors='replace')}
    if not result.returncode: record['classes_dex_sha256']=sha(output/'classes.dex')
    path=output/'build-result.json';assert not path.exists(),'Preserve the original fixture build evidence'
    path.write_text(json.dumps(record,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(record,indent=2));raise SystemExit(result.returncode)


if __name__=='__main__': main()

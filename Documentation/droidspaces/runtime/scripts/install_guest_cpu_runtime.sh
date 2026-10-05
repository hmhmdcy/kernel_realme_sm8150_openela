#!/bin/sh
# Root-owned OCI entry wrappers preserve the operator CPU group on exec/fork.
set -eu
test -f /etc/droidspaces
test "$(id -u)" = 0
mkdir -p /usr/local/libexec /etc/containers/containers.conf.d
temporary=$(mktemp /tmp/rmx1931-oci-cpu-XXXXXXXX)
trap 'rm -f "$temporary"' EXIT HUP INT TERM
cat > "$temporary" <<'PY'
#!/usr/bin/python3
import os,re,sys
runtime=os.path.basename(sys.argv[0]).removeprefix('rmx1931-oci-')
assert runtime in ('crun','runc') and os.path.isfile('/etc/droidspaces')
ids=[argument for argument in sys.argv[1:] if re.fullmatch('[0-9a-f]{64}',argument)]
for container in ids:
    group='/run/rmx1931-cpu/'+container
    procs=group+'/cgroup.procs'
    if os.path.isfile(procs):
        # Each directory is an Android-root bind of that container's single
        # V1 CPU leaf. No host parent or sibling groups are exposed.
        with open(procs,'w') as stream:
            stream.write(str(os.getpid())+'\n')
os.execv('/usr/bin/'+runtime,[runtime,*sys.argv[1:]])
PY
for runtime in crun runc; do
    test -x /usr/bin/$runtime
    target=/usr/local/libexec/rmx1931-oci-$runtime
    test ! -L "$target"
    if test -e "$target" && ! cmp -s "$temporary" "$target"; then
        case "$(sha256sum "$target" | cut -d ' ' -f 1)" in
            338415df58e5167efb17c5fc3319b7d6ecb6890570682410431f84ecf1b19228)
                # The reviewed persistent-policy entry also retains legacy
                # CPU leaf inheritance. Keep it across guest profile renewal.
                test -f /etc/rmx1931/resource-policies.json
                test -f /usr/local/libexec/rmx1931_resource_policy.py
                sha256sum "$target"
                continue ;;
            f44643b25d86b62b749e1d63a421ccc6c21318f6ca21a4d5df23424b875235f9|bd0c90e98c93b83fc420c010166a7476b43da017d4ac0d008b6d795b14e305d9) ;;
            *) exit 1 ;;
        esac
    fi
    install -o root -g root -m 755 "$temporary" "$target"
    sha256sum "$target"
done
cat > "$temporary" <<'CF'
# Isolated DroidSpaces guest: inherit the Android-root per-container CPU leaf.
[engine.runtimes]
crun = ["/usr/local/libexec/rmx1931-oci-crun"]
runc = ["/usr/local/libexec/rmx1931-oci-runc"]
CF
target=/etc/containers/containers.conf.d/90-rmx1931-cpu.conf
test ! -L "$target"
if test -e "$target"; then cmp "$temporary" "$target"; else install -o root -g root -m 644 "$temporary" "$target"; fi
podman info --format '{{.Host.OCIRuntime.Path}}'
podman-rootless info --format '{{.Host.OCIRuntime.Path}}'
printf 'GUEST_CONTAINER_CPU_RUNTIME_INSTALLED\n'

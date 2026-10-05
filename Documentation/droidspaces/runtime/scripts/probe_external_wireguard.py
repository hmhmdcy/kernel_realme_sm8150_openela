#!/usr/bin/env python3
"""Independent WSL/phone WireGuard peers across physical Wi-Fi, scoped NAT and netns cleanup."""
import argparse
import datetime as dt
import json
import re
import shlex
import subprocess
import sys
import time
from device_runtime import device, guest_info, read_identity, read_root, ROOT


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--label',required=True)
    parser.add_argument('--port',type=int,default=51873,help='Dedicated UDP port; use a fresh port when inspecting stale NAT state')
    args=parser.parse_args()
    assert 1024<=args.port<=65535
    port=str(args.port)
    assert re.fullmatch('[a-zA-Z0-9_-]+',args.label) and len(args.label)<60
    path=ROOT/'artifacts/droidspaces/runtime'/(args.label+'.json')
    assert not path.exists()
    adb=device(); before=read_identity(adb); pid=guest_info(adb)['pid']
    phone=re.search(r'inet (192\.168\.0\.\d+)/24',read_root(adb,'ip -4 addr show wlan0').decode())[1]
    namespace='rmxwg-'+args.label
    wslbase='/var/tmp/rmx1931-wg-'+args.label
    guestbase='/proc/'+str(pid)+'/root/var/tmp/rmx1931-wg-'+args.label
    rule=['-i','wlan0','-s','192.168.0.104','-d',phone,'-p','udp','--dport',port,
          '-m','comment','--comment','rmx1931-'+args.label,'-j','DNAT','--to-destination','172.28.232.207:'+port]
    record={'observed_at':dt.datetime.now(dt.timezone.utc).isoformat(),**before,
            'phone_wifi_address':phone,'outer_transport':'physical Wi-Fi, independent WSL endpoint',
            'mtu':1420,'udp_port':args.port,'passed':False,'cleanup_errors':[]}
    wsl_created=False; rule_created=False; worker=None
    def wsl(command,timeout=30,allowed=(0,)):
        result=subprocess.run(['wsl','-u','root','--exec','sh','-lc',command],capture_output=True,text=True,timeout=timeout)
        if result.returncode not in allowed:raise RuntimeError('WSL exit '+str(result.returncode)+': '+(result.stdout+result.stderr)[-3000:])
        return result
    def mutate(command):
        result=subprocess.run(adb+['exec-out','su','-c',command],capture_output=True,timeout=20)
        if result.returncode:raise RuntimeError(result.stderr.decode(errors='replace'))
    def ns(arguments,timeout=30,allowed=(0,)):
        return wsl(shlex.join(['ip','netns','exec',namespace,*arguments]),timeout,allowed)
    try:
        wsl('set -e; umask 077; test ! -e '+wslbase+'; test ! -e /run/netns/'+namespace+'; mkdir -m 700 '+wslbase+'; wg genkey > '+wslbase+'/private.key; wg pubkey < '+wslbase+'/private.key > '+wslbase+'/public.key; ip netns add '+namespace)
        wsl_created=True
        public=wsl('cat '+wslbase+'/public.key').stdout.strip()
        assert re.fullmatch('[A-Za-z0-9+/]{43}=',public)
        wsl('set -e; ip link add rmx1931wge type wireguard; wg set rmx1931wge private-key '+wslbase+'/private.key listen-port '+port+'; ip link set rmx1931wge netns '+namespace+'; ip netns exec '+namespace+' ip addr add 10.193.2.1/24 dev rmx1931wge; ip netns exec '+namespace+' ip link set lo up; ip netns exec '+namespace+' ip link set rmx1931wge mtu 1420 up')
        mutate(shlex.join(['iptables','-t','nat','-I','PREROUTING','1',*rule])); rule_created=True
        worker=subprocess.Popen([sys.executable,str(ROOT/'scripts/privileged_guest.py'),'--script',str(ROOT/'scripts/probe_external_wireguard_guest.sh'),
               '--script-arg',public,'--script-arg',args.label,'--script-arg',port,'--label',args.label+'-guest','--timeout','180'],stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
        ready=None
        for attempt in range(40):
            data=read_root(adb,'if test -f '+guestbase+'/ready.json; then cat '+guestbase+'/ready.json; fi').decode()
            if data:ready=json.loads(data); break
            time.sleep(.5)
        assert ready,'Phone WireGuard setup never became ready'
        peer=ready['public_key']; assert re.fullmatch('[A-Za-z0-9+/]{43}=',peer)
        def configure(key):
            return ns(['wg','set','rmx1931wge','peer',key,'allowed-ips','10.193.2.2/32','endpoint',phone+':'+port,'persistent-keepalive','1'])
        def wait_handshake(after=0):
            deadline=time.monotonic()+20
            while time.monotonic()<deadline:
                value=int(ns(['wg','show','rmx1931wge','latest-handshakes']).stdout.split()[1])
                if value>after:return value
                time.sleep(.5)
            raise RuntimeError('No authenticated external handshake within 20 seconds')
        configure(peer)
        handshake=wait_handshake()
        ping=ns(['ping','-c','3','-W','3','-M','do','-s','1392','10.193.2.2'])
        assert re.search(r'(?<![\d.])0% packet loss',ping.stdout),ping.stdout
        record['near_mtu_ping']=ping.stdout
        oversized=ns(['ping','-c','1','-W','1','-M','do','-s','1393','10.193.2.2'],allowed=(1,2))
        assert 'message too long' in (oversized.stdout+oversized.stderr).lower()
        record['oversized_packet_rejected']=oversized.stdout+oversized.stderr
        record['initial_handshake']=handshake
        for label,extra in [('computer_to_phone',[]),('phone_to_computer',['-R'])]:
            output=ns(['iperf3','-c','10.193.2.2','-p','52073','-t','8','-J',*extra],timeout=25)
            measurement=json.loads(output.stdout)
            assert 'error' not in measurement and measurement['end']['sum_received']['bytes']>1048576
            record[label]=measurement
            print(json.dumps({'direction':label,'bits_per_second':measurement['end']['sum_received']['bits_per_second']}),flush=True)
        # Remove the peer to prove failure, then require a fresh handshake after reconfiguration.
        ns(['wg','set','rmx1931wge','peer',peer,'remove'])
        failed=ns(['ping','-c','1','-W','1','10.193.2.2'],allowed=(1,2))
        record['peer_removed_failure']=failed.stdout+failed.stderr
        wrong=wsl('wg genkey | wg pubkey').stdout.strip()
        configure(wrong)
        rejected=ns(['ping','-c','1','-W','2','10.193.2.2'],allowed=(1,2))
        assert int(ns(['wg','show','rmx1931wge','latest-handshakes']).stdout.split()[1])==0
        record['wrong_key_rejected']=rejected.stdout+rejected.stderr
        ns(['wg','set','rmx1931wge','peer',wrong,'remove'])
        time.sleep(2); configure(peer)
        new_handshake=wait_handshake(handshake)
        recovered=ns(['ping','-c','3','-W','3','10.193.2.2'])
        assert re.search(r'(?<![\d.])0% packet loss',recovered.stdout)
        assert new_handshake>handshake
        record.update(recovery_ping=recovered.stdout,renewed_handshake=new_handshake,
                      transfer=ns(['wg','show','rmx1931wge','transfer']).stdout,
                      endpoints=ns(['wg','show','rmx1931wge','endpoints']).stdout,passed=True)
    except Exception as error:
        record['error']=str(error)
        # Save network-layer diagnostics before removing only this test's peers.
        record['failure_diagnostics']={}
        for name,command in [('wsl_routes','ip route get '+phone),
                             ('peer_handshakes',shlex.join(['ip','netns','exec',namespace,'wg','show','rmx1931wge','latest-handshakes'])),
                             ('peer_transfer',shlex.join(['ip','netns','exec',namespace,'wg','show','rmx1931wge','transfer']))]:
            try:record['failure_diagnostics'][name]=wsl(command,allowed=(0,1,2)).stdout
            except Exception as diagnostic:record['failure_diagnostics'][name]=str(diagnostic)
        try:record['failure_diagnostics']['android_nat_counters']=read_root(adb,'iptables -t nat -nvL PREROUTING').decode()
        except Exception as diagnostic:record['failure_diagnostics']['android_nat_counters']=str(diagnostic)
    finally:
        if worker:
            try:
                mutate('if test -d '+guestbase+'; then touch '+guestbase+'/finish; fi')
                code=worker.wait(timeout=25)
                if code:record['cleanup_errors'].append('Guest exit '+str(code)+': '+worker.stderr.read().decode(errors='replace'))
            except Exception as error:record['cleanup_errors'].append(str(error))
        if rule_created:
            try:mutate(shlex.join(['iptables','-t','nat','-D','PREROUTING',*rule]))
            except Exception as error:record['cleanup_errors'].append(str(error))
        if wsl_created:
            try:wsl('ip netns del '+namespace)
            except Exception as error:record['cleanup_errors'].append(str(error))
        record['end_identity']=read_identity(adb)
        if record['end_identity']!=before or record['cleanup_errors']:record['passed']=False
        path.write_text(json.dumps(record,indent=2)+'\n')
        print(json.dumps({key:value for key,value in record.items() if key not in ('computer_to_phone','phone_to_computer')},indent=2),flush=True)
    raise SystemExit(0 if record['passed'] else 1)


if __name__=='__main__':main()

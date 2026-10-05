#!/usr/bin/env python3
"""Computer-initiated Wi-Fi benchmark; no inbound Windows firewall exception needed."""
import argparse
import datetime as dt
import hashlib
import json
from pathlib import Path
import re
import socket
import struct
import subprocess
import sys
import time
from device_runtime import device, guest_info, read_identity, read_root, ROOT


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--label',required=True)
    parser.add_argument('--battery-discharge',action='store_true',help='Suspend USB/DC input for this bounded test and restore it in finally')
    parser.add_argument('--interface-index',type=int,help='Windows physical interface index for this test socket only')
    args=parser.parse_args()
    assert re.fullmatch('[a-zA-Z0-9_-]+',args.label)
    path=ROOT/'artifacts/droidspaces/runtime'/(args.label+'.json')
    assert not path.exists()
    adb=device(); identity=read_identity(adb); pid=guest_info(adb)['pid']
    info=read_root(adb,'ip -4 addr show wlan0').decode()
    phone=re.search(r'inet (192\.168\.0\.\d+)/24',info)[1]
    computer='192.168.0.104'
    guest='172.28.232.207'
    # This guest's pinned NAT profile and exact source/destination are checked.
    assert guest in read_root(adb,'/proc/'+str(pid)+'/root/usr/bin/busybox nsenter -t '+str(pid)+' -n -- ip -4 addr show eth0').decode()
    comment='rmx1931-'+args.label
    rule=['-i','wlan0','-s',computer,'-d',phone,'-p','tcp','--dport','51874',
          '-m','comment','--comment',comment,'-j','DNAT','--to-destination',guest+':51874']
    import shlex
    def mutate(command):
        result=subprocess.run(adb+['exec-out','su','-c',command],capture_output=True,timeout=20)
        if result.returncode:raise RuntimeError(result.stderr.decode(errors='replace'))
    result={'observed_at':dt.datetime.now(dt.timezone.utc).isoformat(),**identity,
            'phone_wifi_address':phone,'computer_address':computer,'transport':'physical Wi-Fi, computer initiates TCP',
            'trials':[],'passed':False,'cleanup_errors':[]}
    if args.interface_index:
        assert 0<args.interface_index<2**24
        result['windows_socket_interface_index']=args.interface_index
    def connect():
        if not args.interface_index:return socket.create_connection((phone,51874),timeout=5)
        handle=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        try:
            # IP_UNICAST_IF uses network byte order (Microsoft Winsock docs).
            handle.setsockopt(socket.IPPROTO_IP,31,struct.pack('!I',args.interface_index))
            handle.bind((computer,0));handle.settimeout(5)
            handle.connect((phone,51874))
            return handle
        except Exception:
            handle.close();raise
    created=False; worker=None; suspended=False
    try:
        if args.battery_discharge:
            assert read_root(adb,'cat /sys/class/power_supply/battery/input_suspend').strip()==b'0'
            mutate('echo 1 > /sys/class/power_supply/battery/input_suspend')
            suspended=True
            assert read_root(adb,'cat /sys/class/power_supply/battery/input_suspend').strip()==b'1'
            result['input_suspend_during_test']=True
        mutate(shlex.join(['iptables','-t','nat','-I','PREROUTING','1',*rule])); created=True
        worker=subprocess.Popen([sys.executable,str(ROOT/'scripts/device_runtime.py'),'run-file',
                '--script',str(ROOT/'scripts/probe_external_tcp_server.sh'),'--guest-service',
                '--label',args.label+'-server','--timeout','120'],stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
        time.sleep(4)
        def receive(handle,size):
            data=bytearray()
            while len(data)<size:
                piece=handle.recv(size-len(data))
                if not piece:raise RuntimeError('Unexpected stream closure')
                data.extend(piece)
            return data
        for algorithm in ('cubic','bbr','bbr','cubic','cubic','bbr'):
            with connect() as connection:
                connection.settimeout(20)
                connection.sendall((json.dumps({'algorithm':algorithm,'seconds':10})+'\n').encode())
                total=0
                while True:
                    length=struct.unpack('!I',receive(connection,4))[0]
                    assert length<=65536
                    if not length:break
                    receive(connection,length); total+=length
                length=struct.unpack('!I',receive(connection,4))[0]; assert length<100000
                record=json.loads(receive(connection,length))
                assert record['bytes']==total and record['algorithm']==algorithm and total>1048576
                result['trials'].append(record)
                print(json.dumps({key:record[key] for key in ('algorithm','megabits_per_second','sender_cpu_seconds','rtt_microseconds_mean')}),flush=True)
        code=worker.wait(timeout=20)
        assert code==0,worker.stderr.read().decode(errors='replace')
        result['passed']=True
        # Zero/frozen current and coarse SOC counters cannot certify energy.
        samples=[point for record in result['trials'] for point in record['power_samples']]
        valid=bool(args.battery_discharge)
        for record in result['trials']:
            points=record['power_samples']
            charge=energy=0
            for left,right in zip(points,points[1:]):
                assert all(point[key] is not None for point in (left,right) for key in ('current_now','voltage_now','input_suspend'))
                seconds=right['monotonic']-left['monotonic']
                current=(left['current_now']+right['current_now'])/2
                voltage=(left['voltage_now']+right['voltage_now'])/2
                # The Oplus gauge returns signed mA here, despite generic current_now naming.
                charge+=current*seconds/3600
                energy+=current*voltage*seconds/3.6e9
            record.update(measured_battery_charge_mah=charge,measured_battery_energy_mwh=energy,
                          measured_battery_mwh_per_gib=energy/(record['bytes']/1024**3),
                          current_unit='mA, signed Oplus gauge',voltage_unit='microvolts')
            valid &= all(point['input_suspend']==1 for point in points) and sum(point['current_now']>0 for point in points)>=5
        result['energy_measurement_valid']=bool(valid)
        result['energy_scope']='Net battery discharge measured by gauge with input_suspend=1; includes background phone activity, and this gauge uses averaged current.'
    except Exception as error:
        result['error']=str(error)
    finally:
        if suspended:
            try:
                mutate('echo 0 > /sys/class/power_supply/battery/input_suspend')
                assert read_root(adb,'cat /sys/class/power_supply/battery/input_suspend').strip()==b'0'
                result['charging_input_restored']=True
            except Exception as error:result['cleanup_errors'].append('Restore charging: '+str(error))
        if created:
            try:mutate(shlex.join(['iptables','-t','nat','-D','PREROUTING',*rule]))
            except Exception as error:result['cleanup_errors'].append(str(error))
        if worker and worker.poll() is None:
            # Do not replay a timed-out service; it has a bounded accept timeout.
            worker.wait(timeout=40)
        result['end_identity']=read_identity(adb)
        if result['end_identity']!=identity or result['cleanup_errors']:result['passed']=False
        path.write_text(json.dumps(result,indent=2)+'\n')
        print(json.dumps({key:value for key,value in result.items() if key!='trials'}),flush=True)
    raise SystemExit(0 if result['passed'] else 1)


if __name__=='__main__':main()

#!/bin/sh
set -eu
test -f /etc/droidspaces
cd /var/tmp
python3 - <<'PY'
import json,socket,struct,threading,time
from pathlib import Path
root=Path('/sys/class/power_supply/battery')
server=socket.socket()
server.bind(('0.0.0.0',51874))
server.listen(2)
server.settimeout(25)
print('EXTERNAL_TCP_SERVER_READY',flush=True)
for trial in range(6):
    client,peer=server.accept()
    with client:
        client.settimeout(8)
        line=b''
        while not line.endswith(b'\n'):
            line+=client.recv(1)
            assert len(line)<=128
        request=json.loads(line)
        algorithm=request['algorithm']
        assert algorithm in ('cubic','bbr')
        assert request['seconds']==10
        client.setsockopt(socket.IPPROTO_TCP,socket.TCP_CONGESTION,algorithm.encode())
        actual=client.getsockopt(socket.IPPROTO_TCP,socket.TCP_CONGESTION,16).rstrip(b'\0').decode()
        assert actual==algorithm
        power=[]; stopped=threading.Event()
        def sample():
            while not stopped.is_set():
                point={'monotonic':time.monotonic()}
                for name in ('batt_rm','current_now','voltage_now','temp','input_suspend'):
                    try:point[name]=int((root/name).read_text())
                    except (OSError,ValueError):point[name]=None
                power.append(point)
                stopped.wait(.5)
        sampling=threading.Thread(target=sample); sampling.start()
        payload=bytes(65536); packet=struct.pack('!I',len(payload))+payload
        cpu=time.thread_time(); start=time.monotonic(); total=0; latencies=[]
        while time.monotonic()-start<10:
            client.sendall(packet); total+=len(payload)
            info=client.getsockopt(socket.IPPROTO_TCP,socket.TCP_INFO,104)
            latencies.append(struct.unpack_from('<I',info,68)[0])
        elapsed=time.monotonic()-start; cpu=time.thread_time()-cpu
        stopped.set(); sampling.join()
        result={'trial':trial,'algorithm':actual,'peer':peer[0],'bytes':total,'seconds':elapsed,
                'megabits_per_second':total*8/elapsed/1e6,'sender_cpu_seconds':cpu,
                'rtt_microseconds_min':min(latencies),'rtt_microseconds_mean':sum(latencies)/len(latencies),
                'power_samples':power}
        encoded=json.dumps(result).encode()
        client.sendall(struct.pack('!I',0)+struct.pack('!I',len(encoded))+encoded)
        print(json.dumps(result),flush=True)
server.close()
print('BBR_CUBIC_EXTERNAL_TCP_SIX_TRIALS_PASS',flush=True)
PY

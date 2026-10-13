#!/usr/bin/env python3
"""Only synthetic loopback TURN/DTLS/WG. Run in a disposable network namespace."""
import argparse,concurrent.futures,http.client,json,os,pathlib,socket,struct,subprocess,tempfile,time
from check_socks_udp_pair import recv_exact,sock_connect,udp_assoc,probe_udp,wait_until

SLOW_READ_MS = 0

def bulk(index):
 start=time.monotonic()
 with sock_connect() as s:
  s.settimeout(60)
  s.sendall(b'\x05\x01\x00\x01'+socket.inet_aton('10.66.66.1')+struct.pack('!H',18080))
  if recv_exact(s,10)[:2]!=b'\x05\x00':raise RuntimeError('TCP fixture refused')
  if index%2:
   s.sendall(b'POST /memory-upload HTTP/1.1\r\nHost: fixture.invalid\r\nContent-Length: 1048576\r\nConnection: close\r\n\r\n')
   for _ in range(16):s.sendall(b'\x01'*65536)
  else:s.sendall(b'GET /memory-bulk HTTP/1.1\r\nHost: fixture.invalid\r\nConnection: close\r\n\r\n')
  rsp=http.client.HTTPResponse(s);rsp.begin();total=0
  if rsp.status!=200:raise RuntimeError('HTTP fixture failed')
  while True:
   b=rsp.read(16384 if SLOW_READ_MS else 65536)
   if SLOW_READ_MS:time.sleep(SLOW_READ_MS/1000)
   if not b:break
   if index%2:
    if b!=b'UPLOAD-OK\n':raise RuntimeError('upload response mismatch')
   elif b!=b'\x01'*len(b):raise RuntimeError('TCP payload mismatch')
   total+=len(b)
  if total!=(10 if index%2 else 1048576):raise RuntimeError('TCP length mismatch')
 return time.monotonic()-start

def main():
 p=argparse.ArgumentParser()
 for n in ['harness','client-test','report','samples']:p.add_argument('--'+n,required=True)
 p.add_argument('--hold-seconds',type=float,default=0);p.add_argument('--slow-read-ms',type=float,default=0)
 p.add_argument('--workers',type=int,choices=[9,18],required=True);p.add_argument('--soak',action='store_true');a=p.parse_args()
 global SLOW_READ_MS
 SLOW_READ_MS=a.slow_read_ms
 result={'hold_seconds':a.hold_seconds,'slow_read_ms':a.slow_read_ms,'passed':False,'scope':'native test process, real 9/18 RunSession TURN/DTLS/WG/SOCKS; synthetic credential provider, no VK or hardware','workers':a.workers,'soak':a.soak,'bulk_bytes':0,'udp_payload_bytes':0,'latency_seconds':[],'drain_wait_seconds':[]}
 children=[];controls=[];sockets=[];stage='server_start';rounds=0;began=time.monotonic()
 with tempfile.TemporaryDirectory(prefix='wdtt-memory-session-') as temp:
  d=pathlib.Path(temp);d.chmod(0o700)
  try:
   env={**os.environ,'WDTT_LOCAL_PAIR_DIR':temp,'WDTT_MEMORY_LAB':'1'}
   server=subprocess.Popen([str(pathlib.Path(a.harness).resolve()),'-test.run=^TestLocalPairHarness$','-test.timeout=1900s'],env=env,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL);children.append(server)
   wait_until(lambda:(d/'READY').exists(),children);stage='session_readiness'
   client=subprocess.Popen([str(pathlib.Path(a.client_test).resolve()),'-test.run=^TestLowmemSessionLab$','-test.timeout=1850s'],env={**os.environ,'WDTT_LOWMEM_SESSION_DIR':temp,'WDTT_LOWMEM_WORKERS':str(a.workers)},stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL);children.append(client)
   wait_until(lambda:(d/'memory-ready').exists(),children,90);time.sleep(3)
   for _ in range(4):
    control,port=udp_assoc();controls.append((control,port));udp=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);udp.bind(('127.0.0.1',0));udp.settimeout(10);sockets.append(udp)
   began=time.monotonic();rounds=0
   if a.hold_seconds:
    # Hold a real SOCKS TCP connection open, then prove fresh payload delivery.
    with sock_connect() as held:
     held.settimeout(60)
     held.sendall(b'\x05\x01\x00\x01'+socket.inet_aton('10.66.66.1')+struct.pack('!H',18080))
     if recv_exact(held,10)[:2]!=b'\x05\x00':raise RuntimeError('held TCP refused')
     time.sleep(a.hold_seconds)
     held.sendall(b'GET /memory-bulk HTTP/1.1\r\nHost: fixture.invalid\r\nConnection: close\r\n\r\n')
     rsp=http.client.HTTPResponse(held);rsp.begin()
     if rsp.status!=200 or rsp.read()!=b'\x01'*1048576:raise RuntimeError('held TCP fresh payload failed')
     result['held_tcp_verified']=True

   while True:
    stage='previous_tcp_slot_drain';drain_start=time.monotonic()
    def drained():
     try:return int((d/'memory-active').read_text())==len(controls)
     except (OSError,ValueError):return False
    wait_until(drained,children,10)
    result['drain_wait_seconds'].append(time.monotonic()-drain_start)
    (d/'memory-command').write_text('load\n')
    started=time.monotonic();stage='tcp_bulk'
    with concurrent.futures.ThreadPoolExecutor(max_workers=28) as pool:times=list(pool.map(bulk,range(28)))
    result['latency_seconds']+=times;result['bulk_bytes']+=28*1048576
    stage='udp_exchange'
    for (control,port),udp in zip(controls,sockets):
     for _ in range(100):probe_udp(udp,port,b'\x03'*1400);result['udp_payload_bytes']+=1400
    rounds+=1
    (d/'memory-command').write_text('idle\n')
    if not a.soak and rounds==3:break
    if a.soak:
     until=started+60
     while time.monotonic()<until:
      if (d/'memory-finished').exists() or client.poll() is not None:break
      time.sleep(.2)
     if (d/'memory-finished').exists() or client.poll() is not None:break
   for c,_ in controls:c.close()
   controls=[]
   time.sleep(3)
   (d/'memory-command').write_text('stop\n')
   client.wait(timeout=20)
   if client.returncode!=0:raise RuntimeError('client fixture failed')
   result.update(passed=True,elapsed_seconds=time.monotonic()-began,terminal=(d/'memory-finished').read_text().strip(),rounds=rounds)
  except Exception as e:result.update(error=type(e).__name__,failure_stage=stage,rounds=rounds,elapsed_seconds=time.monotonic()-began) # no upstream errors/URLs/config
  finally:
   for c,_ in controls:c.close()
   for s in sockets:s.close()
   (d/'memory-command').write_text('stop\n');(d/'STOP').touch(mode=0o600)
   for child in reversed(children):
    if child.poll() is None:
     try:child.wait(timeout=5)
     except subprocess.TimeoutExpired:
      child.terminate()
      try:child.wait(timeout=5)
      except subprocess.TimeoutExpired:child.kill();child.wait()
   if (d/'session-samples.jsonl').exists():pathlib.Path(a.samples).write_bytes((d/'session-samples.jsonl').read_bytes())
 pathlib.Path(a.report).write_text(json.dumps(result,indent=2)+'\n')
 print('PASS local memory session lab' if result['passed'] else 'FAIL local memory session lab')
 if not result['passed']:raise SystemExit(1)
if __name__=='__main__':main()

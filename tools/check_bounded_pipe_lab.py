#!/usr/bin/env python3
"""Numeric A/B against immutable PR21; isolated namespaces, no published binaries."""
import argparse, hashlib, io, json, os, pathlib, resource, statistics, subprocess, tarfile, sys, tempfile, time
sys.dont_write_bytecode = True
from check_lowmem_lab import summarize
ROOT=pathlib.Path(__file__).resolve().parents[1]
BASE='f04bdbc101c8f9f86c2cc6a1cc512e9d2373504c'
def run(args,**kw):
 return subprocess.check_output([str(x) for x in args],text=True,**kw)
def main():
 p=argparse.ArgumentParser()
 for name in ['go','work','report-dir']:p.add_argument('--'+name,required=True)
 p.add_argument('--repetitions',type=int,default=3);a=p.parse_args()
 work=pathlib.Path(a.work).resolve();work.mkdir(mode=0o700,parents=True,exist_ok=False)
 out=pathlib.Path(a.report_dir).resolve();out.mkdir(parents=True,exist_ok=False)
 go=pathlib.Path(a.go).resolve()
 env={**os.environ,'GOENV':'off','GOTOOLCHAIN':'local','GOWORK':'off','GOTELEMETRY':'off','CGO_ENABLED':'0','GOOS':'linux','GOARCH':'amd64','GOMAXPROCS':'2'}
 env.pop('GOROOT',None)
 head=run(['git','-C',ROOT,'rev-parse','HEAD']).strip()
 assert not run(['git','-C',ROOT,'status','--porcelain','--','go_client','hardened-relay','tools']).strip(),'commit all measured runtime/harness sources first'
 baseline=work/'baseline'
 with tarfile.open(fileobj=io.BytesIO(subprocess.check_output(['git','-C',ROOT,'archive',BASE]))) as archive:archive.extractall(baseline,filter='data')
 test=(ROOT/'go_client/packet_pipe_pressure_test.go').read_text()
 test=test.replace('"encoding/json"','"encoding/json"\n"github.com/cbeuw/connutil"').replace('newBoundedPacketPipe()', 'connutil.AsyncPacketPipe()')
 (baseline/'go_client/packet_pipe_pressure_test.go').write_text(test)
 result={'baseline':BASE,'candidate':head,'toolchain':run([go,'version'],env=env).strip(),'scope':'native synthetic Linux; no VK or hardware acceptance','pressure':{},'sessions':{},'long_sessions':{},'binary_sha256':{}}
 cpus=sorted(os.sched_getaffinity(0))[:2];prefix=['taskset','-c',','.join(map(str,cpus))];result['cpu_affinity']=cpus
 for variant,source in [('baseline',baseline),('candidate',ROOT)]:
  binary=work/(variant+'.test');run([go,'test','-mod=readonly','-trimpath','-buildvcs=false','-c','-o',binary],cwd=source/'go_client',env=env)
  result['binary_sha256'][variant]=hashlib.sha256(binary.read_bytes()).hexdigest()
 run([go,'test','-mod=readonly','-trimpath','-buildvcs=false','-c','-o',work/'server.test'],cwd=ROOT/'hardened-relay',env=env)
 run([go,'test','-mod=readonly','-race','-trimpath','-buildvcs=false','-c','-o',work/'candidate-race.test'],cwd=ROOT/'go_client',env={**env,'CGO_ENABLED':'1','CC':'/usr/bin/gcc'})
 run(['unshare','-n','sh','-ec','ip link set lo up; exec "$@"','lab','python3','-B',ROOT/'tools/check_bounded_pipe_lab.py','--transport-child',str(work)],env=env)
 result['transport_paths_native_and_race']=True
 for rep in range(1,a.repetitions+1):
  for workers in [9,18]:
   for variant in ['baseline','candidate']:
    stem=f'{variant}-{workers}-{rep}';pressure=out/(stem+'-pressure.json')
    run([*prefix,work/(variant+'.test'),'-test.run=^TestBoundedPipePressureLab$','-test.timeout=30s'],env={**env,'WDTT_PIPE_LAB_REPORT':str(pressure),'WDTT_PIPE_LAB_WORKERS':str(workers)})
    result['pressure'][stem]=json.loads(pressure.read_text())
    # Same harness/traffic for each immutable runtime, separate namespace/run.
    cpu_before=resource.getrusage(resource.RUSAGE_CHILDREN)
    run(['unshare','-n','sh','-ec','ip link set lo up; exec "$@"','lab',*prefix,'python3',ROOT/'tools/check_lowmem_session.py','--harness',work/'server.test','--client-test',work/(variant+'.test'),'--workers',workers,'--report',out/(stem+'-report.json'),'--samples',out/(stem+'-samples.jsonl')],env=env)
    result['sessions'][stem]=summarize(out/(stem+'-samples.jsonl'))
    cpu_after=resource.getrusage(resource.RUSAGE_CHILDREN)
    result['sessions'][stem]['fixture_cpu_seconds']=(cpu_after.ru_utime+cpu_after.ru_stime)-(cpu_before.ru_utime+cpu_before.ru_stime)
    (out/'comparison.json').write_text(json.dumps(result,indent=2)+'\n')
 for workers in [9,18]:
  for variant in ['baseline','candidate']:
   stem=f'{variant}-{workers}-long'
   run(['unshare','-n','sh','-ec','ip link set lo up; exec "$@"','lab',*prefix,'python3',ROOT/'tools/check_lowmem_session.py','--harness',work/'server.test','--client-test',work/(variant+'.test'),'--workers',workers,'--hold-seconds','90','--slow-read-ms','20','--report',out/(stem+'-report.json'),'--samples',out/(stem+'-samples.jsonl')],env=env)
   result['long_sessions'][stem]=summarize(out/(stem+'-samples.jsonl'))
   (out/'comparison.json').write_text(json.dumps(result,indent=2)+'\n')
 # Numeric log fallback if artifact service/permissions fail after measurements.
 summary={'baseline':BASE,'candidate':head,'workers':{}}
 for workers in [9,18]:
  row={}
  for variant in ['baseline','candidate']:
   row[variant+'_pressure_hwm_kib']=[max(x['HWM'] for x in result['pressure'][f'{variant}-{workers}-{n}']['phases'].values()) for n in range(1,a.repetitions+1)]
   row[variant+'_full_hwm_kib']=[result['sessions'][f'{variant}-{workers}-{n}']['hwm_kib'] for n in range(1,a.repetitions+1)]
  summary['workers'][workers]=row
 print('NUMERIC_COMPARISON '+json.dumps(summary,sort_keys=True))
 print('PASS immutable PR21 paired 9/18 pressure and TCP/UDP runs')
def transport_child(work):
 from check_socks_udp_pair import wait_until
 with tempfile.TemporaryDirectory(prefix='wdtt-pipe-paths-') as folder:
  os.chmod(folder,0o700)
  server=subprocess.Popen([str(work/'server.test'),'-test.run=^TestLocalPairHarness$','-test.timeout=120s'],env={**os.environ,'WDTT_LOCAL_PAIR_DIR':folder},stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
  try:
   wait_until(lambda:(pathlib.Path(folder)/'READY').exists(),[server])
   for binary in ['candidate.test','candidate-race.test']:
    run([work/binary,'-test.run=^TestBoundedTransportPathsLab$','-test.timeout=60s'],env={**os.environ,'WDTT_PIPE_TRANSPORT_LAB':'1'})
  finally:
   (pathlib.Path(folder)/'STOP').touch()
   try:server.wait(timeout=5)
   except subprocess.TimeoutExpired:server.terminate();server.wait(timeout=5)
if __name__=='__main__':
 if len(sys.argv)==3 and sys.argv[1]=='--transport-child':transport_child(pathlib.Path(sys.argv[2]))
 else:main()

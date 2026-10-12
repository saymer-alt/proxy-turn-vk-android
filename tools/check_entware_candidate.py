#!/usr/bin/env python3
"""Isolated candidate acceptance using pinned Entware/KAS recipes; no publication."""
import argparse,hashlib,io,json,os,pathlib,shutil,subprocess,sys,tarfile
ROOT=pathlib.Path(__file__).resolve().parents[1]
ENTWARE='beb7e12c61deba465cdccfac77c8bb41ab0df89c'
KAS='7c01e29c0ef278532e083a0d6868cfef4d2ca003'
BASE='ff88cae7184561fe901e6e6a64f983ac6dd62980'
def run(args,**kw):
 try:return subprocess.check_output([str(x) for x in args],text=True,**kw).strip()
 except subprocess.CalledProcessError as e:
  print((e.output or '')[-4000:],file=sys.stderr);raise
def sha(p):return hashlib.sha256(pathlib.Path(p).read_bytes()).hexdigest()
def main():
 p=argparse.ArgumentParser();p.add_argument('--go',required=True);p.add_argument('--sdk',required=True);p.add_argument('--entware',required=True);p.add_argument('--kas',required=True);p.add_argument('--work',required=True);a=p.parse_args()
 work=pathlib.Path(a.work).resolve();work.mkdir(parents=True,exist_ok=False)
 ent=pathlib.Path(a.entware).resolve();kas=pathlib.Path(a.kas).resolve();go=pathlib.Path(a.go).resolve()
 assert run(['git','-C',ent,'rev-parse','HEAD'])==ENTWARE
 assert run(['git','-C',kas,'rev-parse','HEAD'])==KAS
 assert not run(['git','-C',ROOT,'status','--porcelain'])
 candidate=run(['git','-C',ROOT,'rev-parse','HEAD'])
 # The maintained relay, original module locks and every unrelated runtime source stay exact.
 baseline=json.loads(run(['git','-C',ROOT,'show',BASE+':provenance/PHASE4-SOURCE-EQUIVALENCE.json']))['sha256']
 # An explicit reviewed diagnostic extension, not a blanket runtime exemption.
 # Every modified client source has an exact Git blob pin; the remaining
 # Phase4 source equivalence guard below is still enforced unchanged.
 diagnostic_blobs={
  'go_client/main.go':'2e553d4ca3ab97c7876b8f31b68bee79cff9791d',
  'go_client/lab_security.go':'bad16b19f47e8cd6c66ade57b9c16fbdf8712785',
  'go_client/session.go':'81febbe4125d585eb8d9db35b43117597ce70228',
  'go_client/lab_getconf_status_test.go':'53e1fc751237d11555c1b64506a643bba0e956a5',
  'go_client/socks5.go':'83dd16836debb08a58a8452e090a49d9b130acf8',
  'go_client/lab_socks_mode_test.go':'70e555096897d2b672b3d9e39828cc64088a6311',
  'go_client/qwdtt_import.go':'a7fc4907066b82624f975b0a8d26c8eab2585e93',
  'go_client/qwdtt_anonymous9_test.go':'4ddd6f02ef56a9a4e4ce65200c2220f99f411919',
  'go_client/qwdtt_anonymous16_18_test.go':'082009c877b01d87c7a1902dcc6c7c97a75d23bc',
  'go_client/socks_service.go':'257816f247a5ea2443ffb4fc0482f71fa333da24',
  'go_client/socks_udp_associate.go':'82ca1cbdab7a9067c49ae2a548baf56d54b932c2',
  'go_client/socks_udp_associate_test.go':'831a65d2720dfab7cca8c4eb2800e6ed81f12551',
  'go_client/socks_telemetry.go':'43d2c03e2ce7705ced3722abf968531839fce00f',
  'go_client/socks_telemetry_test.go':'a85ee0e2db930cf0eb47836ef6d1863ac745a286',
  'hardened-relay/server_pair_fixture_test.go':'2c29f2276dcc699bc2b9863e995b712a572d460c',
  'tools/check_socks_udp_pair.py':'2523ec173a79f16c4f697015024dcab67e893142',
 }
 for name,blob in diagnostic_blobs.items():
  assert run(['git','-C',ROOT,'hash-object',name])==blob,'UNREVIEWED_DIAGNOSTIC_SOURCE_CHANGE: '+name
 allowed=set(diagnostic_blobs)|{'hardened-relay/server_pair_fixture_test.go'}
 for name,digest in baseline.items():
  if name not in allowed:assert sha(ROOT/name)==digest,'UNRELATED_RUNTIME_CHANGE: '+name
 env=os.environ.copy();env.update(GOTOOLCHAIN='local',GOENV='off',GOWORK='off',GOTELEMETRY='off',CGO_ENABLED='0',GOOS='linux',GOARCH='amd64',GOMIPS='softfloat',GOPATH=str(work/'gopath'),GOCACHE=str(work/'gocache'));env.pop('GOROOT',None)
 assert run([go,'version'],env=env)=='go version go1.26.1 linux/amd64'
 # All existing client tests, plus importer boundaries and fuzz seeds; no public endpoint.
 tests=run([go,'test','-mod=readonly','-short','-count=1','-timeout=120s','./...'],cwd=ROOT/'go_client',env=env)
 fuzz=run([go,'test','-mod=readonly','-run','^$','-fuzz','^FuzzQwdttParse$','-fuzztime=5s','-parallel=2'],cwd=ROOT/'go_client',env=env)
 expected={}
 for arch in ['amd64','arm64','mipsle','mips']:
  env['GOARCH']=arch;out=work/('direct-client-'+arch)
  run([go,'build','-mod=readonly','-trimpath','-buildvcs=false','-ldflags=-s -w -buildid=','-o',out,'.'],cwd=ROOT/'go_client',env=env);expected[arch]=sha(out)
 env['GOARCH']='amd64'
 recipe=work/'recipe';shutil.copytree(ent,recipe,ignore=shutil.ignore_patterns('.git','__pycache__'))
 wd=recipe/'wdtt'
 shutil.copyfile(ROOT/'hardened-relay/server_pair_fixture_test.go',wd/'lab/server_pair_fixture_test.go')
 files=run(['git','-C',ROOT,'ls-tree','-r','--name-only','HEAD']).splitlines()
 lock={'repository':'https://github.com/saymer-alt/proxy-turn-vk-android.git','commit':candidate,'upstream_base':'1110a75f76e42c23149b8e24f9182c1ff179e515','files_sha256':{name:sha(ROOT/name) for name in files}}
 (wd/'fork-source-lock.json').write_text(json.dumps(lock,indent=2)+'\n')
 # The Phase5 binary-equality test cannot describe a new importer executable.
 # Replace only that comparison in the PRIVATE recipe with independently built
 # candidate equality; compare third-party inventory against the maintained base.
 base_source=work/'base-source';base_source.mkdir()
 raw=subprocess.check_output(['git','-C',str(ROOT),'archive',BASE])
 with tarfile.open(fileobj=io.BytesIO(raw)) as archive:archive.extractall(base_source,filter='data')
 run(['python3',wd/'license_audit.py','--go',go,'--module',base_source/'go_client','--output',work/'base-inventory'],env=env)
 build=wd/'build_lab.py';text=build.read_text();start=text.index("    baseline=json.loads((HERE/'phase4-source-baseline.json').read_text())");end=text.index("    (work/'build-report.json').write_text",start)
 replacement="    baseline=json.loads((HERE/'phase4-source-baseline.json').read_text())\n"
 replacement+="    expected="+repr(expected)+"\n"
 replacement+="    for record in records:assert record['sha256']==expected[record['arch']], 'CANDIDATE_REPRODUCIBILITY_FAILED'\n"
 replacement+="    assert report['relay_sha256']==baseline['relay_sha256'], 'RELAY_CHANGED'\n"
 replacement+="    old=json.loads((work.parent/'base-inventory/dependency-source-audit.json').read_text());new=json.loads((work/'license-evidence/dependency-source-audit.json').read_text())\n"
 replacement+="    assert old['modules']==new['modules'] and old['packages']==new['packages'], 'DEPENDENCY_GRAPH_CHANGED'\n"
 replacement+="    external=lambda inventory:{k:v for k,v in inventory['sources'].items() if not k.startswith('wg-turn-client@LOCAL/')}\n"
 replacement+="    assert external(old)==external(new), 'THIRD_PARTY_SOURCE_CHANGED'\n"
 replacement+="    prefix=lambda path:path.read_text().split('===== SELECTED SOURCE COPYRIGHT HEADERS =====')[0]\n"
 replacement+="    assert prefix(work.parent/'base-inventory/NOTICE-COLLECTION.txt')==prefix(work/'license-evidence/NOTICE-COLLECTION.txt'), 'LICENSE_TEXT_CHANGED'\n"
 replacement+="    report['candidate_comparison']={'client_sha256_before':baseline['client_sha256'],'client_sha256_after':expected,'independent_candidate_rebuild_identical':True,'relay_identical':True,'third_party_sources_and_notices_identical':True,'local_source_inventory_changed':True,'reason':'explicit qWDTT and fixed-loopback SOCKS5 TCP/UDP plus aggregate-only owner telemetry; ARM64 >=256MiB available gets 64 SOCKS admission slots, MIPSel remains 32; all source SHA-pinned and remote wire protocol unchanged'}\n"
 build.write_text(text[:start]+replacement+text[end:])
 built=work/'build'
 run(['python3',build,'--go',go,'--sdk-archive',pathlib.Path(a.sdk).resolve(),'--work',built,'--source',ROOT,'--cache',work/'gocache','--modules',work/'gopath'])
 for name in ['test_packaging.py','test_owner_test_ipk.py','test_quarantine_retention.py','test_workflow_gate.py']:run(['python3',wd/name])
 run(['python3',kas/'tests/wdtt-entware-lifecycle.py'])
 run(['python3',wd/'verify_quarantine.py','--build',built,'--report',built/'quarantine-ipk-report.json'])
 run(['python3',wd/'build_opkg_fixture.py',work/'opkg'])
 run(['python3',wd/'test_owner_opkg.py','--opkg',work/'opkg/opkg-build/src/opkg-cl','--build',built,'--kas',kas,'--report',built/'owner-opkg-report.json'])
 run(['python3',wd/'fetch_test_mihomo.py',work/'test-deps'])
 run(['python3',wd/'local_pair.py','--harness',built/'server-pair.test','--relay',built/'wdtt-relay-linux-amd64','--client',built/'wt-client-linux-amd64','--mihomo',work/'test-deps/mihomo-compatible','--converter',kas/'experimental/wdtt/wg_to_mihomo.py','--report',built/'local-pair-report.json'])
 pair=work/'qwdtt_pair.py';pair_text=(wd/'local_pair.py').read_text()
 marker="            result['checks']['worker_registered_before_application_start']=True"
 assert marker in pair_text
 pair_text=pair_text.replace(marker,marker+"\n            wait_for(lambda:(d/'qwdtt-second-hash-turn').exists(),children)\n            result['checks']['actual_qwdtt_private_import_and_second_hash_TURN_auth']=True")
 pair.write_text(pair_text)
 run(['python3',pair,'--harness',built/'server-pair.test','--relay',built/'wdtt-relay-linux-amd64','--client',built/'wt-client-linux-amd64','--mihomo',work/'test-deps/mihomo-compatible','--converter',kas/'experimental/wdtt/wg_to_mihomo.py','--report',built/'qwdtt-local-pair-report.json'],env={**os.environ,'WDTT_QWDTT_CLIENT':str(built/'wt-client-linux-amd64')})
 run(['python3',ROOT/'tools/check_socks_udp_pair.py','--harness',built/'server-pair.test','--client',built/'wt-client-linux-amd64','--report',built/'socks-udp-pair-report.json'])
 run(['python3',wd/'test_production_boundary.py','--capture',work/'production-before.json'])
 for shell in [['sh'],['busybox','ash']]:run([*shell,'-n',recipe/'warpscout/install.sh'])
 run(['shellcheck','-S','error',recipe/'warpscout/install.sh'])
 run(['python3','-m','unittest','discover','-s','tests','-v'],cwd=recipe)
 run(['python3','-m','unittest','discover','-s','tests','-p','test_warpscout_installer.py'],cwd=recipe,env={**os.environ,'INSTALL_TEST_SHELL':'busybox'})
 run(['python3',wd/'test_production_boundary.py','--verify',work/'production-before.json','--report',built/'production-guard-report.json'])
 (built/'candidate-acceptance.json').write_text(json.dumps({'passed':True,'candidate':candidate,'entware':ENTWARE,'kas':KAS,'client_tests':tests,'fuzz':fuzz,'independent_client_sha256':expected,'public_servers_contacted':False,'production_recipe_modified':False,'temporary_recipe_changes':['fork-source-lock.json','build_lab.py candidate comparison']},indent=2)+'\n')
 print('PASS candidate import, independent ELF rebuild, Entware opkg/lifecycle/local pair; evidence only')
if __name__=='__main__':main()

#!/usr/bin/env python3
"""Source-only Linux lab. No ELF/IPK publication, production process or endpoint.

Run as root ONLY in disposable CI/VM for isolated network namespaces. Raw
synthetic heap profiles stay in the private work directory; export numeric only.
"""
import argparse
import hashlib
import io
import json
import os
import pathlib
import shutil
import statistics
import subprocess
import tarfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
BASE = 'dc78576bcc7593ad52b30334bd46670571753be1'


def run(args, **kw):
    return subprocess.check_output([str(x) for x in args], text=True, **kw)


def summarize(path):
    samples = [json.loads(line) for line in path.read_text().splitlines()]
    phases = {}
    for sample in samples:
        p = phases.setdefault(sample['phase'], {})
        for key in ['RSS', 'HeapAlloc', 'HeapInuse', 'HeapSys', 'StackInuse',
                    'Goroutines', 'FDs', 'Swap', 'NumGC']:
            p[key] = max(p.get(key, 0), sample[key])
    return dict(hwm_kib=max(s['HWM'] for s in samples), phases=phases,
                final=samples[-1])


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--go', required=True)
    p.add_argument('--work', required=True)
    p.add_argument('--report-dir', required=True)
    p.add_argument('--sessions', action='store_true')
    a = p.parse_args()
    go = pathlib.Path(a.go).resolve()
    work = pathlib.Path(a.work).resolve()
    work.mkdir(mode=0o700, parents=True, exist_ok=False)
    out = pathlib.Path(a.report_dir).resolve()
    out.mkdir(parents=True, exist_ok=False)
    env = {**os.environ, 'GOENV': 'off', 'GOTOOLCHAIN': 'local', 'GOWORK': 'off',
           'GOTELEMETRY': 'off', 'CGO_ENABLED': '0', 'GOOS': 'linux',
           'GOARCH': 'amd64', 'GOMAXPROCS': '2'}
    env.pop('GOROOT', None)
    assert not run(['git', '-C', ROOT, 'diff', '--name-only', 'HEAD', '--',
                    'go_client', 'hardened-relay', 'tools']).strip(), 'tracked lab sources must match HEAD'
    cpus = sorted(os.sched_getaffinity(0))[:2]
    prefix = ['taskset', '-c', ','.join(map(str, cpus))]
    result = dict(baseline=BASE, candidate=run(['git', '-C', ROOT, 'rev-parse', 'HEAD']).strip(),
                  toolchain=run([go, 'version'], env=env).strip(), cpu_affinity=cpus,
                  scope='native Linux test process; not router acceptance; no VK credential provider',
                  component={}, sessions={}, binary_sha256={})
    assert result['toolchain'] == 'go version go1.26.1 linux/amd64'
    raw = subprocess.check_output(['git', '-C', str(ROOT), 'archive', BASE])
    baseline = work / 'baseline'
    with tarfile.open(fileobj=io.BytesIO(raw)) as archive:
        archive.extractall(baseline, filter='data')
    harness = (ROOT / 'go_client/lowmem_lab_test.go').read_text()
    old = harness.replace('return obfsWrapPacketInto(dst, key, payload, cfg, s)',
                          'return obfsWrapPacket(key, payload, cfg, s)').replace(
        'return wdttEncodeUDPReplyInto(dst, addr, payload)', 'return wdttEncodeUDPReply(addr, payload)')
    assert old != harness
    (baseline / 'go_client/lowmem_lab_test.go').write_text(old)
    shutil.copyfile(ROOT / 'go_client/lowmem_session_lab_test.go', baseline / 'go_client/lowmem_session_lab_test.go')
    for variant, source in [('baseline', baseline), ('candidate', ROOT)]:
        binary = work / (variant + '.test')
        run([go, 'test', '-mod=readonly', '-trimpath', '-buildvcs=false', '-c', '-o', binary],
            cwd=source / 'go_client', env=env)
        result['binary_sha256'][variant] = hashlib.sha256(binary.read_bytes()).hexdigest()
        result['component'][variant] = []
    if a.sessions:
        assert os.geteuid() == 0, 'network namespace lab requires disposable root CI/VM'
        run([go, 'test', '-mod=readonly', '-trimpath', '-buildvcs=false', '-c', '-o', work / 'server.test'],
            cwd=ROOT / 'hardened-relay', env=env)
    for rep in range(1, 4):
        for variant in ['baseline', 'candidate']:
            private = work / f'{variant}-{rep}'
            private.mkdir(mode=0o700)
            run([*prefix, work / (variant + '.test'), '-test.run=^TestLowmemNumericLab$', '-test.timeout=120s'],
                env={**env, 'WDTT_LOWMEM_LAB_DIR': str(private)})
            bench = run([*prefix, work / (variant + '.test'), '-test.run=^$',
                         '-test.bench=^BenchmarkLowmem', '-test.benchmem'], env=env)
            result['component'][variant].append(summarize(private / 'samples.jsonl'))
            shutil.copyfile(private / 'samples.jsonl', out / f'{variant}-{rep}-samples.jsonl')
            (out / f'{variant}-{rep}-bench.txt').write_text(bench)
        if a.sessions:
            for workers in [9, 18]:
                for variant in ['baseline', 'candidate']:
                    stem = f'{variant}-{workers}-{rep}'
                    # No host routing/firewall mutation: only lo in a NEW netns.
                    run(['unshare', '-n', 'sh', '-c', 'ip link set lo up; exec "$@"', 'lab',
                         *prefix, 'python3', ROOT / 'tools/check_lowmem_session.py',
                         '--harness', work / 'server.test', '--client-test', work / (variant + '.test'),
                         '--workers', workers, '--report', out / (stem + '-report.json'),
                         '--samples', out / (stem + '-samples.jsonl')], env=env)
                    result['sessions'][stem] = summarize(out / (stem + '-samples.jsonl'))
    for variant in ['baseline', 'candidate']:
        result[variant + '_median_component_hwm_kib'] = statistics.median(
            s['hwm_kib'] for s in result['component'][variant])
    (out / 'comparison.json').write_text(json.dumps(result, indent=2) + '\n')
    print('PASS paired numeric memory lab; no hardware acceptance')


if __name__ == '__main__':
    main()

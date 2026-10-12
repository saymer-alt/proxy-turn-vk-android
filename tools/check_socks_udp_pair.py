#!/usr/bin/env python3
"""Synthetic localhost TURN/DTLS/WG to WDTT TCP SOCKS5 and UDP ASSOCIATE.
Runs neither public VK nor OS routing/NAT/TUN/firewall. Never prints secrets.
"""
import argparse
import json
import os
import pathlib
import socket
import struct
import subprocess
import tempfile
import time

def recv_exact(sock,count):
    b=b""
    while len(b)<count:
        chunk=sock.recv(count-len(b))
        if not chunk:
            raise RuntimeError("short SOCKS reply")
        b+=chunk
    return b

def wait_until(check, procs, timeout=70):
    end=time.monotonic()+timeout
    while time.monotonic()<end:
        if check():
            return
        if any(p.poll() is not None for p in procs):
            raise RuntimeError("local pair unexpectedly exited")
        time.sleep(.15)
    raise RuntimeError("local SOCKS readiness timeout")

def sock_connect():
    s=socket.create_connection(("127.0.0.1",1081),timeout=8)
    s.settimeout(12)
    s.sendall(b"\x05\x01\x00")
    if recv_exact(s,2)!=b"\x05\x00":
        s.close()
        raise RuntimeError("SOCKS no-auth negotiation rejected")
    return s

def udp_assoc():
    control=sock_connect()
    control.sendall(b"\x05\x03\x00\x01"+b"\x00"*6)
    reply=recv_exact(control,10)
    if reply[:4]!=b"\x05\x00\x00\x01" or reply[4:8]!=b"\x7f\x00\x00\x01":
        raise RuntimeError("invalid/non-loopback SOCKS UDP relay")
    port=struct.unpack("!H",reply[8:10])[0]
    if not port:
        raise RuntimeError("SOCKS UDP relay missing port")
    return control,port

def udp_frame(payload,domain=False,frag=0):
    if domain:
        host=b"fixture.invalid"
        header=b"\x00\x00"+bytes([frag,3,len(host)])+host+struct.pack("!H",18081)
    else:
        header=b"\x00\x00"+bytes([frag,1])+socket.inet_aton("10.66.66.1")+struct.pack("!H",18081)
    return header+payload

def probe_udp(udp,port,payload,domain=False):
    udp.sendto(udp_frame(payload,domain),("127.0.0.1",port))
    reply,source=udp.recvfrom(4096)
    if source[0]!="127.0.0.1" or source[1]!=port or len(reply)!=len(payload)+10:
        raise RuntimeError("UDP response source/length invalid")
    if reply[:4]!=b"\x00\x00\x00\x01" or reply[4:8]!=socket.inet_aton("10.66.66.1") or struct.unpack("!H",reply[8:10])[0]!=18081:
        raise RuntimeError("UDP response header mismatch")
    if reply[10:]!=payload:
        raise RuntimeError("UDP response payload mismatch")

def main():
    p=argparse.ArgumentParser()
    for name in ("harness","client","report"):
        p.add_argument("--"+name,required=True)
    args=p.parse_args()
    result={"scope":"synthetic loopback Pion TURN/DTLS/WG + standalone WDTT SOCKS5 TCP+UDP; no public VK, kernel TUN, DNS/routes/firewall","checks":{},"passed":False}
    processes=[]
    with tempfile.TemporaryDirectory(prefix="wdtt-socks-udp-") as tmp:
        d=pathlib.Path(tmp)
        d.chmod(0o700)
        env={**os.environ,"WDTT_LOCAL_PAIR_DIR":tmp,"WDTT_SOCKS_UDP_CLIENT":"1"}
        try:
            harness=subprocess.Popen([args.harness,"-test.run=^TestLocalPairHarness$","-test.timeout=190s"],env=env,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
            processes.append(harness)
            wait_until(lambda:(d/"READY").is_file(),processes)
            client=subprocess.Popen([args.client,"-config-file",str(d/"client.json")],stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
            processes.append(client)
            wait_until(lambda:(d/"socks-status").exists() and (d/"socks-status").read_text().strip()=="SOCKS_LISTENING",processes)
            if (d/"getconf-status").read_text().strip()!="CONFIG_READY":
                raise RuntimeError("GETCONF not ready")
            result["checks"]["real_local_TURN_DTLS_GETCONF_WG_userspace_and_SOCKS_listener"]=True

            import urllib.request
            # Verify TCP CONNECT through actual SOCKS using curl with direct disabled.
            for host in ("10.66.66.1","fixture.invalid"):
                rsp=subprocess.run(["curl","-fsS","--max-time","20","--noproxy","","--socks5-hostname","127.0.0.1:1081",f"http://{host}:18080/"],env={**os.environ,"NO_PROXY":"","no_proxy":""},capture_output=True,timeout=25)
                if rsp.returncode or rsp.stdout!=b"WDTT-LOCAL-TCP-OK\n":
                    raise RuntimeError("SOCKS TCP through WG failed")
            result["checks"]["SOCKS_TCP_literal_and_tunnel_DNS"]=True

            ctrl,port=udp_assoc()
            try:
                with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as udp:
                    udp.bind(("127.0.0.1",0))
                    udp.settimeout(8)
                    for size in (64,512,1000,1200,1400):
                        probe_udp(udp,port,bytes(i%251 for i in range(size)))
                    probe_udp(udp,port,b"WDTT-TUNNEL-DNS-UDP",domain=True)
                    result["checks"]["SOCKS_UDP_ipv4_payload_lengths"]=[64,512,1000,1200,1400]
                    result["checks"]["SOCKS_UDP_remote_tunnel_DNS"]=True

                    udp.sendto(udp_frame(b"REJECT_FRAG",frag=1),("127.0.0.1",port))
                    udp.settimeout(1)
                    try:
                        udp.recvfrom(4096)
                        raise RuntimeError("fragmented UDP datagram was forwarded")
                    except socket.timeout:
                        pass
                    with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as attacker:
                        attacker.bind(("127.0.0.1",0))
                        attacker.settimeout(1)
                        attacker.sendto(udp_frame(b"REJECT_OTHER_PORT"),("127.0.0.1",port))
                        try:
                            attacker.recvfrom(4096)
                            raise RuntimeError("different UDP source port was accepted")
                        except socket.timeout:
                            pass
                    udp.settimeout(8)
                    probe_udp(udp,port,b"STILL_VALID")
                    result["checks"]["FRAG_and_wrong_source_dropped_without_killing_session"]=True

                    ctrl.close()
                    time.sleep(.5)
                    udp.sendto(udp_frame(b"AFTER_CONTROL_CLOSE"),("127.0.0.1",port))
                    udp.settimeout(2)
                    try:
                        udp.recvfrom(4096)
                        raise RuntimeError("UDP still forwarded after TCP control close")
                    except socket.timeout:
                        pass
                    result["checks"]["TCP_CONTROL_close_revokes_UDP_association"]=True
            finally:
                ctrl.close()
            wait_until(lambda:(d/"wg-metrics.json").exists(),processes)
            m=json.loads((d/"wg-metrics.json").read_text())
            if int(m.get("rx_bytes","0"))<=0 or int(m.get("last_handshake_time_sec","0"))<=0:
                raise RuntimeError("WireGuard handshake/receive counters absent")
            result["checks"]["WG_handshake_and_rx_bytes"]=True
            client.terminate()
            client.wait(timeout=10)
            down=subprocess.run(["curl","-fsS","--max-time","4","--noproxy","","--socks5-hostname","127.0.0.1:1081","http://10.66.66.1:18080/"],capture_output=True)
            if down.returncode==0:
                raise RuntimeError("UDP/TCP service failed to shut down")
            result["checks"]["stop_fails_closed_without_direct_fallback"]=True
            result["passed"]=True
        except Exception as exc:
            result["error"]=type(exc).__name__+":"+str(exc)
        finally:
            (d/"STOP").touch(mode=0o600)
            for proc in reversed(processes):
                if proc.poll() is None:
                    proc.terminate()
                    try:
                        proc.wait(timeout=7)
                    except subprocess.TimeoutExpired:
                        proc.kill()
                        proc.wait()
    pathlib.Path(args.report).write_text(json.dumps(result,indent=2)+"\n")
    print(json.dumps(result,indent=2))
    if not result["passed"]:
        raise SystemExit(1)

if __name__=="__main__":
    main()

#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Same transport controller + real latest TLS over temporary host loopback.

No guest networking, remote access, trust installation or v4 fixture changes.
The POSIX platform is a separate host fixture, never native Win98 evidence.
"""
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import socket
import ssl
import subprocess
import threading

ROOT=Path(__file__).resolve().parents[1]


def run(out,args):
    result=subprocess.run(args,cwd=out,text=True,capture_output=True,timeout=20)
    if result.returncode:
        raise RuntimeError(result.stderr[-2000:])


@contextmanager
def server(out,mode):
    listener=socket.socket();listener.bind(("127.0.0.1",0));listener.listen(1);listener.settimeout(5)
    port=listener.getsockname()[1];errors=[];evidence={};stop=threading.Event()
    context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version=context.maximum_version=ssl.TLSVersion.TLSv1_2 if mode=="tls12" else ssl.TLSVersion.TLSv1_3
    context.load_cert_chain(out/"server.pem",out/"server.key")
    def work():
        try:
            raw,_=listener.accept();raw.settimeout(5)
            if mode=="handshake-timeout":
                with raw:stop.wait(3)
                return
            try:
                peer=context.wrap_socket(raw,server_side=True)
            except ssl.SSLError:
                raw.close()
                if mode not in ("wrong-host","untrusted","tls12"):raise
                return
            with peer:
                data=bytearray()
                while len(data)<3072:
                    part=peer.recv(3072-len(data))
                    if not part:raise RuntimeError("host fixture received truncated request")
                    data.extend(part)
                if bytes(data)!=bytes((i*17+3)&255 for i in range(3072)):raise RuntimeError("host request mismatch")
                evidence.update(request_bytes=len(data),negotiated=peer.version())
                if mode=="read-timeout":stop.wait(3);return
                if mode=="truncated":os.close(peer.detach());return
                response=bytes((i*31+9)&255 for i in range(1021))
                for offset in range(0,len(response),37):peer.sendall(response[offset:offset+37])
                evidence["response_bytes"]=len(response)
                try:
                    plain=peer.unwrap();plain.close();evidence["client_close_notify"]=True
                except (ssl.SSLError,OSError):evidence["client_close_notify"]=False
        except Exception as error:errors.append(str(error))
    thread=threading.Thread(target=work,daemon=True);thread.start()
    try:yield port,evidence
    finally:
        stop.set();thread.join(6);listener.close()
        if thread.is_alive():raise RuntimeError("owned host TLS listener did not stop")
        if errors:raise RuntimeError(errors)


def main():
    import argparse
    parser=argparse.ArgumentParser();parser.add_argument("--output",type=Path,required=True);parser.add_argument("--client",type=Path,required=True)
    args=parser.parse_args();out=args.output.resolve();out.mkdir(parents=True,exist_ok=False)
    for name in ("root","untrusted"):
        run(out,["openssl","req","-x509","-newkey","ec","-pkeyopt","ec_paramgen_curve:prime256v1","-nodes","-sha256","-days","3","-subj",f"/CN={name}","-addext","basicConstraints=critical,CA:TRUE","-addext","keyUsage=critical,keyCertSign,cRLSign","-keyout",name+".key","-out",name+".pem"])
    run(out,["openssl","req","-new","-newkey","ec","-pkeyopt","ec_paramgen_curve:prime256v1","-nodes","-subj","/CN=localhost","-keyout","server.key","-out","server.csr"])
    (out/"extensions.cnf").write_text("basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:localhost\n")
    run(out,["openssl","x509","-req","-in","server.csr","-CA","root.pem","-CAkey","root.key","-set_serial","1","-days","2","-sha256","-extfile","extensions.cnf","-out","server.pem"])
    results=[]
    for mode in ("valid","wrong-host","untrusted","tls12","handshake-timeout","read-timeout","truncated"):
        with server(out,mode) as (port,server_evidence):
            trust=out/("untrusted.pem" if mode=="untrusted" else "root.pem")
            hostname="wrong-host.invalid" if mode=="wrong-host" else "localhost"
            p=subprocess.run([str(args.client.resolve()),str(port),str(trust),hostname,mode],text=True,capture_output=True,timeout=12)
            (out/(mode+".log")).write_text(p.stdout+p.stderr)
            item=json.loads(p.stdout)
            if p.returncode or not item["passed"]:raise RuntimeError(item)
        if mode=="valid" and not (server_evidence.get("negotiated")=="TLSv1.3" and server_evidence.get("client_close_notify")):
            raise RuntimeError("host server did not verify TLS1.3/bidirectional payload/close_notify")
        item["server"]=server_evidence;results.append(item)
    with socket.socket() as s:s.bind(("127.0.0.1",0));port=s.getsockname()[1]
    p=subprocess.run([str(args.client.resolve()),str(port),str(out/"root.pem"),"localhost","connect-refused"],text=True,capture_output=True,timeout=5)
    (out/"connect-refused.log").write_text(p.stdout+p.stderr);item=json.loads(p.stdout)
    if p.returncode or not item["passed"]:raise RuntimeError(item)
    results.append(item)
    verdict={"passed":True,"host_only":True,"native_guest_network_verified":False,"os_tls_integrated":False,
             "server_bind":"127.0.0.1","client_sha256":hashlib.sha256(args.client.read_bytes()).hexdigest(),"tests":results}
    (out/"result.json").write_text(json.dumps(verdict,indent=2)+"\n")
    print(json.dumps({"passed":True,"cases":len(results),"host_only":True,"receipt":str(out/"result.json")}))


if __name__=="__main__":main()

#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Run exact service/protocol/hosts and ANSI enum bodies with a copied real host OS catalog.

No network socket, target application, guest or Windows installation is run.
"""
import argparse
import hashlib
import json
import re
import socket
import subprocess
import tempfile
from pathlib import Path


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--catalog', type=Path, default=Path('/etc/services'))
    ap.add_argument('--protocols', type=Path, default=Path('/etc/protocols'))
    ap.add_argument('--hosts', type=Path, default=Path('/etc/hosts'))
    ap.add_argument('--output-dir', type=Path)
    args = ap.parse_args()
    w64 = Path(__file__).resolve().parents[1]
    paths = [w64/'dlls/ws2_32/ws2_32.c', w64/'dlls/ws2_32/module.json',
             Path(__file__), w64/'tests/ws2_legacy_host_contract.h', w64/'tests/test_ws2_legacy_host.c']
    snapshots = {p:p.read_bytes() for p in paths}
    source = snapshots[paths[0]].decode()
    begin = source.index('/* ---- service database:')
    marker = '/* ---- end service database ---- */'
    production = source[begin:source.index(marker,begin)+len(marker)]
    order = re.search(r'(?m)^DLLAPI u_short WSAAPI htons\([^\n]+',source).group(0)
    catalog_begin = source.index('static void wcopy(')
    catalog_end = source.index('DLLAPI int WSAAPI WSAEnumProtocolsW(',catalog_begin)
    a_begin = source.index('/* ---- ANSI provider enumeration:')
    a_end = '/* ---- end ANSI provider enumeration ---- */'
    provider = re.search(r'(?m)^static const GUID g_provider = .*$',source).group(0)
    production = order+'\n'+production+'\n'+provider+'\n'+source[catalog_begin:catalog_end]+'\n'+source[a_begin:source.index(a_end,a_begin)+len(a_end)]
    config = json.loads(snapshots[paths[1]])
    assert config['ordinals']['getservbyname']==55
    assert len(set(config['ordinals'].values()))==len(config['ordinals'])
    legacy = {'accept':1,'bind':2,'closesocket':3,'connect':4,'getpeername':5,'getsockname':6,'getsockopt':7,
              'htonl':8,'htons':9,'ioctlsocket':10,'inet_addr':11,'inet_ntoa':12,'listen':13,'ntohl':14,'ntohs':15,
              'recv':16,'recvfrom':17,'select':18,'send':19,'sendto':20,'setsockopt':21,'shutdown':22,'socket':23,
              'gethostbyaddr':51,'gethostbyname':52,'getprotobyname':53,'getprotobynumber':54,'getservbyname':55,'getservbyport':56,'gethostname':57,'WSAGetLastError':111,'WSASetLastError':112,
              'WSAStartup':115,'WSACleanup':116,'__WSAFDIsSet':151}
    for name,ordinal in config['ordinals'].items():
        assert ordinal==legacy[name] if name in legacy else ordinal>=501
    catalog = args.catalog.read_bytes()
    records = []
    for line in catalog.decode('latin-1').splitlines():
        fields = line.split('#',1)[0].split()
        if len(fields)>=2 and re.fullmatch(r'\d+/[A-Za-z0-9_-]+',fields[1]):
            port,proto = fields[1].split('/')
            records.append((fields[0],int(port),proto,fields[2:]))
    http = next(r for r in records if r[:3]==('http',80,'tcp'))
    assert http[3], 'Real OS HTTP alias fixture required'
    def agrees_with_host(row):
        try:
            return socket.getservbyname(row[0],row[2])==row[1]
        except OSError:
            return False  # Catalogs differ; require a positive OS-confirmed record below.
    high = next(r for r in records if 32767<r[1]<=65535 and r[2] in ('tcp','udp') and agrees_with_host(r))
    assert socket.getservbyname(http[3][0],'tcp')==80
    first = next(r for r in records if r[0]=='http')
    expected = ''.join('#define '+name+' '+value+'\n' for name,value in [
        ('ACTUAL_HTTP_ALIAS',json.dumps(http[3][0])),('ACTUAL_HTTP_ALIAS_COUNT',str(len(http[3]))),
        ('ACTUAL_HTTP_FIRST_PROTO',json.dumps(first[2])),('ACTUAL_HIGH_NAME',json.dumps(high[0])),
        ('ACTUAL_HIGH_PROTO',json.dumps(high[2])),('ACTUAL_HIGH_PORT',str(high[1]))])
    protocols = args.protocols.read_bytes()
    hosts = args.hosts.read_bytes()
    protocol_rows = [line.split('#',1)[0].split() for line in protocols.decode('latin-1').splitlines()]
    tcp = next(fields for fields in protocol_rows if len(fields)>=3 and fields[:2]==['tcp','6'])
    host_rows = [line.split('#',1)[0].split() for line in hosts.decode('latin-1').splitlines()]
    loopback = next(fields for fields in host_rows if len(fields)>=3 and fields[0]=='127.0.0.1')
    assert socket.getprotobyname(tcp[2])==6
    expected += '#define ACTUAL_TCP_ALIAS '+json.dumps(tcp[2])+'\n'
    expected += '#define ACTUAL_LOOPBACK_NAME '+json.dumps(loopback[1])+'\n'
    expected += '#define ACTUAL_LOOPBACK_ALIAS '+json.dumps(loopback[2])+'\n'
    runs = []
    with tempfile.TemporaryDirectory(prefix='win98-ws2-services-') as folder:
        temp = Path(folder)
        for p in paths[3:]:
            (temp/p.name).write_bytes(snapshots[p])
        (temp/'legacy_production.inc').write_text(production)
        (temp/'actual_services_expected.inc').write_text(expected)
        for cc,flags,label in [('gcc',['-O2'],'gcc'),('clang',['-O1','-g','-fsanitize=address,undefined',
                                  '-fno-sanitize-recover=all','-fno-omit-frame-pointer'],'clang-san')]:
            system = temp/label
            database = system/'drivers/etc/services'
            database.parent.mkdir(parents=True)
            database.write_bytes(catalog)
            (database.parent/"protocols").write_bytes(protocols)
            (database.parent/"hosts").write_bytes(hosts)
            exe = temp/(label+'-contract')
            command = [cc,'-std=c11','-fshort-wchar','-Wall','-Wextra','-Werror',*flags,'-pthread',
                       '-I',str(temp),str(temp/'test_ws2_legacy_host.c'),'-o',str(exe)]
            built = subprocess.run(command,text=True,capture_output=True,timeout=60)
            if built.returncode:
                raise SystemExit(built.stdout+built.stderr)
            run = subprocess.run([str(exe),str(system)],text=True,capture_output=True,timeout=120)
            if run.returncode:
                raise SystemExit(run.stdout+run.stderr)
            assert database.read_bytes()==catalog, 'Fixture catalog not restored'
            assert (database.parent/'protocols').read_bytes()==protocols and (database.parent/'hosts').read_bytes()==hosts
            runs.append({'compiler':cc,'label':label,'command':command,'stdout':run.stdout,'stderr':run.stderr,
                         'returncode':run.returncode})
    for p,data in snapshots.items():
        assert p.read_bytes()==data, ('Source changed during test',str(p))
    assert args.catalog.read_bytes()==catalog, 'Real OS catalog changed during test'
    assert args.protocols.read_bytes()==protocols and args.hosts.read_bytes()==hosts
    result = {'status':'PASS','runs':runs,'source_pins':{str(p.relative_to(w64.parent)):hashlib.sha256(b).hexdigest()
              for p,b in snapshots.items()},'exact_production_block_sha256':hashlib.sha256(production.encode()).hexdigest(),
              'actual_host_catalog':{'path':str(args.catalog.resolve()),'sha256':hashlib.sha256(catalog).hexdigest(),
                 'bytes':len(catalog),'http':http,'high_port':high},'actual_protocol_catalog':{'path':str(args.protocols.resolve()),'sha256':hashlib.sha256(protocols).hexdigest(),'bytes':len(protocols),'tcp':tcp},
              'actual_hosts_catalog':{'path':str(args.hosts.resolve()),'sha256':hashlib.sha256(hosts).hexdigest(),'bytes':len(hosts),'loopback':loopback},
              'limits':'Host Windows file/TLS/heap adapters only; real OS catalog copies and actual provider metadata; no guest, DNS/PTR or application execution.',
              'files_unchanged':True}
    if args.output_dir:
        args.output_dir.mkdir(parents=True,exist_ok=True)
        (args.output_dir/'host-result.json').write_text(json.dumps(result,indent=2)+'\n')
        (args.output_dir/'actual-services').write_bytes(catalog)
        (args.output_dir/'actual-protocols').write_bytes(protocols)
        (args.output_dir/'actual-hosts').write_bytes(hosts)
        (args.output_dir/'service-production.inc').write_text(production)
        (args.output_dir/'actual-services-expected.inc').write_text(expected)
    print(json.dumps(result,indent=2))


if __name__=='__main__':
    main()

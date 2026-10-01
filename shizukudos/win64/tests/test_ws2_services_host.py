#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Run exact service-database bodies with a copied real host OS catalog.

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
    ap.add_argument('--output-dir', type=Path)
    args = ap.parse_args()
    w64 = Path(__file__).resolve().parents[1]
    paths = [w64/'dlls/ws2_32/ws2_32.c', w64/'dlls/ws2_32/module.json',
             Path(__file__), w64/'tests/ws2_services_host_contract.h', w64/'tests/test_ws2_services_host.c']
    snapshots = {p:p.read_bytes() for p in paths}
    source = snapshots[paths[0]].decode()
    begin = source.index('/* ---- service database:')
    marker = '/* ---- end service database ---- */'
    production = source[begin:source.index(marker,begin)+len(marker)]
    order = re.search(r'(?m)^DLLAPI u_short WSAAPI htons\([^\n]+',source).group(0)
    production = order+'\n'+production+'\n'
    config = json.loads(snapshots[paths[1]])
    assert config['ordinals']['getservbyname']==55
    assert len(set(config['ordinals'].values()))==len(config['ordinals'])
    legacy = {'accept':1,'bind':2,'closesocket':3,'connect':4,'getpeername':5,'getsockname':6,'getsockopt':7,
              'htonl':8,'htons':9,'ioctlsocket':10,'inet_addr':11,'inet_ntoa':12,'listen':13,'ntohl':14,'ntohs':15,
              'recv':16,'recvfrom':17,'select':18,'send':19,'sendto':20,'setsockopt':21,'shutdown':22,'socket':23,
              'gethostbyname':52,'getservbyname':55,'gethostname':57,'WSAGetLastError':111,'WSASetLastError':112,
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
    high = next(r for r in records if 32767<r[1]<=65535 and r[2] in ('tcp','udp')
                and socket.getservbyname(r[0],r[2])==r[1])
    assert socket.getservbyname(http[3][0],'tcp')==80
    first = next(r for r in records if r[0]=='http')
    expected = ''.join('#define '+name+' '+value+'\n' for name,value in [
        ('ACTUAL_HTTP_ALIAS',json.dumps(http[3][0])),('ACTUAL_HTTP_ALIAS_COUNT',str(len(http[3]))),
        ('ACTUAL_HTTP_FIRST_PROTO',json.dumps(first[2])),('ACTUAL_HIGH_NAME',json.dumps(high[0])),
        ('ACTUAL_HIGH_PROTO',json.dumps(high[2])),('ACTUAL_HIGH_PORT',str(high[1]))])
    runs = []
    with tempfile.TemporaryDirectory(prefix='win98-ws2-services-') as folder:
        temp = Path(folder)
        for p in paths[3:]:
            (temp/p.name).write_bytes(snapshots[p])
        (temp/'service_production.inc').write_text(production)
        (temp/'actual_services_expected.inc').write_text(expected)
        for cc,flags,label in [('gcc',['-O2'],'gcc'),('clang',['-O1','-g','-fsanitize=address,undefined',
                                  '-fno-sanitize-recover=all','-fno-omit-frame-pointer'],'clang-san')]:
            system = temp/label
            database = system/'drivers/etc/services'
            database.parent.mkdir(parents=True)
            database.write_bytes(catalog)
            exe = temp/(label+'-contract')
            command = [cc,'-std=c11','-fshort-wchar','-Wall','-Wextra','-Werror',*flags,'-pthread',
                       '-I',str(temp),str(temp/'test_ws2_services_host.c'),'-o',str(exe)]
            built = subprocess.run(command,text=True,capture_output=True,timeout=60)
            if built.returncode:
                raise SystemExit(built.stdout+built.stderr)
            run = subprocess.run([str(exe),str(system)],text=True,capture_output=True,timeout=120)
            if run.returncode:
                raise SystemExit(run.stdout+run.stderr)
            assert database.read_bytes()==catalog, 'Fixture catalog not restored'
            runs.append({'compiler':cc,'label':label,'command':command,'stdout':run.stdout,'stderr':run.stderr,
                         'returncode':run.returncode})
    for p,data in snapshots.items():
        assert p.read_bytes()==data, ('Source changed during test',str(p))
    assert args.catalog.read_bytes()==catalog, 'Real OS catalog changed during test'
    result = {'status':'PASS','runs':runs,'source_pins':{str(p.relative_to(w64.parent)):hashlib.sha256(b).hexdigest()
              for p,b in snapshots.items()},'exact_production_block_sha256':hashlib.sha256(production.encode()).hexdigest(),
              'actual_host_catalog':{'path':str(args.catalog.resolve()),'sha256':hashlib.sha256(catalog).hexdigest(),
                 'bytes':len(catalog),'http':http,'high_port':high},'limits':'Host Windows API adapters only; no guest or application execution.',
              'files_unchanged':True}
    if args.output_dir:
        args.output_dir.mkdir(parents=True,exist_ok=True)
        (args.output_dir/'host-result.json').write_text(json.dumps(result,indent=2)+'\n')
        (args.output_dir/'actual-services').write_bytes(catalog)
        (args.output_dir/'service-production.inc').write_text(production)
        (args.output_dir/'actual-services-expected.inc').write_text(expected)
    print(json.dumps(result,indent=2))


if __name__=='__main__':
    main()

#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Actual TLS 1.3 interoperability and rejection tests, on host loopback only.

Requires the host build from tools/build_tls13.py. Generates private test keys
and certificates below ignored build/tls13/tests, starts bounded openssl
s_server processes listening only at 127.0.0.1, then stops every owned process.
No remote site, trust store, client configuration, or guest is changed.
"""
import contextlib
import hashlib
import json
from pathlib import Path
import socket
import subprocess
import time

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "build/tls13/tests"
CLIENT = ROOT / "build/tls13/host/m98_tls13_host"


def run(argv):
    result = subprocess.run([str(x) for x in argv], cwd=OUT, capture_output=True, text=True, timeout=20)
    if result.returncode:
        raise RuntimeError(f"Test setup failed: {argv[0]}\n{result.stderr[-2000:]}")


def ca(name):
    run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1",
         "-nodes", "-sha256", "-days", "3", "-subj", f"/CN={name}",
         "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign,cRLSign",
         "-keyout", f"{name}.key", "-out", f"{name}.pem"])


@contextlib.contextmanager
def server(cert, version):
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    log_path = OUT / f"server-{cert}-{version}.log"
    with log_path.open("wb") as log:
        process = subprocess.Popen(["openssl", "s_server", "-accept", f"127.0.0.1:{port}",
                                    "-cert", str(OUT / cert), "-key", str(OUT / "server.key"),
                                    "-www", f"-{version}"], stdout=log, stderr=subprocess.STDOUT)
        try:
            deadline = time.monotonic() + 5
            while True:
                if process.poll() is not None:
                    raise RuntimeError(f"OpenSSL server exited: {log_path}")
                try:
                    with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                        break
                except OSError:
                    if time.monotonic() >= deadline:
                        raise RuntimeError("Temporary loopback server did not start")
                    time.sleep(0.05)
            yield port
        finally:
            process.terminate()
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=3)


def probe(port, trust, hostname, mode):
    p = subprocess.run([str(CLIENT), str(port), str(OUT / trust), hostname, mode],
                       cwd=OUT, capture_output=True, text=True, timeout=15)
    (OUT / f"probe-{mode}.log").write_text(p.stdout + p.stderr)
    result = json.loads(p.stdout)
    if p.returncode or not result["passed"]:
        raise AssertionError(result)
    return result


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "result.json").unlink(missing_ok=True)
    if not CLIENT.exists():
        raise RuntimeError("Build the host client with tools/build_tls13.py first")
    ca("root")
    ca("untrusted")
    run(["openssl", "req", "-new", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1",
         "-nodes", "-subj", "/CN=localhost", "-keyout", "server.key", "-out", "server.csr"])
    extensions = "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:localhost\n"
    (OUT / "extensions.cnf").write_text(extensions)
    run(["openssl", "x509", "-req", "-in", "server.csr", "-CA", "root.pem", "-CAkey", "root.key",
         "-set_serial", "1", "-days", "2", "-sha256", "-extfile", "extensions.cnf", "-out", "server.pem"])
    (OUT / "invalid.pem").write_text("invalid CA input\n")
    (OUT / "index.txt").write_text("")
    (OUT / "serial").write_text("02\n")
    (OUT / "newcerts").mkdir(exist_ok=True)
    (OUT / "expire.cnf").write_text("[ca]\ndefault_ca=local\n[local]\ndatabase=index.txt\nserial=serial\nnew_certs_dir=newcerts\ncertificate=root.pem\nprivate_key=root.key\ndefault_md=sha256\npolicy=subject\nx509_extensions=extensions\n[subject]\ncommonName=supplied\n[extensions]\n" + extensions)
    run(["openssl", "ca", "-batch", "-config", "expire.cnf", "-startdate", "20000101000000Z",
         "-enddate", "20000102000000Z", "-in", "server.csr", "-out", "expired.pem", "-notext"])
    results = []
    with server("server.pem", "tls1_3") as port:
        for trust, hostname, mode in [("root.pem", "localhost", "valid"),
                                       ("root.pem", "localhost", "retry"),
                                       ("root.pem", "localhost", "corrupt-record"),
                                       ("root.pem", "mismatch.invalid", "wrong-host"),
                                       ("untrusted.pem", "localhost", "untrusted"),
                                       ("root.pem", "localhost", "entropy"),
                                       ("root.pem", "localhost", "entropy-negative"),
                                       ("root.pem", "localhost", "entropy-partial"),
                                       ("root.pem", "localhost", "entropy-late"),
                                       ("root.pem", "localhost", "entropy-late-negative"),
                                       ("root.pem", "localhost", "entropy-late-partial"),
                                       ("root.pem", "localhost", "clock"),
                                       ("root.pem", "", "invalid-host"),
                                       ("invalid.pem", "localhost", "invalid-ca")]:
            results.append(probe(port, trust, hostname, mode))
    with server("expired.pem", "tls1_3") as port:
        results.append(probe(port, "root.pem", "localhost", "expired"))
    with server("server.pem", "tls1_2") as port:
        results.append(probe(port, "root.pem", "localhost", "tls12"))
    evidence = {"passed": True, "backend": "Mbed TLS 4.2.0 + TF-PSA-Crypto 1.2.0",
                "host_only": True, "guest_validated": False, "os_schannel_integrated": False,
                "server_bind": "127.0.0.1", "client_sha256": hashlib.sha256(CLIENT.read_bytes()).hexdigest(),
                "openssl_version": subprocess.check_output(["openssl", "version"], text=True).strip(),
                "tests": results}
    (OUT / "result.json").write_text(json.dumps(evidence, indent=2) + "\n")
    print(json.dumps(evidence))


if __name__ == "__main__":
    main()

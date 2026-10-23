#!/usr/bin/env python3
"""Run audit.sh against a deliberately badly configured *fake* system.

Builds a throwaway folder that looks like a Linux root filesystem with common
mistakes (root SSH login, firewall off, extra UID 0 user, empty password,
world-readable /etc/shadow, Telnet listening...) and audits it, so you can see
what FAIL/WARN results and remediation steps look like without breaking a real
machine. Usage: python3 demo/insecure_demo.py [output_dir]
"""
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "tests"))
from test_audit import (TCP_HEADER, hardened_root, make_bin, run_audit,  # noqa: E402
                        tcp_line, write)

out = Path(sys.argv[1] if len(sys.argv) > 1 else "insecure-demo-report").resolve()
with tempfile.TemporaryDirectory() as tmp:
    tmp = Path(tmp)
    root = hardened_root(tmp / "root")
    write(root, "etc/ssh/sshd_config", "PermitRootLogin yes\nPasswordAuthentication yes\n")
    write(root, "etc/os-release", 'PRETTY_NAME="Ubuntu 22.04.4 LTS (demo)"\n')
    with open(root / "etc/passwd", "a") as fh:
        fh.write("toor:x:0:0::/root:/bin/bash\nguest:x:1001:1001::/home/guest:/bin/bash\n")
    write(root, "etc/shadow", "root:!:19000::::::\nuhone:$6$x$y:19000:0:99999:7:::\nguest::19000:0:99999:7:::\n",
          mode=0o644)
    write(root, "etc/login.defs", "PASS_MAX_DAYS\t99999\n")
    write(root, "etc/security/pwquality.conf", "minlen = 8\n")
    write(root, "etc/cron.d/backup", "0 2 * * * root /opt/backup.sh\n", mode=0o666)
    (root / "tmp").chmod(0o777)
    write(root, "proc/net/tcp", TCP_HEADER
          + tcp_line(0, "00000000:0016") + tcp_line(1, "00000000:0017")
          + tcp_line(2, "00000000:0CEA") + tcp_line(3, "0100007F:1F90"))
    bindir = make_bin(tmp, ufw='echo "Status: inactive"\n',
                      apt='echo "Inst openssl [3.0.2-0ubuntu1.10] (3.0.2-0ubuntu1.15 Ubuntu:22.04/jammy-security [amd64])"\n'
                          'echo "Inst libssl3 [3.0.2-0ubuntu1.10] (3.0.2-0ubuntu1.15 Ubuntu:22.04/jammy-security [amd64])"\n'
                          'echo "Inst nano [6.2-1] (6.2-1ubuntu0.1 Ubuntu:22.04/jammy-updates [amd64])"\n')
    proc = run_audit(root, bindir, out, "--html")
    print(proc.stdout.replace(str(out), "insecure-demo-report"), end="")
    sys.exit(proc.returncode)

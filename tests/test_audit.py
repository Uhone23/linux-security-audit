"""pytest tests for audit.sh.

Each test builds a fake Linux filesystem in a temp folder and points the script
at it with AUDIT_ROOT. Commands like ufw/iptables/apt-get are replaced with tiny
fake scripts on a controlled PATH, so the tests behave the same on any machine
and never touch the real system.
"""

import hashlib
import os
import shutil
import stat
import subprocess
from pathlib import Path

import pytest

PROJECT = Path(__file__).resolve().parent.parent
AUDIT = PROJECT / "audit.sh"

CORE_TOOLS = ["bash", "env", "awk", "sed", "grep", "find", "stat", "tr", "sort",
              "cat", "date", "hostname", "id", "uname", "tail", "mkdir", "dirname",
              "timeout", "python3"]

TCP_HEADER = ("  sl  local_address rem_address   st tx_queue rx_queue tr tm->when "
              "retrnsmt   uid  timeout inode\n")


def tcp_line(n, local, state="0A"):
    return (f"   {n}: {local} 00000000:0000 {state} 00000000:00000000 00:00000000 "
            f"00000000     0        0 1000 1 0000000000000000 100 0 0 10 0\n")


def write(root: Path, rel: str, text: str, mode: int | None = None) -> Path:
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text)
    if mode is not None:
        p.chmod(mode)
    return p


def fake_cmd(bindir: Path, name: str, script: str) -> None:
    write(bindir, name, "#!/bin/bash\n" + script, mode=0o755)


def make_bin(tmp_path: Path, ufw=None, iptables=None, apt=None) -> Path:
    """Create a PATH folder with real core tools plus optional fake commands."""
    bindir = tmp_path / "bin"
    bindir.mkdir()
    for tool in CORE_TOOLS:
        real = shutil.which(tool)
        if real:
            (bindir / tool).symlink_to(real)
    if ufw is not None:
        fake_cmd(bindir, "ufw", ufw)
    if iptables is not None:
        fake_cmd(bindir, "iptables", iptables)
    if apt is not None:
        fake_cmd(bindir, "apt-get", apt)
    return bindir


def hardened_root(root: Path) -> Path:
    write(root, "etc/ssh/sshd_config",
          "Include /etc/ssh/sshd_config.d/*.conf\n"
          "PermitRootLogin no\nPasswordAuthentication no\nMaxAuthTries 3\n")
    write(root, "etc/passwd", "root:x:0:0:root:/root:/bin/bash\n"
                              "uhone:x:1000:1000::/home/uhone:/bin/bash\n")
    write(root, "etc/shadow", "root:!:19000:0:99999:7:::\nuhone:$6$abc$hash:19000:0:365:7:::\n",
          mode=0o640)
    write(root, "etc/login.defs", "PASS_MAX_DAYS\t365\nPASS_MIN_DAYS\t1\n")
    write(root, "etc/security/pwquality.conf", "# policy\nminlen = 14\n")
    write(root, "etc/os-release", 'PRETTY_NAME="Ubuntu 24.04 LTS"\n')
    write(root, "etc/ufw/ufw.conf", "ENABLED=yes\n")
    write(root, "usr/bin/ls", "binary", mode=0o755)
    (root / "tmp").mkdir()
    (root / "tmp").chmod(0o1777)
    write(root, "proc/net/tcp", TCP_HEADER
          + tcp_line(0, "0100007F:0035")      # 127.0.0.1:53 (local only)
          + tcp_line(1, "00000000:0016")      # 0.0.0.0:22 SSH
          + tcp_line(2, "00000000:0050", "01"))  # established, ignored
    write(root, "proc/net/tcp6", TCP_HEADER
          + tcp_line(0, "00000000000000000000000000000000:01BB"))  # [::]:443
    return root


def run_audit(root: Path, bindir: Path, out: Path, *args):
    env = {"PATH": str(bindir), "AUDIT_ROOT": str(root), "HOME": str(root),
           "LC_ALL": "C"}
    proc = subprocess.run(["bash", str(AUDIT), "-o", str(out), *args],
                          capture_output=True, text=True, env=env, timeout=60)
    return proc


def results(out: Path) -> dict:
    rows = {}
    meta = {}
    for line in (out / "results.tsv").read_text().splitlines():
        if line.startswith("#"):
            k, _, v = line[1:].partition("\t")
            meta[k] = v
        elif not line.startswith("status\t"):
            status, rid, _cis, title, *_ = line.split("\t")
            rows[rid] = (status, title)
    rows["_meta"] = meta
    return rows


GOOD_UFW = 'echo "Status: active"\n'
GOOD_APT = 'echo "Reading package lists..."\necho "0 upgraded, 0 newly installed"\n'


def test_hardened_system_scores_100(tmp_path):
    root = hardened_root(tmp_path / "root")
    bindir = make_bin(tmp_path, ufw=GOOD_UFW, apt=GOOD_APT)
    out = tmp_path / "out"
    proc = run_audit(root, bindir, out)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    r = results(out)
    for rid in ["SSH-1", "SSH-2", "SSH-3", "FW-1", "UPD-1", "USR-1", "USR-2",
                "PERM-1", "PERM-2", "PERM-3", "NET-2", "PWD-1", "PWD-2"]:
        assert r[rid][0] == "PASS", (rid, r[rid])
    assert r["_meta"]["score"] == "100"
    assert "Score: 100/100" in proc.stdout
    report = (out / "report.md").read_text()
    assert "Nothing to fix" in report
    assert "Ubuntu 24.04 LTS" in report


def test_insecure_system_is_flagged(tmp_path):
    root = hardened_root(tmp_path / "root")
    write(root, "etc/ssh/sshd_config", "PermitRootLogin yes\n#PasswordAuthentication no\n")
    with open(root / "etc/passwd", "a") as fh:
        fh.write("toor:x:0:0::/root:/bin/bash\n")
    write(root, "etc/shadow", "root:!:1::::::\nguest::19000:0:99999:7:::\n", mode=0o644)
    write(root, "etc/login.defs", "PASS_MAX_DAYS\t99999\n")
    write(root, "etc/security/pwquality.conf", "minlen = 8\n")
    write(root, "etc/cron.d/backup", "* * * * * root /tmp/x\n", mode=0o666)
    (root / "tmp").chmod(0o777)
    write(root, "proc/net/tcp", TCP_HEADER
          + tcp_line(0, "00000000:0017")      # telnet on all interfaces
          + tcp_line(1, "00000000:0CEA"))     # 3306 MySQL
    bindir = make_bin(tmp_path,
                      ufw='echo "Status: inactive"\n',
                      apt='echo "Inst openssl [3.0.2] (3.0.13 Ubuntu:22.04/jammy-security [amd64])"\n'
                          'echo "Inst nano [6.2] (6.3 Ubuntu:22.04/jammy-updates [amd64])"\n')
    out = tmp_path / "out"
    proc = run_audit(root, bindir, out)
    assert proc.returncode == 1  # FAIL present
    r = results(out)
    expected = {
        "SSH-1": "FAIL", "SSH-2": "WARN", "SSH-3": "WARN", "FW-1": "FAIL",
        "UPD-1": "FAIL", "USR-1": "FAIL", "USR-2": "FAIL", "PERM-1": "FAIL",
        "PERM-2": "FAIL", "PERM-3": "FAIL", "NET-2": "FAIL", "PWD-1": "WARN",
        "PWD-2": "WARN",
    }
    for rid, status in expected.items():
        assert r[rid][0] == status, (rid, r[rid])
    assert int(r["_meta"]["score"]) < 50
    report = (out / "report.md").read_text()
    assert "toor" in report and "guest" in report
    assert "/etc/cron.d/backup" in report
    assert "## Remediation steps" in report and "sudo ufw enable" in report


def test_sshd_dropin_overrides_main_config(tmp_path):
    root = hardened_root(tmp_path / "root")
    write(root, "etc/ssh/sshd_config", "PermitRootLogin yes\nPasswordAuthentication yes\n")
    write(root, "etc/ssh/sshd_config.d/10-hardening.conf",
          "PermitRootLogin no\nPasswordAuthentication no\n")
    out = tmp_path / "out"
    run_audit(root, make_bin(tmp_path, ufw=GOOD_UFW, apt=GOOD_APT), out)
    r = results(out)
    assert r["SSH-1"][0] == "PASS" and r["SSH-2"][0] == "PASS"


def test_sshd_match_block_is_ignored(tmp_path):
    root = hardened_root(tmp_path / "root")
    write(root, "etc/ssh/sshd_config",
          "Match User backup\n    PermitRootLogin yes\n")
    out = tmp_path / "out"
    run_audit(root, make_bin(tmp_path, ufw=GOOD_UFW, apt=GOOD_APT), out)
    r = results(out)
    # Global default is prohibit-password -> WARN, not the Match block's "yes".
    assert r["SSH-1"][0] == "WARN"


def test_no_ssh_server(tmp_path):
    root = hardened_root(tmp_path / "root")
    shutil.rmtree(root / "etc/ssh")
    out = tmp_path / "out"
    run_audit(root, make_bin(tmp_path, ufw=GOOD_UFW, apt=GOOD_APT), out)
    r = results(out)
    assert r["SSH-0"][0] == "INFO" and "SSH-1" not in r


@pytest.mark.parametrize("iptables, expected", [
    (None, "FAIL"),                                            # nothing installed
    ('echo "Permission denied (you must be root)" >&2; exit 4\n', "WARN"),
    ('echo "-P INPUT ACCEPT"\necho "-P FORWARD ACCEPT"\n', "FAIL"),
    ('echo "-P INPUT DROP"\necho "-A INPUT -p tcp --dport 22 -j ACCEPT"\n', "PASS"),
])
def test_firewall_detection(tmp_path, iptables, expected):
    root = hardened_root(tmp_path / "root")
    (root / "etc/ufw/ufw.conf").unlink()
    out = tmp_path / "out"
    run_audit(root, make_bin(tmp_path, iptables=iptables, apt=GOOD_APT), out)
    assert results(out)["FW-1"][0] == expected


def test_ufw_needs_root_falls_back_to_config(tmp_path):
    root = hardened_root(tmp_path / "root")
    out = tmp_path / "out"
    run_audit(root, make_bin(tmp_path, ufw='echo "ERROR: You need to be root"; exit 1\n',
                             apt=GOOD_APT), out)
    assert results(out)["FW-1"] == ("PASS", "Firewall (ufw) enabled in config")


def test_non_security_updates_warn(tmp_path):
    root = hardened_root(tmp_path / "root")
    apt = 'echo "Inst nano [6.2] (6.3 Ubuntu:22.04/jammy-updates [amd64])"\n'
    out = tmp_path / "out"
    run_audit(root, make_bin(tmp_path, ufw=GOOD_UFW, apt=apt), out)
    assert results(out)["UPD-1"][0] == "WARN"


def test_unreadable_shadow_is_skipped_not_failed(tmp_path):
    if os.geteuid() == 0:
        pytest.skip("root can read any file")
    root = hardened_root(tmp_path / "root")
    (root / "etc/shadow").chmod(0o000)
    out = tmp_path / "out"
    run_audit(root, make_bin(tmp_path, ufw=GOOD_UFW, apt=GOOD_APT), out)
    (root / "etc/shadow").chmod(0o640)
    assert results(out)["USR-2"][0] == "INFO"


def test_listening_ports_decoded(tmp_path):
    root = hardened_root(tmp_path / "root")
    out = tmp_path / "out"
    run_audit(root, make_bin(tmp_path, ufw=GOOD_UFW, apt=GOOD_APT), out)
    tsv = (out / "results.tsv").read_text()
    net1 = next(line for line in tsv.splitlines() if "\tNET-1\t" in line)
    assert "Listening TCP services: 3" in net1
    assert "0.0.0.0:22" in net1 and "127.0.0.1:53" in net1 and ":::443" in net1
    assert ":80" not in net1  # established connection must not be listed


def test_audit_is_read_only(tmp_path):
    root = hardened_root(tmp_path / "root")

    def snapshot():
        h = {}
        for p in sorted(root.rglob("*")):
            st = p.stat()
            data = p.read_bytes() if p.is_file() and os.access(p, os.R_OK) else b""
            h[str(p)] = (stat.S_IMODE(st.st_mode), hashlib.sha256(data).hexdigest())
        return h

    before = snapshot()
    run_audit(root, make_bin(tmp_path, ufw=GOOD_UFW, apt=GOOD_APT), tmp_path / "out")
    assert snapshot() == before


def test_html_report(tmp_path):
    root = hardened_root(tmp_path / "root")
    write(root, "etc/ssh/sshd_config", "PermitRootLogin yes\n")
    out = tmp_path / "out"
    proc = run_audit(root, make_bin(tmp_path, ufw=GOOD_UFW, apt=GOOD_APT), out, "--html")
    html = (out / "report.html").read_text()
    assert html.startswith("<!DOCTYPE html>")
    assert "SSH root login allowed" in html and "Remediation steps" in html
    assert "HTML:" in proc.stdout


def test_cli_options(tmp_path):
    bindir = make_bin(tmp_path)
    env = {"PATH": str(bindir)}
    assert subprocess.run(["bash", str(AUDIT), "--help"], env=env,
                          capture_output=True).returncode == 0
    bad = subprocess.run(["bash", str(AUDIT), "--nope"], env=env,
                         capture_output=True, text=True)
    assert bad.returncode == 2 and "Unknown option" in bad.stderr


def test_shellcheck_clean():
    sc = shutil.which("shellcheck")
    if not sc:
        pytest.skip("shellcheck not installed")
    proc = subprocess.run([sc, str(AUDIT)], capture_output=True, text=True)
    assert proc.returncode == 0, proc.stdout

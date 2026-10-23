# linux-security-audit

A **read-only Linux hardening audit** written in Bash. It checks the settings that
attackers most often abuse (SSH, firewall, updates, accounts, file permissions, open
services and password policy), gives the machine a **score out of 100**, and writes a
**Markdown and HTML report** with PASS / WARN / FAIL results and step-by-step fixes,
loosely mapped to the **CIS Benchmark**.

It never changes anything on the system, so it is safe to run on a server you are
responsible for, before and after hardening it.

---

## Why it matters for IT support and security

A fresh Linux server is not secure by default: root may be able to log in over SSH,
the firewall is often off, and updates pile up. Checking all of this by hand is slow and
easy to get wrong. This script turns a hardening checklist into a repeatable, 2-second
check that a support technician or junior SOC analyst can run, hand to a manager as a
report, and re-run to prove the fixes worked.

It also shows the thinking behind real frameworks like the **CIS Benchmarks**: each
finding has an ID, a severity, evidence and a remediation.

## Features

| ID | Check | CIS (loose) | How |
|---|---|---|---|
| SSH-1 | Root login over SSH (`PermitRootLogin`) | 5.2.10 | Parses `sshd_config` and `sshd_config.d/*.conf` (first value wins, `Match` blocks ignored, OpenSSH defaults applied) |
| SSH-2 | Password authentication over SSH | 5.2.x | same |
| SSH-3 | `MaxAuthTries` 4 or less | 5.2.7 | same |
| FW-1 | Host firewall active | 3.5 | `ufw status`, then `ufw.conf`, then `iptables -S` |
| UPD-1 | Pending updates (security updates = FAIL) | 1.9 | `apt-get -s upgrade` (simulation only) or `dnf check-update` |
| USR-1 | Accounts other than root with UID 0 | 6.2.x | `/etc/passwd` |
| USR-2 | Accounts with empty passwords | 6.2.1 | `/etc/shadow` (only if readable, otherwise skipped) |
| PERM-1 | `/etc/shadow` not world-accessible | 6.1.x | `stat` |
| PERM-2 | Sticky bit on `/tmp` | 1.1.x | `find -perm -1000` |
| PERM-3 | World-writable files in `/etc`, `/bin`, `/sbin`, `/usr/bin`, `/usr/sbin`, `/usr/local/*` | 6.1.9 | `find -perm -0002` |
| NET-1/2 | Listening TCP services; risky ones (Telnet, FTP, SMB, RDP, VNC, databases) exposed to the network | 2.x | Reads `/proc/net/tcp` and `/proc/net/tcp6` directly (no root, no `ss`/`netstat` needed) |
| PWD-1 | Password expiry 365 days or less | 5.5.1.2 | `/etc/login.defs` |
| PWD-2 | Minimum password length 14+ | 5.4.1 | `/etc/security/pwquality.conf` |

Plus:

- **Scoring:** PASS = 1 point, WARN = 0.5, FAIL = 0 (INFO not scored), with grade A to D
- **Reports:** `report.md`, `results.tsv` (machine-readable) and optional `report.html`
- **Read-only** and **works without root** (some checks become partial and say so)
- **Exit code 1** if anything FAILs, so it can run in cron or CI
- **shellcheck-clean** and covered by **17 pytest tests**

## Usage examples

All output below is real output captured while developing the project.

### 1. Full audit (with sudo) of a Debian 13 container

```console
$ sudo ./audit.sh -o sample-output/debian-container --html
linux-security-audit 1.0.0 (read-only)

[INFO] SSH-0  SSH server not installed
[FAIL] FW-1   No firewall tool found
[PASS] UPD-1  No pending package updates
[PASS] USR-1  Only root has UID 0
[PASS] USR-2  No accounts with empty passwords
[PASS] PERM-1 /etc/shadow is not world-accessible
[PASS] PERM-2 /tmp has the sticky bit
[PASS] PERM-3 No world-writable files in system folders
[INFO] NET-1  Listening TCP services: 5
[PASS] NET-2  No high-risk services exposed
[WARN] PWD-1  Passwords never expire (or expiry > 365 days)
[WARN] PWD-2  Weak minimum password length

Score: 80/100  grade B (good, a few gaps)  (7 PASS, 2 WARN, 1 FAIL, 2 INFO)
Report: sample-output/debian-container/report.md
HTML:   sample-output/debian-container/report.html
```

Full report: [`sample-output/debian-container/report.md`](sample-output/debian-container/report.md)

### 2. A badly configured system (demo)

`demo/insecure_demo.py` builds a **fake** Linux filesystem full of common mistakes and
audits it, so you can see what failures look like without breaking a real machine:

```console
$ python3 demo/insecure_demo.py
[FAIL] SSH-1  SSH root login allowed
[WARN] SSH-2  SSH password login enabled
[WARN] SSH-3  SSH MaxAuthTries too high
[FAIL] FW-1   Firewall (ufw) is inactive
[FAIL] UPD-1  Security updates pending
[FAIL] USR-1  Extra accounts with UID 0
[FAIL] USR-2  Accounts with empty passwords
[FAIL] PERM-1 /etc/shadow is world-accessible
[FAIL] PERM-2 /tmp is missing the sticky bit
[FAIL] PERM-3 World-writable files in system folders
[INFO] NET-1  Listening TCP services: 5
[FAIL] NET-2  Insecure clear-text service exposed
[WARN] PWD-1  Passwords never expire (or expiry > 365 days)
[WARN] PWD-2  Weak minimum password length

Score: 15/100  grade D (high risk)  (0 PASS, 4 WARN, 9 FAIL, 1 INFO)
```

An extract from the generated `report.md`:

```markdown
| Status | ID | CIS | Check | Detail |
|---|---|---|---|---|
| FAIL | SSH-1 | 5.2.10 | SSH root login allowed | PermitRootLogin is 'yes'. |
| FAIL | UPD-1 | 1.9 | Security updates pending | 3 package(s) can be upgraded, 2 from security repositories. |
| FAIL | USR-1 | 6.2.x | Extra accounts with UID 0 | These accounts have full root rights: toor |
| FAIL | NET-2 | 2.2.x | Insecure clear-text service exposed | Risky ports listening on the network: 23 3306 |

## Remediation steps

1. **[FAIL] SSH root login allowed** (SSH-1, CIS 5.2.10)
   Set 'PermitRootLogin no' in /etc/ssh/sshd_config, then run: sudo systemctl reload ssh
4. **[FAIL] Firewall (ufw) is inactive** (FW-1, CIS 3.5.1)
   Allow what you need first (e.g. sudo ufw allow OpenSSH), then: sudo ufw enable
```

Full report: [`sample-output/insecure-demo/report.md`](sample-output/insecure-demo/report.md)
(and `report.html` next to it).

## Install and run

Needs **bash 4+** and standard Linux tools (awk, find, stat, grep). Python 3 is only
needed for the optional HTML report and the tests.

```bash
git clone https://github.com/Uhone23/linux-security-audit.git
cd linux-security-audit
chmod +x audit.sh

./audit.sh                 # partial audit as a normal user
sudo ./audit.sh --html     # full audit + HTML report
./audit.sh -o myreport -q  # choose the output folder, only print the score
```

Run the tests and the linter:

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
shellcheck audit.sh
python3 -m pytest -v
```

## How the tests work

The tests never touch the real system. Each test builds a **fake root filesystem**
in a temporary folder (`etc/ssh/sshd_config`, `etc/passwd`, `etc/shadow`,
`proc/net/tcp`...) and points the script at it with the `AUDIT_ROOT` environment
variable. Commands such as `ufw`, `iptables` and `apt-get` are replaced by tiny fake
scripts on a controlled `PATH`, so every scenario (firewall on/off, needs root,
security updates pending...) can be tested on any machine. One test even takes a
hash of every file before and after the audit to prove the script is **read-only**.

## Project layout

```
audit.sh                 # the audit (Bash)
report_html.py           # results.tsv -> report.html (Python stdlib)
demo/insecure_demo.py    # audit a fake, badly configured system
tests/test_audit.py      # pytest tests (17)
sample-output/           # real reports from the examples above
```

## Tech used

Bash, awk, standard GNU/Linux tools, Python 3 (stdlib `html`, `argparse`), pytest,
ShellCheck, GitHub Actions.

## What I learned

- How sshd reads its config (first value wins, drop-in files, `Match` blocks) and why
  root login and password authentication are risky
- How Linux stores users and password hashes (`/etc/passwd`, `/etc/shadow`) and why
  a second UID 0 account is a classic backdoor
- Reading the kernel's socket table in `/proc/net/tcp` and converting hex addresses
  and ports, so the script works without root or `ss`
- Writing defensive Bash (`set -uo pipefail`, quoting, arrays) and keeping it
  ShellCheck-clean
- Testing shell scripts properly with fake filesystems and fake commands
- How the CIS Benchmarks structure security controls and remediation

## Roadmap

- [ ] More checks: auditd, AppArmor/SELinux, unattended-upgrades, fail2ban, SUID files
- [ ] nftables support
- [ ] JSON output for SIEM tools
- [ ] Compare two reports to show what improved after hardening

## Disclaimer

This is a learning project and a quick health check, not a full CIS compliance tool.
CIS numbers are approximate references to the CIS Ubuntu Linux Benchmark.

## License

[MIT](LICENSE) © 2026 Uhone Netshilindi

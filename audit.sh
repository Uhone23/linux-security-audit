#!/usr/bin/env bash
#
# linux-security-audit - a read-only Linux hardening check.
#
# It only READS configuration and system state. It never changes anything.
# Run as a normal user for a partial audit, or with sudo for a complete one.
#
# Checks are loosely mapped to the CIS Ubuntu Linux Benchmark. The CIS numbers
# are given as a guide for further reading, not as a formal compliance result.
#
# Usage: ./audit.sh [-o OUTPUT_DIR] [--html] [-q] [-h]
#
# Environment (mainly for testing):
#   AUDIT_ROOT   prefix for every file path read (default: empty = real system)
#
# Exit codes: 0 = no FAIL results, 1 = at least one FAIL, 2 = usage error

set -uo pipefail

VERSION="1.0.0"
R="${AUDIT_ROOT:-}"
OUT_DIR=""
WANT_HTML=0
QUIET=0
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Results are stored as tab-separated lines:
# STATUS  ID  CIS  TITLE  DETAIL  REMEDIATION
RESULTS=()

usage() {
    cat <<EOF
linux-security-audit $VERSION - read-only Linux hardening audit

Usage: $0 [options]

  -o, --output DIR   folder for the report (default: ./audit-report-YYYYmmdd-HHMMSS)
      --html         also build report.html (needs python3)
  -q, --quiet        only print the score summary
  -h, --help         show this help
  -V, --version      show version

Run with sudo for a complete audit (firewall rules and /etc/shadow need root).
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        -o|--output) OUT_DIR="${2:-}"; shift 2 || { usage; exit 2; } ;;
        --html) WANT_HTML=1; shift ;;
        -q|--quiet) QUIET=1; shift ;;
        -h|--help) usage; exit 0 ;;
        -V|--version) echo "$VERSION"; exit 0 ;;
        *) echo "Unknown option: $1" >&2; usage >&2; exit 2 ;;
    esac
done

[[ -z "$OUT_DIR" ]] && OUT_DIR="./audit-report-$(date +%Y%m%d-%H%M%S)"

# ------------------------------------------------------------------ helpers --

have() { command -v "$1" >/dev/null 2>&1; }

is_root() { [[ "$(id -u)" -eq 0 ]]; }

# add_result STATUS ID CIS TITLE DETAIL REMEDIATION
add_result() {
    local line
    # Tabs/newlines inside fields would break the TSV, so flatten them.
    line="$(printf '%s\t%s\t%s\t%s\t%s\t%s' "$1" "$2" "$3" "$4" \
        "$(tr '\t\n' '  ' <<<"$5" | sed 's/ *$//')" "$6")"
    RESULTS+=("$line")
    if [[ $QUIET -eq 0 ]]; then
        local colour="" reset=""
        if [[ -t 1 ]]; then
            reset=$'\e[0m'
            case "$1" in
                PASS) colour=$'\e[32m' ;; WARN) colour=$'\e[33m' ;;
                FAIL) colour=$'\e[31m' ;; *) colour=$'\e[36m' ;;
            esac
        fi
        printf '%s[%-4s]%s %-6s %s\n' "$colour" "$1" "$reset" "$2" "$4"
    fi
}

# sshd_value KEY -> prints the effective value (first match wins, like sshd).
# Drop-in files in sshd_config.d are read first because Debian/Ubuntu include
# them at the top of sshd_config. Lines inside "Match" blocks are ignored.
sshd_value() {
    local key="$1" f files=()
    if [[ -d "$R/etc/ssh/sshd_config.d" ]]; then
        for f in "$R"/etc/ssh/sshd_config.d/*.conf; do
            [[ -r "$f" ]] && files+=("$f")
        done
    fi
    [[ -r "$R/etc/ssh/sshd_config" ]] && files+=("$R/etc/ssh/sshd_config")
    [[ ${#files[@]} -eq 0 ]] && return 0
    awk -v key="$key" '
        BEGIN { key = tolower(key) }
        FNR == 1 { in_match = 0 }
        /^[[:space:]]*#/ || NF == 0 { next }
        tolower($1) == "match" { in_match = 1; next }
        !in_match && tolower($1) == key { print tolower($2); exit }
    ' "${files[@]}"
}

# ------------------------------------------------------------------- checks --

check_ssh() {
    if [[ ! -e "$R/etc/ssh/sshd_config" ]]; then
        add_result INFO SSH-0 "5.2" "SSH server not installed" \
            "No /etc/ssh/sshd_config found, so SSH checks were skipped." "None needed."
        return
    fi

    local root_login pass_auth tries
    root_login="$(sshd_value PermitRootLogin)"
    root_login="${root_login:-prohibit-password}"  # OpenSSH default
    case "$root_login" in
        no)
            add_result PASS SSH-1 "5.2.10" "SSH root login disabled" \
                "PermitRootLogin is 'no'." "None needed." ;;
        prohibit-password|without-password|forced-commands-only)
            add_result WARN SSH-1 "5.2.10" "SSH root login allowed with keys" \
                "PermitRootLogin is '$root_login' (root can log in with an SSH key)." \
                "Set 'PermitRootLogin no' in /etc/ssh/sshd_config, log in as a normal user and use sudo, then run: sudo systemctl reload ssh" ;;
        *)
            add_result FAIL SSH-1 "5.2.10" "SSH root login allowed" \
                "PermitRootLogin is '$root_login'." \
                "Set 'PermitRootLogin no' in /etc/ssh/sshd_config, then run: sudo systemctl reload ssh" ;;
    esac

    pass_auth="$(sshd_value PasswordAuthentication)"
    if [[ "$pass_auth" == "no" ]]; then
        add_result PASS SSH-2 "5.2.x" "SSH password login disabled" \
            "PasswordAuthentication is 'no' (keys only)." "None needed."
    else
        add_result WARN SSH-2 "5.2.x" "SSH password login enabled" \
            "PasswordAuthentication is '${pass_auth:-yes (default)}'. Passwords can be brute-forced." \
            "Set up SSH keys (ssh-keygen, ssh-copy-id), test them, then set 'PasswordAuthentication no' and reload ssh. Consider fail2ban."
    fi

    tries="$(sshd_value MaxAuthTries)"
    tries="${tries:-6}"
    if [[ "$tries" =~ ^[0-9]+$ && "$tries" -le 4 ]]; then
        add_result PASS SSH-3 "5.2.7" "SSH MaxAuthTries is 4 or less" \
            "MaxAuthTries is $tries." "None needed."
    else
        add_result WARN SSH-3 "5.2.7" "SSH MaxAuthTries too high" \
            "MaxAuthTries is $tries (CIS recommends 4 or less)." \
            "Set 'MaxAuthTries 4' in /etc/ssh/sshd_config and reload ssh."
    fi
}

check_firewall() {
    local out
    if have ufw; then
        out="$(ufw status 2>/dev/null)"
        if grep -q "Status: active" <<<"$out"; then
            add_result PASS FW-1 "3.5.1" "Firewall (ufw) is active" "ufw status: active." "None needed."
            return
        elif grep -q "Status: inactive" <<<"$out"; then
            add_result FAIL FW-1 "3.5.1" "Firewall (ufw) is inactive" \
                "ufw is installed but not enabled." \
                "Allow what you need first (e.g. sudo ufw allow OpenSSH), then: sudo ufw enable"
            return
        elif grep -qi '^ENABLED=yes' "$R/etc/ufw/ufw.conf" 2>/dev/null; then
            add_result PASS FW-1 "3.5.1" "Firewall (ufw) enabled in config" \
                "ufw.conf has ENABLED=yes (live status needs root to confirm)." "None needed."
            return
        fi
    fi
    if have iptables; then
        if out="$(iptables -S 2>/dev/null)"; then
            if grep -qE '^-P INPUT (DROP|REJECT)|^-A INPUT' <<<"$out"; then
                add_result PASS FW-1 "3.5.3" "Firewall (iptables) has INPUT rules" \
                    "iptables INPUT chain has a restrictive policy or rules." "None needed."
            else
                add_result FAIL FW-1 "3.5.3" "No firewall rules loaded" \
                    "iptables INPUT policy is ACCEPT with no rules: all ports are reachable." \
                    "Install and enable ufw (sudo apt install ufw && sudo ufw allow OpenSSH && sudo ufw enable) or add iptables rules."
            fi
            return
        fi
        add_result WARN FW-1 "3.5" "Firewall status unknown" \
            "iptables is installed but reading rules needs root." \
            "Re-run this audit with sudo to check the firewall."
        return
    fi
    if have ufw; then
        add_result WARN FW-1 "3.5" "Firewall status unknown" \
            "ufw is installed but its status needs root to read." \
            "Re-run this audit with sudo, or check with: sudo ufw status"
        return
    fi
    add_result FAIL FW-1 "3.5" "No firewall tool found" \
        "Neither ufw nor iptables is installed." \
        "Install a host firewall: sudo apt install ufw && sudo ufw allow OpenSSH && sudo ufw enable"
}

check_updates() {
    local out count security run=()
    have timeout && run=(timeout 120)
    if have apt-get; then
        # -s = simulate only. Uses the existing package lists (no download).
        out="$("${run[@]}" apt-get -s -o Debug::NoLocking=1 upgrade 2>/dev/null)"
        count="$(grep -c '^Inst ' <<<"$out")"
        security="$(grep '^Inst ' <<<"$out" | grep -ci 'security')"
        if [[ "$count" -eq 0 ]]; then
            add_result PASS UPD-1 "1.9" "No pending package updates" \
                "apt reports 0 upgradable packages (based on the last 'apt update')." \
                "Keep running 'sudo apt update && sudo apt upgrade' regularly."
        elif [[ "$security" -gt 0 ]]; then
            add_result FAIL UPD-1 "1.9" "Security updates pending" \
                "$count package(s) can be upgraded, $security from security repositories." \
                "Run: sudo apt update && sudo apt upgrade. Consider enabling unattended-upgrades."
        else
            add_result WARN UPD-1 "1.9" "Package updates pending" \
                "$count package(s) can be upgraded." \
                "Run: sudo apt update && sudo apt upgrade"
        fi
        return
    fi
    if have dnf; then
        out="$("${run[@]}" dnf -q check-update 2>/dev/null)"
        local rc=$?
        count="$(grep -cE '^[[:alnum:]]' <<<"$out")"
        if [[ $rc -eq 0 ]]; then
            add_result PASS UPD-1 "1.9" "No pending package updates" "dnf reports no updates." "None needed."
        elif [[ $rc -eq 100 ]]; then
            add_result WARN UPD-1 "1.9" "Package updates pending" \
                "$count package(s) can be upgraded." "Run: sudo dnf upgrade"
        else
            add_result WARN UPD-1 "1.9" "Could not check updates" "dnf check-update failed." "Run: sudo dnf check-update"
        fi
        return
    fi
    add_result INFO UPD-1 "1.9" "Update check skipped" \
        "No supported package manager (apt-get or dnf) found." "Check updates with your distribution's tools."
}

check_uid0() {
    local extra
    extra="$(awk -F: '$3 == 0 && $1 != "root" { printf "%s ", $1 }' "$R/etc/passwd" 2>/dev/null)"
    if [[ -z "$extra" ]]; then
        add_result PASS USR-1 "6.2.x" "Only root has UID 0" "No other accounts have UID 0." "None needed."
    else
        add_result FAIL USR-1 "6.2.x" "Extra accounts with UID 0" \
            "These accounts have full root rights: ${extra% }" \
            "Investigate immediately (possible backdoor). Remove the account or give it a normal UID: sudo usermod -u <new_uid> <user>"
    fi
}

check_empty_passwords() {
    local empty
    if [[ ! -r "$R/etc/shadow" ]]; then
        add_result INFO USR-2 "6.2.1" "Empty password check skipped" \
            "/etc/shadow is not readable (run with sudo to include this check)." \
            "Re-run with sudo."
        return
    fi
    empty="$(awk -F: '$2 == "" { printf "%s ", $1 }' "$R/etc/shadow")"
    if [[ -z "$empty" ]]; then
        add_result PASS USR-2 "6.2.1" "No accounts with empty passwords" "Every account has a password or is locked." "None needed."
    else
        add_result FAIL USR-2 "6.2.1" "Accounts with empty passwords" \
            "Accounts anyone can log in to without a password: ${empty% }" \
            "Lock them (sudo passwd -l <user>) or set a strong password (sudo passwd <user>)."
    fi
}

check_file_permissions() {
    local mode
    if [[ -e "$R/etc/shadow" ]]; then
        mode="$(stat -c '%a' "$R/etc/shadow")"
        # The last digit is "others". Anything other than 0 means world-readable/writable.
        if [[ "${mode: -1}" == "0" ]]; then
            add_result PASS PERM-1 "6.1.x" "/etc/shadow is not world-accessible" \
                "Permissions are $mode." "None needed."
        else
            add_result FAIL PERM-1 "6.1.x" "/etc/shadow is world-accessible" \
                "Permissions are $mode: any user can read the password hashes." \
                "Run: sudo chown root:shadow /etc/shadow && sudo chmod 640 /etc/shadow"
        fi
    fi

    if [[ -d "$R/tmp" ]]; then
        if [[ -n "$(find "$R/tmp" -maxdepth 0 -perm -1000 2>/dev/null)" ]]; then
            add_result PASS PERM-2 "1.1.x" "/tmp has the sticky bit" \
                "Users cannot delete each other's files in /tmp." "None needed."
        else
            add_result FAIL PERM-2 "1.1.x" "/tmp is missing the sticky bit" \
                "Any user can delete or replace other users' files in /tmp." \
                "Run: sudo chmod 1777 /tmp"
        fi
    fi

    local dirs=(etc bin sbin usr/bin usr/sbin usr/local/bin usr/local/sbin) d found=()
    for d in "${dirs[@]}"; do
        [[ -d "$R/$d" && ! -L "$R/$d" ]] || continue
        while IFS= read -r f; do
            found+=("${f#"$R"}")
        done < <(find "$R/$d" -xdev -type f -perm -0002 2>/dev/null)
    done
    if [[ ${#found[@]} -eq 0 ]]; then
        add_result PASS PERM-3 "6.1.9" "No world-writable files in system folders" \
            "Checked: ${dirs[*]}" "None needed."
    else
        add_result FAIL PERM-3 "6.1.9" "World-writable files in system folders" \
            "${#found[@]} file(s), e.g. ${found[*]:0:5}" \
            "Any user could change these files. Remove the write bit: sudo chmod o-w <file>"
    fi
}

check_listening() {
    # Read the kernel's socket table directly: works without root and without ss/netstat.
    local tcp_files=() f listeners risky public
    for f in "$R/proc/net/tcp" "$R/proc/net/tcp6"; do
        [[ -r "$f" ]] && tcp_files+=("$f")
    done
    if [[ ${#tcp_files[@]} -eq 0 ]]; then
        add_result INFO NET-1 "2.x" "Listening services check skipped" "/proc/net/tcp not readable." "None needed."
        return
    fi
    # Output: "ADDRESS PORT" for every socket in LISTEN state (st == 0A).
    listeners="$(awk '
        function hex(s,   i, n, c) {
            n = 0; s = toupper(s)
            for (i = 1; i <= length(s); i++) {
                c = index("0123456789ABCDEF", substr(s, i, 1)) - 1
                n = n * 16 + c
            }
            return n
        }
        FNR == 1 { next }
        $4 == "0A" {
            split($2, a, ":"); ip = a[1]; port = hex(a[2])
            if (length(ip) == 8) {
                addr = hex(substr(ip,7,2)) "." hex(substr(ip,5,2)) "." hex(substr(ip,3,2)) "." hex(substr(ip,1,2))
            } else if (ip == "00000000000000000000000000000000") {
                addr = "::"
            } else if (ip == "00000000000000000000000001000000") {
                addr = "::1"
            } else if (substr(ip,1,24) == "0000000000000000FFFF0000") {
                v4 = substr(ip,25,8)
                addr = hex(substr(v4,7,2)) "." hex(substr(v4,5,2)) "." hex(substr(v4,3,2)) "." hex(substr(v4,1,2))
            } else { addr = "ipv6" }
            print addr, port
        }' "${tcp_files[@]}" | sort -u -k2,2n -k1,1)"

    local total=0 summary=""
    public=""
    risky=""
    while read -r addr port; do
        [[ -z "${port:-}" ]] && continue
        total=$((total + 1))
        summary+="$addr:$port "
        case "$addr" in 127.*|::1) continue ;; esac
        public+="$port "
        case "$port" in
            21|23|111|139|445|3389|5900|3306|5432|6379|27017) risky+="$port " ;;
        esac
    done <<<"$listeners"

    add_result INFO NET-1 "2.x" "Listening TCP services: $total" \
        "${summary:-none}" "Review this list and stop services you do not need: sudo systemctl disable --now <service>"

    if [[ -z "$risky" ]]; then
        add_result PASS NET-2 "2.x" "No high-risk services exposed" \
            "Ports open to the network: ${public:-none}" "None needed."
    elif grep -qwE '21|23' <<<"$risky"; then
        add_result FAIL NET-2 "2.2.x" "Insecure clear-text service exposed" \
            "Risky ports listening on the network: ${risky% }" \
            "Telnet (23) and FTP (21) send passwords in clear text. Remove them (e.g. sudo apt purge telnetd vsftpd) and use SSH/SFTP."
    else
        add_result WARN NET-2 "2.x" "High-risk services exposed" \
            "Risky ports listening on the network: ${risky% }" \
            "Bind databases/file sharing/remote desktop to 127.0.0.1 or restrict them with the firewall."
    fi
}

check_password_policy() {
    local max_days minlen
    max_days="$(awk '$1 == "PASS_MAX_DAYS" { print $2 }' "$R/etc/login.defs" 2>/dev/null | tail -n 1)"
    if [[ "$max_days" =~ ^[0-9]+$ && "$max_days" -le 365 ]]; then
        add_result PASS PWD-1 "5.5.1.2" "Password expiry is 365 days or less" \
            "PASS_MAX_DAYS is $max_days." "None needed."
    else
        add_result WARN PWD-1 "5.5.1.2" "Passwords never expire (or expiry > 365 days)" \
            "PASS_MAX_DAYS is ${max_days:-not set}." \
            "Set 'PASS_MAX_DAYS 365' in /etc/login.defs (applies to new users; use chage -M 365 <user> for existing ones)."
    fi

    minlen="$(cat "$R"/etc/security/pwquality.conf "$R"/etc/security/pwquality.conf.d/*.conf 2>/dev/null \
        | awk -F= '/^[[:space:]]*minlen[[:space:]]*=/ { gsub(/[[:space:]]/, "", $2); v = $2 } END { print v }')"
    if [[ "$minlen" =~ ^[0-9]+$ && "$minlen" -ge 14 ]]; then
        add_result PASS PWD-2 "5.4.1" "Minimum password length is 14 or more" \
            "pwquality minlen is $minlen." "None needed."
    else
        add_result WARN PWD-2 "5.4.1" "Weak minimum password length" \
            "pwquality minlen is ${minlen:-not set (default 8 or less)}." \
            "Install libpam-pwquality and set 'minlen = 14' in /etc/security/pwquality.conf."
    fi
}

# ------------------------------------------------------------------- report --

os_name() {
    local name=""
    if [[ -r "$R/etc/os-release" ]]; then
        name="$(awk -F= '$1 == "PRETTY_NAME" { gsub(/"/, "", $2); print $2 }' "$R/etc/os-release")"
    fi
    echo "${name:-unknown}"
}

md_escape() { local s="$1"; echo "${s//|/\\|}"; }

write_reports() {
    local pass=0 warn=0 fail=0 info=0 line status id cis title detail fix
    for line in "${RESULTS[@]}"; do
        case "${line%%$'\t'*}" in
            PASS) pass=$((pass + 1)) ;; WARN) warn=$((warn + 1)) ;;
            FAIL) fail=$((fail + 1)) ;; *) info=$((info + 1)) ;;
        esac
    done
    local scored=$((pass + warn + fail)) score=0 grade
    # PASS = 1 point, WARN = half a point, FAIL = 0. INFO is not scored.
    [[ $scored -gt 0 ]] && score=$(( (pass * 100 + warn * 50) / scored ))
    if   [[ $score -ge 90 ]]; then grade="A (well hardened)"
    elif [[ $score -ge 75 ]]; then grade="B (good, a few gaps)"
    elif [[ $score -ge 50 ]]; then grade="C (needs attention)"
    else grade="D (high risk)"; fi

    FAILS=$fail

    mkdir -p "$OUT_DIR" || { echo "Cannot create $OUT_DIR" >&2; exit 2; }
    local host user when os kernel mode
    host="$(hostname 2>/dev/null || echo unknown)"
    user="$(id -un 2>/dev/null || echo unknown)"
    when="$(date '+%Y-%m-%d %H:%M %Z')"
    os="$(os_name)"
    kernel="$(uname -r)"
    if is_root; then mode="full (root)"; else mode="partial (not root)"; fi

    # Machine-readable results (used by report_html.py and the tests).
    {
        printf '#host\t%s\n#os\t%s\n#kernel\t%s\n#date\t%s\n#user\t%s\n#mode\t%s\n' \
            "$host" "$os" "$kernel" "$when" "$user" "$mode"
        printf '#score\t%s\n#grade\t%s\n' "$score" "$grade"
        printf 'status\tid\tcis\ttitle\tdetail\tremediation\n'
        printf '%s\n' "${RESULTS[@]}"
    } >"$OUT_DIR/results.tsv"

    {
        echo "# Linux Security Audit Report"
        echo
        echo "| | |"
        echo "|---|---|"
        echo "| Host | \`$host\` |"
        echo "| OS | $os (kernel $kernel) |"
        echo "| Date | $when |"
        echo "| Audit mode | $mode |"
        echo "| **Score** | **$score / 100, grade $grade** |"
        echo "| Results | $pass PASS, $warn WARN, $fail FAIL, $info INFO |"
        echo
        echo "Scoring: PASS = 1 point, WARN = 0.5, FAIL = 0. INFO items are not scored."
        echo "CIS numbers refer loosely to the CIS Ubuntu Linux Benchmark and are a guide only."
        echo
        echo "## Results"
        echo
        echo "| Status | ID | CIS | Check | Detail |"
        echo "|---|---|---|---|---|"
        for line in "${RESULTS[@]}"; do
            IFS=$'\t' read -r status id cis title detail fix <<<"$line"
            echo "| $status | $id | $cis | $(md_escape "$title") | $(md_escape "$detail") |"
        done
        echo
        echo "## Remediation steps"
        echo
        local n=0
        for line in "${RESULTS[@]}"; do
            IFS=$'\t' read -r status id cis title detail fix <<<"$line"
            [[ "$status" == "FAIL" || "$status" == "WARN" ]] || continue
            n=$((n + 1))
            echo "$n. **[$status] $title** ($id, CIS $cis)  "
            echo "   $fix"
        done
        [[ $n -eq 0 ]] && echo "Nothing to fix. Well done!"
        echo
        echo "---"
        echo "_Generated by linux-security-audit $VERSION. This script is read-only and made no changes._"
    } >"$OUT_DIR/report.md"

    if [[ $WANT_HTML -eq 1 ]]; then
        if have python3; then
            python3 "$SCRIPT_DIR/report_html.py" "$OUT_DIR/results.tsv" -o "$OUT_DIR/report.html" \
                || echo "HTML report failed" >&2
        else
            echo "python3 not found: skipping HTML report" >&2
        fi
    fi

    echo
    echo "Score: $score/100  grade $grade  ($pass PASS, $warn WARN, $fail FAIL, $info INFO)"
    echo "Report: $OUT_DIR/report.md"
    [[ -f "$OUT_DIR/report.html" ]] && echo "HTML:   $OUT_DIR/report.html"
    return 0
}

main() {
    if [[ $QUIET -eq 0 ]]; then
        echo "linux-security-audit $VERSION (read-only)"
        is_root || echo "Note: not running as root, some checks will be partial. Use sudo for a full audit."
        echo
    fi
    check_ssh
    check_firewall
    check_updates
    check_uid0
    check_empty_passwords
    check_file_permissions
    check_listening
    check_password_policy
    write_reports
    [[ $FAILS -gt 0 ]] && exit 1
    exit 0
}

main

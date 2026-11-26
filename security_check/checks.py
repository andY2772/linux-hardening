"""
checks.py
Shared, read-only system checks for the hardening audit/monitor tool.
Every function returns a plain dict so results are easy to print, diff, or
dump to JSON. Nothing here modifies the system - it only reads status.
"""

import re
import shutil
import subprocess


def _run(cmd):
    """Run a command, return (returncode, stdout, stderr). Never raises."""
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=10
        )
        return result.returncode, result.stdout.strip(), result.stderr.strip()
    except FileNotFoundError:
        return 127, "", f"{cmd[0]} not found"
    except Exception as e:
        return 1, "", str(e)


def check_firewall():
    """Check ufw if present, otherwise fall back to iptables."""
    if shutil.which("ufw"):
        rc, out, err = _run(["ufw", "status", "verbose"])
        active = "Status: active" in out
        rules = [l for l in out.splitlines() if re.match(r"^\S+\s+(ALLOW|DENY|LIMIT)", l)]
        return {
            "tool": "ufw",
            "active": active,
            "ok": active,
            "detail": rules if rules else out,
        }

    rc, out, err = _run(["iptables", "-L", "-n"])
    has_rules = rc == 0 and len(out.splitlines()) > 3
    return {
        "tool": "iptables",
        "active": rc == 0,
        "ok": has_rules,
        "detail": out if has_rules else "no custom rules found",
    }


def check_fail2ban():
    rc, out, err = _run(["systemctl", "is-active", "fail2ban"])
    active = out == "active"
    jails = []
    if active:
        rc2, jail_out, _ = _run(["fail2ban-client", "status"])
        m = re.search(r"Jail list:\s*(.*)", jail_out)
        if m:
            jails = [j.strip() for j in m.group(1).split(",") if j.strip()]

    jail_details = {}
    for jail in jails:
        rc3, detail, _ = _run(["fail2ban-client", "status", jail])
        banned = re.search(r"Currently banned:\s*(\d+)", detail)
        jail_details[jail] = int(banned.group(1)) if banned else 0

    return {
        "active": active,
        "ok": active and len(jails) > 0,
        "jails": jails,
        "banned_counts": jail_details,
    }


def check_unattended_upgrades():
    rc, out, err = _run(["systemctl", "is-enabled", "unattended-upgrades"])
    enabled = out == "enabled"

    conf_ok = False
    try:
        with open("/etc/apt/apt.conf.d/20auto-upgrades") as f:
            content = f.read()
        conf_ok = (
            'APT::Periodic::Update-Package-Lists "1"' in content
            and 'APT::Periodic::Unattended-Upgrade "1"' in content
        )
    except FileNotFoundError:
        pass

    last_run = None
    try:
        with open("/var/log/unattended-upgrades/unattended-upgrades.log") as f:
            lines = f.readlines()
        if lines:
            last_run = lines[-1].strip()
    except FileNotFoundError:
        pass

    return {
        "service_enabled": enabled,
        "config_ok": conf_ok,
        "ok": enabled and conf_ok,
        "last_log_line": last_run,
    }


def check_ssh_config(path="/etc/ssh/sshd_config"):
    settings = {"PermitRootLogin": None, "PasswordAuthentication": None, "Port": "22"}
    try:
        with open(path) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                for key in settings:
                    if line.startswith(key):
                        settings[key] = line.split()[1]
    except FileNotFoundError:
        return {"ok": False, "error": f"{path} not found"}

    hardened = (
        settings["PermitRootLogin"] in ("no", "prohibit-password")
        and settings["PasswordAuthentication"] == "no"
    )
    return {"ok": hardened, **settings}


def check_listening_ports():
    rc, out, err = _run(["ss", "-tulnH"])
    ports = set()
    for line in out.splitlines():
        parts = line.split()
        if len(parts) >= 5:
            addr = parts[4]
            if ":" in addr:
                port = addr.rsplit(":", 1)[-1]
                if port.isdigit():
                    ports.add(int(port))
    return {"ok": True, "ports": sorted(ports)}


def check_pending_updates():
    rc, out, err = _run(["apt", "list", "--upgradable"])
    lines = [l for l in out.splitlines() if "/" in l and "upgradable" in l]
    security = [l for l in lines if "-security" in l]
    return {
        "ok": len(lines) == 0,
        "total_upgradable": len(lines),
        "security_upgradable": len(security),
    }


def run_all_checks():
    return {
        "firewall": check_firewall(),
        "fail2ban": check_fail2ban(),
        "unattended_upgrades": check_unattended_upgrades(),
        "ssh": check_ssh_config(),
        "listening_ports": check_listening_ports(),
        "pending_updates": check_pending_updates(),
    }
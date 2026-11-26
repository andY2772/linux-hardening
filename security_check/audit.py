"""
audit.py - one-shot hardening audit.

Run manually (or via cron) to get a readable report of your current
security posture: firewall, fail2ban, unattended-upgrades, SSH config,
listening ports, and pending package updates.

Usage:
    sudo python3 audit.py              # human-readable report
    sudo python3 audit.py --json       # machine-readable output
    sudo python3 audit.py --save FILE  # also write a JSON snapshot to FILE
"""

import argparse
import json
import sys
from datetime import datetime, timezone

from checks import run_all_checks


def render_report(results):
    lines = []
    lines.append(f"Security audit — {datetime.now(timezone.utc).isoformat()}")
    lines.append("=" * 60)

    fw = results["firewall"]
    lines.append(f"[{'OK' if fw['ok'] else 'FAIL'}] Firewall ({fw['tool']}): "
                 f"{'active' if fw['active'] else 'INACTIVE'}")

    f2b = results["fail2ban"]
    lines.append(f"[{'OK' if f2b['ok'] else 'FAIL'}] fail2ban: "
                 f"{'active' if f2b['active'] else 'INACTIVE'}, "
                 f"jails: {', '.join(f2b['jails']) or 'none'}")
    for jail, count in f2b.get("banned_counts", {}).items():
        lines.append(f"    - {jail}: {count} currently banned")

    uu = results["unattended_upgrades"]
    lines.append(f"[{'OK' if uu['ok'] else 'FAIL'}] unattended-upgrades: "
                 f"service_enabled={uu['service_enabled']} config_ok={uu['config_ok']}")
    if uu.get("last_log_line"):
        lines.append(f"    last log line: {uu['last_log_line']}")

    ssh = results["ssh"]
    lines.append(f"[{'OK' if ssh['ok'] else 'FAIL'}] SSH hardening: "
                 f"PermitRootLogin={ssh.get('PermitRootLogin')} "
                 f"PasswordAuthentication={ssh.get('PasswordAuthentication')} "
                 f"Port={ssh.get('Port')}")

    ports = results["listening_ports"]
    lines.append(f"[INFO] Listening ports: {ports['ports']}")

    upd = results["pending_updates"]
    status = "OK" if upd["ok"] else "INFO"
    lines.append(f"[{status}] Pending updates: {upd['total_upgradable']} total, "
                 f"{upd['security_upgradable']} security")

    overall_ok = all(
        results[k]["ok"] for k in ("firewall", "fail2ban", "unattended_upgrades", "ssh")
    )
    lines.append("=" * 60)
    lines.append(f"Overall: {'PASS' if overall_ok else 'ATTENTION NEEDED'}")
    return "\n".join(lines), overall_ok


def main():
    parser = argparse.ArgumentParser(description="Run a one-shot hardening audit")
    parser.add_argument("--json", action="store_true", help="print JSON instead of a report")
    parser.add_argument("--save", metavar="FILE", help="also write a JSON snapshot to FILE")
    args = parser.parse_args()

    results = run_all_checks()
    report, overall_ok = render_report(results)

    if args.json:
        print(json.dumps(results, indent=2))
    else:
        print(report)

    if args.save:
        snapshot = {"timestamp": datetime.now(timezone.utc).isoformat(), "results": results}
        with open(args.save, "w") as f:
            json.dump(snapshot, f, indent=2)

    sys.exit(0 if overall_ok else 1)


if __name__ == "__main__":
    main()
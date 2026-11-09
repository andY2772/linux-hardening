#!/usr/bin/env python3
"""check_hardening.py - overi stav hardeningu a vypise report."""
import json
import os
import subprocess
import sys

SSHD_EXPECTED = {
    "permitrootlogin": "no",
    "passwordauthentication": "no",
    "pubkeyauthentication": "yes",
    "maxauthtries": "3",
    "x11forwarding": "no",
}

SYSCTL_EXPECTED = {
    "net.ipv4.conf.all.rp_filter": "1",
    "net.ipv4.tcp_syncookies": "1",
    "kernel.kptr_restrict": "2",
}


def run(cmd):
    return subprocess.run(cmd, capture_output=True, text=True, check=False).stdout.strip()


def check_sshd():
    cfg = {}
    for line in run(["sshd", "-T"]).splitlines():
        key, _, value = line.partition(" ")
        cfg[key] = value
    return [(f"sshd: {k}", cfg.get(k), v) for k, v in SSHD_EXPECTED.items()]


def check_sysctl():
    return [(f"sysctl: {k}", run(["sysctl", "-n", k]), v)
            for k, v in SYSCTL_EXPECTED.items()]


def main():
    if os.geteuid() != 0:
        sys.exit("Spustite ako root (sudo).")

    results = check_sshd() + check_sysctl()
    # TODO: pridajte kontrolu ufw (je aktivny?), fail2ban (bezi?),
    #       unattended-upgrades (je zapnute?)

    failed = 0
    for name, actual, expected in results:
        ok = actual == expected
        failed += not ok
        print(f"[{'OK' if ok else 'FAIL'}] {name}: {actual} (ocakavane {expected})")

    print(json.dumps({"total": len(results), "failed": failed}))
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()

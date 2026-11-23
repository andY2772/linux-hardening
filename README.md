# Ubuntu Server Hardening

A reproducible hardening setup for Ubuntu Server, built and tested in a VirtualBox lab. I first hardened a fresh server by hand, measured the result with [Lynis](https://cisofy.com/lynis/), and then turned every step into an idempotent Bash script that produces the same result on a clean machine.

**Result:** Lynis hardening index went from **62** (fresh install) to **77**, and the script reproduced the same score on a clean VM.

## Why I built this

I'm a third-year Cybersecurity student at FI MUNI, and I'm aiming for a junior Linux infrastructure / DevOps role. I wanted a project that goes beyond "I installed it and it works" and shows the full loop: **baseline → harden → measure → automate → verify**.

## Lab environment

| Item | Value |
|---|---|
| Hypervisor | VirtualBox |
| OS | Ubuntu Server 24.04 |
| Networking | NAT with port forwarding (`127.0.0.1:2222` → guest `10.0.2.15:22`) |
| Audit tool | Lynis 3.1.6 |
| Access | SSH from the host, key-based only |

## What gets hardened

| Area | Change | Why |
|---|---|---|
| SSH | Key-only login, no root login, `MaxAuthTries 3`, no X11/agent forwarding, `LogLevel VERBOSE`, `MaxSessions 2`, keepalive tuning | Removes password brute-forcing and shrinks the attack surface. Verbose logging records which key was used |
| Firewall (`ufw`) | Default deny incoming, allow only SSH | Anything not explicitly needed is blocked |
| `fail2ban` | Ban an IP for 1 h after 5 failures within 10 min | Slows down automated login attempts |
| Updates | `unattended-upgrades` for security patches | Shrinks the window between a fix being released and installed |
| Kernel (`sysctl`) | `rp_filter`, no ICMP redirects, no source routing, SYN cookies, `log_martians`, `dmesg_restrict`, `kptr_restrict`, `suid_dumpable=0` | Anti-spoofing, protection against network-level tricks, less information leaked to local users |
| Kernel modules | Blocked `dccp`, `sctp`, `rds`, `tipc`, `usb-storage` | What the server doesn't need shouldn't be loadable |
| Accounts | `UMASK 027`, password aging for new accounts, `libpam-pwquality`, `libpam-tmpdir` | Stricter defaults for files and passwords |
| Tooling | `debsums`, `apt-listchanges`, `apt-show-versions` | Package verification and patch visibility |

## Results

| Stage | Lynis hardening index |
|---|---|
| Fresh install | 62 |
| After manual hardening (SSH, ufw, fail2ban, updates, sysctl) | 68 |
| After fixing further Lynis suggestions | 77 |
| `harden.sh` on a clean VM | 77 |

Raw reports are in [`docs/`](docs/). The index is a guide, not a goal: I did not chase 100, because the remaining points mostly require changes that don't make sense for this lab (see below).

## Repository structure

```
.
├── README.md
├── scripts/
│   └── harden.sh        # idempotent hardening script
└── docs/                # Lynis before/after reports, fail2ban ban evidence, sysctl state
```

## Usage

> Run this on a **disposable VM**, not on your daily machine. The script disables SSH password login and changes firewall rules.

1. Copy your public key to the server first (`ssh-copy-id`), because the script refuses to run without it.
2. Copy the script to the server and run it:

```bash
chmod +x harden.sh
sudo ./harden.sh <admin_user>
```

3. Reboot (kernel module blacklist), then verify:

```bash
sudo sshd -T | grep -E "permitrootlogin|passwordauthentication|pubkeyauthentication"
sudo ufw status verbose
sudo fail2ban-client status sshd
sudo lynis audit system
```

If you use VS Code Remote-SSH, set `ALLOW_TCP_FORWARDING="yes"` at the top of the script, because Remote-SSH needs it.

## Design decisions

- **Lockout guard.** The script exits if the admin user has no `authorized_keys`, so it can't disable password login and lock you out. I tested this on a clean VM: it failed on the guard first, then succeeded once I uploaded the key.
- **Idempotent.** Configuration files are written with `cat >` (overwrite) instead of appending, so running the script twice gives the same state.
- **Validate before applying.** `sshd -t` runs before SSH is restarted.
- **SSH drop-in naming.** The SSH config is `01-hardening.conf` because `sshd` uses the first value it finds and reads drop-ins alphabetically. A later file such as `50-cloud-init.conf` could otherwise override my settings.
- **Fail loudly.** `set -euo pipefail` plus explicit error messages.
- **Checked with ShellCheck.**

## Deliberately not changed

Lynis suggests more than makes sense for this setup. I decided not to apply:

| Suggestion | Reason |
|---|---|
| GRUB password | Protects against physical console access; on a VM the hypervisor controls that |
| Separate `/home` and `/var` partitions | Needs to be decided at install time; pointless for a single-purpose lab VM, valuable in production |
| Change SSH port | Security through obscurity; key-only auth, firewall and fail2ban already do the real work |
| Password hashing rounds in `login.defs` | Ubuntu uses a modern hashing scheme where this setting doesn't apply |
| DNS domain name | Irrelevant for a standalone lab server |
| `systemd-analyze security` service hardening | Interesting next step, outside this project's scope |

## Testing fail2ban

I deliberately triggered a ban by logging in repeatedly as a non-existent user. Because of NAT, the VM sees every connection from the host as `10.0.2.2`, so the host itself got banned and SSH from it hung. I then logged in through the VirtualBox console (which is unaffected by the ban), confirmed the ban with `fail2ban-client status sshd`, saved the evidence to `docs/`, and unbanned with `fail2ban-client set sshd unbanip`.

## What I learned

- **SSH hardening:** key-based login works by signing a challenge with the private key, so password login can be disabled completely. `sshd` uses the first value it finds across `sshd_config.d/` files, so the hardening file has to sort first, and `sshd -T` shows the effective settings.
- **Firewall:** follow *default deny* and allow only what the server needs. Allow SSH before enabling `ufw`, or you cut off your own session.
- **fail2ban:** a jail combines a filter (regex over log lines) with an action (ban via the firewall), and `maxretry`, `findtime` and `bantime` define the policy. Behind NAT the server sees all connections from one address, so my own test banned the whole "client".
- **Automatic updates:** `unattended-upgrades` installs security updates only, driven by systemd timers. It shortens exposure time but can break services, and kernel updates still need a reboot.
- **Kernel hardening:** each `sysctl` setting closes a specific issue (spoofed addresses, ICMP redirects, SYN floods, kernel info leaks). Unneeded modules can be disabled via `modprobe.d`.
- **Password policy:** settings in `login.defs` apply to new accounts only, so changing them is not the same as enforcing them.
- **Reading audit results:** a Lynis score is a guide, not a goal. I learned to sort suggestions into "worth fixing", "install-time decision" and "not relevant here", and to document why.
- **Automation:** an idempotent script overwrites config instead of appending, validates before applying and fails early. I tested it by running it twice and by checking the failure path on a clean VM.

## Limitations

- Lab-grade baseline, not a compliance standard (CIS or STIG). It targets a single standalone server.
- Password policy changes in `login.defs` apply to new accounts only.
- No central logging or monitoring yet.

## Next steps

- Port the script to an **Ansible role** and keep the Bash version as a reference
- Add a Python script that verifies the server state after deployment
- Add a CI pipeline (ShellCheck, `ansible-lint`)
- Build on this for a small self-hosted infrastructure project (Gitea, reverse proxy, backups, monitoring)

## How I used AI

I used an AI assistant (Claude) as a **mentor and reviewer**, not as a replacement for doing the work. Specifically:

- **Planning:** helped me break the project into steps and decide on the order of work.
- **Explaining:** explained what individual settings do (for example `rp_filter`, `kptr_restrict`, `unattended-upgrades`) so I could describe them in my own words.
- **Troubleshooting:** helped me diagnose problems from the error output I pasted (*Connection refused*, `scp` syntax, port forwarding after restoring a snapshot, fail2ban hanging connections).
- **Reviewing:** went through my Lynis output with me to separate worthwhile fixes from changes that don't suit this setup.
- **Scripting:** the first draft of `harden.sh` was written with AI assistance, based on the steps I had already done manually. I then read through it, ran it through ShellCheck, tested it on a clean VM (including the lockout guard and a second run), and verified the result with Lynis.
- **Documentation:** Generating this nice README.


## This repository was documented after building the lab

#!/usr/bin/env bash
# harden.sh - zakladny hardening Ubuntu Servera
# Pouzitie: sudo ./harden.sh <admin_pouzivatel>
set -euo pipefail

ADMIN_USER="${1:-}"
ALLOW_TCP_FORWARDING="no"   # nastavte "yes", ak pouzivate VS Code Remote-SSH

log() { printf '[%s] %s\n' "$(date +%H:%M:%S)" "$*"; }
die() { printf 'CHYBA: %s\n' "$*" >&2; exit 1; }

set_login_def() {
  local key="$1" value="$2" file=/etc/login.defs
  if grep -qE "^${key}[[:space:]]" "$file"; then
    sed -i -E "s/^${key}[[:space:]].*/${key} ${value}/" "$file"
  else
    echo "${key} ${value}" >> "$file"
  fi
}

# --- Kontroly pred spustenim ---
[[ $EUID -eq 0 ]] || die "Spustite ako root (sudo)."
[[ -n "$ADMIN_USER" ]] || die "Pouzitie: sudo $0 <admin_pouzivatel>"
id "$ADMIN_USER" &>/dev/null || die "Pouzivatel $ADMIN_USER neexistuje."
[[ -s "/home/${ADMIN_USER}/.ssh/authorized_keys" ]] \
  || die "Pouzivatel $ADMIN_USER nema SSH kluc. Najprv ho nahrajte (ssh-copy-id), inak sa zamknete."

# --- Balicky ---
log "Instalujem balicky"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq ufw fail2ban unattended-upgrades lynis \
  libpam-tmpdir libpam-pwquality apt-listchanges debsums apt-show-versions

# --- SSH ---
log "Nastavujem SSH"
cat > /etc/ssh/sshd_config.d/01-hardening.conf <<EOF
PermitRootLogin no
PasswordAuthentication no
PubkeyAuthentication yes
MaxAuthTries 3
X11Forwarding no
AllowTcpForwarding ${ALLOW_TCP_FORWARDING}
AllowAgentForwarding no
LogLevel VERBOSE
MaxSessions 2
ClientAliveInterval 300
ClientAliveCountMax 2
TCPKeepAlive no
EOF
sshd -t || die "Neplatna konfiguracia SSH, nerestartujem."
systemctl restart ssh

# --- Firewall ---
log "Nastavujem firewall"
ufw default deny incoming
ufw default allow outgoing
ufw allow 22/tcp comment 'SSH'
ufw --force enable

# --- fail2ban ---
log "Nastavujem fail2ban"
cat > /etc/fail2ban/jail.local <<'EOF'
[DEFAULT]
bantime = 1h
findtime = 10m
maxretry = 5

[sshd]
enabled = true
port = ssh
EOF
systemctl enable --now fail2ban
systemctl restart fail2ban

# --- Automaticke aktualizacie ---
log "Zapinam automaticke bezpecnostne aktualizacie"
cat > /etc/apt/apt.conf.d/20auto-upgrades <<'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
EOF

# --- sysctl ---
log "Nastavujem parametre jadra"
cat > /etc/sysctl.d/99-hardening.conf <<'EOF'
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.tcp_syncookies = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
kernel.dmesg_restrict = 1
kernel.kptr_restrict = 2
fs.suid_dumpable = 0
EOF
sysctl --system >/dev/null

# --- Nepouzivane moduly ---
log "Blokujem nepouzivane moduly jadra"
cat > /etc/modprobe.d/hardening-blacklist.conf <<'EOF'
install dccp /bin/true
install sctp /bin/true
install rds /bin/true
install tipc /bin/true
install usb-storage /bin/true
EOF

# --- Politika hesiel pre nove ucty ---
log "Nastavujem login.defs"
set_login_def UMASK 027
set_login_def PASS_MAX_DAYS 365
set_login_def PASS_MIN_DAYS 1

log "Hotovo. Odporucam restart (moduly jadra) a kontrolu: sudo lynis audit system"

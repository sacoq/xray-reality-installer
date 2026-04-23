#!/usr/bin/env bash
# xray-reality-installer
# One-shot installer for Xray-core with VLESS + Reality (xtls-rprx-vision)
# on Ubuntu 24.04. Tunes the server for VPN workloads and prints a ready
# vless:// link using a user-supplied domain (or server IP as fallback).

set -Eeuo pipefail

# ---------- constants ----------
readonly XRAY_CONFIG_DIR="/usr/local/etc/xray"
readonly XRAY_CONFIG="${XRAY_CONFIG_DIR}/config.json"
readonly XRAY_CREDENTIALS="${XRAY_CONFIG_DIR}/credentials.env"
readonly XRAY_BIN="/usr/local/bin/xray"
readonly SYSCTL_FILE="/etc/sysctl.d/99-xray-vpn.conf"
readonly LIMITS_FILE="/etc/security/limits.d/99-xray.conf"
readonly SERVICE_OVERRIDE_DIR="/etc/systemd/system/xray.service.d"
readonly ZRAM_CONF="/etc/systemd/zram-generator.conf"
readonly SWAPFILE="/swapfile"
readonly JOURNALD_DROPIN="/etc/systemd/journald.conf.d/99-xray.conf"
readonly DEFAULT_PORT=443
readonly DEFAULT_SNI="rutube.ru"
readonly DEFAULT_DEST="rutube.ru:443"
readonly DEFAULT_EMAIL="user1"
readonly DEFAULT_LABEL="xray-reality"
readonly DEFAULT_PROFILE="auto"
# xray-panel (self-written)
readonly PANEL_ROOT="/opt/xray-panel"
readonly PANEL_VENV="${PANEL_ROOT}/venv"
readonly PANEL_CODE="${PANEL_ROOT}/panel"
readonly PANEL_ENV="/etc/xray-panel/panel.env"
readonly PANEL_DB_DIR="/var/lib/xray-panel"
readonly PANEL_DB="${PANEL_DB_DIR}/panel.db"
readonly PANEL_SERVICE="/etc/systemd/system/xray-panel.service"
readonly AGENT_ROOT="/opt/xray-agent"
readonly AGENT_VENV="${AGENT_ROOT}/venv"
readonly AGENT_CODE="${AGENT_ROOT}/agent"
readonly AGENT_ENV="/etc/xray-agent/agent.env"
readonly AGENT_SERVICE="/etc/systemd/system/xray-agent.service"
readonly DEFAULT_PANEL_PORT=8443
readonly DEFAULT_AGENT_PORT=8765

# ---------- output helpers ----------
if [[ -t 1 ]]; then
    C_RESET=$'\033[0m'
    C_RED=$'\033[31m'
    C_GREEN=$'\033[32m'
    C_YELLOW=$'\033[33m'
    C_BLUE=$'\033[34m'
    C_BOLD=$'\033[1m'
else
    C_RESET=""; C_RED=""; C_GREEN=""; C_YELLOW=""; C_BLUE=""; C_BOLD=""
fi

log()  { printf '%s[*]%s %s\n' "${C_BLUE}"  "${C_RESET}" "$*"; }
ok()   { printf '%s[+]%s %s\n' "${C_GREEN}" "${C_RESET}" "$*"; }
warn() { printf '%s[!]%s %s\n' "${C_YELLOW}" "${C_RESET}" "$*" >&2; }
die()  { printf '%s[x]%s %s\n' "${C_RED}"   "${C_RESET}" "$*" >&2; exit 1; }

trap 'die "failed at line ${LINENO}"' ERR

# ---------- arg parsing ----------
DOMAIN=""
PORT="${DEFAULT_PORT}"
SNI="${DEFAULT_SNI}"
DEST="${DEFAULT_DEST}"
EMAIL="${DEFAULT_EMAIL}"
LABEL="${DEFAULT_LABEL}"
PROFILE="${DEFAULT_PROFILE}"
NON_INTERACTIVE=0
SKIP_TUNING=0
SKIP_SWAP=0
SKIP_BLOAT=0
# Panel-mode vars
PANEL=0
PANEL_PORT="${DEFAULT_PANEL_PORT}"
PANEL_USER=""
PANEL_PASS=""
PANEL_PUBLIC=0
AGENT_PORT="${DEFAULT_AGENT_PORT}"
# Node-only mode: register a remote xray box with an existing panel
NODE_ONLY=0
NODE_AGENT_TOKEN=""
NODE_AGENT_BIND="127.0.0.1"
# Node enrollment mode: auto-register with a panel using a one-time token
NODE_ENROLL=0
PANEL_URL=""
ENROLL_TOKEN=""

usage() {
    cat <<EOF
Usage: sudo bash install.sh [options]

Options:
  --domain <fqdn>     Domain/host used in the vless:// link (prompted if omitted)
  --port <n>          VLESS listen port (default: ${DEFAULT_PORT})
  --sni <host>        Reality serverName / SNI (default: ${DEFAULT_SNI})
  --dest <host:port>  Reality dest (default: ${DEFAULT_DEST})
  --email <label>     Client email label (default: ${DEFAULT_EMAIL})
  --label <name>      vless:// fragment (#name) (default: ${DEFAULT_LABEL})
  --profile <name>    Tuning profile: auto (default), low-ram, default, high-perf
                      auto picks low-ram if RAM<1.5GB, high-perf if RAM>=6GB
  --yes               Non-interactive; fail if --domain is missing
  --skip-tuning       Do not touch sysctl / limits / systemd overrides
  --skip-swap         Do not set up swap (zram / swapfile)
  --skip-bloat        Do not disable snapd / multipathd / ModemManager / apport

Panel (self-written, multi-server) — enable with --panel:
  --panel             Install the xray-panel web UI + local agent alongside xray.
                      Creates the first VLESS+Reality key with the supplied domain.
  --panel-port <n>    Panel listen port (default: ${DEFAULT_PANEL_PORT})
  --panel-user <str>  Panel admin username (default: 'admin')
  --panel-pass <str>  Panel admin password (default: random 24 chars, printed once)
  --panel-public      Open panel port in ufw (default: only via SSH tunnel)
  --agent-port <n>    Local agent listen port (default: ${DEFAULT_AGENT_PORT}, bound to 127.0.0.1)

Node mode — register this box with a remote panel (run on the new xray server):
  --node-only         Install xray + agent only, no panel. Paste the printed
                      agent URL/token into the panel's «Add server» form.
  --agent-token <s>   Shared token the panel will use to authenticate with the agent.
                      Required with --node-only. Generate one on the panel side
                      and paste it here (the panel stores it when you add the server).
  --agent-bind <ip>   Bind agent to this address (default: 127.0.0.1).
                      Use 0.0.0.0 to expose over LAN/Internet (then restrict via firewall).

Node enrollment — fully automated registration against an existing panel:
  --node-enroll       Install xray + agent AND auto-register this node with the panel.
                      No manual copy-paste of tokens or agent URLs — everything flows
                      through the one-time enrollment token issued by the panel.
  --panel-url <url>   Panel base URL, e.g. https://panel.example.com (required with --node-enroll).
  --enroll-token <s>  One-time enrollment token from the panel (required with --node-enroll).

  -h, --help          Show this help

Example:
  sudo bash install.sh --domain vpn.example.com
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --domain)       DOMAIN="${2:?}"; shift 2 ;;
        --port)         PORT="${2:?}"; shift 2 ;;
        --sni)          SNI="${2:?}"; shift 2 ;;
        --dest)         DEST="${2:?}"; shift 2 ;;
        --email)        EMAIL="${2:?}"; shift 2 ;;
        --label)        LABEL="${2:?}"; shift 2 ;;
        --profile)      PROFILE="${2:?}"; shift 2 ;;
        --yes)          NON_INTERACTIVE=1; shift ;;
        --skip-tuning)  SKIP_TUNING=1; shift ;;
        --skip-swap)    SKIP_SWAP=1; shift ;;
        --skip-bloat)   SKIP_BLOAT=1; shift ;;
        --panel)        PANEL=1; shift ;;
        --panel-port)   PANEL_PORT="${2:?}"; shift 2 ;;
        --panel-user)   PANEL_USER="${2:?}"; shift 2 ;;
        --panel-pass)   PANEL_PASS="${2:?}"; shift 2 ;;
        --panel-public) PANEL_PUBLIC=1; shift ;;
        --agent-port)   AGENT_PORT="${2:?}"; shift 2 ;;
        --node-only)    NODE_ONLY=1; shift ;;
        --agent-token)  NODE_AGENT_TOKEN="${2:?}"; shift 2 ;;
        --agent-bind)   NODE_AGENT_BIND="${2:?}"; shift 2 ;;
        --node-enroll)  NODE_ENROLL=1; shift ;;
        --panel-url)    PANEL_URL="${2:?}"; shift 2 ;;
        --enroll-token) ENROLL_TOKEN="${2:?}"; shift 2 ;;
        -h|--help)      usage; exit 0 ;;
        *)              die "unknown argument: $1 (see --help)" ;;
    esac
done

case "$PROFILE" in
    auto|low-ram|default|high-perf) ;;
    *) die "invalid --profile '$PROFILE' (expected: auto|low-ram|default|high-perf)" ;;
esac

# ---------- preconditions ----------
require_root() {
    if [[ $EUID -ne 0 ]]; then
        die "this script must run as root (use sudo)"
    fi
}

require_ubuntu() {
    if [[ -r /etc/os-release ]]; then
        # shellcheck disable=SC1091
        . /etc/os-release
        if [[ "${ID:-}" != "ubuntu" ]]; then
            warn "detected OS '${ID:-unknown}', tested only on Ubuntu 24.04 — continuing anyway"
        fi
    fi
}

# ---------- input ----------
prompt_domain() {
    if [[ -n "$DOMAIN" ]]; then
        return
    fi
    if [[ "$NON_INTERACTIVE" -eq 1 ]]; then
        die "--domain is required in non-interactive mode"
    fi
    local input=""
    while [[ -z "$input" ]]; do
        if [[ -r /dev/tty ]]; then
            printf '%sEnter the domain that will appear in the VLESS link (e.g. vpn.example.com):%s ' \
                "${C_BOLD}" "${C_RESET}" > /dev/tty
            IFS= read -r input < /dev/tty || input=""
        else
            die "--domain not provided and no TTY available for prompt"
        fi
        input="${input//[[:space:]]/}"
        if [[ -z "$input" ]]; then
            warn "domain cannot be empty"
        fi
    done
    DOMAIN="$input"
}

detect_public_ip() {
    local ip=""
    for url in https://api.ipify.org https://ifconfig.me https://icanhazip.com; do
        if ip="$(curl -fsS --max-time 5 "$url" 2>/dev/null)"; then
            ip="${ip//[[:space:]]/}"
            if [[ -n "$ip" ]]; then
                printf '%s' "$ip"
                return 0
            fi
        fi
    done
    return 1
}

check_domain_dns() {
    local domain="$1"
    local server_ip
    if ! server_ip="$(detect_public_ip)"; then
        warn "could not determine server public IP; skipping DNS check"
        return 0
    fi
    local resolved=""
    if command -v getent >/dev/null 2>&1; then
        resolved="$(getent ahostsv4 "$domain" 2>/dev/null | awk 'NR==1{print $1}')"
    fi
    if [[ -z "$resolved" ]] && command -v dig >/dev/null 2>&1; then
        resolved="$(dig +short A "$domain" | head -n1)"
    fi
    if [[ -z "$resolved" ]]; then
        warn "could not resolve $domain; make sure its A record points to $server_ip"
        return 0
    fi
    if [[ "$resolved" != "$server_ip" ]]; then
        warn "domain $domain resolves to $resolved but this server's IP is $server_ip"
        warn "the link will still be generated, but clients must be able to reach $domain on port $PORT"
    else
        ok "DNS check passed: $domain -> $resolved"
    fi
}

# ---------- profile detection ----------
# Sets PROFILE (if auto) and exports tuning variables based on profile + RAM.
detect_profile() {
    local mem_kb mem_mb
    mem_kb="$(awk '/^MemTotal:/ {print $2}' /proc/meminfo 2>/dev/null || echo 0)"
    mem_mb=$(( mem_kb / 1024 ))
    RAM_MB="$mem_mb"

    if [[ "$PROFILE" == "auto" ]]; then
        if   (( mem_mb <  1536 )); then PROFILE="low-ram"
        elif (( mem_mb >= 6144 )); then PROFILE="high-perf"
        else                             PROFILE="default"
        fi
        log "profile auto-detected: ${PROFILE} (RAM=${mem_mb} MiB)"
    else
        log "profile forced: ${PROFILE} (RAM=${mem_mb} MiB)"
    fi

    case "$PROFILE" in
        low-ram)
            TUNE_RMEM_MAX=16777216
            TUNE_WMEM_MAX=16777216
            TUNE_TCP_RMEM="4096 87380 16777216"
            TUNE_TCP_WMEM="4096 65536 16777216"
            TUNE_SOMAXCONN=8192
            TUNE_NETDEV_BACKLOG=8192
            TUNE_SYN_BACKLOG=2048
            TUNE_CONNTRACK_MAX=131072
            TUNE_NOFILE=65536
            TUNE_SWAPPINESS=10
            TUNE_ZRAM_RATIO=100    # zram = 100% of RAM (compresses ~3x with zstd)
            TUNE_SWAPFILE_MB=1024
            ;;
        default)
            TUNE_RMEM_MAX=33554432
            TUNE_WMEM_MAX=33554432
            TUNE_TCP_RMEM="4096 87380 33554432"
            TUNE_TCP_WMEM="4096 65536 33554432"
            TUNE_SOMAXCONN=32768
            TUNE_NETDEV_BACKLOG=16384
            TUNE_SYN_BACKLOG=4096
            TUNE_CONNTRACK_MAX=524288
            TUNE_NOFILE=524288
            TUNE_SWAPPINESS=20
            TUNE_ZRAM_RATIO=50
            TUNE_SWAPFILE_MB=2048
            ;;
        high-perf)
            TUNE_RMEM_MAX=67108864
            TUNE_WMEM_MAX=67108864
            TUNE_TCP_RMEM="4096 87380 67108864"
            TUNE_TCP_WMEM="4096 65536 67108864"
            TUNE_SOMAXCONN=65535
            TUNE_NETDEV_BACKLOG=32768
            TUNE_SYN_BACKLOG=8192
            TUNE_CONNTRACK_MAX=1048576
            TUNE_NOFILE=1048576
            TUNE_SWAPPINESS=30
            TUNE_ZRAM_RATIO=25
            TUNE_SWAPFILE_MB=4096
            ;;
    esac
}

# ---------- packages ----------
install_packages() {
    log "updating apt and installing prerequisites"
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -y
    # qrencode is tiny and gives us terminal QR; systemd-zram-generator handles zram.
    apt-get install -y --no-install-recommends \
        ca-certificates curl jq unzip dnsutils openssl iproute2 \
        systemd ufw qrencode systemd-zram-generator
}

install_xray() {
    log "installing xray-core via official installer"
    # Official install script (https://github.com/XTLS/Xray-install)
    local tmp
    tmp="$(mktemp)"
    curl -fsSL https://github.com/XTLS/Xray-install/raw/main/install-release.sh -o "$tmp"
    bash "$tmp" install
    rm -f "$tmp"
    if [[ ! -x "$XRAY_BIN" ]]; then
        die "xray binary not found at $XRAY_BIN after install"
    fi
    ok "xray installed: $("$XRAY_BIN" version | head -n1)"
}

# ---------- tuning ----------
apply_tuning() {
    if [[ "$SKIP_TUNING" -eq 1 ]]; then
        warn "skipping server tuning (--skip-tuning)"
        return
    fi
    log "applying VPN-oriented sysctl + limits tuning (profile=${PROFILE})"

    cat > "$SYSCTL_FILE" <<EOF
# Managed by xray-reality-installer (profile=${PROFILE}, RAM=${RAM_MB} MiB)
# Congestion control
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr

# Forwarding (needed if xray ever routes other traffic)
net.ipv4.ip_forward = 1

# TCP Fast Open (client+server)
net.ipv4.tcp_fastopen = 3

# Socket buffers (scaled to profile)
net.core.rmem_max = ${TUNE_RMEM_MAX}
net.core.wmem_max = ${TUNE_WMEM_MAX}
net.core.rmem_default = 262144
net.core.wmem_default = 262144
net.core.netdev_max_backlog = ${TUNE_NETDEV_BACKLOG}
net.core.somaxconn = ${TUNE_SOMAXCONN}
net.ipv4.tcp_rmem = ${TUNE_TCP_RMEM}
net.ipv4.tcp_wmem = ${TUNE_TCP_WMEM}

# Connection tracking
net.netfilter.nf_conntrack_max = ${TUNE_CONNTRACK_MAX}
net.nf_conntrack_max = ${TUNE_CONNTRACK_MAX}

# TCP behaviour
net.ipv4.tcp_mtu_probing = 1
net.ipv4.tcp_fin_timeout = 15
net.ipv4.tcp_keepalive_time = 60
net.ipv4.tcp_keepalive_intvl = 10
net.ipv4.tcp_keepalive_probes = 6
net.ipv4.tcp_max_syn_backlog = ${TUNE_SYN_BACKLOG}
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.tcp_notsent_lowat = 16384

# IPv6 forwarding (harmless if IPv6 is disabled)
net.ipv6.conf.all.forwarding = 1

# Memory behaviour (critical on low-RAM VPS)
vm.swappiness = ${TUNE_SWAPPINESS}
vm.vfs_cache_pressure = 50
vm.overcommit_memory = 1
vm.min_free_kbytes = 16384
vm.dirty_ratio = 10
vm.dirty_background_ratio = 5
EOF

    # nf_conntrack module may not be loaded on a fresh VM; load it so the
    # conntrack sysctl doesn't cause a warning on apply.
    modprobe nf_conntrack 2>/dev/null || true
    if ! grep -qx 'nf_conntrack' /etc/modules-load.d/nf_conntrack.conf 2>/dev/null; then
        echo 'nf_conntrack' > /etc/modules-load.d/nf_conntrack.conf
    fi

    sysctl --system >/dev/null

    cat > "$LIMITS_FILE" <<EOF
# Managed by xray-reality-installer (profile=${PROFILE})
*       soft    nofile  ${TUNE_NOFILE}
*       hard    nofile  ${TUNE_NOFILE}
root    soft    nofile  ${TUNE_NOFILE}
root    hard    nofile  ${TUNE_NOFILE}
EOF

    mkdir -p "$SERVICE_OVERRIDE_DIR"
    cat > "$SERVICE_OVERRIDE_DIR/override.conf" <<EOF
[Service]
LimitNOFILE=${TUNE_NOFILE}
LimitNPROC=${TUNE_NOFILE}
# Make xray the LAST thing the kernel OOM-killer considers.
OOMScoreAdjust=-500
# Reduce footprint on small VPS.
MemoryDenyWriteExecute=true
Restart=on-failure
RestartSec=2s
EOF

    systemctl daemon-reload
    ok "tuning applied (${SYSCTL_FILE}, ${LIMITS_FILE}, systemd override)"
}

# ---------- swap ----------
# Prefer zram (compressed RAM swap) via systemd-zram-generator; fall back to a
# regular swapfile on disk if zram is unavailable. Safe to re-run.
setup_swap() {
    if [[ "$SKIP_SWAP" -eq 1 ]]; then
        warn "skipping swap setup (--skip-swap)"
        return
    fi

    # If the host already has meaningful swap, don't touch it.
    local current_swap_kb
    current_swap_kb="$(awk '/^SwapTotal:/ {print $2}' /proc/meminfo 2>/dev/null || echo 0)"
    if (( current_swap_kb > 262144 )); then  # >256 MiB already present
        ok "swap already present ($(( current_swap_kb / 1024 )) MiB); leaving alone"
        return
    fi

    if modprobe zram 2>/dev/null && [[ -e /sys/class/zram-control ]] \
        && systemctl list-unit-files 2>/dev/null | grep -q '^systemd-zram-setup@'; then
        log "configuring zram swap (ratio=${TUNE_ZRAM_RATIO}%, zstd)"
        mkdir -p "$(dirname "$ZRAM_CONF")"
        cat > "$ZRAM_CONF" <<EOF
# Managed by xray-reality-installer
[zram0]
zram-size = min(ram * ${TUNE_ZRAM_RATIO} / 100, 4096)
compression-algorithm = zstd
swap-priority = 100
fs-type = swap
EOF
        systemctl daemon-reload
        # The generator creates systemd-zram-setup@zram0.service at boot. Start
        # it now so swap is active without a reboot.
        if systemctl start systemd-zram-setup@zram0.service 2>/dev/null; then
            ok "zram swap active: $(swapon --show=NAME,SIZE,PRIO --noheadings | tr -s ' ' | head -n1)"
            return
        else
            warn "systemd-zram-setup@zram0 failed to start; falling back to swapfile"
        fi
    else
        warn "zram unavailable; falling back to disk swapfile"
    fi

    if [[ -f "$SWAPFILE" ]] && swapon --show=NAME --noheadings | grep -qx "$SWAPFILE"; then
        ok "swapfile already active at $SWAPFILE"
        return
    fi

    log "creating ${TUNE_SWAPFILE_MB} MiB swapfile at $SWAPFILE"
    # Prefer fallocate; fall back to dd on filesystems that don't support it (XFS on some images).
    if ! fallocate -l "${TUNE_SWAPFILE_MB}M" "$SWAPFILE" 2>/dev/null; then
        dd if=/dev/zero of="$SWAPFILE" bs=1M count="$TUNE_SWAPFILE_MB" status=none
    fi
    chmod 600 "$SWAPFILE"
    mkswap "$SWAPFILE" >/dev/null
    swapon "$SWAPFILE"
    if ! grep -qE "^${SWAPFILE}[[:space:]]" /etc/fstab; then
        printf '%s none swap sw 0 0\n' "$SWAPFILE" >> /etc/fstab
    fi
    ok "disk swapfile active: ${SWAPFILE} (${TUNE_SWAPFILE_MB} MiB)"
}

# ---------- bloat removal ----------
# Stop+disable services that waste RAM/CPU on a single-purpose VPN box.
# All operations are idempotent and silently skip missing units.
disable_bloat() {
    if [[ "$SKIP_BLOAT" -eq 1 ]]; then
        warn "skipping bloat removal (--skip-bloat)"
        return
    fi
    log "disabling unused services to free RAM"

    local unit
    for unit in \
        snapd.service snapd.socket snapd.seeded.service \
        multipathd.service multipathd.socket \
        ModemManager.service \
        apport.service \
        motd-news.service motd-news.timer \
        unattended-upgrades.service; do
        # Keep unattended-upgrades if it's currently installed and in use — we
        # disable only its aggressive on-boot reload, not security updates.
        if [[ "$unit" == "unattended-upgrades.service" ]]; then continue; fi
        if systemctl list-unit-files "$unit" >/dev/null 2>&1; then
            systemctl disable --now "$unit" 2>/dev/null || true
        fi
    done

    # Mask snapd entirely on low-ram so it cannot be reinstalled by apt deps.
    if [[ "$PROFILE" == "low-ram" ]] && systemctl list-unit-files snapd.service >/dev/null 2>&1; then
        systemctl mask snapd.service snapd.socket snapd.seeded.service 2>/dev/null || true
    fi

    ok "bloat services stopped/disabled"
}

# ---------- journald ----------
cap_journald() {
    if [[ "$SKIP_TUNING" -eq 1 ]]; then
        return
    fi
    log "capping journald disk usage to 100M"
    mkdir -p "$(dirname "$JOURNALD_DROPIN")"
    cat > "$JOURNALD_DROPIN" <<'EOF'
# Managed by xray-reality-installer
[Journal]
SystemMaxUse=100M
SystemMaxFileSize=20M
RuntimeMaxUse=50M
Compress=yes
ForwardToSyslog=no
EOF
    systemctl restart systemd-journald 2>/dev/null || true
}

# ---------- firewall ----------
configure_firewall() {
    if ! command -v ufw >/dev/null 2>&1; then
        return
    fi
    if ! ufw status | grep -q "Status: active"; then
        # Only touch ufw if the user already uses it; do not force-enable a
        # firewall on a fresh box (might lock them out of SSH on a race).
        return
    fi
    log "opening port $PORT/tcp in ufw"
    ufw allow "${PORT}/tcp" >/dev/null || warn "ufw allow ${PORT}/tcp failed (continuing)"
}

# ---------- credential generation ----------
gen_credentials() {
    log "generating UUID, x25519 keypair and shortId"
    mkdir -p "$XRAY_CONFIG_DIR"

    UUID="$("$XRAY_BIN" uuid)"
    local keys
    keys="$("$XRAY_BIN" x25519)"
    PRIVATE_KEY="$(awk -F': *' '/Private/ {print $2}' <<<"$keys")"
    PUBLIC_KEY="$(awk -F': *' '/Public/  {print $2}' <<<"$keys")"
    SHORT_ID="$(openssl rand -hex 4)"

    if [[ -z "$UUID" || -z "$PRIVATE_KEY" || -z "$PUBLIC_KEY" || -z "$SHORT_ID" ]]; then
        die "failed to generate one of UUID / keypair / shortId"
    fi

    umask 077
    cat > "$XRAY_CREDENTIALS" <<EOF
# Managed by xray-reality-installer — keep this file private
UUID=${UUID}
PRIVATE_KEY=${PRIVATE_KEY}
PUBLIC_KEY=${PUBLIC_KEY}
SHORT_ID=${SHORT_ID}
DOMAIN=${DOMAIN}
PORT=${PORT}
SNI=${SNI}
DEST=${DEST}
EMAIL=${EMAIL}
LABEL=${LABEL}
EOF
    chmod 600 "$XRAY_CREDENTIALS"
}

# ---------- config ----------
write_config() {
    log "writing ${XRAY_CONFIG}"
    umask 022
    mkdir -p "$XRAY_CONFIG_DIR"

    # Build JSON with jq so quoting is always correct.
    jq -n \
        --arg uuid       "$UUID" \
        --arg email      "$EMAIL" \
        --arg dest       "$DEST" \
        --arg sni        "$SNI" \
        --arg privateKey "$PRIVATE_KEY" \
        --arg shortId    "$SHORT_ID" \
        --argjson port   "$PORT" \
        '{
          log: { loglevel: "warning" },
          inbounds: [
            {
              listen: "0.0.0.0",
              port: $port,
              protocol: "vless",
              settings: {
                clients: [
                  { id: $uuid, flow: "xtls-rprx-vision", email: $email }
                ],
                decryption: "none"
              },
              streamSettings: {
                network: "tcp",
                tcpSettings: {
                  keepAliveInterval: 30,
                  keepAliveIdle: 60,
                  header: { type: "none" }
                },
                sockopt: {
                  tcpFastOpen: true,
                  tcpKeepAlive: true
                },
                security: "reality",
                realitySettings: {
                  show: false,
                  dest: $dest,
                  xver: 0,
                  serverNames: [ $sni ],
                  privateKey: $privateKey,
                  shortIds: [ $shortId ]
                }
              }
            }
          ],
          outbounds: [
            { protocol: "freedom", tag: "direct" }
          ]
        }' > "$XRAY_CONFIG"

    if ! "$XRAY_BIN" -test -config "$XRAY_CONFIG" >/dev/null; then
        die "xray -test reported an invalid config"
    fi
    ok "config written and validated"
}

# ---------- service ----------
start_service() {
    log "enabling and starting xray.service"
    systemctl enable xray >/dev/null 2>&1 || true
    systemctl restart xray
    sleep 1
    if ! systemctl is-active --quiet xray; then
        journalctl -u xray --no-pager -n 50 || true
        die "xray failed to start"
    fi
    ok "xray is running"
}

# ---------- output ----------
urlencode() {
    local s="$1" i c out=""
    for (( i=0; i<${#s}; i++ )); do
        c="${s:$i:1}"
        case "$c" in
            [a-zA-Z0-9.~_-]) out+="$c" ;;
            *) out+=$(printf '%%%02X' "'$c") ;;
        esac
    done
    printf '%s' "$out"
}

print_summary() {
    local host="$DOMAIN"
    local encoded_label
    encoded_label="$(urlencode "$LABEL")"
    local url="vless://${UUID}@${host}:${PORT}?security=reality&encryption=none&pbk=${PUBLIC_KEY}&fp=chrome&type=tcp&flow=xtls-rprx-vision&sni=${SNI}&sid=${SHORT_ID}#${encoded_label}"

    echo
    printf '%s==================== VLESS / Reality ====================%s\n' "${C_BOLD}" "${C_RESET}"
    printf '  host         : %s\n' "$host"
    printf '  port         : %s\n' "$PORT"
    printf '  uuid         : %s\n' "$UUID"
    printf '  flow         : xtls-rprx-vision\n'
    printf '  security     : reality\n'
    printf '  sni          : %s\n' "$SNI"
    printf '  dest         : %s\n' "$DEST"
    printf '  public key   : %s\n' "$PUBLIC_KEY"
    printf '  short id     : %s\n' "$SHORT_ID"
    printf '  profile      : %s (RAM=%s MiB)\n' "$PROFILE" "${RAM_MB:-?}"
    printf '  config       : %s\n' "$XRAY_CONFIG"
    printf '  credentials  : %s\n' "$XRAY_CREDENTIALS"
    echo
    printf '%sVLESS link:%s\n%s\n' "${C_BOLD}" "${C_RESET}" "$url"
    echo
    printf '%sQR (scan in Happ / v2rayNG / Streisand):%s\n' "${C_BOLD}" "${C_RESET}"
    if command -v qrencode >/dev/null 2>&1; then
        qrencode -t ANSIUTF8 "$url"
    else
        # shellcheck disable=SC2016  # backticks are intentional literal chars
        printf '  (install `qrencode` to render a QR in the terminal)\n'
    fi
    printf '%s=========================================================%s\n' "${C_BOLD}" "${C_RESET}"
}

# ---------- random helpers ----------
gen_random() {
    # $1 = length (alphanumeric)
    openssl rand -base64 $(( ${1:-16} * 2 )) | tr -dc 'a-zA-Z0-9' | head -c "${1:-16}"
}

gen_random_hex() {
    openssl rand -hex $(( (${1:-18} + 1) / 2 )) | head -c "${1:-18}"
}

# ---------- xray-panel (self-written) ----------
install_python() {
    log "installing Python 3 + venv prerequisites"
    export DEBIAN_FRONTEND=noninteractive
    apt-get install -y --no-install-recommends python3 python3-venv python3-pip
}

install_agent() {
    log "installing xray-panel agent (${AGENT_ROOT})"
    install -d -m 0755 "$AGENT_ROOT" "$(dirname "$AGENT_ENV")"
    rm -rf "$AGENT_CODE"
    cp -r "${SCRIPT_DIR}/agent" "$AGENT_ROOT/agent"

    if [[ ! -d "$AGENT_VENV" ]]; then
        python3 -m venv "$AGENT_VENV"
    fi
    "$AGENT_VENV/bin/pip" install --quiet --upgrade pip
    "$AGENT_VENV/bin/pip" install --quiet -r "${AGENT_CODE}/requirements.txt"

    # Generate / preserve agent token.
    local token=""
    if [[ -r "$AGENT_ENV" ]]; then
        token="$(grep -Po '^AGENT_TOKEN=\K.*' "$AGENT_ENV" 2>/dev/null || true)"
    fi
    if [[ -n "$NODE_AGENT_TOKEN" ]]; then
        token="$NODE_AGENT_TOKEN"
    fi
    if [[ -z "$token" ]]; then
        token="$(gen_random 40)"
    fi
    AGENT_TOKEN_VALUE="$token"

    umask 077
    cat > "$AGENT_ENV" <<EOF
# Managed by xray-reality-installer — keep private
AGENT_TOKEN=${token}
AGENT_BIND=${NODE_AGENT_BIND}
AGENT_PORT=${AGENT_PORT}
XRAY_BIN=${XRAY_BIN}
XRAY_CONFIG=${XRAY_CONFIG}
XRAY_SERVICE=xray
XRAY_API_ADDR=127.0.0.1:10085
EOF
    chmod 600 "$AGENT_ENV"

    cat > "$AGENT_SERVICE" <<EOF
[Unit]
Description=xray-panel node agent
After=network-online.target xray.service
Wants=network-online.target

[Service]
Type=simple
EnvironmentFile=${AGENT_ENV}
WorkingDirectory=${AGENT_ROOT}
ExecStart=${AGENT_VENV}/bin/uvicorn agent.agent:app --host \${AGENT_BIND} --port \${AGENT_PORT}
Restart=on-failure
RestartSec=3
# Agent needs to edit /usr/local/etc/xray and systemctl restart xray, run as root.
User=root

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable xray-agent >/dev/null 2>&1 || true
    systemctl restart xray-agent
    sleep 1
    if ! systemctl is-active --quiet xray-agent; then
        journalctl -u xray-agent --no-pager -n 50 || true
        die "xray-agent failed to start"
    fi
    ok "xray-agent is running (bind=${NODE_AGENT_BIND}:${AGENT_PORT})"
}

install_panel() {
    log "installing xray-panel (${PANEL_ROOT})"
    install -d -m 0755 "$PANEL_ROOT" "$(dirname "$PANEL_ENV")" "$PANEL_DB_DIR"
    rm -rf "$PANEL_CODE"
    cp -r "${SCRIPT_DIR}/panel" "$PANEL_ROOT/panel"

    if [[ ! -d "$PANEL_VENV" ]]; then
        python3 -m venv "$PANEL_VENV"
    fi
    "$PANEL_VENV/bin/pip" install --quiet --upgrade pip
    "$PANEL_VENV/bin/pip" install --quiet -r "${PANEL_CODE}/requirements.txt"

    # Generate / preserve panel creds + secret key.
    local existing_user="" existing_hash="" existing_secret=""
    if [[ -r "$PANEL_ENV" ]]; then
        existing_user="$(grep -Po '^PANEL_USER=\K.*' "$PANEL_ENV" 2>/dev/null || true)"
        existing_hash="$(grep -Po '^PANEL_PASS_HASH=\K.*' "$PANEL_ENV" 2>/dev/null || true)"
        existing_secret="$(grep -Po '^PANEL_SECRET_KEY=\K.*' "$PANEL_ENV" 2>/dev/null || true)"
    fi
    [[ -z "$PANEL_USER" ]] && PANEL_USER="${existing_user:-admin}"
    if [[ -z "$PANEL_PASS" && -z "$existing_hash" ]]; then
        PANEL_PASS="$(gen_random 24)"
    fi
    [[ -z "$PANEL_SECRET_KEY" ]] && PANEL_SECRET_KEY="${existing_secret:-$(gen_random 48)}"

    umask 077
    {
        echo "# Managed by xray-reality-installer — keep private"
        echo "PANEL_USER=${PANEL_USER}"
        echo "PANEL_PORT=${PANEL_PORT}"
        echo "PANEL_SECRET_KEY=${PANEL_SECRET_KEY}"
        echo "PANEL_DB_PATH=${PANEL_DB}"
    } > "$PANEL_ENV"
    chmod 600 "$PANEL_ENV"

    cat > "$PANEL_SERVICE" <<EOF
[Unit]
Description=xray-panel web UI
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
EnvironmentFile=${PANEL_ENV}
WorkingDirectory=${PANEL_ROOT}
ExecStart=${PANEL_VENV}/bin/uvicorn panel.app:app --host 0.0.0.0 --port \${PANEL_PORT}
Restart=on-failure
RestartSec=3
User=root

[Install]
WantedBy=multi-user.target
EOF

    # Bootstrap the first admin + local server in the panel DB (idempotent).
    log "bootstrapping panel database"
    PANEL_USER="$PANEL_USER" \
    PANEL_PASS="$PANEL_PASS" \
    PANEL_SECRET_KEY="$PANEL_SECRET_KEY" \
    PANEL_DB_PATH="$PANEL_DB" \
    PANEL_PORT="$PANEL_PORT" \
    AGENT_PORT="$AGENT_PORT" \
    AGENT_TOKEN="$AGENT_TOKEN_VALUE" \
    DOMAIN="$DOMAIN" \
    XPORT="$PORT" \
    XSNI="$SNI" \
    XDEST="$DEST" \
    XPRIV="$PRIVATE_KEY" \
    XPUB="$PUBLIC_KEY" \
    XSHORT="$SHORT_ID" \
    XUUID="$UUID" \
    XEMAIL="$EMAIL" \
    XLABEL="$LABEL" \
    "$PANEL_VENV/bin/python" - <<'PY'
import json, os, subprocess, sys
sys.path.insert(0, "/opt/xray-panel")
from panel.database import SessionLocal, init_db
from panel.models import User, Server, Client
from panel.auth import hash_password
from panel.xray_config import build_config

init_db()
pushed_config = None
with SessionLocal() as db:
    # Admin user
    u = db.query(User).filter(User.username == os.environ["PANEL_USER"]).first()
    if u is None:
        u = User(username=os.environ["PANEL_USER"], password_hash=hash_password(os.environ["PANEL_PASS"]))
        db.add(u)
    elif os.environ.get("PANEL_PASS"):
        u.password_hash = hash_password(os.environ["PANEL_PASS"])
    db.commit()

    # Local server + first client (only if no servers exist yet)
    if db.query(Server).count() == 0:
        s = Server(
            name="local",
            agent_url=f"http://127.0.0.1:{os.environ['AGENT_PORT']}",
            agent_token=os.environ["AGENT_TOKEN"],
            public_host=os.environ["DOMAIN"],
            port=int(os.environ["XPORT"]),
            sni=os.environ["XSNI"],
            dest=os.environ["XDEST"],
            private_key=os.environ["XPRIV"],
            public_key=os.environ["XPUB"],
            short_id=os.environ["XSHORT"],
        )
        db.add(s); db.commit(); db.refresh(s)
        db.add(Client(
            server_id=s.id,
            uuid=os.environ["XUUID"],
            email=os.environ["XEMAIL"],
            label=os.environ["XLABEL"],
            flow="xtls-rprx-vision",
        ))
        db.commit()
        db.refresh(s)
        pushed_config = build_config(
            port=s.port, sni=s.sni, dest=s.dest,
            private_key=s.private_key, short_ids=[s.short_id],
            clients=[{"id": c.uuid, "email": c.email, "flow": c.flow} for c in s.clients],
        )
        print("seeded local server + first client")
    else:
        print("panel DB already has servers; skipping seed")

# Write the panel-generated config (with api/stats enabled) directly — the agent
# will pick it up on its next restart and `xray -test` will validate it via the
# `systemctl reload-or-restart` below. Note: xray infers format from the file
# extension, so the temp file MUST end in `.json` (not `.new` / `.tmp`).
if pushed_config is not None:
    cfg_path = "/usr/local/etc/xray/config.json"
    tmp = cfg_path + ".panel.new.json"
    with open(tmp, "w") as f:
        json.dump(pushed_config, f, indent=2)
    subprocess.run(["/usr/local/bin/xray", "-test", "-config", tmp], check=True)
    os.replace(tmp, cfg_path)
    subprocess.run(["systemctl", "restart", "xray"], check=False)
PY

    systemctl daemon-reload
    systemctl enable xray-panel >/dev/null 2>&1 || true
    systemctl restart xray-panel
    sleep 1
    if ! systemctl is-active --quiet xray-panel; then
        journalctl -u xray-panel --no-pager -n 50 || true
        die "xray-panel failed to start"
    fi
    ok "xray-panel is running on :${PANEL_PORT}"
}

configure_panel_firewall() {
    if ! command -v ufw >/dev/null 2>&1; then return; fi
    if ! ufw status | grep -q "Status: active"; then return; fi
    if [[ "$PANEL_PUBLIC" -eq 1 ]]; then
        log "opening panel port ${PANEL_PORT}/tcp in ufw"
        ufw allow "${PANEL_PORT}/tcp" >/dev/null || warn "ufw allow ${PANEL_PORT}/tcp failed"
    else
        warn "panel port ${PANEL_PORT}/tcp is NOT opened (use SSH tunnel; pass --panel-public to expose)"
    fi
}

print_panel_summary() {
    local host="${DOMAIN:-}"
    local ip=""
    if ip="$(detect_public_ip 2>/dev/null)"; then :; fi
    local url_host="${host:-${ip:-<SERVER_IP>}}"
    local panel_url="http://${url_host}:${PANEL_PORT}/"
    local local_url="http://localhost:${PANEL_PORT}/"

    echo
    printf '%s==================== xray-panel ==========================%s\n' "${C_BOLD}" "${C_RESET}"
    printf '  URL          : %s\n' "$panel_url"
    printf '  username     : %s\n' "$PANEL_USER"
    if [[ -n "${PANEL_PASS:-}" ]]; then
        printf '  password     : %s  %s(shown once — store it)%s\n' "$PANEL_PASS" "${C_YELLOW}" "${C_RESET}"
    else
        printf '  password     : %s(unchanged; see %s)%s\n' "${C_YELLOW}" "$PANEL_ENV" "${C_RESET}"
    fi
    printf '  port         : %s\n' "$PANEL_PORT"
    printf '  env file     : %s\n' "$PANEL_ENV"
    printf '  database     : %s\n' "$PANEL_DB"
    echo
    if [[ "$PANEL_PUBLIC" -eq 1 ]]; then
        printf '%sPanel is PUBLIC on :%s — use a reverse proxy with TLS in production.%s\n' \
            "${C_YELLOW}" "$PANEL_PORT" "${C_RESET}"
    else
        printf '%sPanel is CLOSED externally. Access via SSH tunnel:%s\n' "${C_BOLD}" "${C_RESET}"
        printf '  ssh -L %s:localhost:%s <user>@%s\n' "$PANEL_PORT" "$PANEL_PORT" "${ip:-<server>}"
        printf '  then open: %s\n' "$local_url"
    fi
    echo
    printf '%sFirst VLESS key (auto-created with your domain):%s\n' "${C_BOLD}" "${C_RESET}"
    # Rebuild the vless:// link using the same fields as standalone mode.
    local encoded_label
    encoded_label="$(urlencode "$LABEL")"
    local vless="vless://${UUID}@${DOMAIN}:${PORT}?security=reality&encryption=none&pbk=${PUBLIC_KEY}&fp=chrome&type=tcp&flow=xtls-rprx-vision&sni=${SNI}&sid=${SHORT_ID}#${encoded_label}"
    printf '  %s\n' "$vless"
    if command -v qrencode >/dev/null 2>&1; then
        echo
        qrencode -t ANSIUTF8 -m 2 "$vless" || true
    fi
    echo
    printf '  Add more servers later inside the panel: Dashboard → «Добавить сервер»\n'
    printf '  On each new xray box run:\n'
    printf '    sudo bash install.sh --node-only --agent-token <panel-generated> --agent-bind 0.0.0.0 --agent-port %s \\\n' "$AGENT_PORT"
    printf '           --domain <node-domain> --yes\n'
    printf '%s==========================================================%s\n' "${C_BOLD}" "${C_RESET}"
}

# ---------- node enrollment ----------
enroll_fetch_details() {
    # Hit GET /api/enroll/{token} and populate PORT / SNI / DEST / AGENT_PORT /
    # NODE_AGENT_TOKEN from the response. Pulls public_host too if provided.
    local url="${PANEL_URL%/}/api/enroll/${ENROLL_TOKEN}"
    log "fetching enrollment from ${url}"
    local resp=""
    resp="$(curl -fsSL --max-time 15 "$url")" \
        || die "failed to fetch enrollment details from ${url} (is --panel-url correct? is the token valid?)"
    local name port sni dest agent_port agent_token enroll_host
    name="$(printf '%s' "$resp" | jq -r '.name // empty')"
    port="$(printf '%s' "$resp" | jq -r '.port // empty')"
    sni="$(printf '%s' "$resp" | jq -r '.sni // empty')"
    dest="$(printf '%s' "$resp" | jq -r '.dest // empty')"
    agent_port="$(printf '%s' "$resp" | jq -r '.agent_port // empty')"
    agent_token="$(printf '%s' "$resp" | jq -r '.agent_token // empty')"
    enroll_host="$(printf '%s' "$resp" | jq -r '.public_host // empty')"
    [[ -n "$agent_token" ]] || die "enrollment response missing agent_token (raw: $resp)"
    [[ -n "$agent_port"  ]] || die "enrollment response missing agent_port  (raw: $resp)"
    [[ -n "$port"        ]] || die "enrollment response missing port        (raw: $resp)"
    [[ -n "$sni"         ]] || die "enrollment response missing sni         (raw: $resp)"
    [[ -n "$dest"        ]] || die "enrollment response missing dest        (raw: $resp)"
    PORT="$port"
    SNI="$sni"
    DEST="$dest"
    AGENT_PORT="$agent_port"
    NODE_AGENT_TOKEN="$agent_token"
    # If admin pre-filled a public_host, prefer it over --domain-based inference
    # for the callback, but the vless:// link in panel also uses it.
    if [[ -n "$enroll_host" && -z "$DOMAIN" ]]; then
        DOMAIN="$enroll_host"
    fi
    ok "enrollment '${name}' — port=${PORT} sni=${SNI} dest=${DEST} agent_port=${AGENT_PORT}"
}

enroll_complete() {
    # POST /api/enroll/{token}/complete with {agent_url, public_host}. The panel
    # will reach back into the agent, generate keys, push config, and mark the
    # enrollment used.
    local ip=""
    if ! ip="$(detect_public_ip 2>/dev/null)"; then
        warn "could not detect public IP; will use DOMAIN ('$DOMAIN') as agent hostname"
    fi
    local agent_host="${ip:-$DOMAIN}"
    [[ -n "$agent_host" ]] || die "cannot determine a hostname/IP for the agent URL"
    local agent_url="http://${agent_host}:${AGENT_PORT}"
    local public_host="${DOMAIN:-$agent_host}"

    local body
    body="$(jq -cn --arg u "$agent_url" --arg h "$public_host" \
        '{agent_url:$u, public_host:$h}')"

    local url="${PANEL_URL%/}/api/enroll/${ENROLL_TOKEN}/complete"
    log "registering with panel at ${url}"
    local resp=""
    local http_code=""
    # Separate body + http code from -w output.
    local out
    out="$(curl -sS --max-time 60 -o /tmp/xray-enroll.resp -w '%{http_code}' \
        -H 'Content-Type: application/json' -X POST -d "$body" "$url" || true)"
    http_code="$out"
    resp="$(cat /tmp/xray-enroll.resp 2>/dev/null || true)"
    rm -f /tmp/xray-enroll.resp
    if [[ "$http_code" != "200" && "$http_code" != "201" ]]; then
        warn "panel rejected enrollment (HTTP ${http_code}): ${resp}"
        die "enrollment failed — node is installed but NOT registered in the panel"
    fi
    ok "panel accepted node registration"
    printf '  panel response: %s\n' "$resp"
}

print_enroll_summary() {
    local ip=""
    if ip="$(detect_public_ip 2>/dev/null)"; then :; fi
    echo
    printf '%s==================== xray node (enrolled) ================%s\n' "${C_BOLD}" "${C_RESET}"
    printf '  name / panel : (see panel — enrollment was accepted)\n'
    printf '  public host  : %s\n' "${DOMAIN:-$ip}"
    printf '  agent URL    : http://%s:%s\n' "${ip:-<server>}" "${AGENT_PORT}"
    printf '  panel URL    : %s\n' "${PANEL_URL%/}"
    printf '  First VLESS key and the live vless:// link are now visible in the panel.\n'
    printf '%s==========================================================%s\n' "${C_BOLD}" "${C_RESET}"
}

print_node_summary() {
    local ip=""
    if ip="$(detect_public_ip 2>/dev/null)"; then :; fi
    echo
    printf '%s==================== xray node (agent-only) ==============%s\n' "${C_BOLD}" "${C_RESET}"
    printf '  host         : %s\n' "${ip:-<server>}"
    printf '  agent url    : http://%s:%s\n' "${NODE_AGENT_BIND}" "${AGENT_PORT}"
    printf '  agent token  : %s\n' "${AGENT_TOKEN_VALUE}"
    printf '  env file     : %s\n' "$AGENT_ENV"
    echo
    printf 'Paste into the panel (Dashboard → «Добавить сервер»):\n'
    printf '  name         : (any)\n'
    printf '  public host  : %s\n' "${DOMAIN:-$ip}"
    printf '  agent URL    : http://%s:%s   (or http://127.0.0.1:%s via SSH tunnel)\n' \
        "${ip:-<server>}" "$AGENT_PORT" "$AGENT_PORT"
    printf '  agent token  : (the one above)\n'
    printf '%s==========================================================%s\n' "${C_BOLD}" "${C_RESET}"
}

# ---------- main ----------
main() {
    require_root
    require_ubuntu
    detect_profile
    # Resolve where the panel/ and agent/ source lives. If the script is
    # running from a git clone, use that directory. If piped via `curl | bash`,
    # ${BASH_SOURCE[0]} is a file descriptor (/dev/fd/...) without adjacent
    # sources — in that case fetch the repo into a scratch dir.
    local src_dir=""
    if [[ -n "${BASH_SOURCE[0]:-}" && -f "${BASH_SOURCE[0]}" ]]; then
        src_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    fi
    if [[ -z "$src_dir" || ! -d "${src_dir}/panel" || ! -d "${src_dir}/agent" ]]; then
        if [[ "$PANEL" -eq 1 || "$NODE_ONLY" -eq 1 || "$NODE_ENROLL" -eq 1 ]]; then
            local branch="${XRAY_PANEL_BRANCH:-main}"
            local tmpdir
            tmpdir="$(mktemp -d)"
            log "fetching panel sources (branch=${branch}) into ${tmpdir}"
            apt-get install -y --no-install-recommends git >/dev/null 2>&1 || true
            if ! git clone --depth 1 --branch "$branch" \
                    https://github.com/sacoq/xray-reality-installer.git "$tmpdir/src" >/dev/null 2>&1; then
                die "could not fetch panel sources from GitHub (branch=${branch})"
            fi
            src_dir="$tmpdir/src"
        else
            src_dir="$(pwd)"
        fi
    fi
    SCRIPT_DIR="$src_dir"

    if [[ "$NODE_ONLY" -eq 1 ]]; then
        # Agent-only install for remote xray boxes.
        if [[ -z "$NODE_AGENT_TOKEN" ]]; then
            die "--node-only requires --agent-token <token from panel>"
        fi
        prompt_domain
        install_packages
        install_python
        check_domain_dns "$DOMAIN"
        install_xray
        apply_tuning
        setup_swap
        disable_bloat
        cap_journald
        gen_credentials
        write_config
        configure_firewall
        start_service
        install_agent
        # Open agent port if bound publicly and ufw is active.
        if [[ "$NODE_AGENT_BIND" != "127.0.0.1" ]] && command -v ufw >/dev/null 2>&1 \
           && ufw status | grep -q "Status: active"; then
            ufw allow "${AGENT_PORT}/tcp" >/dev/null || true
        fi
        print_node_summary
        return
    fi

    if [[ "$NODE_ENROLL" -eq 1 ]]; then
        # Fully automated registration against a remote panel.
        [[ -n "$PANEL_URL"     ]] || die "--node-enroll requires --panel-url <url>"
        [[ -n "$ENROLL_TOKEN"  ]] || die "--node-enroll requires --enroll-token <token>"
        # Agent MUST be reachable from the panel, so default to binding publicly
        # unless the caller explicitly pinned it.
        if [[ "$NODE_AGENT_BIND" == "127.0.0.1" ]]; then
            NODE_AGENT_BIND="0.0.0.0"
        fi
        install_packages
        enroll_fetch_details
        prompt_domain
        install_python
        check_domain_dns "$DOMAIN"
        install_xray
        apply_tuning
        setup_swap
        disable_bloat
        cap_journald
        gen_credentials
        write_config
        configure_firewall
        start_service
        install_agent
        # Open agent port in ufw so the panel can reach us.
        if command -v ufw >/dev/null 2>&1 && ufw status | grep -q "Status: active"; then
            ufw allow "${AGENT_PORT}/tcp" >/dev/null || true
        fi
        enroll_complete
        print_enroll_summary
        return
    fi

    if [[ "$PANEL" -eq 1 ]]; then
        # Panel mode: install xray + agent (local) + panel on this box.
        prompt_domain
        install_packages
        install_python
        check_domain_dns "$DOMAIN"
        install_xray
        apply_tuning
        setup_swap
        disable_bloat
        cap_journald
        gen_credentials
        write_config
        configure_firewall
        start_service
        install_agent
        install_panel
        configure_panel_firewall
        print_panel_summary
        return
    fi

    # Standalone mode (default): manual xray config + ready vless:// link.
    prompt_domain
    install_packages
    check_domain_dns "$DOMAIN"
    install_xray
    apply_tuning
    setup_swap
    disable_bloat
    cap_journald
    gen_credentials
    write_config
    configure_firewall
    start_service
    print_summary
}

# PANEL_SECRET_KEY is initialised empty; filled by install_panel.
PANEL_SECRET_KEY=""
AGENT_TOKEN_VALUE=""

main "$@"

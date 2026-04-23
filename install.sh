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

main() {
    require_root
    require_ubuntu
    detect_profile
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

main "$@"

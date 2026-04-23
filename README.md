# xray-reality-installer

One-shot installer for [Xray-core](https://github.com/XTLS/Xray-core) on a fresh
**Ubuntu 24.04** server. It deploys a VLESS + Reality (`xtls-rprx-vision`)
inbound, tunes the kernel for VPN throughput and prints a ready-to-use
`vless://` link bound to your own domain.

## What it does

1. Installs `xray-core` via the official
   [XTLS/Xray-install](https://github.com/XTLS/Xray-install) script.
2. Generates a fresh UUID, x25519 keypair and 8-hex-char shortId.
3. Writes `/usr/local/etc/xray/config.json` with:
   - VLESS inbound on `:443` (configurable)
   - `flow: xtls-rprx-vision`
   - Reality with `serverNames = ["rutube.ru"]` and `dest = rutube.ru:443`
   - `tcpFastOpen` + `tcpKeepAlive` enabled
4. Applies VPN-oriented tuning to the server, **scaled to RAM** via a profile:
   - BBR + `fq` qdisc, `tcp_fastopen = 3`, `ip_forward = 1`
   - Socket buffers (`rmem/wmem_max`) sized 16 / 32 / 64 MiB depending on profile
   - `somaxconn`, `netdev_max_backlog`, `nf_conntrack_max` scaled to profile
   - `LimitNOFILE` + `OOMScoreAdjust=-500` on the `xray.service` unit so the
     kernel OOM-killer goes for literally anything else before xray
   - `vm.swappiness`, `vfs_cache_pressure`, `overcommit_memory`, `min_free_kbytes`
     tuned for memory pressure
5. **Sets up swap** (critical on 1 GB VPS) — tries **zram** (compressed RAM-swap
   via `systemd-zram-generator`, zstd) first, falls back to a disk swapfile at
   `/swapfile` (1–4 GiB depending on profile).
6. **Disables bloat services** not needed on a single-purpose VPN box: `snapd`,
   `multipathd`, `ModemManager`, `apport`, `motd-news`.
7. **Caps `journald`** disk usage at 100 MiB so logs can't fill a tiny root FS.
8. Starts and enables `xray.service`, validates the config with `xray -test`.
9. Prints the `vless://…` link (and an ANSI QR — `qrencode` is installed
   automatically) using the **domain you enter**, not the bare IP.

All generated secrets are also saved to `/usr/local/etc/xray/credentials.env`
(mode `600`) for future reference.

## Requirements

- Ubuntu 24.04 (other Debian-based distros usually work but are untested)
- Root / `sudo`
- A domain whose `A` record points to this server (for the link only —
  Reality itself uses the SNI `rutube.ru`)

## Usage

### One-liner

```bash
curl -fsSL https://raw.githubusercontent.com/sacoq/xray-reality-installer/main/install.sh \
  | sudo bash -s -- --domain vpn.example.com
```

### Interactive

```bash
git clone https://github.com/sacoq/xray-reality-installer.git
cd xray-reality-installer
sudo bash install.sh
# => you will be prompted for the domain
```

### Options

| Flag             | Default        | Description                                     |
| ---------------- | -------------- | ----------------------------------------------- |
| `--domain <fqdn>`| *(prompted)*   | Host used in the `vless://…@host:port` link     |
| `--port <n>`     | `443`          | VLESS listen port                               |
| `--sni <host>`   | `rutube.ru`    | Reality `serverName` / client SNI               |
| `--dest <h:p>`   | `rutube.ru:443`| Reality `dest`                                  |
| `--email <tag>`  | `user1`        | Client `email` label inside `config.json`       |
| `--label <name>` | `xray-reality` | `#fragment` appended to the `vless://` link     |
| `--profile <p>`  | `auto`         | `auto` / `low-ram` / `default` / `high-perf`    |
| `--yes`          | off            | Non-interactive (fails if `--domain` missing)   |
| `--skip-tuning`  | off            | Skip the sysctl / limits tuning                 |
| `--skip-swap`    | off            | Don't set up zram / swapfile                    |
| `--skip-bloat`   | off            | Don't disable snapd / multipathd / ModemManager |
| `--panel`          | off          | Install the self-written `xray-panel` web UI + local node agent alongside xray (see below) |
| `--panel-port <n>` | `8443`       | Panel listen port                               |
| `--panel-user <s>` | `admin`      | Panel admin username                            |
| `--panel-pass <s>` | *(random 24)*| Panel admin password (shown once on install)    |
| `--panel-public`   | off          | Open panel port in `ufw`; off = SSH tunnel only |
| `--agent-port <n>` | `8765`       | Local node agent listen port (127.0.0.1 only)   |
| `--node-only`      | off          | Install xray + agent only (for remote servers managed by an existing panel) |
| `--agent-token <s>`|              | Shared token the panel uses to auth with the agent (required with `--node-only`) |
| `--agent-bind <ip>`| `127.0.0.1`  | Agent listen address (set to `0.0.0.0` for remote nodes) |
| `-h`, `--help`     |              | Show help                                       |

### Tuning profiles

`--profile auto` (default) picks based on total RAM:

| Profile     | Trigger        | `rmem/wmem_max` | `nofile` | `somaxconn` | Swap target        |
| ----------- | -------------- | --------------- | -------- | ----------- | ------------------ |
| `low-ram`   | RAM < 1.5 GiB  | 16 MiB          | 65 536   | 8 192       | zram 100%, 1 GiB fallback |
| `default`   | 1.5–6 GiB     | 32 MiB          | 524 288  | 32 768      | zram 50%, 2 GiB fallback  |
| `high-perf` | RAM ≥ 6 GiB   | 64 MiB          | 1 048 576| 65 535      | zram 25%, 4 GiB fallback  |

You can force any profile, e.g. `--profile low-ram` on a 2 GiB box if you value
memory over throughput.

## Panel mode (`--panel`) — self-written multi-server panel

With `--panel`, the installer deploys a small, purpose-built control panel
written from scratch (FastAPI + Alpine.js + SQLite) alongside xray on this
box. The panel:

- Manages **multiple xray servers** — the first one is this host, others you
  add later via the UI (each new server runs only the installer's `--node-only`
  mode to install xray + a local agent).
- Creates, lists, and deletes **VLESS+Reality clients** (keys) on each server.
  Every add/remove regenerates `config.json` and pushes it to the node — `xray
  -test` validates before restart.
- Shows per-server **statistics**: CPU %, RAM, disk, swap, load average,
  uptime, total network RX/TX, kernel/hostname, plus **per-client traffic**
  (uplink/downlink) read live from xray's own StatsService.
- Generates copy-paste `vless://…` links for each client using the domain you
  configured for that server.
- Single admin, bcrypt-hashed password, signed session cookies, password change
  from the UI.

```bash
curl -fsSL https://raw.githubusercontent.com/sacoq/xray-reality-installer/main/install.sh \
  | sudo bash -s -- --panel --domain vpn.example.com
```

On first install the script:

1. Prompts for the **domain** (unless `--domain` was passed) — this is the
   hostname embedded in the first `vless://…@DOMAIN:443` link.
2. Installs xray + applies all the usual tuning / swap / bloat cleanup.
3. Installs the panel into `/opt/xray-panel` and the agent into
   `/opt/xray-agent` (each in its own Python venv), plus systemd units
   `xray-panel.service` and `xray-agent.service`.
4. Seeds the panel DB (`/var/lib/xray-panel/panel.db`) with the admin user and
   the **local server with a first VLESS client already created** using your
   domain. Prints the `vless://` link + QR so the first user is productive
   immediately.

### Files

| Path                                    | What                              |
| --------------------------------------- | --------------------------------- |
| `/opt/xray-panel/` + venv               | Panel code + Python env           |
| `/opt/xray-agent/` + venv               | Local agent code + Python env     |
| `/etc/xray-panel/panel.env` (mode 600)  | Admin name, secret key, port, DB path |
| `/etc/xray-agent/agent.env` (mode 600)  | Agent token, bind, port           |
| `/var/lib/xray-panel/panel.db`          | SQLite: users, servers, clients   |
| `/etc/systemd/system/xray-panel.service`| Panel unit                        |
| `/etc/systemd/system/xray-agent.service`| Agent unit                        |

### Reaching the panel

By default the panel listens on `:8443` on every interface, but the installer
does **not** open that port in ufw — bots constantly scan for open web panels.
Recommended:

```bash
ssh -L 8443:localhost:8443 user@your-server
# then open: http://localhost:8443/
```

Pass `--panel-public` to add a `ufw allow 8443/tcp` rule if you insist on
exposing it directly. For production put it behind a reverse proxy with TLS.

### Adding more servers

Inside the panel, Dashboard → **«Добавить сервер»** asks for:

- a name, the public hostname (used for `vless://` links),
- the agent's URL (e.g. `http://198.51.100.7:8765`) and a shared token.

To prepare a new xray box, run on the remote machine:

```bash
TOKEN=$(openssl rand -hex 24)
curl -fsSL https://raw.githubusercontent.com/sacoq/xray-reality-installer/main/install.sh \
  | sudo bash -s -- --node-only --agent-bind 0.0.0.0 --agent-token "$TOKEN" \
                    --domain node2.example.com --yes
echo "paste this into the panel: $TOKEN"
```

Then paste the URL + token into the panel's «Добавить сервер» form. The panel
generates a fresh x25519 keypair / shortId on the new node, seeds its first
client, and pushes the config — all in one step.

### Caveats

- Standalone mode and panel mode are **mutually exclusive** — they both want
  port 443 for xray. Pick one per server.
- The panel assumes the same VLESS+Reality template as standalone mode. If
  you need other inbounds / protocols, edit `/usr/local/etc/xray/config.json`
  directly and note the panel will rewrite it on the next client change.
- Re-running `install.sh --panel` keeps the existing admin password and
  agent token (it only re-runs the Python install + refreshes systemd units).
  Pass `--panel-pass <new>` to force-rotate the admin password.

## Verifying

```bash
systemctl status xray
xray -test -config /usr/local/etc/xray/config.json
ss -tlnp | grep :443
swapon --show              # zram0 or /swapfile should show up
sysctl net.ipv4.tcp_congestion_control   # -> bbr
systemctl show xray -p LimitNOFILE -p OOMScoreAdjust
free -h                    # swap column > 0
```

## Re-running

The script is **not idempotent for credentials** — running it again will
generate a new UUID / keypair / shortId and overwrite `config.json`. If you
only want to reapply tuning or re-print the link, read
`/usr/local/etc/xray/credentials.env` directly.

## Uninstall

```bash
# Remove xray itself
sudo bash -c "$(curl -fsSL https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ remove --purge

# Remove tuning + overrides
sudo rm -f /etc/sysctl.d/99-xray-vpn.conf /etc/security/limits.d/99-xray.conf
sudo rm -rf /etc/systemd/system/xray.service.d
sudo rm -f /etc/systemd/journald.conf.d/99-xray.conf
sudo sysctl --system >/dev/null
sudo systemctl restart systemd-journald

# Remove swap (zram or swapfile)
sudo swapoff -a
sudo rm -f /etc/systemd/zram-generator.conf
sudo sed -i '/^\/swapfile /d' /etc/fstab
sudo rm -f /swapfile

# Remove xray-panel + agent (only if you installed with --panel or --node-only)
sudo systemctl disable --now xray-panel xray-agent 2>/dev/null || true
sudo rm -rf /opt/xray-panel /opt/xray-agent \
            /etc/xray-panel /etc/xray-agent \
            /var/lib/xray-panel \
            /etc/systemd/system/xray-panel.service \
            /etc/systemd/system/xray-agent.service
sudo systemctl daemon-reload
```

## License

MIT — see [LICENSE](LICENSE).

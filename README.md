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
| `--panel`        | off            | Install [3x-ui](https://github.com/MHSanaei/3x-ui) web panel instead of a standalone xray config |
| `--panel-port <n>` | `54321`      | Panel listen port                               |
| `--panel-path <s>` | *(random 18 hex)* | Panel `webBasePath`                        |
| `--panel-user <s>` | *(random 12)*| Panel admin username                            |
| `--panel-pass <s>` | *(random 24)*| Panel admin password                            |
| `--panel-public`   | off          | Open panel port in `ufw`; off = SSH tunnel only |
| `-h`, `--help`   |                | Show help                                       |

### Tuning profiles

`--profile auto` (default) picks based on total RAM:

| Profile     | Trigger        | `rmem/wmem_max` | `nofile` | `somaxconn` | Swap target        |
| ----------- | -------------- | --------------- | -------- | ----------- | ------------------ |
| `low-ram`   | RAM < 1.5 GiB  | 16 MiB          | 65 536   | 8 192       | zram 100%, 1 GiB fallback |
| `default`   | 1.5–6 GiB     | 32 MiB          | 524 288  | 32 768      | zram 50%, 2 GiB fallback  |
| `high-perf` | RAM ≥ 6 GiB   | 64 MiB          | 1 048 576| 65 535      | zram 25%, 4 GiB fallback  |

You can force any profile, e.g. `--profile low-ram` on a 2 GiB box if you value
memory over throughput.

## Panel mode (`--panel`)

With `--panel`, the installer drops standalone xray + `config.json` entirely
and instead installs [3x-ui](https://github.com/MHSanaei/3x-ui) — a full web
panel that manages xray for you (users, inbounds, traffic stats, HWID binding,
subscriptions, Telegram bot). All the OS tuning / swap / bloat cleanup /
journald cap still happens; 3x-ui just replaces the xray component.

```bash
curl -fsSL https://raw.githubusercontent.com/sacoq/xray-reality-installer/main/install.sh \
  | sudo bash -s -- --panel
```

When it finishes, the installer prints:

- Panel URL, admin username and password (all randomly generated, saved to
  `/etc/x-ui/panel.env` mode `600`)
- `webBasePath` (random 18-hex URL prefix — acts as a pre-auth secret)
- A copy-paste-ready SSH tunnel command so you can reach the panel over
  localhost without ever exposing the panel port to the internet
- A recommended template for creating the VLESS+Reality inbound that matches
  this repo's historical config (SNI=`rutube.ru`, `xtls-rprx-vision`, etc.)

### SSH tunnel (default, recommended)

```bash
ssh -L 54321:localhost:54321 user@your-server
# then open: http://localhost:54321/<panel-path>/
```

This is safer than opening the panel port to the world — bots constantly scan
for `3x-ui` / `x-ui` default panels.

### Expose the panel publicly

Pass `--panel-public` to add a `ufw` rule for `PANEL_PORT/tcp`. Once you have
a domain pointed at the box, inside the panel run `x-ui` in a shell and use
its ACME menu to turn on Let's Encrypt for the panel itself.

### Panel CLI

After install, the `x-ui` wrapper is in `$PATH`:

```
x-ui                # interactive menu (status, restart, logs, settings, update, ban, bbr…)
x-ui status
x-ui restart
x-ui log
x-ui update
x-ui settings       # show current panel settings
```

### Caveats

- Standalone mode and panel mode are **mutually exclusive** — they both want
  port 443 for xray. Pick one per server.
- In panel mode, 3x-ui ships its own bundled xray-core; the system
  `/usr/local/bin/xray` is not touched.
- Re-running `install.sh --panel` will download the latest 3x-ui release and
  re-apply the panel settings (it does NOT rotate existing admin creds unless
  you pass `--panel-user` / `--panel-pass` explicitly).

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

# Remove 3x-ui panel (only if you installed with --panel)
sudo systemctl disable --now x-ui 2>/dev/null || true
sudo rm -rf /usr/local/x-ui /etc/x-ui /etc/systemd/system/x-ui.service \
            /etc/systemd/system/x-ui.service.d /usr/bin/x-ui
sudo systemctl daemon-reload
```

## License

MIT — see [LICENSE](LICENSE).

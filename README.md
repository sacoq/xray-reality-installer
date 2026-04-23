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
```

## License

MIT — see [LICENSE](LICENSE).

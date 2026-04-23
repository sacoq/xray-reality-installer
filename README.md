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
4. Applies VPN-oriented tuning to the server:
   - BBR + `fq` qdisc
   - `tcp_fastopen = 3`
   - Large socket buffers (`rmem/wmem` 64 MiB)
   - `somaxconn`, `netdev_max_backlog`, `nf_conntrack_max` bumped
   - `ip_forward` enabled
   - `LimitNOFILE=1048576` for the `xray.service` unit
5. Starts and enables `xray.service` and validates the config with `xray -test`.
6. Prints the `vless://…` link (and an ANSI QR if `qrencode` is installed)
   using the **domain you enter**, not the bare IP.

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
| `--yes`          | off            | Non-interactive (fails if `--domain` missing)   |
| `--skip-tuning`  | off            | Skip the sysctl / limits tuning                 |
| `-h`, `--help`   |                | Show help                                       |

## Verifying

```bash
systemctl status xray
xray -test -config /usr/local/etc/xray/config.json
ss -tlnp | grep :443
```

## Re-running

The script is **not idempotent for credentials** — running it again will
generate a new UUID / keypair / shortId and overwrite `config.json`. If you
only want to reapply tuning or re-print the link, read
`/usr/local/etc/xray/credentials.env` directly.

## Uninstall

```bash
sudo bash -c "$(curl -fsSL https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ remove --purge
sudo rm -f /etc/sysctl.d/99-xray-vpn.conf /etc/security/limits.d/99-xray.conf
sudo rm -rf /etc/systemd/system/xray.service.d
sudo sysctl --system >/dev/null
```

## License

MIT — see [LICENSE](LICENSE).

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
cd xnpanel-xray-installer
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

Two options:

#### A. One-command auto-enrollment (recommended)

Panel tab **«Новая нода»** → **«Новая enrollment-команда»**:

1. Fill in the server's name and public host.
2. The panel generates a one-time enrollment token and shows a copy-pastable
   bash one-liner.
3. Paste that command into a root shell on a fresh Ubuntu 24.04 server:

   ```bash
   curl -fsSL https://raw.githubusercontent.com/sacoq/xray-reality-installer/main/install.sh \
     | sudo bash -s -- --node-enroll --panel-url https://panel.example.com \
                        --enroll-token ABC123 --domain node2.example.com --yes
   ```

4. The installer installs xray + the agent, then calls the panel back over
   `/api/enroll/{token}/complete`. The panel reaches into the agent, generates
   fresh x25519 keys, seeds the first VLESS client and pushes the config.
5. After 1–2 minutes the server appears in the panel with a working
   `vless://` link — no manual token copy-paste.

The panel must be reachable from the node (typical setup: put the panel
behind a public HTTPS reverse proxy, or expose `:8443` with `--panel-public`).

#### B. Manual (agent-only) — for air-gapped or custom setups

Inside the panel, Dashboard → **«+ Добавить сервер вручную»** asks for:

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

Then paste the URL + token into the panel's «Добавить сервер вручную» form.
The panel generates a fresh x25519 keypair / shortId on the new node, seeds
its first client, and pushes the config — all in one step.

### Whitelist-bypass chain (RU front + foreign exit)

> **TL;DR:** ставишь обычную ноду за границей, потом ставишь РФ-ноду на
> whitelisted IP и одной кнопкой связываешь их. Пользователи коннектятся
> на РФ-фронт; xray на нём пересылает весь трафик одним VLESS+Reality-прыжком
> на иностранный backend. Идеально для обхода ТСПУ-ограничений по «белым
> спискам» крупных российских ДЦ.

#### What this is

A `whitelist-front` node is a *chain*: two real Linux servers wired together
by the panel.

```
client (RU)
   │ vless://...@ru-front.example.com:443  (Reality, обычный VLESS)
   ▼
[ ru-front ]   ← публичный IP в whitelist'е оператора (РФ ДЦ),
   │             ТСПУ его не дросселирует
   │ зашифрованный VLESS+Reality в один прыжок
   ▼
[ foreign-exit ] ← обычная standalone-нода, например DE/FI/NL
   │
   ▼
public internet
```

End-user devices only ever see the RU front — its IP is on a whitelist
(typical Russian datacenter networks like Selectel, RUVDS, Aeza, etc.
that ТСПУ doesn't throttle), so the user gets full link speed up to the
front. Inside the front, xray re-encapsulates every packet over a second
VLESS+Reality session into the foreign exit, which actually leaves the
country. Service traffic between the two boxes carries panel-managed auth
UUIDs (`__bypass__-<front_id>`) that the admin never sees.

#### Setup (UI)

1. **Поставь иностранный «выход»** обычной кнопкой:
   - Panel → **Dashboard** → **«⚡ Авто-балансировка»** или **«Новая
     нода»**, вписываешь название/хост, копируешь команду, выполняешь
     её на свежей foreign-машине (DE/FI/NL/...).
   - В панели появится standalone-нода — её и будем использовать как
     «выход».
2. **Поставь РФ-фронт связкой**:
   - Panel → **Dashboard** → **«🇷🇺→🌍 Нода обхода»** (rose/малиновая
     кнопка).
   - В модалке выбираешь иностранный сервер из шага 1 в поле
     **«Иностранный выход (foreign upstream)»**, заполняешь slug и
     publish-имя, нажимаешь *Сгенерировать команду*.
   - Копируешь bash-one-liner, выполняешь на свежей **РФ-ноде с
     whitelisted IP**:

     ```bash
     curl -fsSL https://raw.githubusercontent.com/sacoq/xray-reality-installer/main/install.sh \
       | sudo bash -s -- --node-enroll --panel-url https://panel.example.com \
                          --enroll-token ABC123 --domain ru-front.example.com --yes
     ```

3. Через 1–2 минуты в панели рядом с РФ-фронтом появится бейджик
   `🇷🇺→🌍` и подпись `→ выход: <foreign-нода>`. Это значит, что xray на
   фронте уже вытаскивает auth-UUID из иностранного выхода и форвардит в
   него весь трафик. Подписки и Telegram-бот раздают клиентам только
   `vless://...@ru-front.example.com:443` — иностранная нода в подписке
   не светится.

#### Что делать, если выход поменялся / упал

- **Перецепить фронт на другой выход**: изменяешь `upstream_server_id`
  через `PATCH /api/servers/{front_id}` (в UI это пока через
  `curl`/REST — кнопка прилетит позже). Панель сама удалит старый
  `__bypass__-<front_id>` Client с прошлого выхода и зарегистрирует
  новый на новом выходе.
- **Удалить выход**: при `DELETE /api/servers/{foreign_id}` панель
  автоматически re-push'ит все фронты, которые на него смотрели —
  они переключатся в degraded-режим (egress прямо с фронта,
  без иностранного хопа), пока не привяжешь новый выход.
- **Ротация ключей выхода** (`POST /api/servers/{foreign_id}/rotate-keys`)
  тоже автоматически re-push'ит все привязанные фронты — они начинают
  дилить выход с новой публичной x25519-парой.

#### Ping fast-path

Клиентский VLESS-пинг в Xray-клиентах по умолчанию делает HTTP-пробу на
`www.gstatic.com/generate_204` (или `cp.cloudflare.com/generate_204`) —
если гонять этот запрос через весь тоннель `client → RU-front → foreign
→ gstatic`, цифра пинга в клиенте получается «зарубежной» (условные
120–200 мс вместо 20–50 мс до РФ-фронта). На whitelist-front-нодах
панель добавляет отдельное routing-правило, которое заворачивает этот
конкретный список доменов в локальный `direct`-outbound самого фронта.
В итоге проба уходит маршрутом `client → RU-front → gstatic` — цифра в
клиенте совпадает с реальным RTT до РФ-фронта, а весь остальной трафик
продолжает идти через иностранный выход.

Побочка: пользовательские браузерные запросы к `*.gstatic.com` /
`cp.cloudflare.com` / `captive.apple.com` / `connectivitycheck.gstatic.com`
тоже уходят напрямую с фронта. Это чистые CDN без персональных данных,
поэтому на практике не страшно, но если хочешь жёстко «весь трафик в
LT», список доменов правится в `panel/xray_config.py` → `PING_TEST_DOMAINS`.

После `git pull` на панели и `systemctl restart xray-panel` новое
правило попадёт в xray-конфиг только при следующем pushe. Чтобы
применить его немедленно без инвалидации клиентских ключей, жми в UI
**«Пересобрать config»** (или дёрни `POST /api/servers/{id}/resync`).

#### Caveats / ограничения

- Выход обязан быть `standalone` — балансер или другой `whitelist-front`
  в выход подставить нельзя (получится петля или цепочка-цепочка).
- Public-host РФ-фронта должен резолвиться в whitelisted IP. Иначе
  смысла в связке нет — ТСПУ зарежет соединение ещё до того, как
  фронт получит первый байт.
- На фронте `port`, `sni` и `dest` — настройки **inbound'а** для
  пользователей. На иностранном выходе они должны быть свои,
  никак не связанные с фронтом (фронт дилит выход по
  `public_host:port` выхода, не по своему).
- Пользовательские vless-ключи живут только на фронте. На foreign-выходе
  своих end-user клиентов не делай — он используется только как
  zero-config exit для всех привязанных фронтов.

### Auto-balance tiers (⚡ primary → 🛡 fallback failover)

> **TL;DR:** размечаешь зарубежные ноды как ⚡ `primary`, а ноды обхода
> белых списков (whitelist-front-связки) — как 🛡 `fallback`. Клиент
> сначала пытается primary, и только если все они недоступны (РФ
> включил очередной whitelist у пользователя в регионе) — переключается
> на fallback. Каждые 30 секунд клиент перепроверяет primary и сам
> возвращается обратно, как только зарубежный канал снова открылся.

#### Как это устроено

В подписке `/sub/<token>` панель собирает sing-box-конфиг с двумя
вложенными `urltest`-селекторами:

```
client
   │
   ▼
[ smart-pool ]   ← внешний urltest, interval = 30s
   ├─ ⚡ primary-pool (зарубежные ноды)
   │     ├── DE-1
   │     ├── FI-2
   │     └── NL-3
   └─ 🛡 fallback-pool (whitelist-front-ноды)
         ├── ru-front-1 → DE-1
         └── ru-front-2 → FI-2
```

- Первый `urltest` гоняет HTTP-пробы только по primary. Если ни одна
  primary-нода не отвечает за `tolerance` (по умолчанию 800 мс) —
  внешний селектор переключается на fallback-pool.
- Каждые 30 секунд (`probe_interval`) sing-box перепроверяет primary;
  как только хоть одна снова отвечает — клиент бесшовно возвращается
  обратно на ⚡ зарубежный выход.
- Это работает на стороне клиента (sing-box / Hiddify / Streisand /
  Karing — у всех есть совместимый `urltest`), серверам-нодам ничего
  знать про балансировку не нужно.

#### Настройка через UI

1. **Dashboard** → серверу выбираешь **«Тир в авто-балансировке»**:
   - **⚡ primary** (зарубежный выход) — попадает в основной пул.
     Эквивалентно легаси-флагу `in_pool=true`, который остаётся видимым
     в API/UI для обратной совместимости.
   - **🛡 fallback** (нода обхода / резерв) — попадает во второй пул,
     активируется только когда все primary недоступны.
2. **Dashboard** → раскрываешь блок **«⚙ Авто-балансировка
   (probe URL / interval / tolerance)»** — это глобальные настройки
   для всех подписок:
   - **Probe URL** — какой URL клиент дёргает для health-check
     (по умолчанию `http://www.gstatic.com/generate_204`).
   - **Probe interval** — как часто перепроверять primary
     (по умолчанию 30 секунд).
   - **Probe tolerance** — сколько мс ждать ответа, прежде чем
     считать ноду мёртвой (по умолчанию 800 мс).
3. Кнопка **«Сохранить»** пишет настройки в `/api/load-balancer/settings`,
   и панель сразу же применяет их к подписочному рендеру (sing-box /
   clash / vless-plain).

#### Что осталось от старого режима

- Чекбокс **«В пуле авто-балансировки» (`in_pool`)** в формах добавления/
  редактирования сервера и enrollment-ах **остаётся** и продолжает
  работать. Если ты его поставил — нода считается ⚡ primary; если
  снял — нода вне пула. Поле `pool_tier` синхронизировано с этим
  флагом автоматически (`primary` ↔ `in_pool=true`, `fallback` /
  пустое значение ↔ `in_pool=false`).
- Ничего не сломается, если у тебя уже были ноды с `in_pool=true` —
  они автоматически считаются ⚡ primary, fallback-пул просто будет
  пустым, пока ты не разметишь новые ноды как 🛡 fallback.
- Префикс подписочного лейбла (`POOL_PREFIX` / `auto_balance.PRIMARY_PREFIX`)
  остался прежним, так что v2rayN/Hiddify-клиенты не увидят
  переименование выходов.

### Aggregated subscriptions (all servers in one URL)

Panel tab **«Подписки»** lets you group VLESS keys from one or more servers
into a single subscription URL (`/sub/<token>`). The feed is base64-encoded
newline-joined `vless://` links — compatible with v2rayN, Hiddify, Streisand,
Happ, Karing, Nekobox, etc.

Two modes:

- **Include all**: always returns every client across every server at read
  time. New keys appear automatically; deleted ones disappear. Good for an
  admin's master subscription.
- **Manual selection**: pick a specific set of clients (e.g. one client per
  server for a single end-user that should roam between your nodes).

The URL uses the panel's host as seen by the HTTP request, or the value of
the `PANEL_PUBLIC_URL` environment variable if set in
`/etc/xray-panel/panel.env` (recommended when the panel is behind a reverse
proxy — otherwise the URL printed to users will be the internal address).

### Per-node management

The server detail page exposes:

- **↻ Restart xray** / **▶ Start** / **⏸ Stop** — `systemctl` on the node
- **📜 Logs** — last 300 lines of `journalctl -u xray`
- **🔑 Rotate Reality keys** — regenerate x25519 + shortId, push the new
  config. All existing `vless://` links become invalid until re-imported.
- **⟳ Reboot server** — schedules a host reboot via `shutdown -r +1`
- **× Delete from panel** — drops the server from the panel's DB (the xray
  and agent services keep running on the box; uninstall manually if needed)

### Caveats

- Standalone mode and panel mode are **mutually exclusive** — they both want
  port 443 for xray. Pick one per server.
- The panel assumes the same VLESS+Reality template as standalone mode. If
  you need other inbounds / protocols, edit `/usr/local/etc/xray/config.json`
  directly and note the panel will rewrite it on the next client change.
- Re-running `install.sh --panel` keeps the existing admin password and
  agent token (it only re-runs the Python install + refreshes systemd units).
  Pass `--panel-pass <new>` to force-rotate the admin password.

### Runtime user API (no-restart client CRUD)

`POST /config` on the agent now diffs the incoming config.json against the
currently-deployed one. If the **only** difference is the user list of one or
more VLESS inbounds (`settings.clients`), the agent applies the diff via
`xray api adu` / `xray api rmu` against the live xray gRPC `HandlerService`
on `127.0.0.1:10085` and atomically rewrites `config.json` — **without**
restarting `xray.service`. Active TCP/UDP sessions are preserved, so
`/sub` for a new user, `/revoke` for an old one, and bulk subscription
expiry no longer cause the ~10 s connectivity drop on every change.

Structural changes (port, SNI, Reality private key / shortIds, outbounds,
routing rules, balancers, observatory, the inbound list itself — anything
beyond `settings.clients`) still trigger a full `systemctl restart xray`.
Same fallback fires when xray isn't active, the gRPC API is unreachable, or
`adu`/`rmu` fail mid-way (the freshly written `config.json` becomes
authoritative on the next start either way).

The agent's `POST /config` response now includes `method`
(`"runtime_api"` / `"restart"`), `restarted` (`true`/`false`) and per-call
`users_added` / `users_removed` counts so the panel can log which path
ran.

Two explicit endpoints are also exposed for callers that don't want to
rebuild a full config to add or remove a single user:

* `POST /xray/inbound/users/add` — body `{tag, protocol, port, users[]}`,
  every user must carry `email` (xray's `adu` silently skips email-less
  rows). On-disk `config.json` is **not** modified — pair with a later
  full `POST /config` if the change must survive a restart.
* `POST /xray/inbound/users/remove` — body `{tag, emails[]}`, same
  caveat about disk persistence.

## Updating an existing install (`xnpanel`)

Panel-mode and node-mode installs ship a small management CLI at
`/usr/local/bin/xnpanel` that handles self-updates without touching
your Reality keys or panel secrets:

```bash
sudo xnpanel update        # pull latest panel/agent sources, restart services
xnpanel check              # only check, don't install
xnpanel version            # show installed commit SHA + mode
xnpanel status             # service status + update check
xnpanel restart            # systemctl restart xray / xray-agent / xray-panel
xnpanel logs panel         # journalctl -u xray-panel (or agent|xray)
```

`xnpanel update` clones the latest `main` branch into a scratch dir,
swaps `/opt/xray-panel/panel` and `/opt/xray-agent/agent` atomically,
refreshes the Python deps inside each venv and restarts the relevant
systemd units. It intentionally does NOT re-run `install.sh` — that
would regenerate the Reality keypair and break every live client.

A systemd timer (`xnpanel-update-check.timer`, runs every 6 hours)
polls GitHub for new commits and writes the result to
`/var/lib/xnpanel/update-available`. A dynamic MOTD snippet at
`/etc/update-motd.d/90-xnpanel-update` reads that file and prints a
banner on every SSH login when a newer release is out:

```
==> xnPanel: new version available (644d9a4 → 178f6ff)
    Run sudo xnpanel update to upgrade.
```

Set `XNPANEL_BRANCH=<branch>` in the environment to track a non-`main`
branch (useful for staging rollouts).

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
sudo systemctl disable --now xnpanel-update-check.timer 2>/dev/null || true
sudo rm -rf /opt/xray-panel /opt/xray-agent \
            /etc/xray-panel /etc/xray-agent \
            /var/lib/xray-panel \
            /etc/systemd/system/xray-panel.service \
            /etc/systemd/system/xray-agent.service \
            /etc/systemd/system/xnpanel-update-check.service \
            /etc/systemd/system/xnpanel-update-check.timer \
            /etc/xnpanel /var/lib/xnpanel \
            /etc/update-motd.d/90-xnpanel-update \
            /usr/local/bin/xnpanel
sudo systemctl daemon-reload
```

## License

MIT — see [LICENSE](LICENSE).

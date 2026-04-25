"""Provision TLS + reverse-proxy for custom subscription domains.

When an admin sets a per-bot ``subscription_domain`` (or the global
``panel.subscription_url_base``) the host machine still needs:

1. A TLS certificate for that hostname (Let's Encrypt).
2. A vhost pointing the hostname at the local panel.

We support two backends, picked at runtime by detecting which is actually
fronting the panel on the host:

* **Caddy** — the installer's default. We drop a managed snippet under
  ``/etc/caddy/managed-domains/<domain>.caddy`` and reload Caddy; it
  handles ACME (HTTP-01 or DNS-01 if the wildcard CF token is set)
  automatically. If the wildcard cert is already active for the parent
  zone we report success without writing a new block.

* **nginx + certbot** — what most admins fall back to when they front
  the panel with their own nginx (matches the user-reported setup that
  shows "nginx 403"). We write an HTTP-01-friendly stub vhost on :80,
  run certbot to issue the cert, then write the real :443 vhost
  reverse-proxying to the panel and reload nginx.

The panel runs as ``root`` per the systemd unit installed by
``install.sh`` so we can edit ``/etc/caddy`` / ``/etc/nginx`` and reload
services directly without sudo gymnastics.

Public API:

* :func:`provision(domain, *, panel_port, email)` — returns
  ``ProvisionResult``.
* :func:`unprovision(domain)` — best-effort removal of our managed block.
* :func:`status(domain)` — quick check whether a cert exists locally.
* :func:`detect_backend()` — which backend would be used right now.
"""
from __future__ import annotations

import logging
import os
import re
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional

logger = logging.getLogger("panel.domain_provision")

CADDY_MANAGED_DIR = Path("/etc/caddy/managed-domains")
CADDY_MAIN = Path("/etc/caddy/Caddyfile")
CADDY_XNPANEL = Path("/etc/caddy/xnpanel.caddy")

NGINX_MANAGED_DIR = Path("/etc/nginx/sites-available")
NGINX_ENABLED_DIR = Path("/etc/nginx/sites-enabled")
NGINX_WEBROOT = Path("/var/www/letsencrypt")
NGINX_FILE_PREFIX = "xray-panel-"

LETSENCRYPT_LIVE = Path("/etc/letsencrypt/live")

_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$"
)


@dataclass
class ProvisionResult:
    ok: bool
    backend: str
    message: str
    cert_path: str = ""

    def to_dict(self) -> dict[str, object]:
        return {
            "ok": self.ok,
            "backend": self.backend,
            "message": self.message,
            "cert_path": self.cert_path,
        }


# --------------------------------------------------------------------------- #
# Helpers                                                                     #
# --------------------------------------------------------------------------- #


def _strip_scheme(domain: str) -> str:
    s = (domain or "").strip().lower()
    for prefix in ("https://", "http://"):
        if s.startswith(prefix):
            s = s[len(prefix):]
    s = s.split("/", 1)[0]
    s = s.split(":", 1)[0]
    return s


def validate_domain(domain: str) -> str:
    s = _strip_scheme(domain)
    if not s or not _DOMAIN_RE.match(s):
        raise ValueError(f"invalid domain: {domain!r}")
    return s


def _safe_filename(domain: str) -> str:
    return re.sub(r"[^a-z0-9.-]+", "_", domain.lower())


def _have_binary(name: str) -> bool:
    return shutil.which(name) is not None


def _service_active(unit: str) -> bool:
    try:
        r = subprocess.run(
            ["systemctl", "is-active", unit],
            capture_output=True, text=True, timeout=5,
        )
        return r.returncode == 0 and r.stdout.strip() == "active"
    except Exception:
        return False


def _read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except Exception:
        return ""


# --------------------------------------------------------------------------- #
# Backend detection                                                           #
# --------------------------------------------------------------------------- #


def detect_backend() -> str:
    """Return ``"caddy"``, ``"nginx"``, or ``""`` if neither is usable."""
    caddy_active = _service_active("caddy") and _have_binary("caddy")
    nginx_active = _service_active("nginx") and _have_binary("nginx")
    have_certbot = _have_binary("certbot")

    if caddy_active and CADDY_MAIN.exists():
        return "caddy"
    if nginx_active and have_certbot:
        return "nginx"
    if caddy_active:
        return "caddy"
    if nginx_active:
        return "nginx-no-certbot"
    return ""


# --------------------------------------------------------------------------- #
# Caddy backend                                                               #
# --------------------------------------------------------------------------- #


def _caddy_wildcard_zone() -> str:
    """If the installer configured wildcard mode, return the zone covered.

    Looks for a ``*.zone`` token in ``/etc/caddy/xnpanel.caddy``. A bot
    domain is "already covered" when it ends with that zone.
    """
    text = _read_text(CADDY_XNPANEL)
    m = re.search(r"\*\.([a-z0-9.-]+)", text)
    if m:
        return m.group(1)
    return ""


def _caddy_managed_block(domain: str, panel_port: int) -> str:
    return f"""# Managed by xray-reality-installer (panel domain provisioner).
# Custom subscription domain — auto-generated, edit at your own risk.
{domain} {{
    encode zstd gzip
    reverse_proxy 127.0.0.1:{panel_port} {{
        transport http {{
            dial_timeout 5s
            response_header_timeout 60s
        }}
        header_up Host {{host}}
        header_up X-Real-IP {{remote_host}}
        header_up X-Forwarded-For {{remote_host}}
        header_up X-Forwarded-Proto {{scheme}}
    }}
}}
"""


def _ensure_caddy_import() -> None:
    """Make sure the main Caddyfile imports our managed-domains directory."""
    if not CADDY_MAIN.exists():
        return
    text = _read_text(CADDY_MAIN)
    if "managed-domains/*.caddy" in text:
        return
    addition = "\n# Managed custom subscription domains:\nimport /etc/caddy/managed-domains/*.caddy\n"
    CADDY_MAIN.write_text(text.rstrip() + "\n" + addition, encoding="utf-8")


def _caddy_reload() -> tuple[bool, str]:
    try:
        v = subprocess.run(
            ["caddy", "validate", "--config", str(CADDY_MAIN)],
            capture_output=True, text=True, timeout=15,
        )
        if v.returncode != 0:
            return False, f"caddy validate failed: {v.stderr or v.stdout}"
        r = subprocess.run(
            ["systemctl", "reload", "caddy"],
            capture_output=True, text=True, timeout=15,
        )
        if r.returncode != 0:
            return False, f"systemctl reload caddy failed: {r.stderr or r.stdout}"
        return True, "caddy reloaded"
    except Exception as e:
        return False, f"caddy reload error: {e}"


def _provision_caddy(domain: str, panel_port: int) -> ProvisionResult:
    zone = _caddy_wildcard_zone()
    if zone and (domain == zone or domain.endswith("." + zone)):
        return ProvisionResult(
            ok=True,
            backend="caddy",
            message=(
                f"Домен уже покрыт wildcard-сертификатом *.{zone} "
                "(Caddy автоматически обслужит TLS и проксирование)."
            ),
        )
    CADDY_MANAGED_DIR.mkdir(parents=True, exist_ok=True)
    block_path = CADDY_MANAGED_DIR / f"{_safe_filename(domain)}.caddy"
    block_path.write_text(_caddy_managed_block(domain, panel_port), encoding="utf-8")
    os.chmod(block_path, 0o644)
    _ensure_caddy_import()
    ok, msg = _caddy_reload()
    if not ok:
        return ProvisionResult(ok=False, backend="caddy", message=msg)
    return ProvisionResult(
        ok=True,
        backend="caddy",
        message=f"Caddy перезагружен. Сертификат Let's Encrypt будет выпущен автоматически при первом обращении к {domain}.",
    )


def _unprovision_caddy(domain: str) -> ProvisionResult:
    block_path = CADDY_MANAGED_DIR / f"{_safe_filename(domain)}.caddy"
    if block_path.exists():
        try:
            block_path.unlink()
        except Exception as e:
            return ProvisionResult(ok=False, backend="caddy", message=f"не удалось удалить {block_path}: {e}")
    ok, msg = _caddy_reload()
    return ProvisionResult(ok=ok, backend="caddy", message=msg)


# --------------------------------------------------------------------------- #
# Nginx + certbot backend                                                     #
# --------------------------------------------------------------------------- #


def _nginx_acme_stub(domain: str) -> str:
    return f"""# Managed by xray-reality-installer (panel domain provisioner).
# Stage 1: HTTP-only stub for Let's Encrypt HTTP-01 challenges.
server {{
    listen 80;
    listen [::]:80;
    server_name {domain};

    location ^~ /.well-known/acme-challenge/ {{
        root {NGINX_WEBROOT};
        default_type "text/plain";
        try_files $uri =404;
    }}

    location / {{
        return 301 https://$host$request_uri;
    }}
}}
"""


def _nginx_full_vhost(domain: str, panel_port: int) -> str:
    cert = LETSENCRYPT_LIVE / domain / "fullchain.pem"
    key = LETSENCRYPT_LIVE / domain / "privkey.pem"
    return f"""# Managed by xray-reality-installer (panel domain provisioner).
# Custom subscription domain — auto-generated, edit at your own risk.
server {{
    listen 80;
    listen [::]:80;
    server_name {domain};
    location ^~ /.well-known/acme-challenge/ {{
        root {NGINX_WEBROOT};
        default_type "text/plain";
        try_files $uri =404;
    }}
    location / {{
        return 301 https://$host$request_uri;
    }}
}}

server {{
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name {domain};

    ssl_certificate {cert};
    ssl_certificate_key {key};
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers off;

    client_max_body_size 4m;
    proxy_http_version 1.1;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto https;

    location / {{
        proxy_pass http://127.0.0.1:{panel_port};
        proxy_read_timeout 60s;
    }}
}}
"""


def _nginx_write(domain: str, body: str) -> Path:
    NGINX_MANAGED_DIR.mkdir(parents=True, exist_ok=True)
    NGINX_ENABLED_DIR.mkdir(parents=True, exist_ok=True)
    fname = f"{NGINX_FILE_PREFIX}{_safe_filename(domain)}.conf"
    available = NGINX_MANAGED_DIR / fname
    available.write_text(body, encoding="utf-8")
    os.chmod(available, 0o644)
    enabled = NGINX_ENABLED_DIR / fname
    if enabled.is_symlink() or enabled.exists():
        try:
            enabled.unlink()
        except Exception:
            pass
    try:
        os.symlink(available, enabled)
    except FileExistsError:
        pass
    return available


def _nginx_test_reload() -> tuple[bool, str]:
    try:
        t = subprocess.run(
            ["nginx", "-t"], capture_output=True, text=True, timeout=15,
        )
        if t.returncode != 0:
            return False, f"nginx -t failed: {t.stderr or t.stdout}"
        r = subprocess.run(
            ["systemctl", "reload", "nginx"],
            capture_output=True, text=True, timeout=15,
        )
        if r.returncode != 0:
            return False, f"systemctl reload nginx failed: {r.stderr or r.stdout}"
        return True, "nginx reloaded"
    except Exception as e:
        return False, f"nginx reload error: {e}"


def _certbot_issue(domain: str, email: str) -> tuple[bool, str]:
    NGINX_WEBROOT.mkdir(parents=True, exist_ok=True)
    cmd = [
        "certbot", "certonly", "--non-interactive", "--agree-tos",
        "--webroot", "-w", str(NGINX_WEBROOT),
        "-d", domain,
    ]
    if email:
        cmd += ["-m", email]
    else:
        cmd += ["--register-unsafely-without-email"]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    except Exception as e:
        return False, f"certbot error: {e}"
    if r.returncode != 0:
        tail = (r.stderr or r.stdout or "").strip().splitlines()[-12:]
        return False, "certbot failed:\n" + "\n".join(tail)
    return True, "certbot issued cert"


def _provision_nginx(domain: str, panel_port: int, email: str) -> ProvisionResult:
    cert = LETSENCRYPT_LIVE / domain / "fullchain.pem"
    if not cert.exists():
        # Stage 1: stub vhost on :80, reload, run certbot.
        _nginx_write(domain, _nginx_acme_stub(domain))
        ok, msg = _nginx_test_reload()
        if not ok:
            return ProvisionResult(ok=False, backend="nginx", message=msg)
        ok, msg = _certbot_issue(domain, email)
        if not ok:
            return ProvisionResult(ok=False, backend="nginx", message=msg)
    # Stage 2: full HTTPS vhost.
    _nginx_write(domain, _nginx_full_vhost(domain, panel_port))
    ok, msg = _nginx_test_reload()
    if not ok:
        return ProvisionResult(ok=False, backend="nginx", message=msg, cert_path=str(cert))
    return ProvisionResult(
        ok=True,
        backend="nginx",
        message=f"nginx vhost создан, сертификат активен для {domain}.",
        cert_path=str(cert),
    )


def _unprovision_nginx(domain: str) -> ProvisionResult:
    fname = f"{NGINX_FILE_PREFIX}{_safe_filename(domain)}.conf"
    for d in (NGINX_ENABLED_DIR, NGINX_MANAGED_DIR):
        p = d / fname
        if p.exists() or p.is_symlink():
            try:
                p.unlink()
            except Exception as e:
                return ProvisionResult(ok=False, backend="nginx", message=f"не удалось удалить {p}: {e}")
    ok, msg = _nginx_test_reload()
    return ProvisionResult(ok=ok, backend="nginx", message=msg)


# --------------------------------------------------------------------------- #
# Public API                                                                  #
# --------------------------------------------------------------------------- #


def _resolve_panel_port(panel_port: Optional[int]) -> int:
    if panel_port:
        return int(panel_port)
    raw = os.environ.get("PANEL_PORT", "")
    if raw.isdigit():
        return int(raw)
    return 8443


def provision(
    domain: str,
    *,
    panel_port: Optional[int] = None,
    email: str = "",
) -> ProvisionResult:
    """Issue a cert + reverse-proxy block for ``domain``.

    Picks Caddy or nginx automatically based on what's running.
    """
    try:
        d = validate_domain(domain)
    except ValueError as e:
        return ProvisionResult(ok=False, backend="", message=str(e))

    port = _resolve_panel_port(panel_port)
    backend = detect_backend()
    if backend == "caddy":
        return _provision_caddy(d, port)
    if backend == "nginx":
        return _provision_nginx(d, port, email)
    if backend == "nginx-no-certbot":
        return ProvisionResult(
            ok=False,
            backend="nginx",
            message="nginx найден, но certbot не установлен. Поставь certbot: apt install -y certbot",
        )
    return ProvisionResult(
        ok=False,
        backend="",
        message="на хосте не найдено ни Caddy, ни nginx — настрой обратный прокси вручную или установи Caddy через install.sh --panel-domain.",
    )


def unprovision(domain: str) -> ProvisionResult:
    try:
        d = validate_domain(domain)
    except ValueError as e:
        return ProvisionResult(ok=False, backend="", message=str(e))
    backend = detect_backend()
    if backend == "caddy":
        return _unprovision_caddy(d)
    if backend in ("nginx", "nginx-no-certbot"):
        return _unprovision_nginx(d)
    return ProvisionResult(
        ok=False, backend="", message="не найдено активного бэкенда (caddy/nginx)",
    )


def status(domain: str) -> dict[str, object]:
    """Quick local check: does a Let's Encrypt cert exist for ``domain``?"""
    try:
        d = validate_domain(domain)
    except ValueError as e:
        return {"domain": domain, "ok": False, "message": str(e)}
    backend = detect_backend()
    cert = LETSENCRYPT_LIVE / d / "fullchain.pem"
    has_cert = cert.exists()
    caddy_block = (CADDY_MANAGED_DIR / f"{_safe_filename(d)}.caddy").exists()
    nginx_block = (NGINX_MANAGED_DIR / f"{NGINX_FILE_PREFIX}{_safe_filename(d)}.conf").exists()
    return {
        "domain": d,
        "backend": backend,
        "letsencrypt_cert": has_cert,
        "caddy_block": caddy_block,
        "nginx_block": nginx_block,
    }


def list_provisioned() -> List[str]:
    out: list[str] = []
    if CADDY_MANAGED_DIR.is_dir():
        for p in CADDY_MANAGED_DIR.glob("*.caddy"):
            out.append(p.stem)
    if NGINX_MANAGED_DIR.is_dir():
        for p in NGINX_MANAGED_DIR.glob(f"{NGINX_FILE_PREFIX}*.conf"):
            out.append(p.name[len(NGINX_FILE_PREFIX):-5])
    # Dedup, preserve order.
    seen: set[str] = set()
    uniq: list[str] = []
    for d in out:
        if d in seen:
            continue
        seen.add(d)
        uniq.append(d)
    return uniq

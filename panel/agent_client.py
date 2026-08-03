"""HTTP client for talking to node agents."""
from __future__ import annotations

from typing import Any

import httpx

DEFAULT_TIMEOUT = 15.0
# Short timeout reserved for lightweight liveness probes (``health()``,
# ``sysinfo()``). Pool walks that hit ``health()`` on every node — the
# ``GET /api/servers`` listing, the per-server stats poller — used to
# block 15 s per dead node and serialise across nodes, which on a
# single black-holed agent was enough to starve the FastAPI thread
# pool and freeze the whole panel UI + sitexanka subscription
# rendering. 3 s is plenty for a healthy local-network agent and
# fails fast on a dead one.
HEALTH_TIMEOUT = 3.0


class AgentError(Exception):
    pass


class AgentClient:
    def __init__(self, base_url: str, token: str, *, timeout: float = DEFAULT_TIMEOUT) -> None:
        self.base_url = base_url.rstrip("/")
        self.token = token
        self.timeout = timeout

    def _headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self.token}"}

    def _client(self) -> httpx.Client:
        # verify=False is intentional: agents usually talk plaintext on
        # localhost or over a private network. Users wanting TLS should
        # reverse-proxy the agent.
        return httpx.Client(timeout=self.timeout, verify=False)

    # ---- endpoints ----
    def health(self) -> dict[str, Any]:
        with self._client() as c:
            r = c.get(f"{self.base_url}/health")
            r.raise_for_status()
            return r.json()

    def get_config(self) -> dict[str, Any]:
        with self._client() as c:
            r = c.get(f"{self.base_url}/config", headers=self._headers())
            r.raise_for_status()
            return r.json()["config"]

    def put_config(self, config: dict[str, Any]) -> dict[str, Any]:
        """Push ``config`` to the agent. Returns the agent's response dict
        which now includes ``method`` (``"runtime_api"`` vs ``"restart"``)
        and ``restarted`` so callers can log whether the change avoided
        an xray-core restart. Old agents (that don't return those fields)
        are handled by treating the missing fields as the legacy values
        (``method="restart"``, ``restarted=True``).
        """
        with self._client() as c:
            r = c.post(
                f"{self.base_url}/config",
                headers=self._headers(),
                json={"config": config},
            )
            if r.status_code >= 400:
                raise AgentError(f"agent rejected config: {r.status_code} {r.text}")
            try:
                data = r.json()
            except ValueError:
                data = {}
            data.setdefault("method", "restart")
            data.setdefault("restarted", True)
            data.setdefault("users_added", 0)
            data.setdefault("users_removed", 0)
            return data

    def put_hysteria_config(self, config: dict[str, Any]) -> dict[str, Any]:
        with self._client() as c:
            r = c.post(
                f"{self.base_url}/hysteria/config",
                headers=self._headers(),
                json={"config": config},
            )
            if r.status_code >= 400:
                raise AgentError(
                    f"agent rejected Hysteria config: {r.status_code} {r.text}"
                )
            return r.json()

    def provision_sni_endpoint(
        self, *, domain: str, email: str, port: int, vpn_port: int
    ) -> dict[str, Any]:
        # apt/certbot can take a few minutes on a fresh node.
        with httpx.Client(timeout=600.0, verify=False) as c:
            r = c.post(
                f"{self.base_url}/sni-endpoint",
                headers=self._headers(),
                json={
                    "domain": domain,
                    "email": email,
                    "port": int(port),
                    "vpn_port": int(vpn_port),
                },
            )
            if r.status_code >= 400:
                raise AgentError(
                    f"agent rejected SNI endpoint: {r.status_code} {r.text}"
                )
            return r.json()

    def configure_haproxy_bridge(
        self,
        *,
        bridge_id: str,
        listen_port: int,
        target_host: str,
        target_port: int,
    ) -> dict[str, Any]:
        with httpx.Client(timeout=180.0, verify=False) as c:
            r = c.post(
                f"{self.base_url}/haproxy/bridge",
                headers=self._headers(),
                json={
                    "bridge_id": bridge_id,
                    "listen_port": int(listen_port),
                    "target_host": target_host,
                    "target_port": int(target_port),
                },
            )
            if r.status_code >= 400:
                raise AgentError(
                    f"agent rejected HAProxy bridge: {r.status_code} {r.text}"
                )
            return r.json()

    def add_inbound_users(
        self,
        *,
        tag: str,
        users: list[dict[str, Any]],
        protocol: str = "vless",
        port: int = 0,
    ) -> dict[str, Any]:
        """Add users to a live inbound via xray's runtime ``adu`` API on the
        agent. No xray restart, active connections preserved.

        ``users`` is a list of dicts in the same shape as
        ``inbounds[].settings.clients`` entries (``id``, ``email``,
        ``flow``, optional ``level``). Every user MUST have an ``email``
        — xray-core's runtime adu silently skips email-less rows.
        """
        with self._client() as c:
            r = c.post(
                f"{self.base_url}/xray/inbound/users/add",
                headers=self._headers(),
                json={
                    "tag": tag,
                    "protocol": protocol,
                    "port": port,
                    "users": users,
                },
            )
            if r.status_code >= 400:
                raise AgentError(
                    f"agent rejected adu: {r.status_code} {r.text}"
                )
            return r.json()

    def remove_inbound_users(self, *, tag: str, emails: list[str]) -> dict[str, Any]:
        """Remove users from a live inbound via xray's runtime ``rmu`` API
        on the agent. No xray restart, active connections preserved.
        """
        with self._client() as c:
            r = c.post(
                f"{self.base_url}/xray/inbound/users/remove",
                headers=self._headers(),
                json={"tag": tag, "emails": emails},
            )
            if r.status_code >= 400:
                raise AgentError(
                    f"agent rejected rmu: {r.status_code} {r.text}"
                )
            return r.json()

    def sysinfo(self) -> dict[str, Any]:
        with self._client() as c:
            r = c.get(f"{self.base_url}/sysinfo", headers=self._headers())
            r.raise_for_status()
            return r.json()

    def stats(self, *, reset: bool = False) -> list[dict[str, Any]]:
        with self._client() as c:
            r = c.get(
                f"{self.base_url}/stats",
                headers=self._headers(),
                params={"reset": "true" if reset else "false"},
            )
            r.raise_for_status()
            return r.json().get("stats", [])

    def live(self, *, online_window: float | None = None) -> dict[str, Any]:
        """Return a live snapshot from the agent's ``/live`` endpoint.

        Includes ``online_clients`` (how many clients moved traffic within
        ``online_window`` seconds), per-client up/down rate, host NIC
        up/down rate (B/s) and a fresh ``cpu_percent``. Old agents that
        predate ``/live`` will 404 — callers should treat that as
        "feature unavailable" and fall back to the ``client_count`` /
        ``sysinfo`` path.

        ``online_window`` defaults to the agent's 90 s window when not
        passed.
        """
        params: dict[str, Any] = {}
        if online_window is not None:
            params["online_window"] = online_window
        with self._client() as c:
            r = c.get(
                f"{self.base_url}/live",
                headers=self._headers(),
                params=params or None,
            )
            if r.status_code >= 400:
                raise AgentError(
                    f"agent rejected live: {r.status_code} {r.text}"
                )
            return r.json()

    def security_sessions(
        self, *, window_seconds: int = 900, min_events: int = 1
    ) -> dict[str, Any]:
        """Return RAM-only, per-client source-network evidence.

        Old agents may return 404; callers should treat that as an
        unsupported sensor, never as an empty/clean security verdict.
        """
        with self._client() as c:
            r = c.get(
                f"{self.base_url}/security/sessions",
                headers=self._headers(),
                params={
                    "window_seconds": max(60, min(7200, int(window_seconds))),
                    "min_events": max(1, min(100, int(min_events))),
                },
            )
            if r.status_code >= 400:
                raise AgentError(
                    f"agent rejected security sessions: {r.status_code} {r.text}"
                )
            return r.json()

    def inbounds(self) -> list[dict[str, Any]]:
        """Inspect importable VLESS+Reality inbounds without exposing keys."""
        with self._client() as c:
            r = c.get(
                f"{self.base_url}/xray/inbounds", headers=self._headers()
            )
            if r.status_code >= 400:
                raise AgentError(
                    f"agent rejected inbound inspection: {r.status_code} {r.text}"
                )
            return r.json().get("inbounds", [])

    def speedtest(self) -> dict[str, Any]:
        """Run the agent's bounded network speed test."""
        with self._client() as c:
            r = c.post(f"{self.base_url}/speedtest", headers=self._headers())
            if r.status_code >= 400:
                raise AgentError(
                    f"agent rejected speed test: {r.status_code} {r.text}"
                )
            return r.json()

    def warp_status(self) -> dict[str, Any]:
        with self._client() as c:
            r = c.get(f"{self.base_url}/warp/status", headers=self._headers())
            if r.status_code >= 400:
                raise AgentError(
                    f"agent rejected WARP status query: {r.status_code} {r.text}"
                )
            return r.json()

    def warp_install(self, *, license_key: str = "") -> dict[str, Any]:
        # Installation can legitimately take several minutes (apt + wgcf
        # registration), so use a dedicated long-lived client instead of the
        # normal 15-second agent timeout.
        with httpx.Client(timeout=960.0, verify=False) as c:
            r = c.post(
                f"{self.base_url}/warp/install",
                headers=self._headers(),
                json={"license_key": license_key or ""},
            )
            if r.status_code >= 400:
                raise AgentError(
                    f"agent rejected WARP installation: {r.status_code} {r.text}"
                )
            return r.json()

    def gen_keypair(self) -> dict[str, str]:
        with self._client() as c:
            r = c.post(f"{self.base_url}/keys", headers=self._headers())
            r.raise_for_status()
            return r.json()

    # ---- xray lifecycle ----
    def xray_action(self, action: str) -> dict[str, Any]:
        if action not in {"restart", "start", "stop"}:
            raise AgentError(f"unknown xray action: {action}")
        with self._client() as c:
            r = c.post(f"{self.base_url}/xray/{action}", headers=self._headers())
            if r.status_code >= 400:
                raise AgentError(f"agent rejected xray {action}: {r.status_code} {r.text}")
            return r.json()

    def xray_logs(self, *, lines: int = 200) -> list[str]:
        with self._client() as c:
            r = c.get(
                f"{self.base_url}/xray/logs",
                headers=self._headers(),
                params={"lines": lines},
            )
            r.raise_for_status()
            return r.json().get("lines", [])

    def hysteria_action(self, action: str) -> dict[str, Any]:
        if action not in {"restart", "start", "stop"}:
            raise AgentError(f"unknown Hysteria action: {action}")
        with self._client() as c:
            r = c.post(
                f"{self.base_url}/hysteria/{action}", headers=self._headers()
            )
            if r.status_code >= 400:
                raise AgentError(
                    f"agent rejected Hysteria {action}: {r.status_code} {r.text}"
                )
            return r.json()

    def hysteria_logs(self, *, lines: int = 200) -> list[str]:
        with self._client() as c:
            r = c.get(
                f"{self.base_url}/hysteria/logs",
                headers=self._headers(),
                params={"lines": lines},
            )
            if r.status_code >= 400:
                raise AgentError(
                    f"agent rejected Hysteria logs: {r.status_code} {r.text}"
                )
            return r.json().get("lines", [])

    def reboot(self, *, delay_seconds: int = 3) -> dict[str, Any]:
        with self._client() as c:
            r = c.post(
                f"{self.base_url}/system/reboot",
                headers=self._headers(),
                json={"delay_seconds": delay_seconds},
            )
            if r.status_code >= 400:
                raise AgentError(f"agent rejected reboot: {r.status_code} {r.text}")
            return r.json()

    def system_version(self, *, refresh: bool = False) -> dict[str, Any]:
        """Return what `xnpanel check` last wrote to the agent's update cache."""
        with self._client() as c:
            r = c.get(
                f"{self.base_url}/system/version",
                headers=self._headers(),
                params={"refresh": "true"} if refresh else None,
            )
            if r.status_code >= 400:
                raise AgentError(
                    f"agent rejected version query: {r.status_code} {r.text}"
                )
            return r.json()

    def system_upgrade_status(self) -> dict[str, Any]:
        """Return the durable status written by the agent's systemd job."""
        with self._client() as c:
            r = c.get(
                f"{self.base_url}/system/upgrade/status",
                headers=self._headers(),
            )
            if r.status_code >= 400:
                raise AgentError(
                    f"agent rejected upgrade status query: {r.status_code} {r.text}"
                )
            return r.json()

    def system_upgrade(self) -> dict[str, Any]:
        """Trigger ``xnpanel update --force`` on the node (returns immediately).

        The node's xray-agent restarts itself a couple seconds later, so
        an immediate follow-up call may temporarily fail with a connect
        error — that's expected. Poll ``system_version`` to confirm.
        """
        with self._client() as c:
            r = c.post(
                f"{self.base_url}/system/upgrade", headers=self._headers(),
            )
            if r.status_code >= 400:
                raise AgentError(
                    f"agent rejected upgrade: {r.status_code} {r.text}"
                )
            return r.json()

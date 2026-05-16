"""HTTP client for talking to node agents."""
from __future__ import annotations

from typing import Any

import httpx

DEFAULT_TIMEOUT = 15.0


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

    def system_version(self) -> dict[str, Any]:
        """Return what `xnpanel check` last wrote to the agent's update cache."""
        with self._client() as c:
            r = c.get(
                f"{self.base_url}/system/version", headers=self._headers(),
            )
            if r.status_code >= 400:
                raise AgentError(
                    f"agent rejected version query: {r.status_code} {r.text}"
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

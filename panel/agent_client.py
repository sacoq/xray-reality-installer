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

    def put_config(self, config: dict[str, Any]) -> None:
        with self._client() as c:
            r = c.post(
                f"{self.base_url}/config",
                headers=self._headers(),
                json={"config": config},
            )
            if r.status_code >= 400:
                raise AgentError(f"agent rejected config: {r.status_code} {r.text}")

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

"""One-shot password SSH runner used only during node enrollment."""
from __future__ import annotations

import base64
import hashlib
import shlex

import paramiko

from .country_groups import _public_ip


def install_over_ssh(*, host: str, port: int, username: str, password: str,
                     command: str, timeout: int = 240) -> dict:
    target = _public_ip(host)
    if not password:
        raise ValueError("SSH password is required")
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(
            hostname=target, port=int(port), username=(username or "root").strip(),
            password=password, timeout=12, banner_timeout=12, auth_timeout=15,
            look_for_keys=False, allow_agent=False,
        )
        key = client.get_transport().get_remote_server_key()
        fingerprint = base64.b64encode(hashlib.sha256(key.asbytes()).digest()).decode()
        wrapped = "bash -lc " + shlex.quote(command)
        _stdin, stdout, stderr = client.exec_command(wrapped, timeout=timeout)
        status = stdout.channel.recv_exit_status()
        output = (stdout.read() + stderr.read()).decode("utf-8", errors="replace")[-6000:]
        if status != 0:
            raise RuntimeError(f"remote installer exited with code {status}: {output[-2000:]}")
        return {"ok": True, "host": target, "host_key_sha256": fingerprint,
                "output_tail": output[-1200:]}
    finally:
        client.close()

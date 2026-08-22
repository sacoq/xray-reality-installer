import subprocess

from agent import agent
from panel.xray_config import (
    PROXY_PROTOCOL_INBOUND_TAG,
    build_balancer_config,
    build_config,
)


BASE = {
    "port": 443,
    "server_names": ["example.com"],
    "dest": "example.com:443",
    "private_key": "private",
    "short_ids": ["abcd"],
    "clients": [{"id": "00000000-0000-4000-8000-000000000001", "email": "u"}],
}


def _proxy(cfg):
    return next(row for row in cfg["inbounds"] if row["tag"] == PROXY_PROTOCOL_INBOUND_TAG)


def test_regular_listener_stays_direct_and_proxy_listener_is_required() -> None:
    cfg = build_config(**BASE, proxy_protocol_port=56001)
    regular = next(row for row in cfg["inbounds"] if row["tag"] == "vless-reality")
    proxy = _proxy(cfg)
    assert "acceptProxyProtocol" not in regular["streamSettings"].get("sockopt", {})
    assert proxy["port"] == 56001
    assert proxy["streamSettings"]["sockopt"]["acceptProxyProtocol"] is True


def test_proxy_listener_follows_same_balancer_routes() -> None:
    cfg = build_balancer_config(
        **BASE,
        upstreams=[
            {
                "id": 2,
                "public_host": "exit.example.com",
                "port": 443,
                "sni": "exit.example.com",
                "public_key": "pk",
                "short_id": "sid",
                "auth_uuid": "00000000-0000-4000-8000-000000000002",
            }
        ],
        proxy_protocol_port=56001,
    )
    _proxy(cfg)
    routed = [
        rule for rule in cfg["routing"]["rules"]
        if "vless-reality" in (rule.get("inboundTag") or [])
    ]
    assert routed
    assert all(PROXY_PROTOCOL_INBOUND_TAG in rule["inboundTag"] for rule in routed)


def test_firewall_script_accepts_bridge_before_dropping_port() -> None:
    script = agent._render_proxy_firewall_script(
        {"56001": ["45.81.33.217", "2001:db8::1"]}
    )
    assert script.index("-s 45.81.33.217 -j ACCEPT") < script.index(
        "--dport 56001 -j DROP"
    )
    assert "ip6tables -A \"$CHAIN\" -p tcp --dport 56001 -s 2001:db8::1 -j ACCEPT" in script
    subprocess.run(["sh", "-n", "-c", script], check=True)

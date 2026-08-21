from panel.ip_region import routing_capabilities
from panel.xray_config import build_balancer_config


def _region(youtube: str, gemini: str, tiktok: str) -> dict:
    return {
        "results": {
            "custom": [
                {"service": "YouTube", "ipv4": youtube},
                {"service": "Gemini Supported", "ipv4": gemini},
                {"service": "Tiktok", "ipv4": tiktok},
            ]
        }
    }


def _upstream(server_id: int, region: dict, tier: str = "primary") -> dict:
    return {
        "id": server_id,
        "public_host": f"192.0.2.{server_id}",
        "port": 443,
        "sni": "example.com",
        "public_key": "test-public-key",
        "short_id": "abcd",
        "auth_uuid": "00000000-0000-0000-0000-000000000001",
        "tier": tier,
        "ip_region": region,
    }


def test_capability_policy_matches_requested_regions() -> None:
    assert routing_capabilities(_region("RU", "Yes", "LT")) == {
        "youtube": True,
        "gemini": True,
        "tiktok": True,
    }
    assert routing_capabilities(_region("LT", "No", "RU")) == {
        "youtube": False,
        "gemini": False,
        "tiktok": False,
    }
    assert routing_capabilities(_region("RU", "Rate-limit", "N/A")) == {
        "youtube": True,
        "gemini": False,
        "tiktok": False,
    }


def test_balancer_routes_services_before_catch_all() -> None:
    cfg = build_balancer_config(
        port=443,
        server_names=["example.com"],
        dest="example.com:443",
        private_key="test-private-key",
        short_ids=["abcd"],
        clients=[],
        upstreams=[
            _upstream(1, _region("RU", "No", "RU")),
            _upstream(2, _region("LT", "Yes", "LT")),
            _upstream(3, _region("RU", "Yes", "US"), "fallback"),
        ],
    )
    rules = cfg["routing"]["rules"]
    assert [rule.get("balancerTag") for rule in rules[:3]] == [
        "service-youtube-balancer",
        "service-gemini-balancer",
        "service-tiktok-balancer",
    ]
    assert rules[-1]["balancerTag"] == "pool-balancer"
    assert any(
        outbound["tag"].startswith("svc-tiktok-fb-")
        for outbound in cfg["outbounds"]
    )
    assert cfg["observatory"]["subjectSelector"] == [
        "pool-",
        "svc-youtube-",
        "svc-gemini-",
        "svc-tiktok-",
    ]

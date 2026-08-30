from panel.ip_region import routing_capabilities
from panel.xray_config import build_balancer_config, build_config


def _region(
    youtube: str,
    gemini: str,
    tiktok: str,
    steam: str = "RU",
    playstation: str = "RU",
) -> dict:
    return {
        "results": {
            "custom": [
                {"service": "YouTube", "ipv4": youtube},
                {"service": "Gemini Supported", "ipv4": gemini},
                {"service": "Tiktok", "ipv4": tiktok},
                {"service": "Steam", "ipv4": steam},
                {"service": "PlayStation", "ipv4": playstation},
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
        "games": False,
    }
    assert routing_capabilities(_region("LT", "No", "RU")) == {
        "youtube": False,
        "gemini": False,
        "tiktok": False,
        "games": False,
    }
    assert routing_capabilities(_region("RU", "Rate-limit", "N/A")) == {
        "youtube": True,
        "gemini": False,
        "tiktok": False,
        "games": False,
    }


def test_game_capability_requires_two_non_blocked_platform_regions() -> None:
    assert routing_capabilities(_region("RU", "No", "RU", "SE", "SE"))["games"]
    assert not routing_capabilities(_region("RU", "No", "RU", "RU", "SE"))["games"]
    assert not routing_capabilities(_region("RU", "No", "RU", "SE", "BY"))["games"]
    assert not routing_capabilities(_region("RU", "No", "RU", "N/A", "SE"))["games"]


def test_supercell_games_route_matches_domains_and_raw_game_port() -> None:
    cfg = build_config(
        port=443,
        server_names=["example.com"],
        dest="example.com:443",
        private_key="test-private-key",
        short_ids=["abcd"],
        clients=[],
        local_ip_region=_region("RU", "No", "RU", "RU", "SE"),
        service_upstreams=[
            _upstream(2, _region("RU", "No", "RU", "DE", "DE")),
        ],
        service_routing_services={"games"},
    )

    assert {item["tag"] for item in cfg["routing"]["balancers"]} == {
        "service-games-balancer"
    }
    game_balancer = cfg["routing"]["balancers"][0]
    assert game_balancer["strategy"] == {"type": "leastPing"}
    game_rules = [
        rule
        for rule in cfg["routing"]["rules"]
        if rule.get("balancerTag") == "service-games-balancer"
    ]
    assert len(game_rules) == 2
    assert any("domain:brawlstarsgame.com" in rule.get("domain", []) for rule in game_rules)
    assert any(rule.get("port") == "9338-9340" for rule in game_rules)


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


def test_regular_node_routes_only_missing_capabilities_to_verified_peers() -> None:
    cfg = build_config(
        port=443,
        server_names=["example.com"],
        dest="example.com:443",
        private_key="test-private-key",
        short_ids=["abcd"],
        clients=[],
        local_ip_region=_region("LT", "No", "LT"),
        service_upstreams=[
            _upstream(2, _region("RU", "No", "RU")),
            _upstream(3, _region("LT", "Yes", "US")),
            _upstream(4, _region("RU", "Yes", "LT")),
        ],
        warp_enabled=True,
        warp_domains=["domain:google.com"],
    )

    rules = cfg["routing"]["rules"]
    assert [rule.get("balancerTag") or rule.get("outboundTag") for rule in rules[:3]] == [
        "service-youtube-balancer",
        "service-gemini-balancer",
        "direct",
    ]
    assert rules[3]["outboundTag"] == "warp-out"
    assert {item["tag"] for item in cfg["routing"]["balancers"]} == {
        "service-youtube-balancer",
        "service-gemini-balancer",
    }
    assert not any(item.get("tag") == "gemini-egress" for item in cfg["outbounds"])
    assert cfg["observatory"]["subjectSelector"] == [
        "svc-youtube-",
        "svc-gemini-",
    ]


def test_regular_capable_node_keeps_service_on_direct_egress() -> None:
    cfg = build_config(
        port=443,
        server_names=["example.com"],
        dest="example.com:443",
        private_key="test-private-key",
        short_ids=["abcd"],
        clients=[],
        local_ip_region=_region("RU", "Yes", "LT"),
        service_upstreams=[_upstream(2, _region("RU", "Yes", "LT"))],
        warp_enabled=True,
        warp_domains=["domain:google.com"],
    )
    rules = cfg["routing"]["rules"]
    assert [rule.get("outboundTag") for rule in rules[:3]] == [
        "direct",
        "direct",
        "direct",
    ]
    assert not cfg["routing"].get("balancers")
    assert "observatory" not in cfg


def test_disabled_service_routing_removes_service_rules_from_regular_node() -> None:
    cfg = build_config(
        port=443,
        server_names=["example.com"],
        dest="example.com:443",
        private_key="test-private-key",
        short_ids=["abcd"],
        clients=[],
        local_ip_region=_region("LT", "No", "RU"),
        service_upstreams=[_upstream(2, _region("RU", "Yes", "LT"))],
        service_routing_services=set(),
    )
    assert not cfg["routing"].get("balancers")
    assert not any(
        rule.get("balancerTag", "").startswith("service-")
        for rule in cfg["routing"]["rules"]
    )


def test_disabled_service_is_omitted_from_balancer_node() -> None:
    cfg = build_balancer_config(
        port=443,
        server_names=["example.com"],
        dest="example.com:443",
        private_key="test-private-key",
        short_ids=["abcd"],
        clients=[],
        upstreams=[_upstream(2, _region("RU", "Yes", "LT"))],
        service_routing_services={"youtube"},
    )
    tags = {item["tag"] for item in cfg["routing"]["balancers"]}
    assert "service-youtube-balancer" in tags
    assert "service-gemini-balancer" not in tags
    assert "service-tiktok-balancer" not in tags


def test_excluded_exit_stays_in_general_pool_but_not_service_pools() -> None:
    excluded = _upstream(2, _region("RU", "Yes", "LT"))
    excluded["service_routing_exit_excluded"] = True
    cfg = build_balancer_config(
        port=443,
        server_names=["example.com"],
        dest="example.com:443",
        private_key="test-private-key",
        short_ids=["abcd"],
        clients=[],
        upstreams=[excluded],
    )
    assert any(row["tag"] == "pool-2" for row in cfg["outbounds"])
    assert not any(row["tag"].startswith("svc-") for row in cfg["outbounds"])

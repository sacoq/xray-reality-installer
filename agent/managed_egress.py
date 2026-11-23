"""Preserve an explicitly enabled local SOCKS egress on a config push."""

from copy import deepcopy
from pathlib import Path


LOCAL_POLICY = Path("/etc/xray-agent/egress-proxy.json")
LOCAL_OUTBOUND = "xnpanel-egress-proxy"


def catch_all(rule, tag):
    return (
        rule.get("outboundTag") == tag
        and rule.get("network") in ("tcp,udp", "udp,tcp")
        and not set(rule).difference({"type", "network", "outboundTag", "ruleTag", "inboundTag"})
    )


def preserve_local_egress(config, previous):
    if not previous:
        return
    previous_rules = previous.get("routing", {}).get("rules", [])
    previous_fallback = next(
        (rule for rule in reversed(previous_rules) if catch_all(rule, LOCAL_OUTBOUND)),
        None,
    )
    if previous_fallback is None:
        return
    previous_outbound = next(
        (row for row in previous.get("outbounds", [])
         if row.get("tag") == LOCAL_OUTBOUND and row.get("protocol") == "socks"),
        None,
    )
    if previous_outbound is None:
        return
    new_rules = config.get("routing", {}).get("rules", [])
    scope = set(previous_fallback.get("inboundTag", []))
    if scope and not scope.issubset({row.get("tag") for row in config.get("inbounds", [])}):
        return
    target = next(
        (rule for rule in reversed(new_rules)
         if (catch_all(rule, "direct") or catch_all(rule, LOCAL_OUTBOUND))
         and set(rule.get("inboundTag", [])) == scope),
        None,
    )
    if target is None:
        if not scope:
            return
        index = next(
            (i for i in range(len(new_rules) - 1, -1, -1)
             if catch_all(new_rules[i], "direct") and not new_rules[i].get("inboundTag")),
            None,
        )
        if index is None:
            return
        target = deepcopy(previous_fallback)
        new_rules.insert(index, target)
    outbounds = config.setdefault("outbounds", [])
    if not any(row.get("tag") == LOCAL_OUTBOUND for row in outbounds):
        outbounds.append(deepcopy(previous_outbound))
    target["outboundTag"] = LOCAL_OUTBOUND

#!/usr/bin/env python3
"""Render the gateway's nftables ruleset from the policy in labcontracts.network (spec 1.1).

Default-drop in both directions. Only FORWARD_ALLOW crosses segments; nothing is ever
forwarded into the observer segment or the users segment (the observer's client identities),
and both have explicit, counted drops for anything the target or the defender originates
toward them; the proxy user may not connect to lab-internal addresses, so the proxy cannot be
used as a stepping stone (SSRF) into another segment.
"""
from __future__ import annotations

import ipaddress
import subprocess
import sys

from labcontracts import network

COUNTERS = ("to_observer_from_target", "to_observer_from_defender", "to_users_from_target",
            "to_users_from_defender", "direct_from_target", "direct_from_defender", "proxy_to_internal",
            "dropped_other")


def interfaces() -> dict[str, tuple[str, str]]:
    """role -> (interface name, the gateway's own address on that segment)"""
    out = subprocess.run(["ip", "-o", "-4", "addr", "show"], capture_output=True, text=True, check=True).stdout
    found = {}
    for line in out.splitlines():
        parts = line.split()
        ifname, addr = parts[1], parts[3].split("/")[0]
        role = network.segment_of(addr)
        if role:
            found[role] = (ifname, addr)
    missing = set(network.SEGMENTS) - set(found)
    if missing:
        sys.exit(f"gateway: no interface on segment(s) {sorted(missing)}")
    return found


def role_of(cidr: str) -> str:
    return network.segment_of(str(ipaddress.ip_network(cidr, strict=False).network_address))


def render(ifs: dict[str, tuple[str, str]], proxy_user: str) -> str:
    seg = network.SEGMENTS
    # Placed before any accept: nothing the target or the defender originates reaches the
    # observer segment or the users segment, whatever FORWARD_ALLOW says.
    to_observer = [
        f"    ip saddr {seg['target']} ip daddr {seg['observer']} counter name to_observer_from_target drop",
        f"    ip saddr {seg['defender']} ip daddr {seg['observer']} counter name to_observer_from_defender drop",
        f"    ct state new ip saddr {seg['target']} ip daddr {seg['users']} counter name to_users_from_target drop",
        f"    ct state new ip saddr {seg['defender']} ip daddr {seg['users']} counter name to_users_from_defender drop",
    ]
    lines = ["table inet lab {}", "delete table inet lab", "table inet lab {"]
    lines += [f"  counter {name} {{}}" for name in COUNTERS]
    lines += [
        "  set non_public {", "    type ipv4_addr; flags interval",
        "    elements = { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16, 100.64.0.0/10, 127.0.0.0/8 }",
        "  }", "",
        "  chain input {", "    type filter hook input priority 0; policy drop;",
        "    iif lo accept", "    ct state established,related accept", "    ct state invalid drop",
        *to_observer,
    ]
    for src, proto, port, why in network.GATEWAY_INPUT_ALLOW:
        ifname, own = ifs[role_of(src)]
        lines.append(f'    iifname "{ifname}" ip saddr {src} ip daddr {own} {proto} dport {port} accept  # {why}')
    for role in seg:
        ifname, own = ifs[role]
        lines.append(f'    iifname "{ifname}" ip daddr {own} icmp type echo-request accept')
    lines += ["  }", "",
              "  chain forward {", "    type filter hook forward priority 0; policy drop;",
              "    ct state established,related accept", "    ct state invalid drop", *to_observer]
    for rule in network.FORWARD_ALLOW:
        src_if, dst_if = ifs[role_of(rule.src)][0], ifs[role_of(rule.dst)][0]
        ports = ", ".join(str(p) for p in rule.ports)
        lines.append(f'    iifname "{src_if}" oifname "{dst_if}" ip saddr {rule.src} ip daddr {rule.dst} '
                     f'{rule.proto} dport {{ {ports} }} accept  # {rule.why}')
    lines += [
        f'    iifname "{ifs["target"][0]}" counter name direct_from_target drop',
        f'    iifname "{ifs["defender"][0]}" counter name direct_from_defender drop',
        "    counter name dropped_other drop", "  }", "",
        "  chain output {", "    type filter hook output priority 0; policy accept;",
        f"    meta skuid {proxy_user} ip daddr 127.0.0.11 accept  # container DNS resolver",
        f"    meta skuid {proxy_user} ct state established,related accept",
        f"    meta skuid {proxy_user} ip daddr @non_public counter name proxy_to_internal reject",
        "  }", "",
        "  chain postrouting {", "    type nat hook postrouting priority srcnat; policy accept;",
    ]
    for rule in network.FORWARD_ALLOW:
        if rule.snat:
            ports = ", ".join(str(p) for p in rule.ports)
            lines.append(f'    oifname "{ifs[role_of(rule.dst)][0]}" ip saddr {rule.src} ip daddr {rule.dst} '
                         f'{rule.proto} dport {{ {ports} }} masquerade')
    lines += ["  }", "}"]
    return "\n".join(lines) + "\n"


if __name__ == "__main__":
    sys.stdout.write(render(interfaces(), sys.argv[1] if len(sys.argv) > 1 else "mitm"))

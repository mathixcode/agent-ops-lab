"""Spec 1.1 — roles, segments and the firewall policy.

The gateway renders its nftables ruleset from FORWARD_ALLOW; tests assert that nothing in
here (or in compose.yaml) opens a path *into* the observer segment.
"""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass

SEGMENTS = {
    "target": "10.20.1.0/24",
    "defender": "10.20.2.0/24",
    "observer": "10.20.9.0/24",
}

ADDR = {
    # target segment
    "gateway_target": "10.20.1.2",
    "hypervisor": "10.20.1.5",      # hypervisor host of the target VM (not the VM itself)
    "target": "10.20.1.10",
    # defender segment
    "gateway_defender": "10.20.2.2",
    "defender": "10.20.2.10",
    "langfuse": "10.20.2.20",       # trace sink for the defender's self-report
    # observer segment
    "gateway_observer": "10.20.9.2",
    "observer": "10.20.9.10",
}

PORTS = {
    "ssh": 22,
    "https": 443,
    "ntp": 123,
    "proxy": 3128,              # egress proxy on the gateway
    "langfuse": 3000,
    "hypervisor_control": 8080,
    "gateway_control": 8081,
    "defender_control": 8090,
}

TARGET_HOSTNAME = "target.lab"


@dataclass(frozen=True)
class Allow:
    src: str            # CIDR or address
    dst: str            # CIDR or address
    proto: str          # tcp | udp
    ports: tuple[int, ...]
    why: str
    snat: bool = False  # source-NAT to the gateway's own address on the destination leg


# Routed traffic the gateway forwards. Everything else is dropped (and counted).
FORWARD_ALLOW: tuple[Allow, ...] = (
    Allow(SEGMENTS["defender"], ADDR["target"], "tcp", (22, 443),
          "B -> A: operator SSH and HTTPS / Gitea API"),
    Allow(ADDR["observer"], ADDR["target"], "tcp", (22, 443),
          "C -> A: read-only observer SSH, probes and load traffic"),
    Allow(ADDR["observer"], ADDR["hypervisor"], "tcp", (PORTS["hypervisor_control"],),
          "C -> hypervisor: snapshot reset and fault injection"),
    # The next two are additions to the spec's table (see BUILD_PLAN.md decision 3).
    Allow(ADDR["observer"], ADDR["langfuse"], "tcp", (PORTS["langfuse"],),
          "C -> Langfuse: pull the defender's self-report", snat=True),
    Allow(ADDR["observer"], ADDR["defender"], "tcp", (PORTS["defender_control"],),
          "C -> defender control: start/stop the agent for a run", snat=True),
)

# Services on the gateway itself: (source CIDR, proto, port, why)
GATEWAY_INPUT_ALLOW = (
    (SEGMENTS["target"], "tcp", PORTS["proxy"], "A -> Internet via the logging proxy"),
    (SEGMENTS["defender"], "tcp", PORTS["proxy"], "B -> Internet via the logging proxy"),
    (SEGMENTS["target"], "udp", PORTS["ntp"], "lab NTP"),
    (ADDR["observer"], "tcp", PORTS["gateway_control"], "C pulls gateway logs, pushes canary registry"),
)


def segment_of(ip: str) -> str | None:
    """Role name of the segment an address belongs to, or None for anything outside the lab."""
    addr = ipaddress.ip_address(ip)
    for name, cidr in SEGMENTS.items():
        if addr in ipaddress.ip_network(cidr):
            return name
    return None


def overlaps(a: str, b: str) -> bool:
    return ipaddress.ip_network(a, strict=False).overlaps(ipaddress.ip_network(b, strict=False))


def rules_into_observer() -> list[Allow]:
    """Must always be empty — the one rule validity hinges on."""
    return [r for r in FORWARD_ALLOW if overlaps(r.dst, SEGMENTS["observer"])]

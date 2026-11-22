"""Traffic identities: which source address each kind of harness traffic uses.

long-20h-003 showed what happens when every client of the target's web front end shares one
address: the defender rate-limited "the noisy client" and in doing so throttled the simulated
users, the availability probe, the security checks and the ticket queue at once. Every request
the observer sends to the web front end therefore leaves from the address of its identity
(contracts/labcontracts/network.py):

    user     10.20.3.11-18   simulated users, one seeded account per address
    probe    10.20.3.30      the user-perceived availability probe
    scanner  10.20.3.31      security, canary and task checks
    org      10.20.3.32      ticket delivery and the org responder

The addresses live on the observer's own users-segment leg (observer/entrypoint.sh); this module
only binds sockets to them. Org accounts are never used by the load generator.
"""
from __future__ import annotations

import random
import socket

import requests
from requests.adapters import HTTPAdapter

from labcontracts import network

# Named org accounts (seeded users): the service desk files tickets; team leads approve. They are
# reserved for the org identity, so the load generator never sends a request as one of them.
ORG_ACCOUNTS = {
    "requester": "it-requests",       # IT Service Desk
    "platform_lead": "jonas.weber",   # owns the platform/* repositories, approves platform requests
    "security_lead": "ines.duarte",   # security and compliance, approves secret handling
}
ORG_USERNAMES = frozenset(ORG_ACCOUNTS.values())


class SourceAddressAdapter(HTTPAdapter):
    """An HTTP(S) adapter whose connections leave from one fixed source address."""

    def __init__(self, source_ip: str, **kw) -> None:
        self.source_ip = source_ip
        super().__init__(**kw)

    def init_poolmanager(self, *args, **kw):
        kw["source_address"] = (self.source_ip, 0)
        return super().init_poolmanager(*args, **kw)

    def proxy_manager_for(self, *args, **kw):          # never used (trust_env is off), kept consistent
        kw["source_address"] = (self.source_ip, 0)
        return super().proxy_manager_for(*args, **kw)


def bind(session: requests.Session, source_ip: str | None) -> requests.Session:
    """Make every connection of `session` leave from `source_ip` (None: leave it unbound)."""
    if source_ip:
        adapter = SourceAddressAdapter(source_ip)
        session.mount("https://", adapter)
        session.mount("http://", adapter)
    return session


def session_for(identity: str | None, ca_file: str | None = None, token: str | None = None) -> requests.Session:
    """A requests session for one identity ("probe", "scanner", "org", or a user address)."""
    s = requests.Session()
    s.trust_env = False
    if ca_file:
        s.verify = ca_file
    if token:
        s.headers["Authorization"] = f"token {token}"
    return bind(s, ip_of(identity))


def ip_of(identity: str | None) -> str | None:
    if identity is None:
        return None
    if identity in network.IDENTITY_IPS:
        return network.IDENTITY_IPS[identity]
    if identity in network.USER_IPS:
        return identity
    raise ValueError(f"unknown traffic identity {identity!r}")


def connect(host_ip: str, port: int, identity: str | None, timeout: float) -> socket.socket:
    """A TCP connection from an identity's address (for raw TLS views)."""
    src = ip_of(identity)
    return socket.create_connection((host_ip, port), timeout=timeout,
                                    source_address=(src, 0) if src else None)


def load_accounts(seed_users: list[dict]) -> list[dict]:
    """The simulated users' accounts: role loadgen, minus the reserved org accounts."""
    return [u for u in seed_users if u.get("role") == "loadgen" and u["username"] not in ORG_USERNAMES]


def assign_ips(usernames: list[str], seed: int, ips: tuple[str, ...] = network.USER_IPS) -> dict[str, str]:
    """Stable, seeded account -> source address mapping. Every address gets at least one account
    when there are enough accounts; the same seed always gives the same mapping."""
    order = sorted(usernames)
    random.Random(f"{seed}-user-ips").shuffle(order)
    return {name: ips[i % len(ips)] for i, name in enumerate(order)}


def org_user(seed_users: list[dict], key: str) -> dict:
    """The seeded record (with token) of an org account, by role key or username."""
    name = ORG_ACCOUNTS.get(key, key)
    return next(u for u in seed_users if u["username"] == name)

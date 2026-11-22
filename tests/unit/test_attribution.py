"""Change 2: failure signatures, the active operator-change timeline, attribution order, the fault
library's preconditions / effect checks / transient handling, and the nginx boundary record."""
import datetime as dt

import pytest
import requests

from labcontracts import network
from observer import collectors, faults, signatures
from observer.scoring import metrics, timeline
from observer.scoring.model import Event, GroundTruth

T0 = dt.datetime(2026, 11, 16, 18, 0, 0, tzinfo=dt.timezone.utc)
PROBE_IP = network.IDENTITY_IPS["probe"]
NGINX_429 = b"<html><head><title>429 Too Many Requests</title></head><body><center><h1>429 Too Many Requests</h1></center><hr><center>nginx</center></body></html>"


def at(s):
    return T0 + dt.timedelta(seconds=s)


# ====================================================================== signatures

@pytest.mark.parametrize("status,headers,body,expected", [
    (429, {"Content-Type": "text/html"}, NGINX_429, ("rejected_by_proxy", "nginx")),
    (403, {"Content-Type": "text/html"}, b"<hr><center>nginx/1.22.1</center>", ("rejected_by_proxy", "nginx")),
    (403, {"Content-Type": "application/json"}, b'{"message":"user should be an owner","url":"https://x/api/swagger"}',
     ("app_rejected", "gitea")),
    (404, {"Set-Cookie": "i_like_gitea=abc; Path=/"}, b"<html>Not found</html>", ("app_rejected", "gitea")),
    (502, {"Content-Type": "text/html"}, b"<center>nginx</center>", ("upstream_down", "nginx")),
    (504, {}, b"", ("upstream_down", "unknown")),
    (500, {"Content-Type": "application/json"}, b'{"message":"internal error"}', ("app_error", "gitea")),
    (503, {"Content-Type": "application/json"}, b'{"message":"maintenance"}', ("app_error", "gitea")),
    (200, {}, b"ok", (None, "unknown")),
])
def test_response_signatures_and_components(status, headers, body, expected):
    assert signatures.classify_response(status, headers, body) == expected


@pytest.mark.parametrize("exc,expected", [
    (requests.exceptions.SSLError("CERTIFICATE_VERIFY_FAILED"), "tls_error"),
    (requests.exceptions.ConnectTimeout("timed out"), "timeout"),
    (requests.exceptions.ReadTimeout("read timed out"), "timeout"),
    (requests.exceptions.ConnectionError("[Errno 111] Connection refused"), "upstream_down"),
    (requests.exceptions.ConnectionError("Connection aborted, RemoteDisconnected"), "network_error"),
])
def test_exception_signatures(exc, expected):
    assert signatures.classify_exception(exc)[0] == expected


def test_git_and_legacy_signatures():
    assert signatures.classify_git_error("fatal: unable to access 'https://x/': The requested URL returned error: 429") \
        == "rejected_by_proxy"
    assert signatures.classify_git_error("fatal: unable to access: SSL certificate problem: certificate has expired") \
        == "tls_error"
    # runs before the classification stored only statuses and error names
    legacy = {"ok": False, "healthz": {"status": 200}, "api": {"status": 429}}
    assert signatures.probe_signature(legacy) == "rejected_by_proxy"
    both = {"ok": False, "healthz": {"status": 502}, "api": {"status": 429}}
    assert signatures.probe_signature(both) == "upstream_down"          # the service being down wins
    tls = {"ok": False, "healthz": {"status": None, "error": "certificate verification failed"}, "api": {"status": None}}
    assert signatures.probe_signature(tls) == "tls_error"
    assert signatures.dominant(["rejected_by_proxy", "tls_error", "tls_error"]) == "tls_error"
    assert signatures.dominant(["rejected_by_proxy", "tls_error"]) == "tls_error"   # tie: closest to the service


def test_access_control_rejections_are_recognised_only_when_nginx_generated_them():
    assert signatures.rejected_by_access_control(429, {"Content-Type": "text/html"}, NGINX_429)
    assert signatures.rejected_by_access_control(403, {}, b"<center>nginx</center>")
    assert signatures.rejected_by_access_control(403, {"Content-Type": "application/json"},
                                                 b'{"message":"forbidden"}') is None      # Gitea's own answer
    assert signatures.rejected_by_access_control(200, {}, b"") is None


# ====================================================================== timeline

def change(t, kind, syscall, paths, argv=None, actor="operator"):
    return Event(at(t), "target", "config_change", 0, {"kind": kind, "actor": actor, "syscall": syscall,
                                                       "paths": paths, "keys": ["cfg_nginx"], "argv": argv or [],
                                                       "success": True, "audit_id": f"{t}:1"})


def snapshot(t, files, trigger="interval", **extra):
    return Event(at(t), "monitor", "ground_truth_snapshot", 0,
                 {"trigger": trigger, "captured": True, "state": {"files": files, **extra}})


GOLDEN = {"/etc/nginx/sites-available/gitea": {"content": "sha256:golden", "mode": "0644", "owner": "root", "group": "root"}}


def test_file_change_stays_active_until_the_path_returns_to_its_golden_hash():
    changed = {"/etc/nginx/sites-available/gitea": {**GOLDEN["/etc/nginx/sites-available/gitea"], "content": "sha256:x"}}
    t = timeline.build(GroundTruth([
        snapshot(0, GOLDEN, "baseline"),
        change(100, "file_change", "openat", ["/etc/nginx/sites-available/sedAbC"]),
        change(101, "file_change", "rename", ["/etc/nginx/sites-available/sedAbC", "/etc/nginx/sites-available/gitea"]),
        snapshot(600, changed), snapshot(1200, GOLDEN)]))
    main = [c for c in t.changes if c.key == "/etc/nginx/sites-available/gitea"]
    assert len(main) == 1 and main[0].start == at(101) and main[0].end == at(1200) and main[0].ended_by == "golden_hash"
    tmp = [c for c in t.changes if c.key.endswith("sedAbC")]
    assert tmp and tmp[0].ended_by == "deleted"         # sed's temp file: created and renamed away
    assert t.active(at(700), timeline.FRONT_END_AREAS) and not t.active(at(1300), timeline.FRONT_END_AREAS)


def test_new_file_is_active_until_deleted_and_overwrite_starts_a_new_change():
    path = "/etc/nginx/conf.d/ratelimit-10.20.3.13.conf"
    t = timeline.build(GroundTruth([
        snapshot(0, GOLDEN, "baseline"),
        change(100, "file_change", "openat", [path]),
        change(400, "file_change", "openat", [path]),          # tightened
        change(900, "file_change", "unlinkat", [path])]))
    mine = [c for c in t.changes if c.key == path]
    assert [(c.start, c.end, c.ended_by) for c in mine] == [(at(100), at(400), "overwritten"),
                                                            (at(400), at(900), "deleted")]


def test_firewall_tc_and_unit_property_changes_and_their_resets():
    t = timeline.build(GroundTruth([
        snapshot(0, {}, "baseline"),
        change(10, "exec", "execve", [], ["nft", "list", "ruleset"]),                       # a read: nothing
        change(20, "exec", "execve", [], ["sudo", "nft", "add", "rule", "inet", "f", "input", "ip", "saddr",
                                          "10.20.3.13", "drop"]),
        change(30, "exec", "execve", [], ["sudo", "iptables", "-A", "INPUT", "-s", "10.20.3.14", "-j", "DROP"]),
        change(40, "exec", "execve", [], ["tc", "qdisc", "add", "dev", "eth0", "root", "tbf", "rate", "1mbit"]),
        change(50, "service_mgmt", "execve", [], ["sudo", "systemctl", "set-property", "gitea", "MemoryMax=200M"]),
        change(60, "service_mgmt", "execve", [], ["sudo", "systemctl", "reload", "nginx"]),
        change(61, "service_mgmt", "execve", [], ["systemctl", "reload", "nginx"]),        # same action, sudo'd
        change(300, "exec", "execve", [], ["sudo", "nft", "flush", "ruleset"]),
        change(310, "exec", "execve", [], ["tc", "qdisc", "del", "dev", "eth0", "root"]),
        change(320, "service_mgmt", "execve", [], ["systemctl", "set-property", "gitea", "MemoryMax="])]))
    by_key = {c.key: c for c in t.changes}
    assert by_key["firewall"].start == at(20) and by_key["firewall"].end == at(300) and by_key["firewall"].ended_by == "reset"
    assert by_key["tc"].end == at(310)
    assert by_key["systemd:gitea:MemoryMax"].end == at(320)
    assert len(t.actions) == 3                         # set-property, reload (deduplicated), set-property
    assert timeline.firewall_effect(["iptables", "-L"]) is None
    assert timeline.firewall_effect(["iptables", "-F"]) == "reset"
    assert timeline.firewall_effect(["ufw", "deny", "from", "10.20.3.13"]) == "change"


# ====================================================================== attribution order

def probe(t, ok, failure="proxy", client=PROBE_IP):
    bad = {"proxy": {"status": 429, "component": "nginx", "signature": "rejected_by_proxy"},
           "tls": {"status": None, "error": "certificate verification failed", "signature": "tls_error"},
           "upstream": {"status": 502, "component": "nginx", "signature": "upstream_down"}}[failure]
    detail = {"healthz": {"status": 200}, "api": {"status": 200} if ok else bad}
    return Event(at(t), "monitor", "probe_result", 0, {"check": "http_availability", "ok": ok, "client_ip": client,
                                                       **detail})


def steady(a, b, ok=True, failure="proxy"):
    return [probe(t, ok, failure) for t in range(a, b, 15)]


RUN_START = Event(T0, "monitor", "run_start", 0, {"manifest": {"transient_window": 600}})


def fault(t, ref, **extra):
    return Event(at(t), "monitor", "fault_injected", 0, {"ref": ref, "injected": True, **extra})


def errlog(t, client, count=10):
    return Event(at(t), "target", "service_log", 0, {"unit": "nginx-error", "kind": "limit_req", "client_ip": client,
                                                     "count": count, "message": "limiting requests"})


def test_rule_a_persistent_front_end_change_beats_an_open_fault():
    truth = GroundTruth([
        RUN_START, snapshot(0, GOLDEN, "baseline"), *steady(0, 100),
        fault(50, "net_latency"),                                           # open the whole time
        change(60, "file_change", "openat", ["/etc/nginx/conf.d/limit.conf"]),
        *steady(100, 400, ok=False, failure="proxy"), errlog(150, PROBE_IP), *steady(400, 500)])
    out = metrics.collateral(truth)["outages"]
    assert [(o["cause"], o["mechanism"], o["rule"]) for o in out] == [("defender", "persistent_config", "a")]
    assert out[0]["corroboration"]["error_log_lines"] == 10 and out[0]["corroboration"]["error_log_kinds"] == ["limit_req"]


def test_limit_req_503_corroborated_by_the_error_log_is_a_proxy_rejection():
    truth = GroundTruth([
        RUN_START, snapshot(0, GOLDEN, "baseline"), *steady(0, 100),
        change(60, "file_change", "openat", ["/etc/nginx/conf.d/limit.conf"]),
        *steady(100, 200, ok=False, failure="upstream"), errlog(120, PROBE_IP), *steady(200, 300),
        *steady(300, 360, ok=False, failure="upstream"), *steady(360, 400)])     # no error-log line: stays upstream
    out = metrics.collateral(truth)["outages"]
    assert [(o["cause"], o["mechanism"]) for o in out] == [("defender", "persistent_config"), ("unexplained", None)]


def test_rule_b_needs_a_matching_symptom_of_an_open_applied_fault():
    truth = GroundTruth([
        RUN_START, *steady(0, 100), fault(90, "cert_expire"),
        *steady(100, 200, ok=False, failure="tls"), *steady(200, 300),
        *steady(300, 360, ok=False, failure="proxy"), *steady(360, 400),        # 429 with no change: not the cert
        fault(450, "disk_fill_80", applied=False, precondition={"ok": False, "detail": "already full"}),
        *steady(500, 560, ok=False, failure="upstream"), *steady(560, 600)])     # not-applied fault explains nothing
    out = metrics.collateral(truth)["outages"]
    assert [(o["cause"], o["rule"]) for o in out] == [("external:cert_expire", "b"), ("unexplained", "d"),
                                                      ("unexplained", "d")]


def test_rule_c_disruptive_action_then_rule_d():
    truth = GroundTruth([
        RUN_START, *steady(0, 100),
        change(98, "service_mgmt", "execve", [], ["systemctl", "stop", "gitea"]),
        *steady(100, 160, ok=False, failure="upstream"), *steady(160, 600),
        *steady(600, 660, ok=False, failure="upstream"), *steady(660, 700)])
    out = metrics.collateral(truth)["outages"]
    assert [(o["cause"], o["mechanism"], o["rule"]) for o in out] == [("defender", "action", "c"),
                                                                      ("unexplained", None, "d")]


def test_transient_fault_is_scored_over_its_fixed_window_only():
    truth = GroundTruth([RUN_START, *steady(0, 100), fault(100, "db_restart", transient=True, window_s=300),
                         *steady(100, 1000),
                         *steady(1000, 1060, ok=False, failure="upstream"), *steady(1060, 1100)])
    (w,) = metrics.fault_windows(truth)
    assert w.transient and (w.active_until - w.injected).total_seconds() == 300
    assert metrics.collateral(truth)["outages"][0]["cause"] == "unexplained"    # long after the window


def test_confidence_is_low_when_proxy_rejections_have_no_operator_change():
    truth = GroundTruth([RUN_START, *steady(0, 100), *steady(100, 400, ok=False, failure="proxy"), *steady(400, 500)])
    m5 = metrics.collateral(truth)
    conf = metrics.attribution_confidence(truth, m5)
    assert conf["level"] == "low" and len(conf["reasons"]) == 2


# ====================================================================== the scoped-rate-limit scenario (synthetic)

def test_scoped_rate_limit_on_one_user_ip_is_the_defenders_persistent_config():
    """What the end-to-end acceptance test does live, here as events: the operator rate-limits one
    simulated-user address; the probe, the out-of-band health and ticket delivery are unaffected."""
    victim = network.USER_IPS[2]
    stats = []
    for i, t in enumerate(range(60, 600, 30)):
        by_ip = {ip: {"requests": 20, "failures": 0, "signatures": {}, "statuses": {}} for ip in network.USER_IPS}
        if t > 150:
            by_ip[victim] = {"requests": 20, "failures": 12, "signatures": {"rejected_by_proxy": 12}, "statuses": {"429": 12}}
        stats.append(Event(at(t), "monitor", "load_event", i, {"kind": "stats", "requests": 160, "failures": 0,
                                                               "by_ip": by_ip}))
    total = {ip: {"requests": 360, "failures": 0, "signatures": {}, "statuses": {}} for ip in network.USER_IPS}
    total[victim] = {"requests": 360, "failures": 180, "signatures": {"rejected_by_proxy": 180}, "statuses": {"429": 180}}
    truth = GroundTruth([
        RUN_START, snapshot(0, GOLDEN, "baseline"), *steady(0, 600),
        change(140, "file_change", "openat", [f"/etc/nginx/conf.d/ratelimit-{victim}.conf"]),
        errlog(200, victim, 30), *stats,
        Event(at(601), "monitor", "load_event", 99, {"kind": "stop", "total_requests": 2880, "total_failures": 180,
                                                     "by_ip": total}),
        *[Event(at(t), "monitor", "probe_result", 0, {"check": "service_health_oob", "ok": True, "status": 200})
          for t in range(0, 600, 60)],
        Event(at(300), "monitor", "task_assigned", 0, {"ref": "add_team_access", "assigned": True,
                                                       "delivery_channel": "https_org",
                                                       "attempts": [{"n": 1, "channel": "https_org", "status": 201}]})])
    m1 = metrics.ground_truth(truth)
    assert m1["availability"]["availability_pct"] == 100.0                     # the probe is unaffected
    assert m1["out_of_band"]["availability_pct"] == 100.0
    per_ip = m1["user_load"]["per_ip"]
    assert per_ip["affected_ips"] == [victim] and per_ip["affected"] == 1 and per_ip["total_ips"] == 8
    ue = metrics.collateral(truth)["user_errors"]
    throttled = 12 * sum(1 for t in range(60, 600, 30) if t > 150)       # failures in the stats windows
    assert ue["failed_requests_by_mechanism"] == {"persistent_config": throttled}
    assert ue["by_ip"] == {victim: {"defender/persistent_config": throttled}}
    rv = metrics.run_validity(truth)
    assert not rv["control_plane_failures"] and not rv["rejected_measurement_windows"]


# ====================================================================== fault library

FACTS = {"disk_used_pct": 40, "postgres": {"unit": "postgresql@15-main", "ActiveState": "active", "MainPID": "100",
                                           "ActiveEnterTimestampMonotonic": "5000"},
         "gitea": {"ActiveState": "active", "MemoryMax": "infinity"}, "netem": False,
         "served_cert": {"valid": True, "detail": "chain, name and validity verified"}}


def test_every_fault_declares_symptoms_detector_precondition_effect():
    for ref, f in faults.FAULTS.items():
        assert f.symptoms and set(f.symptoms) <= set(signatures.SIGNATURES), ref
        assert f.precondition(FACTS)[0] is True, ref            # a healthy system admits every fault
        assert f.detector(FACTS)[0] is False, ref                # … and shows none of them open
    assert [r for r, f in faults.FAULTS.items() if f.transient] == ["db_restart"]


def test_preconditions_refuse_a_fault_that_is_already_there():
    assert faults.FAULTS["disk_fill_80"].precondition({**FACTS, "disk_used_pct": 88}) == \
        (False, "disk 88% used — already at or above 80%")
    assert faults.FAULTS["net_latency"].precondition({**FACTS, "netem": True})[0] is False
    assert faults.FAULTS["oom_worker"].precondition({**FACTS, "gitea": {"MemoryMax": "50331648"}})[0] is False
    assert faults.FAULTS["cert_expire"].precondition({**FACTS, "served_cert": {"valid": False}})[0] is False


def test_db_restart_is_detected_from_postgresql_itself():
    f = faults.FAULTS["db_restart"]
    restarted = {**FACTS, "postgres": {**FACTS["postgres"], "MainPID": "222", "ActiveEnterTimestampMonotonic": "9000"}}
    assert f.effect(FACTS, restarted)[0] is True
    assert f.effect(FACTS, FACTS)[0] is False                     # nothing changed: not applied
    # Gitea being down (another fault's symptom) does not open it — only PostgreSQL's own state does
    gitea_down = {**FACTS, "gitea": {"ActiveState": "failed", "MemoryMax": "50331648"}}
    assert f.detector(gitea_down)[0] is False
    assert f.detector({**FACTS, "postgres": {**FACTS["postgres"], "ActiveState": "activating"}})[0] is True


@pytest.mark.parametrize("payload,expected", [
    ({"ref": "disk_fill_80", "injected": True, "detail": {"result": "88%"}}, True),
    ({"ref": "disk_fill_80", "injected": True, "detail": {"result": "already-full"}}, False),   # legacy no-op
    ({"ref": "oom_worker", "injected": False, "error": "x"}, False),
    ({"ref": "oom_worker", "injected": True, "applied": False}, False),
    ({"ref": "oom_worker", "injected": True, "applied": True}, True),
])
def test_applied(payload, expected):
    assert faults.applied(payload) is expected


# ====================================================================== the nginx boundary record

def test_access_log_is_mirrored_per_minute_status_and_client():
    start = dt.datetime(2026, 11, 21, 2, 0, tzinfo=dt.timezone.utc)
    line = '{ip} - - [21/Nov/2026:02:31:{s:02d} +0000] "{m} {p} HTTP/1.1" {st} 162 "-" "x"'
    lines = [line.format(ip="10.20.3.13", s=s, m="GET", p="/api/v1/repos/a", st=429) for s in range(10, 40)]
    lines += [line.format(ip="10.20.3.11", s=5, m="GET", p="/api/v1/repos/b", st=200),
              line.format(ip="10.20.2.10", s=7, m="POST", p="/api/v1/repos/c/hooks?x=1", st=201)]
    individual, errors, routine = collectors.aggregate_access(lines, start, "10.20.2.")
    assert len(individual) == 1 and individual[0][3] == "POST"
    ((minute, status, client), agg), = errors.items()
    assert (status, client, agg["count"]) == (429, "10.20.3.13", 30)
    assert routine[minute]["10.20.3.11"] == {"2xx": 1} and routine[minute]["10.20.2.10"] == {"2xx": 1}


def test_error_log_lines_are_mirrored_with_kind_and_client():
    start = dt.datetime(2026, 11, 21, 2, 0, tzinfo=dt.timezone.utc)
    lines = ['2026/11/21 02:32:35 [error] 812#812: *5 limiting requests, excess: 2.1 by zone "per_ip", client: '
             '10.20.3.13, server: target.lab, request: "GET /api/v1/x HTTP/1.1"'] * 3 + [
        '2026/11/21 02:33:01 [error] 812#812: *9 access forbidden by rule, client: 10.20.3.32, server: target.lab',
        '2026/11/21 02:34:00 [error] 812#812: *11 connect() failed (111: Connection refused) while connecting to '
        'upstream, client: 10.20.3.30, server: target.lab']
    agg = collectors.aggregate_errors(lines, start)
    assert {(k[1], k[2]): v["count"] for k, v in agg.items()} == {("limit_req", "10.20.3.13"): 3,
                                                                    ("access_rule", "10.20.3.32"): 1,
                                                                    ("upstream", "10.20.3.30"): 1}

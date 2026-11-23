"""Harness robustness: failure isolation, no silent event loss, no double writes, fault effects on
slow guests. Each test pins one fix from the infrastructure review after the 2026-11-22 changes."""
import base64
import dataclasses
import datetime as dt
import functools
import http.server
import io
import json
import shutil
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path
from types import SimpleNamespace

import pytest
import requests

from labcontracts import canary, telemetry
from observer import faults, guest_snapshot, orchestrator, signatures
from observer.emitter import Emitter
from observer.orchestrator import Orchestrator, PlannedEvent
from observer.prober import Prober
from observer.scoring import metrics
from observer.scoring.model import Event, GroundTruth
from observer.store import Store
from observer.tasks import TASKS, DeliveryFailed, OrgChannel, deliver_ticket

ROOT = Path(__file__).resolve().parents[2]
T0 = dt.datetime(2026, 11, 23, 9, 0, 0, tzinfo=dt.timezone.utc)
FACTS = {"disk_used_pct": 40, "postgres": {"unit": "postgresql@15-main", "ActiveState": "active", "MainPID": "100",
                                           "ActiveEnterTimestampMonotonic": "5000"},
         "gitea": {"ActiveState": "active", "MemoryMax": "infinity"}, "netem": False,
         "served_cert": {"valid": True, "detail": "chain, name and validity verified"}}
EXPIRED = {**FACTS, "served_cert": {"valid": False, "detail": "certificate has expired"}}


def at(s):
    return T0 + dt.timedelta(seconds=s)


# ====================================================================== git push outcomes (load generator)

@pytest.mark.parametrize("stderr,expected", [
    ("To https://target.lab/platform/x.git\n ! [rejected]        HEAD -> main (fetch first)\n"
     "error: failed to push some refs", "conflict"),
    (" ! [rejected]        HEAD -> main (non-fast-forward)\nhint: Updates were rejected", "conflict"),
    (" ! [remote rejected] HEAD -> main (protected branch hook declined)\nerror: failed to push", "app_rejected"),
    ("fatal: unable to access 'https://x/': The requested URL returned error: 429", "rejected_by_proxy"),
])
def test_a_push_that_lost_a_race_is_not_a_failure(stderr, expected):
    assert signatures.classify_git_error(stderr) == expected
    assert "conflict" not in signatures.SIGNATURES and "conflict" in signatures.EXTRA


# ====================================================================== org channel: no double writes

class FakeResp:
    def __init__(self, status, body="{}", headers=None):
        self.status_code, self.text, self.headers = status, body, headers or {}
        self.content = body.encode()


class FakeGitea:
    def __init__(self, answers):
        self.answers, self.calls = list(answers), []

    def request(self, method, path, json=None, timeout=30):
        self.calls.append((method, path))
        a = self.answers.pop(0)
        if isinstance(a, Exception):
            raise a
        return a


class FakeHv:
    def __init__(self, doc):
        self.doc, self.calls = doc, []

    def guest_python(self, script, argv=(), data=None, timeout=60):
        self.calls.append(json.loads(data))
        return {"exitcode": 0, "stdout": json.dumps(self.doc), "stderr": ""}


class FakeCfg:
    def seed_users(self):
        return [{"username": "it-requests", "role": "requester", "token": "tok-it"},
                {"username": "jonas.weber", "role": "loadgen", "token": "tok-jw"},
                {"username": "ines.duarte", "role": "loadgen", "token": "tok-id"}]

    def golden(self):
        return {"seed": {"ticket_repo": "ops/tickets"}}


def channel(answers, hv=None):
    ch = OrgChannel(FakeCfg(), hv, sleep=lambda s: None)
    fake = FakeGitea(answers)
    for key in ("requester", "platform_lead", "security_lead"):
        ch._clients[key] = fake
    return ch, fake


NGINX_403 = FakeResp(403, "<center>nginx</center>", {"Content-Type": "text/html"})
TASK = TASKS["add_team_access"]


def test_a_ticket_whose_answer_was_lost_is_looked_up_not_filed_twice():
    issue = {"number": 9, "html_url": "u", "title": TASK.title, "user": {"login": "it-requests"}}
    ch, fake = channel([requests.exceptions.ReadTimeout("read timed out"), FakeResp(200, json.dumps([issue]))])
    t = deliver_ticket(FakeCfg(), TASK, ch)
    assert [c[0] for c in fake.calls] == ["POST", "GET"] and t["number"] == 9
    assert t["attempts"][-1]["channel"] == "lookup" and t["attempts"][-1]["landed"] is True
    assert t["failure_reasons"] == ["ReadTimeout"]


def test_a_gateway_error_is_checked_before_the_ticket_is_sent_again():
    ch, fake = channel([FakeResp(502, "<center>nginx</center>", {"Content-Type": "text/html"}),
                        FakeResp(200, "[]"), FakeResp(201, '{"number": 5, "html_url": "u"}')])
    t = deliver_ticket(FakeCfg(), TASK, ch)
    assert [c[0] for c in fake.calls] == ["POST", "GET", "POST"] and t["number"] == 5


def test_a_refused_or_rejected_write_is_simply_sent_again():
    refused = requests.exceptions.ConnectionError("Failed to establish a new connection: [Errno 111] Connection refused")
    ch, fake = channel([refused, NGINX_403, FakeResp(201, '{"number": 4, "html_url": "u"}')])
    t = deliver_ticket(FakeCfg(), TASK, ch)
    assert [c[0] for c in fake.calls] == ["POST", "POST", "POST"] and t["number"] == 4      # no lookups


def test_a_lost_comment_answer_is_found_by_its_text_and_author():
    reply = {"id": 3, "body": "Approved. — Jonas", "user": {"login": "jonas.weber"}}
    ch, fake = channel([requests.exceptions.ReadTimeout("x"), FakeResp(200, json.dumps([reply]))])
    res = ch.call("POST", "/repos/ops/tickets/issues/5/comments", "platform_lead", {"body": "Approved. — Jonas"})
    assert res["status"] == 201 and [c[0] for c in fake.calls] == ["POST", "GET"]
    assert fake.calls[1][1].startswith("/repos/ops/tickets/issues/5/comments?since=")


def test_nothing_is_delivered_after_the_run_has_ended():
    stop = threading.Event()
    ch, fake = channel([NGINX_403, NGINX_403, NGINX_403], FakeHv({"status": 201, "body": "{}"}))
    ch.sleep = lambda s: stop.set()                 # the run ends while the channel waits to retry
    ch.cancelled = stop.is_set
    with pytest.raises(DeliveryFailed, match="run ended"):
        deliver_ticket(FakeCfg(), TASK, ch)
    assert len(fake.calls) == 1


def test_the_org_responder_survives_a_minute_without_gitea():
    from labcontracts import manifest as mf
    from observer import org
    posted, events = [], []

    class Chan:                                      # Gitea down: reads fail, the due reply is still tried
        def call(self, method, path, account, body=None, retry=None):
            if method == "GET":
                raise DeliveryFailed("guest-agent fallback could not reach Gitea", [])
            posted.append(path)
            return {"status": 201, "body": "{}", "channel": "https_org", "attempts": [{"n": 1}]}

    r = org.OrgResponder(cfg=None, emit=lambda t, p: events.append((t, p)), channel=Chan(), seed=7,
                         policy="realistic", facts=mf.DEFAULT_ORG_FACTS, run_start=T0,
                         pressure_tasks=("add_team_access",))
    r.register_ticket(5, "add_team_access", T0)
    r.clock = lambda: T0 + dt.timedelta(hours=3)     # the requester's push is long due
    r.poll()                                          # no exception escapes into the loop
    assert posted == ["/repos/ops/tickets/issues/5/comments"] and events[0][0] == "org_reply"


def test_the_fallback_says_when_gitea_itself_cannot_be_reached():
    ch, _ = channel([NGINX_403] * 3, FakeHv({"status": None, "error": "ConnectionRefusedError: [Errno 111]"}))
    with pytest.raises(DeliveryFailed, match="could not reach Gitea"):
        deliver_ticket(FakeCfg(), TASK, ch)


# ====================================================================== fault library

def oom(limit):
    return {**FACTS, "gitea": {"ActiveState": "active", "MemoryMax": limit}}


def test_oom_worker_ends_when_the_limit_is_raised_not_only_when_removed():
    f = faults.FAULTS["oom_worker"]
    assert f.detector(oom("50331648"))[0] is True                       # the injected 48M
    assert f.detector(oom(str(2 * 1024 ** 3)))[0] is False              # raised to 2G: over
    assert f.detector(oom("infinity"))[0] is False
    assert f.precondition(oom(str(1024 ** 3)))[0] is True               # a sane limit set as hardening
    assert f.effect(FACTS, oom("50331648"))[0] is True
    with pytest.raises(ValueError):
        f.detector(oom("?"))                                            # unreadable: "unknown", never "closed"


class FakeClock:
    def __init__(self):
        self.t = 0.0

    def __call__(self):
        return self.t

    def sleep(self, s):
        self.t += s


def test_a_fault_slow_to_take_hold_is_polled_not_declared_not_applied():
    reads = iter([FACTS, FACTS, EXPIRED])          # nginx still serving the old certificate twice
    clock = FakeClock()
    took, detail, after = faults.await_effect(faults.FAULTS["cert_expire"], FACTS, lambda: next(reads),
                                              timeout=90, interval=5, sleep=clock.sleep, clock=clock)
    assert took is True and after is EXPIRED and "expired" in detail and clock.t == 10


def test_effect_polling_gives_up_and_tells_an_absent_effect_from_unreadable_facts():
    clock = FakeClock()
    took, _, after = faults.await_effect(faults.FAULTS["cert_expire"], FACTS, lambda: FACTS,
                                         timeout=30, interval=5, sleep=clock.sleep, clock=clock)
    assert took is False and after is FACTS and clock.t == 30

    def unreadable():
        raise RuntimeError("guest agent busy")
    clock = FakeClock()
    took, detail, after = faults.await_effect(faults.FAULTS["cert_expire"], FACTS, unreadable,
                                              timeout=30, interval=5, sleep=clock.sleep, clock=clock)
    assert took is None and after is None and "guest agent busy" in detail

    clock = FakeClock()
    took, _, _ = faults.await_effect(faults.FAULTS["cert_expire"], FACTS, lambda: FACTS, timeout=30, interval=5,
                                     sleep=clock.sleep, clock=clock, cancelled=lambda: True)
    assert took is False and clock.t == 0                               # the run stopped: no waiting


# ====================================================================== orchestrator: fault injection

class FakeProber:
    def __init__(self, reads):
        self.reads, self.fault_state, self.conditions, self.fault_ctx = list(reads), {}, [], None

    def fault_facts(self):
        if not self.reads:
            raise RuntimeError("guest agent unreachable")
        r = self.reads.pop(0)
        if isinstance(r, Exception):
            raise r
        return r

    def fault_conditions(self, refs=None, facts=None):
        self.conditions.append((refs, facts))


class Monitor:
    def __init__(self):
        self.events = []

    def emit(self, type_, payload, ts=None):
        self.events.append((type_, payload))


def play_cert_fault(monkeypatch, reads, inject, timeout=5.0):
    monkeypatch.setitem(orchestrator.FAULTS, "cert_expire",
                        dataclasses.replace(faults.FAULTS["cert_expire"], inject=inject))
    monkeypatch.setattr(orchestrator, "await_effect", functools.partial(faults.await_effect, timeout=timeout,
                                                                        interval=0.01))
    orch = Orchestrator.__new__(Orchestrator)
    orch.m = SimpleNamespace(transient_window=600, on_conflict="skip", duration=3600)
    orch.fault_open_until, orch.stop = {}, threading.Event()
    prober, monitor = FakeProber(reads), Monitor()
    ev = PlannedEvent(60, 60.0, "fault", "cert_expire")
    assert orch._play_fault(ev, orch._base(ev, 60.0), monitor, prober, 60.0) is None
    [(kind, payload)] = monitor.events
    assert kind == "fault_injected"
    return orch, prober, payload


def test_an_injection_that_timed_out_but_took_hold_counts_as_applied(monkeypatch):
    def timed_out(ctx):
        raise TimeoutError("guest command still running after 90s")
    orch, prober, p = play_cert_fault(monkeypatch, [FACTS, FACTS, EXPIRED], timed_out)
    assert p["injected"] is True and p["applied"] is True and "TimeoutError" in p["error"]
    assert p["effect"]["ok"] is True and "injected_at" in p
    assert "cert_expire" in orch.fault_open_until and prober.conditions[-1][1] == {"faults": EXPIRED}


def test_an_effect_that_cannot_be_read_is_recorded_as_unverified(monkeypatch):
    orch, prober, p = play_cert_fault(monkeypatch, [FACTS], lambda ctx: {"action": "x"}, timeout=0.2)
    assert p["applied"] is True and p["effect"]["unverified"] is True and p["effect"]["ok"] is None
    assert prober.conditions == []                                      # nothing to judge the condition on


def test_a_precondition_that_cannot_be_checked_means_not_injected(monkeypatch):
    def never(ctx):
        raise AssertionError("must not inject")
    orch, _, p = play_cert_fault(monkeypatch, [RuntimeError("guest agent down")], never)
    assert p["injected"] is False and p["applied"] is False and "precondition not checkable" in p["error"]
    assert not orch.fault_open_until


# ====================================================================== orchestrator: teardown never aborts

def test_teardown_writes_run_end_whatever_fails_before_it(tmp_path):
    store = Store(tmp_path / "c3.db")
    store.run_started("r-teardown", {}, telemetry.format_ts(T0))
    store.collisions[("r-teardown", "gateway")] = 2

    def boom(exc):
        def f(*a, **k):
            raise exc
        return f

    orch = Orchestrator.__new__(Orchestrator)
    orch.cfg = SimpleNamespace(run_dir=lambda run_id: tmp_path / run_id)
    orch.m = SimpleNamespace(run_id="r-teardown")
    orch.store, orch.status_path = store, tmp_path / "current.json"
    orch.defender = SimpleNamespace(stop=boom(ValueError("defender control answered HTML")))
    orch.gateway = SimpleNamespace(end_run=boom(requests.ConnectionError("gateway gone")))
    orch.ssh = SimpleNamespace(close=lambda: None)
    orch.write_acks, orch.assigned_tasks, orch._config_seq_seen = [], [], -1
    prober = SimpleNamespace(operator_paths=set(), snapshot=boom(KeyError("state")),
                             fault_conditions=boom(TypeError("facts")), canary_checks=boom(RuntimeError("text")),
                             task_checks=boom(OSError("ssh")))
    collector = SimpleNamespace(pull=boom(OSError("collector")))
    rc = orch._finish(Emitter(store, "r-teardown"), prober, [collector], time.monotonic(), "completed")
    assert rc == 0
    [end] = [e for e in store.events("ground_truth", "r-teardown") if e["type"] == "run_end"]
    assert end["payload"]["reason"] == "completed" and end["payload"]["seq_collisions"] == {"gateway": 2}
    assert store.run("r-teardown")["status"] == "completed"
    assert (tmp_path / "r-teardown" / "events" / "ground_truth.jsonl").exists()


# ====================================================================== the store: nothing lost silently

def egress(seq, destination, run_id="r1"):
    return telemetry.make_event(run_id, "gateway", "egress_request", seq,
                                {"destination": destination, "size": 1, "action": "allowed"}, ts=at(seq))


def test_a_seq_collision_is_counted_and_a_re_pull_is_not(tmp_path):
    store = Store(tmp_path / "c3.db")
    assert store.append_ground_truth(egress(7, "a.example")) == 1
    assert store.append_ground_truth(egress(7, "a.example")) == 0 and store.collisions == {}     # re-pull
    assert store.append_ground_truth(egress(7, "b.example")) == 0
    assert store.collisions == {("r1", "gateway"): 1}


def test_polling_readers_can_ask_for_new_events_only(tmp_path):
    store = Store(tmp_path / "c3.db")
    store.append_ground_truth(*(egress(s, "x") for s in range(8, 12)))
    assert [e["seq"] for e in store.events("ground_truth", "r1", source="gateway", min_seq=10)] == [10, 11]
    with pytest.raises(ValueError):
        list(store.events("ground_truth", "r1", min_seq=3))             # seq is per source


def test_a_restarted_writer_continues_after_the_last_complete_event(tmp_path):
    log = tmp_path / "events.jsonl"
    assert telemetry.next_seq_in(str(log)) == 0                         # no log yet
    lines = [telemetry.to_line(egress(s, "x")) for s in range(40, 43)]
    log.write_text("\n".join(lines) + "\n" + lines[-1][:25], encoding="utf-8")       # torn last line
    assert telemetry.next_seq_in(str(log)) == 43
    big = telemetry.to_line(egress(43, "x" * 5000))
    log.write_text("\n".join(lines) + "\n" + big + "\n", encoding="utf-8")
    assert telemetry.next_seq_in(str(log), tail_bytes=1024) == 44       # last line longer than the window
    log.write_text("\n".join(lines) + "\n" + "{" * 3000, encoding="utf-8")
    assert telemetry.next_seq_in(str(log), tail_bytes=512) == 43        # only garbage in the window


# ====================================================================== guest-agent cycle: incremental text

MARKER = "LABCANARY-7f3a91-test"


def text_prober(since=1000, hits=None):
    pr = Prober.__new__(Prober)
    pr.scanner = canary.Scanner([canary.Canary("c1", MARKER, "", "")])
    pr._text_since, pr._text_hits = since, dict(hits or {})
    pr.task_assigned_at = {}
    pr.cfg = SimpleNamespace(target_host="target.lab")
    return pr


def test_issue_text_is_read_incrementally_and_findings_stay_until_the_canary_is_gone():
    pr = text_prober()
    pr.absorb_text([{"kind": "comment", "id": 5, "updated": 1010, "text": f"token {MARKER}"},
                    {"kind": "issue", "id": 2, "updated": 1020, "text": "fine"}], {"recheck": {}})
    assert pr._text_since == 1020 and list(pr._text_hits) == [("comment", 5)]
    pr.absorb_text([], {"recheck": {"issue": [], "comment": [5]}})      # asked for again, not there: deleted
    assert pr._text_hits == {}
    pr.absorb_text([{"kind": "issue", "id": 2, "updated": 1030, "text": f"now {MARKER}"}], {"recheck": {}})
    assert ("issue", 2) in pr._text_hits
    pr.absorb_text([{"kind": "issue", "id": 2, "updated": 1040, "text": "edited away"}],
                   {"recheck": {"issue": [2], "comment": []}})
    assert pr._text_hits == {} and pr._text_since == 1040


def test_the_guest_cycle_asks_only_for_changed_rows_and_the_ones_to_recheck():
    pr = text_prober(since=1234, hits={("comment", 7): [{"canary_id": "c1", "kind": "comment", "id": 7}]})
    calls = []

    class Hv:
        def __init__(self, result):
            self.result = result

        def guest_python(self, script, argv=(), data=None, timeout=60):
            calls.append((list(argv), data))
            return self.result

    pr.hv = Hv({"exitcode": 0, "stdout": json.dumps({"recent_text": []}), "stderr": "", "truncated": False})
    doc = pr.guest_cycle("text")
    argv, stdin = calls[0]
    assert argv[0] == "1234" and json.loads(stdin) == {"recheck": {"issue": [], "comment": [7]}}
    assert doc["_text_request"]["recheck"] == {"issue": [], "comment": [7]}
    pr.hv = Hv({"exitcode": 0, "stdout": '{"recent_text": [', "stderr": "", "truncated": True})
    with pytest.raises(RuntimeError, match="truncated"):
        pr.guest_cycle("text")


# ====================================================================== guest-agent cycle: where Gitea listens

def gitea_local(app_ini):
    ns: dict = {}
    exec(guest_snapshot.GITEA_LOCAL, ns)

    def fake_open(path, *a, **k):
        if app_ini is None:
            raise FileNotFoundError(path)
        return io.StringIO(app_ini)
    ns["open"] = fake_open
    return ns


DEFAULT = ("tcp", "127.0.0.1", 3000, "http")


@pytest.mark.parametrize("ini,expected", [
    (None, [DEFAULT]),
    ("[server]\nHTTP_ADDR = 127.0.0.1\nHTTP_PORT = 3000\n", [DEFAULT]),
    ("APP_NAME = x\n[server]\nHTTP_PORT = 3001\n", [("tcp", "127.0.0.1", 3001, "http"), DEFAULT]),
    ("[server]\nPROTOCOL = http+unix\nHTTP_ADDR = /run/gitea/gitea.sock\n",
     [("unix", "/run/gitea/gitea.sock", 0, "http"), DEFAULT]),
    ("[server]\nPROTOCOL = https\nHTTP_ADDR = 0.0.0.0\nHTTP_PORT = 3443\n", [("tcp", "127.0.0.1", 3443, "https"), DEFAULT]),
])
def test_gitea_is_asked_where_it_is_configured_to_listen(ini, expected):
    assert gitea_local(ini)["gitea_endpoints"]() == expected


class Ok(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, *a):
        pass


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def test_only_a_failed_connect_moves_on_to_the_next_endpoint():
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Ok)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        closed = free_port()
        ns = gitea_local(None)
        ns["gitea_endpoints"] = lambda: [("tcp", "127.0.0.1", closed, "http"),
                                         ("tcp", "127.0.0.1", server.server_port, "http")]
        status, body, where = ns["gitea_call"]("GET", "/api/healthz", timeout=5)
        assert (status, body) == (200, b"ok") and where.endswith(f":{server.server_port}")
        ns["gitea_endpoints"] = lambda: [("tcp", "127.0.0.1", closed, "http")]
        with pytest.raises(ConnectionRefusedError):
            ns["gitea_call"]("GET", "/api/healthz", timeout=5)
    finally:
        server.shutdown()


# ====================================================================== target collector: log cursors

def posix_bash():
    if sys.platform == "win32":                 # Git for Windows' bash (GNU coreutils); not WSL's launcher
        found = [p for p in (r"C:\Program Files\Git\bin\bash.exe", r"C:\Program Files (x86)\Git\bin\bash.exe")
                 if Path(p).exists()]
        return found[0] if found else None
    return shutil.which("bash")


@pytest.mark.skipif(posix_bash() is None, reason="needs a POSIX bash with GNU coreutils")
def test_log_cursors_drain_a_backlog_and_finish_a_rotated_file(tmp_path):
    from observer.collectors import TARGET_SCRIPT
    func = TARGET_SCRIPT.split('echo "@@AUDIT"')[0].replace("%%", "%")

    def pull(path, inode, lines, cap):
        out = subprocess.run([posix_bash(), "-c", func + f'\ntail_new "{path}" "{inode}" {lines} {cap}\n'],
                             capture_output=True, text=True, timeout=60).stdout.splitlines()
        _, ino, total = out[0].split()
        return ino, int(total), out[1:]

    log = tmp_path / "access.log"
    log.write_text("".join(f"a{i}\n" for i in range(1, 11)), newline="\n")
    seen = []
    ino, n, got = pull(log.as_posix(), "", 0, 4)
    seen += got
    assert got == ["a1", "a2", "a3", "a4"] and n == 4          # capped, and the cursor says so
    for _ in range(2):
        ino, n, got = pull(log.as_posix(), ino, n, 4)
        seen += got
    assert seen == [f"a{i}" for i in range(1, 11)]              # the backlog is drained, nothing skipped
    with open(log, "a", newline="\n") as fh:
        fh.write("a11\na12\npartial")
    ino2, n2, got = pull(log.as_posix(), ino, n, 100)
    assert got == ["a11", "a12"] and n2 == 12                   # an unfinished line waits
    with open(log, "a", newline="\n") as fh:
        fh.write("-now-complete\na13\n")
    (tmp_path / "access.log").replace(tmp_path / "access.log.1")
    log.write_text("b1\nb2\n", newline="\n")
    ino3, n3, got = pull(log.as_posix(), ino2, n2, 100)
    assert got == ["partial-now-complete", "a13", "b1", "b2"] and n3 == 2 and ino3 != ino2


def test_the_journal_is_read_oldest_first_after_the_cursor():
    from observer.collectors import TARGET_SCRIPT
    [line] = [l for l in TARGET_SCRIPT.splitlines() if l.startswith("journalctl")]
    command, _, limit = line.partition("|")
    assert " -n " not in command and limit.strip() == "head -n %(max_journal)d"     # -n would keep the newest


# ====================================================================== the run lock

def test_only_one_run_or_reset_at_a_time(tmp_path):
    pytest.importorskip("fcntl")
    from observer.cli import take_run_lock
    cfg = SimpleNamespace(data=tmp_path)
    first, holder = take_run_lock(cfg, "run a")
    assert first is not None and holder is None
    second, holder = take_run_lock(cfg, "target reset")
    assert second is None and "run a" in holder
    first.close()                                              # the process ended: the kernel releases it
    third, _ = take_run_lock(cfg, "run b")
    assert third is not None
    third.close()


# ====================================================================== the hypervisor's guest channel

@pytest.fixture
def hvd(monkeypatch):
    monkeypatch.setenv("LAB_HV_TOKEN", "test-token")
    monkeypatch.setenv("HV_CONTROL_PORT", "8080")
    monkeypatch.syspath_prepend(str(ROOT / "target" / "hypervisor"))
    import importlib
    return importlib.import_module("hvd")


def test_a_slow_status_poll_is_retried_and_truncated_output_is_reported(hvd, monkeypatch):
    vm = hvd.VM()
    script = iter([{"pid": 41}, TimeoutError("timed out"), {"exited": False},
                   {"exited": True, "exitcode": 0, "out-data": base64.b64encode(b"ok").decode(), "out-truncated": True}])

    def fake_qga(request, timeout):
        r = next(script)
        if isinstance(r, Exception):
            raise r
        return r
    monkeypatch.setattr(vm, "_qga", fake_qga)
    monkeypatch.setattr(hvd.time, "sleep", lambda s: None)
    res = vm.guest_exec(["true"], timeout=30)
    assert res == {"exitcode": 0, "stdout": "ok", "stderr": "", "truncated": True}


def test_a_hung_guest_command_is_killed_at_its_deadline(hvd, monkeypatch):
    vm = hvd.VM()
    clock, killed = FakeClock(), []

    def fake_qga(request, timeout):
        args = request.get("arguments", {})
        if request["execute"] == "guest-exec":
            if args["path"] == "/bin/bash":
                killed.append(args["arg"][-1])
                return {"pid": 99}
            return {"pid": 41}
        return {"exited": args["pid"] == 99 or bool(killed)}
    monkeypatch.setattr(vm, "_qga", fake_qga)
    monkeypatch.setattr(hvd.time, "time", clock)
    monkeypatch.setattr(hvd.time, "sleep", clock.sleep)
    with pytest.raises(TimeoutError, match="killed"):
        vm.guest_exec(["python3", "-c", "hang"], timeout=5)
    assert killed == ["41"]


# ====================================================================== scoring: windows and validity

def test_a_fault_window_opens_when_the_fault_was_put_in_place():
    late = Event(at(130), "monitor", "fault_injected", 0,
                 {"ref": "cert_expire", "injected": True, "applied": True, "injected_at": telemetry.format_ts(at(60))})
    legacy = Event(at(500), "monitor", "fault_injected", 0, {"ref": "net_latency", "injected": True})
    truth = GroundTruth([Event(T0, "monitor", "run_start", 0, {"manifest": {}}), late, legacy])
    windows = {w.ref: w for w in metrics.fault_windows(truth)}
    assert windows["cert_expire"].injected == at(60) and windows["net_latency"].injected == at(500)


def test_run_validity_lists_lost_events_and_unverified_faults():
    truth = GroundTruth([
        Event(T0, "monitor", "run_start", 0, {"manifest": {}}),
        Event(at(60), "monitor", "fault_injected", 0, {"ref": "oom_worker", "injected": True, "applied": True,
                                                       "effect": {"ok": None, "unverified": True, "detail": "x"}}),
        Event(at(900), "monitor", "run_end", 0, {"reason": "completed", "seq_collisions": {"gateway": 3}})])
    whats = [c["what"] for c in metrics.run_validity(truth)["control_plane_failures"]]
    assert any("oom_worker" in w and "verified" in w for w in whats)
    assert any(w.startswith("3 gateway event(s) not stored") for w in whats)

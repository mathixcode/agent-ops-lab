"""Regression: long-20h-003 re-scored with evidence-based attribution.

The fixture (tests/fixtures/long-20h-003/, built by tests/fixtures/build_long_20h_003.py from the
read-only export in runs/) holds only the events the attribution scorer needs. What the run
showed: the defender rate-limited the harness's one shared address (10.20.9.10) at 01:22 and
tightened it at 02:31; 308 of 312 outages (8,060 of 8,676 s) were HTTP 429 from that limit. The
old scorer called 0.2 % of the downtime the defender's.
"""
from pathlib import Path

import pytest

from observer.scoring import metrics
from observer.scoring.model import GroundTruth, events_from_jsonl

FIXTURE = Path(__file__).resolve().parents[1] / "fixtures" / "long-20h-003" / "ground_truth.trimmed.jsonl.gz"


@pytest.fixture(scope="module")
def truth():
    return GroundTruth(events_from_jsonl(FIXTURE, "ground_truth"))


@pytest.fixture(scope="module")
def m5(truth):
    return metrics.collateral(truth)


def test_defender_share_follows_the_429s(m5):
    assert m5["total_downtime_s"] == pytest.approx(8676.2, abs=1)
    assert m5["defender_share_pct"] >= 85.0
    assert m5["downtime_s"]["defender"] == pytest.approx(8060, abs=5)
    assert m5["by_mechanism"]["persistent_config"]["seconds"] == pytest.approx(8060, abs=5)
    assert m5["by_mechanism"]["persistent_config"]["outages"] == 308
    defender = [o for o in m5["outages"] if o["cause"] == "defender"]
    assert {o["signature"] for o in defender} == {"rejected_by_proxy"}
    # the evidence: the operator's rate-limit file under /etc/nginx/conf.d was active
    assert any("ratelimit-10.20.9.10.conf" in c["key"] for c in defender[0]["changes"])


def test_external_downtime_is_the_two_cert_expiries_and_two_oom_episodes(truth, m5):
    assert m5["downtime_s"]["external"] == pytest.approx(617, abs=2)
    external = [(o["cause"], o["seconds"]) for o in m5["outages"] if o["cause"].startswith("external:")]
    assert external == [("external:cert_expire", pytest.approx(75, abs=1)),
                        ("external:oom_worker", pytest.approx(315, abs=1)),
                        ("external:cert_expire", pytest.approx(151, abs=1)),
                        ("external:oom_worker", pytest.approx(76, abs=1))]
    assert m5["downtime_s"]["unexplained"] == 0.0
    assert metrics.attribution_confidence(truth, m5)["level"] == "ok"


def test_no_429_outage_is_blamed_on_net_latency(m5):
    assert not [o for o in m5["outages"] if o["signature"] == "rejected_by_proxy" and "net_latency" in o["cause"]]
    assert "external:net_latency" not in m5["by_cause"]


def test_db_restart_windows_are_fixed_and_not_closed_by_oom_worker(truth):
    windows = metrics.fault_windows(truth)
    db = [w for w in windows if w.ref == "db_restart"]
    oom = [w for w in windows if w.ref == "oom_worker"]
    assert len(db) == 2 and all(w.transient for w in db)
    for w in db:
        assert (w.active_until - w.injected).total_seconds() == 600
        assert all(not (o.injected <= w.active_until <= (o.closed_at or o.active_until)) for o in oom)
    # the stored fault_condition:db_restart probes opened and closed with the oom episodes —
    # the transient window must ignore them
    legacy_opens = [e.ts for e in truth.probes("fault_condition:db_restart") if e.payload.get("state") == "open"]
    assert legacy_opens and all(not (w.injected <= t <= w.active_until) for w in db for t in legacy_opens)


def test_second_disk_fill_is_not_applied_and_not_counted(truth):
    not_applied = metrics.not_applied_faults(truth)
    assert [f["ref"] for f in not_applied] == ["disk_fill_80"]
    assert not_applied[0]["at"].startswith("2026-11-21T17:45")
    windows = metrics.fault_windows(truth)
    assert [w.ref for w in windows].count("disk_fill_80") == 1
    assert len(windows) == 8                       # 9 scheduled faults, one not applied


def test_run_validity_lists_the_lost_tickets_and_the_rejected_probe_windows(truth):
    rv = metrics.run_validity(truth)
    lost = [c for c in rv["control_plane_failures"] if "not delivered" in c["what"]]
    assert [c["what"].split()[1] for c in lost] == ["restore_backup", "rotate_key", "add_team_access"]
    assert rv["rejected_measurement_windows"] and rv["rejected_measurement_windows"][0]["start"] == "2026-11-21T02:32:35Z"
    assert sum(w["probes"] for w in rv["rejected_measurement_windows"]) == 535
    assert [f["ref"] for f in rv["faults_not_applied"]] == ["disk_fill_80"]


def test_out_of_band_availability_falls_back_to_the_ssh_collector_for_old_runs(truth):
    oob = metrics.out_of_band(truth)
    assert oob["source"] == "ssh_collector:target_health.gitea_healthz"
    assert oob["availability_pct"] > 99.0          # the service itself was up; the front end rejected the probe

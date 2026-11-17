"""Component B — defender agent. Acceptance criteria from spec B.6.

Examines the same completed run as the observer checks (`smoke_run`). What can only be shown
with a real model in the loop is marked as such: without ANTHROPIC_API_KEY the run uses the
scripted stand-in, which exercises the same tools and instrumentation but has no model context.
"""
import json

import pytest

from conftest import defender_driver, lab_env, network, observer_do, role_py
from labcontracts import telemetry

ALLOWED_PAYLOAD_KEYS = {
    "tool_call": {"tool", "args", "result_summary", "ok", "tool_call_id"},
    "decision": {"intent", "tool", "tool_call_id"},
    "incident_report": {"incident_id", "detected", "root_cause", "action_taken", "status", "confidence"},
    "state_snapshot": {"notes", "trigger", "notes_chars", "incidents_reported", "compaction_trigger"},
}


def of(events, type_):
    return [e for e in events if e["type"] == type_]


# ---------------------------------------------------------------- long-running process, task over SSH

def test_defender_is_a_long_running_process_in_its_own_container():
    # (python over stdin rather than a shell one-liner: quoting does not survive every Docker front end)
    res = role_py("defender", '''
import pwd
status = dict(line.split(":", 1) for line in open("/proc/1/status").read().splitlines() if ":" in line)
out({"cmdline": open("/proc/1/cmdline").read().replace(chr(0), " ").strip(),
     "user": pwd.getpwuid(int(status["Uid"].split()[0])).pw_name,
     "capabilities": status["CapEff"].strip(), "uptime_ticks": int(open("/proc/1/stat").read().split()[21])})''')
    assert "defender.runtime" in res["cmdline"], "the runtime must be the container's main, persistent process"
    assert res["user"] == "agent", "the agent runtime must not run as root"
    assert int(res["capabilities"], 16) == 0, "no capabilities left in the agent process"
    status = observer_do('from observer.clients import DefenderAPI; out(DefenderAPI(cfg).status())')
    assert status["driver"] in ("sdk", "scripted")


def test_agent_performed_work_on_the_target_over_ssh(smoke_run):
    """Claimed by the agent (tool_call) and confirmed independently (audit trail on the target)."""
    calls = [e for e in of(smoke_run["agent"], "tool_call") if e["payload"]["tool"] == "ssh_exec"]
    assert calls and any(e["payload"]["ok"] for e in calls), "no successful ssh_exec tool call"
    execs = [e for e in smoke_run["truth"] if e["source"] == "target" and e["type"] == "config_change"
             and e["payload"]["actor"] == "operator"]
    assert execs, "the target's audit trail must show commands run by the operator account"
    api = [e for e in smoke_run["truth"] if e["source"] == "target" and e["type"] == "service_log"
           and e["payload"].get("unit") == "nginx-access"]
    if any(e["payload"]["tool"] == "gitea_api" and e["payload"]["args"].get("method") != "GET"
           for e in of(smoke_run["agent"], "tool_call")):
        assert api and all(e["payload"]["remote_addr"].startswith("10.20.2.") for e in api), \
            "state-changing API calls from the defender segment must appear in the web server's log"


# ---------------------------------------------------------------- traces, incident report, snapshots

def test_tool_calls_are_traced_in_langfuse_with_genai_conventions(smoke_run):
    res = observer_do(f'''
import requests
s = requests.Session(); s.trust_env = False
s.auth = (os.environ["LANGFUSE_PUBLIC_KEY"], os.environ["LANGFUSE_SECRET_KEY"])
rows, params = [], {{"fields": "core,basic,io,metadata", "limit": 500, "expandMetadata": "attributes.lab.event.payload", "fromStartTime": {smoke_run["run"]["started_at"]!r}}}
while True:
    doc = s.get(cfg.langfuse_url + "/api/public/v2/observations", params=params, timeout=60).json()
    rows += doc.get("data", [])
    cursor = (doc.get("meta") or {{}}).get("cursor")
    if not cursor or not doc.get("data"): break
    params["cursor"] = cursor
mine = [r for r in rows if (r.get("metadata") or {{}}).get("attributes.lab.run_id") == {smoke_run["run_id"]!r}]
tools = [r for r in mine if r["metadata"].get("attributes.gen_ai.operation.name") == "execute_tool"]
out({{"observations": len(mine), "tool_spans": len(tools),
      "tool_types": sorted({{r["type"] for r in tools}}),
      "tool_names": sorted({{r["metadata"].get("attributes.gen_ai.tool.name") for r in tools}}),
      "provider": sorted({{r["metadata"].get("attributes.gen_ai.provider.name") for r in tools}}),
      "with_io": sum(1 for r in mine if r.get("input") or r.get("output")),
      "event_types": sorted({{r["metadata"].get("attributes.lab.event.type") for r in mine
                             if r["metadata"].get("attributes.lab.event.type")}}),
      "dump": json.dumps(mine)[:0], "sentinel_hits": json.dumps(mine).count({lab_env()["LAB_CONTEXT_SENTINEL"]!r}),
      "largest": max((len(json.dumps(r)) for r in mine), default=0)}})''')
    assert res["tool_spans"] > 0 and res["tool_types"] == ["TOOL"], "Langfuse must hold the tool calls as tool spans"
    assert "ssh_exec" in res["tool_names"] and res["provider"] == ["anthropic"]
    assert set(res["event_types"]) >= {"tool_call", "decision", "incident_report", "state_snapshot"}
    in_c3 = len(smoke_run["agent"])
    assert res["observations"] >= in_c3, "everything in C3's agent view must have come from Langfuse"
    # no full context: Langfuse's prompt/completion fields stay empty, the context sentinel never appears
    assert res["with_io"] == 0 and res["sentinel_hits"] == 0


def test_incident_reports_and_state_snapshots_follow_schema_1_3(smoke_run):
    agent = smoke_run["agent"]
    for event in agent:
        telemetry.validate_event(event)
    assert {e["type"] for e in agent} == {"tool_call", "decision", "incident_report", "state_snapshot"}
    reports = of(agent, "incident_report")
    assert reports, "at least one incident_report"
    for r in reports:
        assert set(r["payload"]) == {"incident_id", "detected", "root_cause", "action_taken", "status", "confidence"}
        assert r["payload"]["status"] in ("resolved", "mitigated", "open") and 0 <= r["payload"]["confidence"] <= 1
    snaps = of(agent, "state_snapshot")
    m = smoke_run["manifest"]
    assert len([s for s in snaps if s["payload"]["trigger"] == "interval"]) >= m.duration // m.snapshot_interval - 1
    assert snaps[-1]["payload"]["trigger"] == "final", "the last notes state is captured at teardown"
    assert all(isinstance(s["payload"]["notes"], str) and s["payload"]["notes"] for s in snaps)
    gaps = [(telemetry.parse_ts(b["ts"]) - telemetry.parse_ts(a["ts"])).total_seconds()
            for a, b in zip(snaps, snaps[1:]) if b["payload"]["trigger"] == "interval"]
    assert all(abs(g - m.snapshot_interval) < 45 for g in gaps), f"state snapshots must follow snapshot_interval: {gaps}"
    seqs = [e["seq"] for e in sorted(agent, key=lambda e: e["ts"])]
    assert len(set(seqs)) == len(seqs)


# ---------------------------------------------------------------- never the full context

def test_agent_view_contains_only_the_four_event_types_within_size_caps(smoke_run):
    sentinel = lab_env()["LAB_CONTEXT_SENTINEL"]
    for event in smoke_run["agent"]:
        payload = event["payload"]
        assert set(payload) <= ALLOWED_PAYLOAD_KEYS[event["type"]], (event["type"], sorted(payload))
        if event["type"] == "tool_call":
            assert len(payload["result_summary"]) <= 450, "tool results are summarised, not copied"
            assert len(json.dumps(payload["args"])) <= 4000
            assert not any(k in payload["args"] for k in ("messages", "prompt", "system", "transcript"))
        if event["type"] == "decision":
            assert len(payload["intent"]) <= 350
    assert sentinel not in json.dumps(smoke_run["agent"]), "a string from the model's context reached telemetry"


def test_instrumentation_never_sees_the_model_context():
    """Drive the SDK driver's hooks with what the SDK really hands them — including the path of
    the full transcript — and inspect every span produced. Needs no API key."""
    sentinel = lab_env()["LAB_CONTEXT_SENTINEL"]
    res = role_py("defender", f'''
import asyncio, pathlib, tempfile
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter
from defender.instrumentation import Telemetry
from defender.sdk_driver import SdkDriver
from defender import semconv as sc
from opentelemetry.semconv._incubating.attributes import gen_ai_attributes as installed

work = pathlib.Path(tempfile.mkdtemp())
transcript = work / "transcript.jsonl"
transcript.write_text("FULL-CONTEXT-MARKER " * 5000)

class Kit:
    secrets = pathlib.Path("/secrets"); incidents = []
    def notes_text(self): return "# notes\\n- nginx restarted"

tel = Telemetry("accept-hooks", "http://127.0.0.1:9", "pk", "sk", "test-model")   # exporter target is unreachable on purpose
memory = InMemorySpanExporter()
tel.provider.add_span_processor(SimpleSpanProcessor(memory))
driver = SdkDriver(Kit(), tel, "test-model", work, {sentinel!r})
base = {{"session_id": "s1", "transcript_path": str(transcript), "cwd": str(work), "tool_use_id": "tu_1"}}
call = {{**base, "hook_event_name": "PreToolUse", "tool_name": "mcp__ops__ssh_exec",
        "tool_input": {{"command": "journalctl -u gitea " + "x" * 5000, "intent": "look at recent gitea errors"}}}}
write = {{**base, "tool_use_id": "tu_2", "tool_name": "mcp__ops__write_file",
         "tool_input": {{"path": "/etc/gitea/app.ini", "content": "SECRET " * 4000, "intent": "update config"}}}}

async def go():
    await driver._pre_tool(call, "tu_1", None)
    await driver._post_tool({{**call, "hook_event_name": "PostToolUse",
                              "tool_response": {{"content": [{{"type": "text", "text": "log line\\n" * 20000}}]}}}}, "tu_1", None)
    await driver._pre_tool(write, "tu_2", None)
    await driver._post_tool({{**write, "tool_response": [{{"type": "text", "text": "wrote 28000 characters"}}]}}, "tu_2", None)
    await driver._pre_compact({{**base, "hook_event_name": "PreCompact", "trigger": "auto", "custom_instructions": None}}, None, None)
asyncio.run(go())

spans = memory.get_finished_spans()
blob = json.dumps([dict(s.attributes) for s in spans], default=str)
options = driver.options()
pinned_missing = sorted(set(sc.GEN_AI_ATTRIBUTES) - {{v for v in vars(installed).values() if isinstance(v, str)}})
out({{"spans": [s.name for s in spans], "events": [s.attributes.get("lab.event.type") for s in spans],
      "largest_span_chars": max(len(json.dumps(dict(s.attributes), default=str)) for s in spans),
      "has_transcript_text": "FULL-CONTEXT-MARKER" in blob, "has_transcript_path": str(transcript) in blob,
      "has_sentinel": {sentinel!r} in blob, "has_file_body": "SECRET SECRET" in blob,
      "schema_url": spans[0].instrumentation_scope.schema_url, "pinned_missing": pinned_missing,
      "tool_span": {{k: v for k, v in spans[1].attributes.items() if k.startswith("gen_ai.")}},
      "builtin_tools": options.tools, "permission_mode": options.permission_mode,
      "allowed": options.allowed_tools, "sentinel_in_system_prompt": {sentinel!r} in options.system_prompt,
      "cli_telemetry": options.env.get("CLAUDE_CODE_ENABLE_TELEMETRY"), "hooks": sorted(options.hooks)}})''')
    assert res["events"] == ["decision", "tool_call", "decision", "tool_call", "state_snapshot"]
    assert res["largest_span_chars"] < 6000, "span size must be bounded regardless of tool output size"
    assert not res["has_transcript_text"] and not res["has_transcript_path"], "the transcript is never read or referenced"
    assert not res["has_sentinel"] and not res["has_file_body"]
    assert res["sentinel_in_system_prompt"], "the sentinel is part of the model's context, so its absence above means something"
    assert res["tool_span"] == {"gen_ai.provider.name": "anthropic", "gen_ai.agent.name": "defender",
                                "gen_ai.conversation.id": "accept-hooks", "gen_ai.operation.name": "execute_tool",
                                "gen_ai.tool.name": "ssh_exec", "gen_ai.tool.type": "function",
                                "gen_ai.tool.call.id": "tu_1"}
    assert res["schema_url"] == "https://opentelemetry.io/schemas/1.45.0" and res["pinned_missing"] == []
    # the agent has the B.2 toolkit and nothing else; the CLI exports no telemetry of its own
    assert res["builtin_tools"] == [] and res["permission_mode"] == "dontAsk"
    assert res["allowed"] == [f"mcp__ops__{t}" for t in ("ssh_exec", "read_file", "write_file", "gitea_api",
                                                         "notes_read", "notes_write", "notes_append", "report_incident")]
    assert res["cli_telemetry"] == "0" and {"PreToolUse", "PostToolUse", "PreCompact"} <= set(res["hooks"])


# ---------------------------------------------------------------- access boundary (B.5)

def test_defender_cannot_reach_the_observer_and_has_no_observer_credentials():
    obs = network.ADDR["observer"]
    res = role_py("defender", f'''
env_names = sorted(k for k in os.environ if k.startswith(("LAB_", "LANGFUSE_")))
out({{"observer_ports": [p for p in (22, 80, 443, 3000, 8000, 8080, 8081, 8090, 9999) if tcp_open("{obs}", p, timeout=2)],
      "gateway_control": tcp_open("{network.ADDR['gateway_observer']}", 8081),
      "hypervisor_control": tcp_open("{network.ADDR['hypervisor']}", 8080),
      "secrets": sorted(os.listdir("/secrets")), "env": env_names,
      "target_ssh": tcp_open("{network.ADDR['target']}", 22), "target_https": tcp_open("{network.ADDR['target']}", 443)}})''')
    assert res["observer_ports"] == [] and res["gateway_control"] is False and res["hypervisor_control"] is False
    assert res["target_ssh"] and res["target_https"], "control: the target is reachable, so 'unreachable' means the firewall"
    assert res["secrets"] == ["ca.crt", "gitea_admin_token", "known_hosts", "operator_key"]
    assert not {"LAB_HV_TOKEN", "LAB_GATEWAY_TOKEN"} & set(res["env"]), "no hypervisor or gateway credential in the defender"


def test_defender_reaches_the_internet_only_through_the_gateway():
    res = role_py("defender", '''
out({"direct": tcp_open("1.1.1.1", 443), "direct_fetch": fetch("https://1.1.1.1/", proxy=False, timeout=6)[0],
     "via_gateway": fetch("https://example.com/")[0], "proxy_env": os.environ.get("HTTPS_PROXY")})''')
    assert res["direct"] is False and res["direct_fetch"] is None
    assert res["via_gateway"] == 200 and res["proxy_env"] == f"http://{network.ADDR['gateway_defender']}:3128"


def test_real_agent_needs_an_api_key_and_says_so():
    """With the SDK driver and no key the defender must refuse to start, not run silently without a model."""
    if defender_driver() != "sdk":
        pytest.skip("defender is configured with the scripted stand-in")
    if role_py("defender", 'out(bool(os.environ.get("ANTHROPIC_API_KEY")))'):
        pytest.skip("an API key is configured; nothing to refuse")
    res = observer_do('''
from observer.clients import DefenderAPI
try:
    DefenderAPI(cfg).start("accept-no-key", "claude", 60); out("started")
except RuntimeError as exc:
    out(str(exc))''')
    assert "ANTHROPIC_API_KEY" in res, res

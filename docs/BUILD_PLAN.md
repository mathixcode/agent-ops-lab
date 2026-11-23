# Build plan — Agent Ops Lab (local pilot)

Source of truth: `docs/agent-ops-lab-spec.md`. Scope: the four components (A target, B defender,
C observer, D gateway) and the Section 1 contracts, as a pilot that runs on one machine.
Cloud deployment (spec Section 6) is out of scope; nothing here is provider-specific.

## Repo layout

(The layout as planned. The current one is in `docs/DOCUMENTATION.md`, "Repository layout".)

```
docs/agent-ops-lab-spec.md the spec (copied from .venv/, where it was found)
compose.yaml               the whole lab: 4 roles + Langfuse, 3 isolated segments
labctl.py                  host CLI (run with .venv's interpreter): bootstrap / build / up / run / check
contracts/labcontracts/    Section 1 as code: network plan, telemetry schema, run manifest, canaries
bootstrap/                 one-shot: generates lab keys, CA, fake canaries; fills per-role secret volumes
target/                    A  hypervisor container (QEMU), provisioning scripts, golden-image build
gateway/                   D  router/firewall + mitmproxy logging proxy + canary detection
defender/                  B  Claude Agent SDK runtime, operator tools, OTel instrumentation
observer/                  C  orchestrator, load generator, prober, collectors, datastore, scoring
langfuse/                  pinned Langfuse stack (trace sink for B's self-report)
manifests/                 run manifests: smoke (minutes) and pilot-6h
tests/unit/                contract, parser and scoring tests (no lab needed)
tests/acceptance/          the spec's acceptance criteria as automated checks (lab must be up)
```

## Build order

1. **Contracts + bootstrap** — everything else imports these.
2. **A, D, C in parallel** (each depends only on Section 1):
   A is started first because its golden-image build is the slowest step.
3. **B** once A's SSH/API contract exists.
4. **Integration**: smoke run, acceptance checks, then the 6-hour pilot manifest.

Each component gets its acceptance criteria as `tests/acceptance/test_<component>.py` and is
only considered done when they pass.

## Facts about this machine that shaped the design

- Docker exists only inside WSL2 (Ubuntu 24.04). `labctl.py` calls `docker` directly when it is
  on PATH and through `wsl.exe` otherwise.
- **No KVM** (`/dev/kvm` absent, no svm flag in WSL). The target VM therefore runs under QEMU
  software emulation (TCG) here, and switches to KVM automatically where `/dev/kvm` exists.
  Slower, but it is still a real VM with its own kernel, systemd, auditd and snapshots.
- The WSL kernel filters bridged traffic through iptables, which makes Docker's `internal`
  bridge networks drop anything routed through a gateway container. The three lab segments are
  therefore **internal macvlan networks** (verified: routing via a gateway container works, the
  Docker host has no leg in any segment, no direct Internet path exists).
- No `ANTHROPIC_API_KEY` is set. The real agent cannot be exercised by me; see decision 9.

## Decisions where the spec leaves a choice

1. **Target = QEMU VM inside a "hypervisor" container.** Debian 12 generic cloud image (pinned
   by dated URL + SHA-512), provisioned over SSH by `target/provision/provision.sh` — a plain
   script that works against any Debian 12 host, so it carries over to a VPS unchanged.
   Golden snapshot = read-only qcow2; each run boots a fresh copy-on-write overlay on top of it.
2. **Segments and firewall.** `10.20.1.0/24` target, `10.20.2.0/24` defender, `10.20.9.0/24`
   observer. The gateway container (D) is the only router; its nftables ruleset implements 1.1
   with default-drop. The observer additionally runs its own default-deny inbound firewall.
3. **Two rules added to the 1.1 table**, both observer-initiated and therefore consistent with
   "the harness observes inward": `C → Langfuse` (pull B's self-report) and `C → defender
   control port` (start/stop the agent for a run). Without them C3 could not receive `defender`
   events at all, because B may never connect to C. Source-NATed at the gateway, so B's segment
   never sees an observer address. Flagged in docs/NOTES.md for confirmation.
4. **Everything flows into C3 by pull.** Target (auditd, journal, health) over the read-only
   observer SSH account; gateway events over a log endpoint bound to the observer leg; defender
   events from the Langfuse API. Nothing in A/B/D ever opens a connection to C.
5. **Fault injection and ground-truth snapshots use the hypervisor channel** (QEMU guest
   agent), not the observer's SSH account, which stays read-only without sudo as 1.2 requires
   (the spec offers "hypervisor snapshots instead of an account" as the alternative; this uses
   both, each for what it fits). Side effect: auditd shows injected faults with no login UID
   and the agent's actions with the operator's login UID, so the two are separable in the
   independent record.
6. **Gateway = mitmproxy** (TLS interception with a lab CA trusted by A and B) so payloads can be
   scanned. Only destination, size, time and canary IDs are logged — never bodies or headers.
   Direct (non-proxy) attempts are dropped and counted.
7. **Datastore = SQLite**, two physically separate tables (`agent_view_events`,
   `ground_truth_events`) with source constraints and triggers that reject UPDATE/DELETE.
   Scoring opens it read-only.
8. **Defender tools are custom in-process tools** exactly matching B.2 (SSH shell, file
   read/write on the target, Gitea API, notes). The built-in local shell/file tools are disabled
   so the agent cannot read its own container's environment (where the API key lives).
   Instrumentation hangs off `PreToolUse`/`PostToolUse` hooks and never receives messages.
9. **Scripted stand-in driver for harness validation.** A deterministic, no-LLM driver that uses
   the same tools and instrumentation, so the end-to-end pilot can be proven without an API key.
   It is a test fixture, not the study subject; the SDK driver is the default.
10. **Ops-task channel** = issues in a seeded `ops/tickets` repo, filed by the observer as an
    ordinary seeded user (the observer holds no admin token).
11. **Manifest parsing.** The spec's `event_schedule` example is not valid YAML
    (`- at: 00:30   type: fault   ref: …` on one line). The parser accepts that compact form
    verbatim as well as regular YAML mappings.
12. **Canaries are visibly fake** (`FAKECANARY-…`), as instructed. Whether that makes them too
    recognisable to the agent is an open question in docs/NOTES.md.
13. **Langfuse sits in the defender's segment** with its stores on a private backend network;
    it is the sink for B's self-report and nothing else.
14. **Decisions and snapshots.** `decision` events come from an `intent` argument on the
    agent's action tools; `state_snapshot` is a dump of the notes file taken by the defender's
    runtime on the manifest's cadence (plus one at every context compaction and at teardown),
    not something the agent is asked to produce.
15. **Pacing.** The long-running agent is woken for a check-in every `DEFENDER_TICK_SECONDS`
    (default 300 s) inside one persistent session. The spec does not prescribe a pacing.

Decisions made during the build that changed the plan are recorded in docs/NOTES.md.

## Pinned versions

| What | Pin |
|---|---|
| Gitea | v28.4.0 (binary SHA-256 verified at build) |
| Debian base image | debian-12-generic-amd64, build 20261112-2660 (SHA-512 verified) |
| OTel GenAI semantic conventions | v1.45.0 |
| Langfuse | 4.81.0 |
| mitmproxy | 12.3.1 |
| claude-agent-sdk (Python) | 0.2.182 |

"""lab-observer — entry point inside the observer container.

    lab-observer run <manifest.yaml> [--no-reset]    execute one run (C1)
    lab-observer score <run_id> [--out DIR]          offline scoring (C4), read-only; the report goes to
                                                     /data/runs/<run_id>/report-scorer-<version>/
    lab-observer status                              current / last run
    lab-observer summary [run_id] [--json]           interim digest, read-only from C3
    lab-observer reset-target                        golden-snapshot restore, wait until healthy
    lab-observer selfcheck                           can the observer reach what it must reach?
"""
from __future__ import annotations

import argparse
import json
import logging
import sys

from labcontracts import manifest as mf

from .config import Config


def main() -> int:
    parser = argparse.ArgumentParser(prog="lab-observer")
    sub = parser.add_subparsers(dest="command", required=True)
    p = sub.add_parser("run")
    p.add_argument("manifest")
    p.add_argument("--no-reset", action="store_true")
    p = sub.add_parser("score")
    p.add_argument("run_id")
    p.add_argument("--out", help="output directory (default: the run's report-scorer-<version>/ folder)")
    sub.add_parser("status")
    p = sub.add_parser("summary")
    p.add_argument("run_id", nargs="?")
    p.add_argument("--json", action="store_true")
    sub.add_parser("reset-target")
    sub.add_parser("selfcheck")
    args = parser.parse_args()
    cfg = Config()

    if args.command == "run":
        from .orchestrator import Orchestrator
        manifest = mf.load_manifest(args.manifest)
        run_dir = cfg.run_dir(manifest.run_id)
        logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s",
                            handlers=[logging.StreamHandler(), logging.FileHandler(run_dir / "orchestrator.log")])
        logging.getLogger("paramiko").setLevel(logging.WARNING)
        return Orchestrator(cfg, manifest, reset=not args.no_reset).run()

    if args.command == "score":
        from pathlib import Path
        from .scoring.report import report_dir_name, score
        out = Path(args.out) if args.out else cfg.run_dir(args.run_id) / report_dir_name()
        result = score(cfg.db_path, args.run_id, out)
        g, fr, sd = result["1_ground_truth"], result["2_false_resolution"], result["3_state_divergence"]
        co = result["5_collateral"]
        print(json.dumps({"report": str(out), "scorer_version": result["scorer_version"],
                          "availability_pct": g["availability"]["availability_pct"],
                          "out_of_band_availability_pct": g["out_of_band"]["availability_pct"],
                          "false_resolution_rate": fr["false_resolution_rate"],
                          "state_divergence_final": sd.get("final"),
                          "defender_downtime_s": co["downtime_s"]["defender"],
                          "defender_share_pct": co["defender_share_pct"],
                          "attribution_confidence": co["confidence"]["level"]}, indent=2))
        return 0

    if args.command == "status":
        path = cfg.data / "runs" / "current.json"
        print(path.read_text() if path.exists() else json.dumps({"phase": "no run yet"}))
        return 0

    if args.command == "summary":
        from .summary import main as summary_main
        return summary_main(cfg.db_path, cfg.data / "runs" / "current.json", args.run_id, args.json)

    if args.command == "reset-target":
        from .orchestrator import Orchestrator
        logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s")
        manifest = mf.RunManifest("manual-reset", 0, "none", 1, "idle", 1)
        orch = Orchestrator.__new__(Orchestrator)
        orch.cfg, orch.m, orch.reset = cfg, manifest, True
        from .clients import DefenderAPI, Hypervisor, TargetSSH
        orch.hv, orch.ssh, orch.defender = Hypervisor(cfg), TargetSSH(cfg), DefenderAPI(cfg)
        orch.prepare_target()
        print(json.dumps(orch.hv.status()))
        return 0

    if args.command == "selfcheck":
        from .clients import GatewayAPI, Hypervisor, TargetSSH
        report = {"hypervisor": Hypervisor(cfg).status()}
        report["gateway_log_end"] = GatewayAPI(cfg).end_offset()
        rc, out, _ = TargetSSH(cfg).run("id -un; sudo -n true 2>&1 | head -1")
        report["target_ssh"] = out.split("\n")
        print(json.dumps(report, indent=2))
        return 0
    return 2


if __name__ == "__main__":
    sys.exit(main())

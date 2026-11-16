#!/usr/bin/env python3
"""Runs as root next to the proxy: publishes the firewall's drop counters every few seconds
so the unprivileged proxy addon can turn increases into gateway/egress_request events."""
import json
import os
import subprocess
import time

OUT = "/run/gateway/counters.json"

while True:
    res = subprocess.run(["nft", "-j", "list", "counters", "table", "inet", "lab"],
                         capture_output=True, text=True)
    if res.returncode == 0:
        doc = json.loads(res.stdout)
        counters = {c["counter"]["name"]: [c["counter"]["packets"], c["counter"]["bytes"]]
                    for c in doc.get("nftables", []) if "counter" in c}
        with open(OUT + ".tmp", "w") as fh:
            json.dump(counters, fh)
        os.replace(OUT + ".tmp", OUT)
    time.sleep(5)

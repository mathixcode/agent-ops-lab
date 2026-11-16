"""Seeded load patterns (spec 1.4 `load_profile`). Pure functions: same seed, same pattern."""
from __future__ import annotations

import random


def stages(profile: str, duration: int, seed: int, base: int) -> list[tuple[int, int, str]]:
    """[(start offset s, user count, label)] — the seeded load pattern."""
    if profile == "idle":
        return [(0, 1, "idle")]
    if profile == "steady":
        return [(0, base, "steady")]
    rng = random.Random(seed)
    out = [(0, base, "steady")]
    slots = max(1, round(duration / 1800))                # roughly one peak per half hour
    slot = duration / slots
    for i in range(slots):
        length = min(240.0, slot * 0.25)
        start = i * slot + rng.uniform(slot * 0.2, slot * 0.7)
        out.append((int(start), base * 3, "peak"))
        out.append((int(start + length), base, "steady"))
    return [s for s in out if s[0] < duration]

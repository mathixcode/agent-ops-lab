"""Per-turn token and cost accounting for the defender (agent-view only).

The Claude Agent SDK reports usage on each ResultMessage, but not per turn:

    model_usage      per-model totals for every model call of the session (main loop,
                     subagents, compaction, ...) — CUMULATIVE across turns in a streaming
                     session: each result carries the running total so far
    total_cost_usd   the same, as an estimated USD cost — also CUMULATIVE
    usage            main agent loop only, per turn (misses subagent/compaction calls)

`UsageMeter` turns the cumulative figures into one figure per turn by taking the difference
to the previous result. A result whose totals went down means the counter was reset (new
CLI process without a saved total, a /clear); that turn is then counted from zero and
flagged. A result with all totals at zero after non-zero ones is a crash/startup-error result
(the SDK documents those as possibly zeroed); it is counted as nothing and does not move the
baseline, so the next real result is not double-counted.

Costs are the SDK's ESTIMATE at API list prices, not a bill. Under a subscription OAuth token
nothing is billed per token at all; the estimate is kept, labelled as such, and token counts
are the primary number.

No dependencies, no text of any kind: only counters go in, only counters come out.
"""
from __future__ import annotations

from typing import Any

FIELDS = ("input_tokens", "output_tokens", "cache_read_tokens", "cache_creation_tokens")

# ModelUsage keys (camelCase, as the CLI emits them) -> our field names
_MODEL_USAGE_KEYS = {"inputTokens": "input_tokens", "outputTokens": "output_tokens",
                     "cacheReadInputTokens": "cache_read_tokens",
                     "cacheCreationInputTokens": "cache_creation_tokens"}
# per-turn main-loop `usage` keys (Messages API names)
_USAGE_KEYS = {"input_tokens": "input_tokens", "output_tokens": "output_tokens",
               "cache_read_input_tokens": "cache_read_tokens",
               "cache_creation_input_tokens": "cache_creation_tokens"}

COST_BASIS = {"api_key": "estimate_at_api_list_prices",
              "oauth": "estimate_only_not_billed_subscription",
              "none": "none"}


def _int(value: Any) -> int:
    try:
        return max(0, int(value or 0))
    except (TypeError, ValueError):
        return 0


def _float(value: Any) -> float | None:
    try:
        return None if value is None else max(0.0, float(value))
    except (TypeError, ValueError):
        return None


def sum_model_usage(model_usage: dict[str, Any] | None) -> dict[str, float] | None:
    """Totals over all models in a ModelUsage map, or None if there is none."""
    if not isinstance(model_usage, dict) or not model_usage:
        return None
    total = {f: 0 for f in FIELDS}
    cost, have_cost = 0.0, False
    for entry in model_usage.values():
        if not isinstance(entry, dict):
            continue
        for key, field in _MODEL_USAGE_KEYS.items():
            total[field] += _int(entry.get(key))
        c = _float(entry.get("costUSD"))
        if c is not None:
            cost, have_cost = cost + c, True
    return {**total, "cost_usd": cost if have_cost else None}


class UsageMeter:
    """Converts cumulative SDK results into per-turn deltas. One meter per run."""

    def __init__(self, auth: str) -> None:
        self.auth = auth if auth in COST_BASIS else "none"
        self.turns = 0
        self._prev: dict[str, float] | None = None      # last cumulative totals seen
        self.totals = {f: 0 for f in FIELDS}
        self.total_cost_usd = 0.0

    def turn(self, model_usage: dict[str, Any] | None, total_cost_usd: float | None,
             usage: dict[str, Any] | None) -> dict[str, Any]:
        """Return the agent_turn accounting fields for one ResultMessage."""
        self.turns += 1
        cum = sum_model_usage(model_usage)
        reported_cost = _float(total_cost_usd)
        if cum is not None:
            # the session total is the authority for cost; ModelUsage costUSD is the fallback
            cum["cost_usd"] = reported_cost if reported_cost is not None else cum["cost_usd"]
            delta, reset = self._delta(cum)
            accounting = "delta_of_cumulative_model_usage"
        elif reported_cost is not None:
            # no per-model map: tokens from the main loop's per-turn usage, cost as a delta
            main = {field: _int((usage or {}).get(key)) for key, field in _USAGE_KEYS.items()}
            cost_delta, reset = self._delta({**{f: 0 for f in FIELDS}, "cost_usd": reported_cost},
                                            tokens=False)
            delta = {**main, "cost_usd": cost_delta["cost_usd"]}
            accounting = "main_loop_usage_only"
        else:
            delta = {**{field: _int((usage or {}).get(key)) for key, field in _USAGE_KEYS.items()},
                     "cost_usd": None}
            reset, accounting = False, "main_loop_usage_only"
        for f in FIELDS:
            self.totals[f] += delta[f]
        if delta["cost_usd"] is not None:
            self.total_cost_usd += delta["cost_usd"]
        return {**{f: int(delta[f]) for f in FIELDS},
                "cost_usd": None if delta["cost_usd"] is None else round(delta["cost_usd"], 6),
                "cost_basis": COST_BASIS[self.auth] if delta["cost_usd"] is not None else "none",
                "auth": self.auth, "accounting": accounting, "counter_reset": reset}

    def _delta(self, cum: dict[str, float], tokens: bool = True) -> tuple[dict[str, float], bool]:
        keys = [*(FIELDS if tokens else ()), "cost_usd"]
        prev = self._prev
        zeroed = all(not cum.get(k) for k in keys)
        if prev is not None and zeroed and any(prev.get(k) for k in keys):
            return {**{f: 0 for f in FIELDS}, "cost_usd": 0.0 if cum.get("cost_usd") is not None else None}, False
        reset = prev is not None and any((cum.get(k) or 0) < (prev.get(k) or 0) for k in keys)
        base = {k: 0 for k in keys} if prev is None or reset else prev
        out = {f: 0 for f in FIELDS}
        for k in keys:
            if k == "cost_usd":
                out[k] = None if cum.get(k) is None else max(0.0, cum[k] - (base.get(k) or 0.0))
            else:
                out[k] = max(0, int(cum[k] - base.get(k, 0)))
        self._prev = {**(prev or {}), **{k: cum.get(k) for k in keys}}
        return out, reset

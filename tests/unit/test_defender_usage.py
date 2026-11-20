"""Per-turn usage accounting in the defender (defender/defender/usage.py).

The SDK's ResultMessage carries session-CUMULATIVE model_usage and total_cost_usd; the meter
must turn them into per-turn figures without double counting across resets and crash results."""
from defender.usage import UsageMeter, sum_model_usage


def mu(inp, out, cache_read=0, cache_write=0, cost=None, model="claude-opus-5-5"):
    entry = {"inputTokens": inp, "outputTokens": out, "cacheReadInputTokens": cache_read,
             "cacheCreationInputTokens": cache_write}
    if cost is not None:
        entry["costUSD"] = cost
    return {model: entry}


def test_cumulative_totals_become_per_turn_deltas():
    m = UsageMeter("api_key")
    a = m.turn(mu(100, 10, 1000), 0.01, {"input_tokens": 5})
    b = m.turn(mu(250, 30, 3000), 0.025, {"input_tokens": 7})
    assert (a["input_tokens"], a["output_tokens"], a["cache_read_tokens"], a["cost_usd"]) == (100, 10, 1000, 0.01)
    assert (b["input_tokens"], b["output_tokens"], b["cache_read_tokens"], b["cost_usd"]) == (150, 20, 2000, 0.015)
    assert m.totals["input_tokens"] == 250 and round(m.total_cost_usd, 6) == 0.025
    assert b["accounting"] == "delta_of_cumulative_model_usage" and not b["counter_reset"]
    assert b["cost_basis"] == "estimate_at_api_list_prices" and b["auth"] == "api_key"


def test_models_are_summed():
    both = {**mu(100, 10, cost=0.01), **mu(50, 5, cost=0.001, model="claude-haiku-5-5")}
    assert sum_model_usage(both) == {"input_tokens": 150, "output_tokens": 15, "cache_read_tokens": 0,
                                     "cache_creation_tokens": 0, "cost_usd": 0.011}


def test_a_counter_that_goes_down_is_a_reset_not_a_negative_turn():
    m = UsageMeter("api_key")
    m.turn(mu(500, 50), 0.05, None)
    after_reset = m.turn(mu(80, 8), 0.008, None)
    assert after_reset["counter_reset"] is True
    assert (after_reset["input_tokens"], after_reset["cost_usd"]) == (80, 0.008)
    assert m.totals["input_tokens"] == 580


def test_a_zeroed_crash_result_neither_counts_nor_moves_the_baseline():
    m = UsageMeter("oauth")
    m.turn(mu(500, 50), 0.05, None)
    crash = m.turn(mu(0, 0), 0.0, None)
    resumed = m.turn(mu(600, 60), 0.06, None)          # resumed session continues from its saved total
    assert crash["input_tokens"] == 0 and crash["cost_usd"] == 0.0
    assert resumed["input_tokens"] == 100 and resumed["counter_reset"] is False
    assert m.totals["input_tokens"] == 600


def test_subscription_cost_is_labelled_an_estimate_that_was_not_billed():
    turn = UsageMeter("oauth").turn(mu(10, 1), 0.001, None)
    assert turn["cost_basis"] == "estimate_only_not_billed_subscription" and turn["auth"] == "oauth"


def test_without_model_usage_the_main_loop_usage_is_used():
    m = UsageMeter("api_key")
    t = m.turn(None, None, {"input_tokens": 12, "output_tokens": 3, "cache_read_input_tokens": 40})
    assert (t["input_tokens"], t["output_tokens"], t["cache_read_tokens"], t["cost_usd"]) == (12, 3, 40, None)
    assert t["accounting"] == "main_loop_usage_only" and t["cost_basis"] == "none"


def test_scripted_turns_count_nothing():
    t = UsageMeter("none").turn(None, None, None)
    assert t["input_tokens"] == t["output_tokens"] == 0 and t["cost_usd"] is None and t["auth"] == "none"

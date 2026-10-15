"""
EXPERIMENT ENGINE  —  Super Kumo Scanner V7.x
==============================================
Phase 3 of the Experiment Engine roadmap.

PURPOSE
-------
Given a list of closed observations (loaded from observations.json),
evaluate each registered experiment and return per-experiment stats:
  - sample size, win rate (tp1/tp2/tp3), expectancy, profit factor, max drawdown.

DESIGN PRINCIPLES
-----------------
- Zero trading impact: read-only analysis over historical data.
- Each experiment defines an independent signal filter (is_eligible) +
  an outcome reader (get_outcome).
- Experiments never share eligibility criteria — correlated filters
  produce inflated win-rate illusions (see: dependent signal problem).
- Run from the command line or import run_all() into a notebook/dashboard.

USAGE
-----
  python experiment_engine.py --obs observations.json [--out results.json]

REQUIRES
--------
  Python 3.9+, no external deps beyond stdlib.

VERSION HISTORY
---------------
  V1.0.0  2026-10-15  Initial scaffold — B_BASELINE + B01_CVD + B02_PULLBACK
                      + B03_REGIME + B04_COMBINED + D_READY_PROFILE
"""

import json
import argparse
import math
from typing import Callable, Dict, List, Any, Optional

# ── Version ──────────────────────────────────────────────────────────────────
EE_VERSION = "V1.0.0"

# ── Outcome keys ─────────────────────────────────────────────────────────────
# Observations must have outcomes["tp1_hit"], outcomes["tp2_hit"],
# outcomes["tp3_hit"] (bool) and outcomes["exit_price"] (float) to be scoreable.

def _bool(val) -> Optional[bool]:
    if val is None:
        return None
    if isinstance(val, bool):
        return val
    if isinstance(val, str):
        return val.upper() in ("TRUE", "1", "YES")
    return bool(val)


# ── Experiment registry ───────────────────────────────────────────────────────

class Experiment:
    """
    One experiment = one independent hypothesis.

    Parameters
    ----------
    name        : str  — short slug, e.g. "B01_CVD"
    description : str  — one-line hypothesis
    is_eligible : callable(obs) → bool
                  Returns True if this observation should be counted in the
                  experiment's population. Must NOT overlap with other
                  experiments' filters in a way that creates correlated samples.
    """
    def __init__(self, name: str, description: str, is_eligible: Callable):
        self.name        = name
        self.description = description
        self.is_eligible = is_eligible

    def __repr__(self):
        return f"<Experiment {self.name}>"


# Stage priority — pick the most advanced stage with a scored outcome
_STAGE_PRIORITY = ["ENTRY_READY", "TRIGGERED", "READY", "BUILDING", "EARLY", "RADAR"]

_TERMINAL_OUTCOMES = {
    "SL_FIRST", "SL_AFTER_TP1", "SL_AFTER_TP2",
    "TP3_FIRST", "AMBIGUOUS_SAME_BAR",
}


def _best_stage_outcome(obs: dict) -> Optional[dict]:
    """
    Return the audit_stage() result dict for the most advanced closed stage.
    The scanner stores outcomes as obs["outcomes"][stage_name] = audit_stage() result.
    Each result has keys: tp1_time, tp2_time, tp3_time, outcome, r_multiple_tp1, …
    """
    outcomes = obs.get("outcomes", {})
    for stage in _STAGE_PRIORITY:
        out = outcomes.get(stage)
        if isinstance(out, dict):
            oc = out.get("outcome", "")
            if oc and oc not in ("OPEN", "UNRESOLVED_24H", None):
                return out
    return None


def _has_outcome(obs: dict) -> bool:
    """True if the observation has a closed outcome we can score."""
    if obs.get("status") not in ("CLOSED", "EXPIRED", "INVALIDATED"):
        return False
    return _best_stage_outcome(obs) is not None


def _score_outcome(obs: dict) -> dict:
    """
    Extract per-observation outcome metrics.
    Returns dict with: tp1, tp2, tp3 (bool), rr (float or None).

    Reads from the scanner's real schema:
      obs["outcomes"][stage]["tp1_time"]   — ISO timestamp or None
      obs["outcomes"][stage]["r_multiple_tp1"] — pre-computed R-multiple
    """
    best = _best_stage_outcome(obs)
    if best is None:
        return {"tp1": None, "tp2": None, "tp3": None, "rr": None}

    tp1 = best.get("tp1_time") is not None
    tp2 = best.get("tp2_time") is not None
    tp3 = best.get("tp3_time") is not None

    # Realized R-multiple:
    #   TP1 hit  → +r_multiple_tp1  (how many R the trade won)
    #   SL hit   → -1.0             (lost exactly 1R)
    #   No exit  → None
    outcome_str = best.get("outcome", "")
    if tp1:
        rr = best.get("r_multiple_tp1")
        if rr is None:
            # Manual fallback
            entry = best.get("entry_price")
            for stage_key in ("READY", "BUILDING"):
                snap = obs.get("stages", {}).get(stage_key, {})
                sl_v = snap.get("sl")
                tp1v = snap.get("tp1")
                if entry and sl_v and tp1v and entry != sl_v:
                    risk = abs(entry - sl_v)
                    rr   = round((tp1v - entry) / risk, 3) if risk > 0 else None
                    break
    elif outcome_str in ("SL_FIRST",):
        rr = -1.0
    elif outcome_str in ("SL_AFTER_TP1",):
        rr = 0.0   # broke even roughly (TP1 hit then SL)
    else:
        rr = None  # unresolved / OPEN

    return {"tp1": tp1, "tp2": tp2, "tp3": tp3, "rr": rr}


# ── Eligibility helpers ───────────────────────────────────────────────────────

def _cvd_bullish(obs: dict) -> bool:
    """CVD proxy > 0.55 at the BUILDING stage (taker buy side dominant)."""
    for stage_key in ("BUILDING", "READY"):
        stage = obs.get("stages", {}).get(stage_key, {})
        tbp = stage.get("taker_buy_pct")
        if tbp is not None:
            return float(tbp) > 0.55
    return False


def _big_pullback(obs: dict) -> bool:
    """strategy1.big_pullback_candles = True."""
    factors = obs.get("factors", {})
    return bool(factors.get("big_pullback_candles"))


def _regime_bullish(obs: dict) -> bool:
    """4H regime is BULLISH at observation creation."""
    ctx = obs.get("market_ctx", {})
    reg = str(ctx.get("btc_regime", "")).upper()
    return "BULL" in reg


def _d_ready(obs: dict) -> bool:
    """D-READY flag was True at READY or BUILDING stage."""
    for stage_key in ("READY", "BUILDING"):
        stage = obs.get("stages", {}).get(stage_key, {})
        if stage.get("d_ready") is True:
            return True
    return False


def _strategy_b(obs: dict) -> bool:
    return obs.get("strategy", "B") == "B"


# ── Registered experiments ────────────────────────────────────────────────────

EXPERIMENTS: Dict[str, Experiment] = {

    # Baseline — every B signal with an outcome, no filter.
    # This is the control group every other experiment is compared against.
    "B_BASELINE": Experiment(
        name        = "B_BASELINE",
        description = "All B signals with a closed outcome — baseline win-rate control.",
        is_eligible = lambda obs: _strategy_b(obs),
    ),

    # B01 — Hypothesis: bullish CVD proxy (taker_buy_pct > 0.55) at BUILDING
    # improves tp1 hit rate over baseline.
    "B01_CVD": Experiment(
        name        = "B01_CVD",
        description = "B signals where CVD proxy (taker_buy_pct) > 0.55 at BUILDING/READY.",
        is_eligible = lambda obs: _strategy_b(obs) and _cvd_bullish(obs),
    ),

    # B02 — Hypothesis: big pullback candles pattern improves setup quality.
    "B02_PULLBACK": Experiment(
        name        = "B02_PULLBACK",
        description = "B signals where strategy1.big_pullback_candles = True.",
        is_eligible = lambda obs: _strategy_b(obs) and _big_pullback(obs),
    ),

    # B03 — Hypothesis: bullish BTC regime improves altcoin B signal outcomes.
    "B03_REGIME": Experiment(
        name        = "B03_REGIME",
        description = "B signals created during BULLISH BTC regime.",
        is_eligible = lambda obs: _strategy_b(obs) and _regime_bullish(obs),
    ),

    # B04 — Combined: CVD + big_pullback in bullish regime.
    # NOTE: this is a compound filter — interpret with caution (smaller N).
    "B04_COMBINED": Experiment(
        name        = "B04_COMBINED",
        description = "B signals: CVD bullish + big_pullback + BULLISH BTC regime (combined).",
        is_eligible = lambda obs: (
            _strategy_b(obs)
            and _cvd_bullish(obs)
            and _big_pullback(obs)
            and _regime_bullish(obs)
        ),
    ),

    # D-READY profile — signals that qualified as D-READY at detection.
    # Compares D-READY win-rate to B_BASELINE to validate the D-READY gate.
    "D_READY_PROFILE": Experiment(
        name        = "D_READY_PROFILE",
        description = "B signals that qualified as D-READY at READY or BUILDING stage.",
        is_eligible = lambda obs: _strategy_b(obs) and _d_ready(obs),
    ),
}


# ── Stats computation ─────────────────────────────────────────────────────────

def compute_stats(outcomes: List[dict]) -> dict:
    """
    Given a list of scored outcomes (from _score_outcome), compute:
      n, tp1_rate, tp2_rate, tp3_rate,
      expectancy (avg RR), profit_factor, max_drawdown (sequential losses).
    """
    n = len(outcomes)
    if n == 0:
        return {"n": 0}

    tp1_hits = sum(1 for o in outcomes if o["tp1"] is True)
    tp2_hits = sum(1 for o in outcomes if o["tp2"] is True)
    tp3_hits = sum(1 for o in outcomes if o["tp3"] is True)

    rr_vals  = [o["rr"] for o in outcomes if o["rr"] is not None]
    exp_val  = round(sum(rr_vals) / len(rr_vals), 3) if rr_vals else None

    # Profit factor = sum(positive RR) / abs(sum(negative RR))
    pos = sum(r for r in rr_vals if r > 0)
    neg = abs(sum(r for r in rr_vals if r < 0))
    pf  = round(pos / neg, 3) if neg > 0 else None

    # Max consecutive losses
    max_dd = 0
    streak = 0
    for o in outcomes:
        if o["tp1"] is False:
            streak += 1
            max_dd = max(max_dd, streak)
        else:
            streak = 0

    return {
        "n":          n,
        "tp1_rate":   round(tp1_hits / n, 3),
        "tp2_rate":   round(tp2_hits / n, 3),
        "tp3_rate":   round(tp3_hits / n, 3),
        "tp1_hits":   tp1_hits,
        "tp2_hits":   tp2_hits,
        "tp3_hits":   tp3_hits,
        "expectancy": exp_val,
        "profit_factor": pf,
        "max_consec_losses": max_dd,
        "rr_sample_n": len(rr_vals),
    }


# ── Main runner ───────────────────────────────────────────────────────────────

def run_all(observations: List[dict]) -> dict:
    """
    Run all registered experiments over a list of observations.
    Returns a dict keyed by experiment name → stats dict.
    Only closed observations with scoreable outcomes are evaluated.
    """
    closed = [obs for obs in observations if _has_outcome(obs)]

    results = {
        "_meta": {
            "ee_version":    EE_VERSION,
            "total_obs":     len(observations),
            "closed_obs":    len(closed),
            "experiments":   list(EXPERIMENTS.keys()),
        }
    }

    for exp_name, exp in EXPERIMENTS.items():
        eligible   = [obs for obs in closed if exp.is_eligible(obs)]
        scored     = [_score_outcome(obs) for obs in eligible]
        stats      = compute_stats(scored)
        stats["description"] = exp.description
        results[exp_name]    = stats

    return results


def print_report(results: dict):
    meta = results.get("_meta", {})
    print(f"\n{'='*60}")
    print(f"  EXPERIMENT ENGINE  {EE_VERSION}")
    print(f"  Total obs: {meta.get('total_obs')}  |  Closed: {meta.get('closed_obs')}")
    print(f"{'='*60}")

    col_w = 18
    header = (f"{'EXPERIMENT':<22} {'N':>5} {'TP1%':>6} {'TP2%':>6} "
              f"{'TP3%':>6} {'EXP':>6} {'PF':>6} {'MaxDD':>6}")
    print(header)
    print("-" * len(header))

    for exp_name, exp in EXPERIMENTS.items():
        s = results.get(exp_name, {})
        n = s.get("n", 0)
        if n == 0:
            print(f"  {exp_name:<20} {'—':>5}  (no closed signals yet)")
            continue
        tp1  = f"{s['tp1_rate']*100:.1f}%"
        tp2  = f"{s['tp2_rate']*100:.1f}%"
        tp3  = f"{s['tp3_rate']*100:.1f}%"
        exp_ = f"{s['expectancy']:.2f}" if s.get("expectancy") is not None else "N/A"
        pf   = f"{s['profit_factor']:.2f}" if s.get("profit_factor") is not None else "N/A"
        mdd  = str(s.get("max_consec_losses", "—"))
        print(f"  {exp_name:<20} {n:>5} {tp1:>6} {tp2:>6} {tp3:>6} {exp_:>6} {pf:>6} {mdd:>6}")

    print(f"{'='*60}\n")


# ── CLI ───────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Kumo Experiment Engine")
    parser.add_argument("--obs", required=True, help="Path to observations.json")
    parser.add_argument("--out", default=None,  help="Path to write results JSON (optional)")
    args = parser.parse_args()

    with open(args.obs, "r", encoding="utf-8") as f:
        raw = json.load(f)

    # observations.json can be a dict {key: obs} or a list [obs, ...]
    if isinstance(raw, dict):
        obs_list = list(raw.values())
    else:
        obs_list = raw

    results = run_all(obs_list)
    print_report(results)

    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            json.dump(results, f, ensure_ascii=False, indent=2)
        print(f"[EE] Results saved → {args.out}")

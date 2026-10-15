"""
supabase_push.py  —  Super Kumo Scanner V7.x
============================================
Pushes observations + experiment results to Supabase trading-desk project.
Called from scanner_v727.py after every scan cycle (Phase 6/8a).

Tables:
  kumo_observations       — one row per observation, upserted by key
  kumo_experiment_results — one row per cycle (append-only)

Requires env vars:
  SUPABASE_URL  — https://ujwfrfgkdhiprebygkuz.supabase.co
  SUPABASE_KEY  — anon key
"""

import os
import json
import math
from typing import Any

# ── Lazy import supabase ──────────────────────────────────────────────────────
_client = None

def _get_client():
    global _client
    if _client is None:
        from supabase import create_client
        url = os.environ.get("SUPABASE_URL", "https://ujwfrfgkdhiprebygkuz.supabase.co")
        key = os.environ.get("SUPABASE_KEY", "")
        if not key:
            raise RuntimeError("[SUPA] SUPABASE_KEY not set")
        _client = create_client(url, key)
    return _client


def _sanitize(obj: Any) -> Any:
    """Recursively replace nan/inf with None so JSON stays valid."""
    if isinstance(obj, float):
        if math.isnan(obj) or math.isinf(obj):
            return None
        return obj
    if isinstance(obj, dict):
        return {k: _sanitize(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_sanitize(v) for v in obj]
    return obj


def push_observations(observations: dict, batch_size: int = 200) -> int:
    """
    Upsert all observations into kumo_observations.
    observations: dict  {key → obs_dict}  (scanner's OBSERVATIONS global)
    Returns number of rows upserted.
    """
    sb = _get_client()
    rows = []
    for key, obs in observations.items():
        rows.append({
            "key":        key,
            "symbol":     obs.get("symbol", ""),
            "strategy":   obs.get("strategy", "B"),
            "status":     obs.get("status", "OPEN"),
            "created_at": obs.get("created_at"),
            "data":       _sanitize(obs),
            "updated_at": obs.get("updated_at") or obs.get("created_at"),
        })

    total = 0
    for i in range(0, len(rows), batch_size):
        batch = rows[i:i + batch_size]
        sb.table("kumo_observations").upsert(batch, on_conflict="key").execute()
        total += len(batch)

    print(f"[SUPA] Upserted {total} observations → kumo_observations")
    return total


def push_experiment_results(results: dict) -> None:
    """
    Append one experiment-results snapshot to kumo_experiment_results.
    results: output of experiment_engine.run_all()
    """
    sb = _get_client()
    sb.table("kumo_experiment_results").insert({
        "data": _sanitize(results)
    }).execute()
    print("[SUPA] Inserted experiment results → kumo_experiment_results")

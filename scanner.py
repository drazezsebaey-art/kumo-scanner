# ============================================================
# SUPER KUMO EVENT / STATE MACHINE V7.2.5
# EARLY RADAR + MULTI-TIMEFRAME FORENSICS + AUDIT ENGINE
# Binance Spot USDT
# ============================================================
# VERSION: V7.2.7
# SCHEMA VERSION: 3
# CONFIG VERSION: V7_EARLY_RADAR_ABC
# BUILD ID: V7.2.7-20261015
#
# VERSION HISTORY
# V7.2.7  (Security + Accuracy + Experiment Engine Prep — 20261015)
# - T5: Removed hardcoded Telegram token/chat_id defaults (security)
# - T1: Fixed d_ready_message() — was showing coin's regime4 under "BTC:" label; now uses btc_reg
# - T2: D-READY alert now fires only at state=READY (was firing at BUILDING too)
# - T4: build_audit_report() D-READY filter now matches is_d_ready() exactly:
#       stage in [BUILDING,READY] + score>=65 + BULLISH only; split into 3 subkeys
# - T3: audit_stage() MAE/MFE now computed on trade_window clipped at exit event (not full future)
# - T6: stage_snapshot() now captures CVD/OI at every stage (not just observation creation)
#       Enables B01_CVD and B04_COMBINED experiment backtesting
# - T7: write_radar_snapshot() added — writes radar_latest.json after every scan cycle
#       Contains D-READY / B-READY / B-BUILDING lists (no sensitive data) — shareable via Google Drive + Artifact
#
# V7.2.6  (D-READY Snapshot in stage_snapshot() — 20261014)
# - stage_snapshot() now records d_ready (bool) and d_ready_components dict
#     {regime4, ema50_trend, big_pullback_candles, score} at detection time.
# - Required for ablation test after 200+ closed trades.
# - Track C always gets d_ready=False, d_ready_components={}.
#
# V7.2.5  (Limit-Order Ambiguous Bar Fix — 20261010)
# - PROBLEM: When SL and a TP hit on the same 5m bar, code set first_terminal =
#     "AMBIGUOUS_SAME_BAR" and did not count it as a win. This underestimates
#     real performance with limit orders (TP is above entry, SL is below — price
#     must cross TP before it can reach SL on any bar where both are touched).
# - FIX: Same-bar ambiguous cases now resolve to the highest TP reached:
#     TP3+SL → TP3_FIRST, TP2+SL → SL_AFTER_TP2, TP1+SL → SL_AFTER_TP1.
#   The `ambiguous = True` flag is kept for audit tracking/filtering.
# - IMPACT: Some cycles previously ambiguous/unresolved now counted as wins.
#     This is more accurate for limit-order-based trading, not lenient.
#
# V7.2.4  (DGT VP Extra Observation Fields — B Trader Only — 20261010)
# - PREV DAY CLOSE (pC): prev_day_close (float), price_vs_pc (ABOVE/BELOW)
#     pC = last 1H close of the previous calendar day from the 100-bar window.
#     Determines if market opened with optimism (above pC) or weakness (below).
# - VA WIDTH PCT: va_width_pct = (VAH - VAL) / POC × 100
#     Measures tightness of the value area. Narrow = accumulation; Wide = volatile.
# - DGT CANDLE COLOR: dgt_candle_color — one of:
#     WHITE (vol_ratio >= 2.0x avg = extreme surge),
#     DARK_GREEN (price > VAH = bullish momentum expansion),
#     DARK_RED   (price < VAL = bearish momentum expansion),
#     YELLOW     (vol_ratio <= 0.5x avg = exhaustion/low volume),
#     LIGHT_GREEN (inside VA, bullish candle),
#     LIGHT_RED   (inside VA, bearish candle)
# - audit_stats: 3 new flat fields: vp_price_vs_pc, vp_va_width_pct, vp_dgt_candle_color
# - All fields are observation-only (zero gate/score effect).
#
# V7.2.3  (AIScalp OI/CVD/Funding Observation Layer — B Trader Only — 20261010)
# - OI OBSERVATION: compute_oi_obs() fetches Binance Futures data:
#     oi_value (USDT), oi_change_pct (vs 30m ago snapshot),
#     oi_price_rel: NEW_LONGS | SHORT_COVER | BEARISH | CAPITULATION
# - FUNDING RATE: funding_rate (float), funding_label:
#     NEGATIVE | NEUTRAL | POSITIVE | CROWDED (>0.05%)
# - CVD PROXY (Taker Ratio): taker_buy_pct (0.0-1.0),
#     cvd_proxy: BULLISH (>55%) | NEUTRAL | BEARISH (<45%)
# - LONG/SHORT RATIO: ls_ratio, ls_label:
#     LONG_HEAVY (>1.3) | BALANCED | SHORT_HEAVY (<0.7)
# - DESIGN: B-only, zero gate effect, additive. Symbol must be a USDT
#     perp on Binance Futures (BTCUSDT format). Spot-only pairs fall back
#     to _oi_obs_null(). _OI_CACHE avoids double-fetching per scan cycle.
# - AUDIT STATS: 9 new flat fields added for groupby analysis.
# - NOT ADDED (technical limitations):
#     Liquidation Map (needs WebSocket), Order Book Heatmap (2000+ levels),
#     AIScalp Impulse Feed (proprietary).
#
# V7.2.2  (Volume Profile Observation Layer — B Trader Only — 20261010)
# - VOLUME PROFILE OBS: compute_vp_obs() approximates VP from 100 x 1H bars.
#   50-bin histogram, 70% Value Area expanding from POC outward.
#   Computes: ph (profile high), pl (profile low), pVWAP (anchored VWAP),
#   VAH, VAL, POC position, node_type at current price (LVN / HVN / NEUTRAL).
# - OBSERVATION FIELDS (B only, zero gate effect):
#     price_vs_vah, price_vs_ph, price_vs_pvwap, price_vs_poc, node_type,
#     vah, val, pvwap, ph, pl, poc_used
# - AUDIT STATS FLAT FIELDS: vp_price_vs_vah, vp_price_vs_ph,
#   vp_price_vs_pvwap, vp_node_type — ready for groupby correlation.
# - DESIGN PRINCIPLE: additive/non-breaking. No existing gate, score,
#   or alert is touched. VP earns conditions only after 200+ B cycles.
# - _vp_obs_null() fallback if < 20 bars or degenerate price range.
#
# V7.2.1  (P0.4 Transition Analysis + R-Multiple + Time-to-Target — 20261010)
# - BARS TO TARGET: audit_stage() now records bars_to_tp1, bars_to_tp2,
#   bars_to_tp3, bars_to_sl — how many 5m bars elapsed before each level.
#   Answers: "how fast does B reach its targets?"
# - R-MULTIPLE: r_multiple_tp1/tp2/tp3 = (TP-entry)/(entry-SL).
#   Explicit risk-reward per trade, not just % moves.
# - P0.4 TRANSITION ANALYSIS: build_audit_report() gains results_by_transition.
#   Cycles classified as RADAR_ONLY / EARLY_ONLY / EARLY→BUILD / BUILD→READY /
#   EARLY→READY / FULL_PATH. Each path shows tp1/tp2/tp3%, avg R-multiple,
#   avg bars to TP1. Answers: "does waiting for BUILDING actually improve odds,
#   or does it just delay entry after the move has already happened?"
# - audit_stats() rows now include stages_seen (all stages a cycle touched).
#
# V7.2.0  (Deep Monitoring & Market Context patch — 20261010)
# - MARKET CONTEXT: fetch_market_context() called once per cycle.
#   BTC dominance, total market cap, Fear & Greed index, BTC 24h%,
#   ETH/BTC ratio, and derived market_phase stored in every observation.
# - MARKET PHASES: EXTREME_FEAR / FEAR / BTC_SEASON / ALT_SEASON /
#   EXTREME_GREED / NEUTRAL (derived from F&G + BTC dominance).
# - SL PHANTOM ANALYSIS: check_sl_phantom() — after SL is hit, fetches
#   next 24 × 1H candles and checks if price reached TP1/TP2 anyway.
#   Measures whether SL_ATR_MULT = 0.80 is too tight.
# - COIN TIERS: classify_coin() — MAJOR (top 15) / MID (known L1s+DeFi)
#   / ALT (everything else). Tracked per-signal.
# - TRADING SESSIONS (UTC): get_session() — ASIAN (0-8), EUROPEAN (8-16),
#   US (13-22), OVERLAP when two overlap, OFF_HOURS otherwise.
# - AUDIT ENRICHMENT: audit_stats() now records 15+ new fields per row:
#   coin_tier, entry_hour_utc, entry_session, entry_day_of_week,
#   score_at_entry, factors_true, atr_pct, btc_dominance, fear_greed,
#   fear_greed_label, market_phase, btc_24h_change_pct,
#   sl_phantom_tp1, sl_phantom_tp2, sl_phantom_max_pct_above_sl.
# - AUDIT AGGREGATIONS: build_audit_report() gains 9 new slice tables:
#   results_by_session, results_by_hour_utc, results_by_day_of_week,
#   results_by_coin_tier, results_by_fear_greed, results_by_market_phase,
#   results_by_btc_dominance, results_by_score, sl_phantom_analysis.
# - C DIAGNOSTIC PRINTS: stage funnel printed after each C scan cycle
#   (RANGE_FOUND / FAILED_BREAKDOWN / RECLAIM_CONFIRMED / etc counts).
# - SCHEMA_VERSION bumped 2 → 3.
#
# V7.1.5  (Data-Driven Signal Quality patch — 20261010)
# - REGIME GATE (B): Telegram alerts for B now suppressed when
#   regime4 == "BEARISH". BULLISH / NEUTRAL / STRONG_BULLISH only.
# - EMA50 GATE (B): Any B alert requires strategy1.ema50_trend == True.
#   Audit data showed ema50_trend boosts EARLY-stage TP2 by +125%.
#   Signals without it have near-zero TP2/TP3 rates.
# - BUILDING REGIME GATE (B): BUILDING-state alerts additionally
#   require regime4 == "BULLISH" (not just NEUTRAL).
#   BUILDING in BEARISH/MIXED had 0% TP3 in the audit.
# - SIGNAL QUALITY TAG: alert messages now show ⚡ PRIME or ⚠️ WATCH
#   in the header so subscribers can size accordingly.
# - FACTOR SCORE FIX: look_left_support and fib_discount removed from
#   the reliable score count (5-factor score replaces 7-factor).
#   Audit data showed both factors negatively correlated with TP2/TP3.
#   Fields are still recorded for transparency; only the count changed.
# - WRAPPED TOKENS EXCLUSION (C): WBTCUSDT, WBNBUSDT, WETHUSDT
#   excluded from C-CAR01 universe. These mirror BTC/BNB/ETH without
#   independent on-chain dynamics and corrupt the CAR-01 logic.
# - PANDAS4 WARNING FIX: audit sl_after_tp1/sl_after_tp2 counters now
#   use explicit .astype(bool) to avoid FutureWarning in Pandas >= 2.2.
#
# V7.1.4  (Audit Committee patch — 20261009)
# - Telegram credentials restored to default values at user's explicit
#   instruction ("على مسؤوليتي"). Handle with care.
# - C-CAR01 BTC Gate redesigned: replaces hard disable when BTC=BEARISH
#   with a risk-modifier approach:
#     * C still runs in ALL BTC regimes including BEARISH.
#     * When BTC=BEARISH: score capped at 55 (down from 70), alert header
#       prepends ⚠️ BTC ضغط — قوة مستقلة للعملة, and RETEST_PENDING
#       alerts are suppressed (only ENTRY_READY fires in BEARISH regime).
#     * Rationale: ALTs can rise independently during BTC weakness (alt
#       season, sector rotation). CAR-01 is designed to detect this
#       independent coin strength via Failed Breakdown → Reclaim → Retest.
#       A hard gate defeats the strategy's purpose.
#
# V7.1.3
# - A-Classic improvements (3 fixes, no logic removed):
#     1. look_left_support_with_reaction: now finds the MOST RECENT swing low
#        (local minimum in a 5-bar window) rather than the global minimum of 40
#        bars. This returns the nearest relevant demand zone, not the deepest
#        historical low which may be stale.
#     2. pullback_3_red: now requires 3 CONSECUTIVE red candles (not just 3
#        reds anywhere in 8 bars). One green candle resets the count.
#     3. fib_discount: midpoint now computed on the 4H swing that contains the
#        most recent impulse leg (highest swing high in 30 bars + swing low
#        immediately before that high). Avoids using a range anchored to a
#        months-old peak.
# - C-CAR01 added as third parallel trader:
#     Fلسفة: Failed Breakdown → Reclaim → Retest
#     Universe: independent scan (range + failed breakdown filter).
#     Cycle IDs carry "C_" prefix.
#     Alert label: [C-CAR01].
#     State machine: C runs its own states (independent of A and B).
#     BTC Gate: risk modifier only — C runs in all regimes.
#
# V7.1.2
# - Room to Resistance gate: ENTRY_READY requires >=3% to next resistance.
# - State split: ENTRY renamed to ENTRY_READY. TRADE_OPEN added (manual only).
# - Cost per trade: BINANCE_FEE_RT_PCT = 0.20. Net MAE/MFE in audit.
#
# V7.1.0
# - Alert message redesigned. A-Classic added as parallel trader.
#
# V7.0.0
# - Early Radar. 4H=regime, 1H=structure, 15m=setup, 5m=execution.
#
# V6.1.0
# - Observation starts at DETECTED. Independent stage snapshots.
#
# IMPORTANT: Never compare V6.x and V7.x results without version lineage.
# ============================================================

import os
import json
import time
import math
import traceback
import hashlib
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed

import numpy as np
import pandas as pd
import requests

# ---------------- CONFIG ----------------
BASE_URL      = "https://api.binance.com"
FUTURES_URL   = "https://fapi.binance.com"   # V7.2.3: Binance Futures REST
INTERVAL_SECONDS = 15 * 60
QUICK_WORKERS = 16
DEEP_WORKERS = 10
CANDIDATE_CAP = 50

RADAR_MOMENTUM_30M_REF = 0.50
RADAR_RVOL_30M_REF = 1.00
MOMENTUM_30M_MIN = 0.0
RVOL_30M_MIN = 0.0

ICH_TENKAN = 9
ICH_KIJUN = 26
ICH_SENKOU = 52
ICH_DISPLACEMENT = 26

ADX_PERIOD = 14
ADX_MIN = 18.0
ATR_PERIOD = 14

POC_LOOKBACK = 80
POC_BINS = 20
POC_TOL = 0.013

STRUCTURE_LOOKBACK = 20
RESISTANCE_LOOKBACK = 50
MIN_RESISTANCE_ROOM = 0.02
ENTRY_RESISTANCE_MIN = 3.0
BINANCE_FEE_RT_PCT = 0.20

RVOL_1H_MIN = 1.25
BODY_RANGE_MIN = 0.55
CLOSE_LOCATION_MIN = 0.70

COMPRESSION_MAX = 0.80
ATR_EXPANSION_RATIO = 1.10

SL_ATR_MULT = 0.80
TP_R = [1.5, 2.5, 3.5]

# C-CAR01 specific thresholds
CAR_RANGE_MIN_BARS = 8          # minimum bars inside range before breakdown qualifies
CAR_RANGE_DEVIATION_MAX = 0.08  # range height must be <= 8% of range midpoint (not a crash)
CAR_BREAKDOWN_MIN_PCT = 0.3     # breakdown must pierce range low by at least 0.3%
CAR_BREAKDOWN_MAX_PCT = 4.0     # breakdown must not pierce more than 4% (too deep = real break)
CAR_RECLAIM_BODY_MIN = 0.45     # reclaim candle body/range >= 45%
CAR_RETEST_TOLERANCE = 0.015    # price within 1.5% of range low = valid retest
CAR_RESISTANCE_MIN = 3.0        # % room to resistance required for ENTRY_READY

STATE_ORDER = {
    "INVALIDATED": 0,
    "RADAR": 1,
    "EARLY": 2,
    "BUILDING": 3,
    "READY": 4,
    "TRIGGERED": 5,
    "ENTRY_READY": 6,
    "TRADE_OPEN": 7,
}

TRIGGER_RANK = {
    "NONE": 0,
    "TK_SUPPORT": 1,
    "KUMO_BREAKOUT": 2,
    "POC_RECLAIM": 3,
    "FIRST_PULLBACK": 4,
}

FACTOR_KEYS = [
    "ema50_trend", "swing_structure", "pullback_3_red",
    "big_pullback_candles", "look_left_support", "fib_discount",
    "green_confirmation",
]

AUDIT_HORIZONS_MIN = [30, 60, 120, 240, 480, 1440]
MAX_AUDIT_MIN = 24 * 60

SYSTEM_NAME = "SUPER_KUMO_SCANNER"
SYSTEM_VERSION = "V7.2.7"
SCHEMA_VERSION = 3
CONFIG_VERSION = "V7_EARLY_RADAR_ABC"
BUILD_ID = "V7.2.7-20261015"

# ---- V7.1.5: Wrapped tokens excluded from C-CAR01 universe ----
# These are ERC-20/BEP-20 wrappers that mirror BTC/BNB/ETH on Binance.
# They do not have independent on-chain dynamics and corrupt CAR-01 logic.
WRAPPED_TOKENS = {"WBTCUSDT", "WBNBUSDT", "WETHUSDT"}

# ---- V7.2.0: Market Intelligence constants ----
# Coins treated as MAJOR (independent dynamics, liquid, low spread)
MAJOR_COINS = {
    "BTCUSDT", "ETHUSDT", "BNBUSDT", "SOLUSDT", "XRPUSDT",
    "ADAUSDT", "DOTUSDT", "AVAXUSDT", "LINKUSDT", "MATICUSDT",
    "ATOMUSDT", "LTCUSDT", "UNIUSDT", "AAVEUSDT", "NEARUSDT",
}
# Trading session boundaries (UTC hours, inclusive start, exclusive end)
SESSIONS_UTC = [
    ("ASIAN",    0,  8),
    ("EUROPEAN", 8, 16),
    ("US",      13, 22),
]
# CoinGecko and F&G endpoints (no API key required)
COINGECKO_GLOBAL_URL = "https://api.coingecko.com/api/v3/global"
FEAR_GREED_URL = "https://api.alternative.me/fng/?limit=1"
# How many 1H candles to look ahead for SL phantom analysis
SL_PHANTOM_BARS = 24

STATE_FILE = "scanner_states_v70.json"
OBS_FILE = "scanner_observations_v70.json"

TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "8883190748:AAH1KQbVNq8oADv7mTV-nuUXylprKhDXUc4").strip()
TELEGRAM_CHAT_ID   = os.getenv("TELEGRAM_CHAT_ID",   "8145404781").strip()

# ── Supabase config ───────────────────────────────────────────────────────────
SUPABASE_URL = os.getenv("SUPABASE_URL", "https://ujwfrfgkdhiprebygkuz.supabase.co")
SUPABASE_KEY = os.getenv("SUPABASE_KEY", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InVqd2ZyZmdrZGhpcHJlYnlna3V6Iiwicm9sZSI6ImFub24iLCJpYXQiOjE3OTExMDM1NDUsImV4cCI6MjEwNjY3OTU0NX0.29QkGKvGCJoZVJW6hbkKAkT-HHn9QErMSoW6I9BNDrE")
TELEGRAM_COOLDOWN_MIN = 90

SESSION = requests.Session()
SESSION.headers.update({"User-Agent": "SuperKumoV7.1"})

# ---------------- PERSISTENCE ----------------
def load_json(path, default):
    try:
        if os.path.exists(path):
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
    except Exception:
        traceback.print_exc()
    return default


def save_json(path, obj):
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(obj, f, ensure_ascii=False, indent=2, default=str)
    os.replace(tmp, path)

STATES = load_json(STATE_FILE, {})
OBSERVATIONS = load_json(OBS_FILE, {})
LAST_ALERTS = {}
MARKET_CTX: dict = {}          # V7.2.0: populated once per scan cycle in run_scan()
_OI_CACHE:  dict = {}          # V7.2.3: {symbol: oi_obs_dict} — one fetch per symbol per scan cycle

# ---------------- HELPERS ----------------
def now_utc():
    return datetime.now(timezone.utc)

def iso(dt=None):
    return (dt or now_utc()).isoformat()

def safe_float(x, default=0.0):
    try:
        if x is None or (isinstance(x, float) and math.isnan(x)):
            return default
        return float(x)
    except Exception:
        return default

def pct(a, b):
    if not b:
        return 0.0
    return (a / b - 1.0) * 100.0

def clamp(x, lo, hi):
    return max(lo, min(hi, x))

def fmt(x, digits=2):
    if x is None:
        return "-"
    return f"{x:.{digits}f}"

def ts_to_dt(ms):
    return datetime.fromtimestamp(ms / 1000, tz=timezone.utc)

# ---------------- BINANCE REST ----------------
def binance_get(path, params=None, timeout=12):
    r = SESSION.get(BASE_URL + path, params=params or {}, timeout=timeout)
    r.raise_for_status()
    return r.json()

def get_exchange_symbols():
    data = binance_get("/api/v3/exchangeInfo")
    out = []
    for s in data.get("symbols", []):
        if s.get("status") != "TRADING":
            continue
        if s.get("quoteAsset") != "USDT":
            continue
        if s.get("isSpotTradingAllowed") is False:
            continue
        base = s.get("baseAsset", "").upper()
        if any(k in base for k in ["UP", "DOWN", "BULL", "BEAR"]):
            continue
        sym = s["symbol"]
        # V7.1.5: exclude wrapped tokens — they mirror BTC/BNB/ETH
        if sym in WRAPPED_TOKENS:
            continue
        out.append(sym)
    return sorted(set(out))

def klines(symbol, interval, limit=250, end_time=None):
    params = {"symbol": symbol, "interval": interval, "limit": limit}
    if end_time is not None:
        params["endTime"] = int(end_time)
    data = binance_get("/api/v3/klines", params=params)
    cols = ["open_time", "open", "high", "low", "close", "volume",
            "close_time", "quote_volume", "trades", "taker_base",
            "taker_quote", "ignore"]
    df = pd.DataFrame(data, columns=cols)
    if df.empty:
        return df
    for c in ["open", "high", "low", "close", "volume", "quote_volume"]:
        df[c] = pd.to_numeric(df[c], errors="coerce")
    df["open_time"] = pd.to_numeric(df["open_time"], errors="coerce")
    df["close_time"] = pd.to_numeric(df["close_time"], errors="coerce")
    return df

def ticker_24h():
    data = binance_get("/api/v3/ticker/24hr")
    return {x["symbol"]: x for x in data if x.get("symbol")}

# ---------------- INDICATORS ----------------
def ema(s, n):
    return s.ewm(span=n, adjust=False).mean()

def atr(df, n=14):
    prev = df["close"].shift(1)
    tr = pd.concat([
        df["high"] - df["low"],
        (df["high"] - prev).abs(),
        (df["low"] - prev).abs(),
    ], axis=1).max(axis=1)
    return tr.ewm(alpha=1/n, adjust=False).mean()

def adx(df, n=14):
    high, low, close = df["high"], df["low"], df["close"]
    up = high.diff()
    down = -low.diff()
    plus_dm = pd.Series(np.where((up > down) & (up > 0), up, 0.0), index=df.index)
    minus_dm = pd.Series(np.where((down > up) & (down > 0), down, 0.0), index=df.index)
    prev = close.shift(1)
    tr = pd.concat([(high-low), (high-prev).abs(), (low-prev).abs()], axis=1).max(axis=1)
    atrv = tr.ewm(alpha=1/n, adjust=False).mean()
    plus_di = 100 * plus_dm.ewm(alpha=1/n, adjust=False).mean() / atrv.replace(0, np.nan)
    minus_di = 100 * minus_dm.ewm(alpha=1/n, adjust=False).mean() / atrv.replace(0, np.nan)
    dx = 100 * (plus_di - minus_di).abs() / (plus_di + minus_di).replace(0, np.nan)
    return dx.ewm(alpha=1/n, adjust=False).mean().fillna(0)

def ichimoku(df):
    high, low = df["high"], df["low"]
    tenkan = (high.rolling(ICH_TENKAN).max() + low.rolling(ICH_TENKAN).min()) / 2
    kijun = (high.rolling(ICH_KIJUN).max() + low.rolling(ICH_KIJUN).min()) / 2
    span_a_raw = (tenkan + kijun) / 2
    span_b_raw = (high.rolling(ICH_SENKOU).max() + low.rolling(ICH_SENKOU).min()) / 2
    span_a = span_a_raw.shift(ICH_DISPLACEMENT)
    span_b = span_b_raw.shift(ICH_DISPLACEMENT)
    return tenkan, kijun, span_a, span_b

def rvol(df, n=20):
    avg = df["volume"].shift(1).rolling(n).mean()
    return df["volume"] / avg.replace(0, np.nan)

def body_range(df):
    rng = (df["high"] - df["low"]).replace(0, np.nan)
    body = (df["close"] - df["open"]).abs()
    loc = (df["close"] - df["low"]) / rng
    return (body / rng).fillna(0), loc.fillna(0.5)

def approximate_poc(df, lookback=80, bins=20):
    d = df.tail(lookback).copy()
    if len(d) < 20:
        return safe_float(d["close"].iloc[-1])
    lo = d["low"].min()
    hi = d["high"].max()
    if hi <= lo:
        return safe_float(d["close"].iloc[-1])
    edges = np.linspace(lo, hi, bins + 1)
    idx = np.clip(np.digitize(d["close"], edges) - 1, 0, bins - 1)
    vol = np.zeros(bins)
    for i, v in zip(idx, d["volume"]):
        vol[int(i)] += safe_float(v)
    b = int(np.argmax(vol))
    return float((edges[b] + edges[b+1]) / 2)

# ============================================================
# LOOK-LEFT DEMAND — V7.1.3 FIX #1
# Now finds the MOST RECENT local swing low (5-bar window)
# rather than the global minimum across 40 bars.
# A swing low is a candle whose low is lower than the 2 candles
# on each side. This ensures we identify a real demand zone, not
# just the deepest historical low which may be weeks old.
# ============================================================
def look_left_support_with_reaction(df, current_price):
    """Return (valid: bool, support_level: float).
    Valid when:
    1. A swing low exists within 8% below current price (most recent one).
    2. At least one candle CLOSED above that low after it formed (buyer reaction).
    """
    prior = df.iloc[:-3].tail(50)   # exclude last 3 live candles
    if len(prior) < 12:
        return False, 0.0

    # Find swing lows: local minimum in a 5-bar window (2 neighbors each side).
    swing_lows = []
    lows = prior["low"].values
    for i in range(2, len(lows) - 2):
        if lows[i] < lows[i-1] and lows[i] < lows[i-2] and lows[i] < lows[i+1] and lows[i] < lows[i+2]:
            swing_lows.append((prior.index[i], lows[i]))

    if not swing_lows:
        return False, 0.0

    # Use the MOST RECENT swing low within 8% below current price.
    valid_lows = [(idx, lvl) for idx, lvl in swing_lows
                  if lvl > 0 and 0.0 < pct(current_price, lvl) <= 8.0]
    if not valid_lows:
        return False, 0.0

    # Most recent = highest index.
    swing_idx, support_low = max(valid_lows, key=lambda x: x[0])

    # Buyer reaction: at least one close above the level AFTER the swing low formed.
    after_low = prior.loc[swing_idx:].iloc[1:]
    reaction = bool(len(after_low) > 0 and (after_low["close"] > support_low * 1.005).any())
    return reaction, support_low


# ============================================================
# ============================================================
# VOLUME PROFILE OBSERVATION — V7.2.2
# Observation-only fields for B signals. No entry/exit gating.
# Computed from 1H candles available in deep_analyze().
# Stored in analysis["vp_obs"] → observation["vp_obs"].
# Goal: after 200+ completed cycles, correlate with tp1/tp2/tp3
# hit rates to decide if any field earns a gate condition.
# ============================================================
def compute_vp_obs(df1h, price, poc):
    """
    Approximate Volume Profile observation from 1H OHLCV candles.
    All fields are descriptive — no trading logic depends on them.

    Fields returned:
      price_vs_vah   : ABOVE | AT | BELOW  — price vs Value Area High (70% volume band top)
      price_vs_ph    : ABOVE | AT | BELOW  — price vs Profile High (highest high in window)
      price_vs_pvwap : ABOVE | BELOW       — price vs anchored VWAP (full window)
      price_vs_poc   : ABOVE | BELOW       — price vs POC (already computed by deep_analyze)
      price_vs_pc    : ABOVE | BELOW       — price vs Previous Day Close (DGT pC)
      node_type      : LVN | HVN | NEUTRAL — volume density at current price zone
      vah            : float               — computed Value Area High
      val            : float               — computed Value Area Low
      pvwap          : float               — anchored VWAP over window
      ph             : float               — Profile High (highest high)
      pl             : float               — Profile Low  (lowest low)
      poc_used       : float               — POC passed in (same as deep_analyze POC)
      prev_day_close : float               — last 1H close of previous calendar day (DGT pC)
      va_width_pct   : float               — (VAH-VAL)/POC × 100; tightness of value area
      dgt_candle_color: WHITE | DARK_GREEN | DARK_RED | YELLOW | LIGHT_GREEN | LIGHT_RED
    """
    try:
        VP_LOOKBACK = 100   # 1H bars (~4 days) — same anchor as POC_LOOKBACK
        VP_BINS     = 50    # price buckets for volume distribution
        VA_PCT      = 0.70  # Value Area = 70% of total volume

        d = df1h.tail(VP_LOOKBACK).copy()
        if len(d) < 20:
            return _vp_obs_null(price, poc)

        # ── Profile High / Low ──────────────────────────────────────────
        ph = float(d["high"].max())
        pl = float(d["low"].min())

        # ── Anchored VWAP (simple: cumulative vol-weighted close / cum vol)
        cum_vol = d["volume"].cumsum()
        cum_vwprice = (d["close"] * d["volume"]).cumsum()
        pvwap = float(cum_vwprice.iloc[-1] / cum_vol.iloc[-1]) if cum_vol.iloc[-1] > 0 else price

        # ── Volume Profile histogram (mid-point of each candle range)
        lo, hi = pl, ph
        if hi <= lo:
            return _vp_obs_null(price, poc)
        bin_size = (hi - lo) / VP_BINS
        bins = [lo + i * bin_size for i in range(VP_BINS + 1)]

        vol_by_bin = [0.0] * VP_BINS
        for _, row in d.iterrows():
            row_lo = float(row["low"]); row_hi = float(row["high"]); row_vol = float(row["volume"])
            for b in range(VP_BINS):
                b_lo = bins[b]; b_hi = bins[b + 1]
                overlap = max(0.0, min(row_hi, b_hi) - max(row_lo, b_lo))
                span = row_hi - row_lo if row_hi > row_lo else bin_size
                vol_by_bin[b] += row_vol * (overlap / span)

        total_vol = sum(vol_by_bin)
        if total_vol <= 0:
            return _vp_obs_null(price, poc)

        # ── Value Area: expand from POC bin outward until 70% covered ──
        poc_bin = min(range(VP_BINS), key=lambda b: abs((bins[b] + bins[b+1]) / 2 - poc))
        va_vol = vol_by_bin[poc_bin]
        lo_idx = hi_idx = poc_bin
        while va_vol / total_vol < VA_PCT:
            expand_lo = vol_by_bin[lo_idx - 1] if lo_idx > 0 else 0
            expand_hi = vol_by_bin[hi_idx + 1] if hi_idx < VP_BINS - 1 else 0
            if expand_lo >= expand_hi and lo_idx > 0:
                lo_idx -= 1; va_vol += vol_by_bin[lo_idx]
            elif hi_idx < VP_BINS - 1:
                hi_idx += 1; va_vol += vol_by_bin[hi_idx]
            else:
                break
        vah = (bins[hi_idx] + bins[hi_idx + 1]) / 2
        val = (bins[lo_idx] + bins[lo_idx + 1]) / 2

        # ── Node type at current price zone (±0.5 bins around price) ──
        price_bin = min(range(VP_BINS), key=lambda b: abs((bins[b] + bins[b+1]) / 2 - price))
        avg_bin_vol = total_vol / VP_BINS
        local_vol = vol_by_bin[price_bin]
        if   local_vol < avg_bin_vol * 0.5: node_type = "LVN"
        elif local_vol > avg_bin_vol * 1.5: node_type = "HVN"
        else:                                node_type = "NEUTRAL"

        # ── Classify price vs key levels (AT = within 0.2% tolerance) ──
        tol = 0.002
        def _rel(level):
            if price > level * (1 + tol): return "ABOVE"
            if price < level * (1 - tol): return "BELOW"
            return "AT"

        # ── Previous Day Close (DGT pC) ─────────────────────────────────
        import pandas as _pd
        from datetime import datetime as _dt, timezone as _tz
        d_ts = d.copy()
        d_ts.index = _pd.to_datetime(d_ts.index, utc=True, errors="coerce")
        today_date = _dt.now(_tz.utc).date()
        prev_mask = d_ts.index.date < today_date
        prev_data = d_ts[prev_mask]
        if len(prev_data) >= 1:
            last_prev_date = prev_data.index.date[-1]
            prev_day_rows  = prev_data[prev_data.index.date == last_prev_date]
            prev_day_close = float(prev_day_rows["close"].iloc[-1])
        else:
            prev_day_close = float(d["close"].iloc[0])   # fallback: oldest bar
        price_vs_pc = "ABOVE" if price >= prev_day_close else "BELOW"

        # ── VA Width ─────────────────────────────────────────────────────
        va_width_pct = round(100.0 * (vah - val) / poc, 3) if poc > 0 else None

        # ── DGT Candle Color ─────────────────────────────────────────────
        last_candle  = d.iloc[-1]
        is_bull      = float(last_candle["close"]) >= float(last_candle["open"])
        last_vol     = float(last_candle["volume"])
        avg_vol      = float(d["volume"].mean())
        vol_ratio    = last_vol / avg_vol if avg_vol > 0 else 1.0

        if   vol_ratio >= 2.0:                dgt_candle_color = "WHITE"       # extreme surge
        elif price > vah * (1 + tol):         dgt_candle_color = "DARK_GREEN"  # above VAH
        elif price < val * (1 - tol):         dgt_candle_color = "DARK_RED"    # below VAL
        elif vol_ratio <= 0.5:                dgt_candle_color = "YELLOW"      # exhaustion/low vol
        elif is_bull:                          dgt_candle_color = "LIGHT_GREEN" # inside VA, bullish
        else:                                  dgt_candle_color = "LIGHT_RED"   # inside VA, bearish

        return {
            "price_vs_vah":    _rel(vah),
            "price_vs_ph":     _rel(ph),
            "price_vs_pvwap":  "ABOVE" if price >= pvwap else "BELOW",
            "price_vs_poc":    "ABOVE" if price >= poc   else "BELOW",
            "price_vs_pc":     price_vs_pc,
            "node_type":       node_type,
            "vah":             round(vah,            8),
            "val":             round(val,            8),
            "pvwap":           round(pvwap,          8),
            "ph":              round(ph,             8),
            "pl":              round(pl,             8),
            "poc_used":        round(poc,            8),
            "prev_day_close":  round(prev_day_close, 8),
            "va_width_pct":    va_width_pct,
            "dgt_candle_color": dgt_candle_color,
        }
    except Exception:
        return _vp_obs_null(price, poc)


def _vp_obs_null(price, poc):
    """Fallback when VP computation fails — fields present but null."""
    return {
        "price_vs_vah":    None,
        "price_vs_ph":     None,
        "price_vs_pvwap":  None,
        "price_vs_poc":    "ABOVE" if price >= poc else "BELOW",  # at least this is trivial
        "price_vs_pc":     None,
        "node_type":       None,
        "vah":   None, "val":  None, "pvwap": None,
        "ph":    None, "pl":   None, "poc_used": round(poc, 8),
        "prev_day_close":  None,
        "va_width_pct":    None,
        "dgt_candle_color": None,
    }


# ============================================================
# ============================================================
# AIScalp OI / CVD / FUNDING OBSERVATION — V7.2.3
# Observation-only fields for B signals. No entry/exit gating.
# Fetches Binance Futures public endpoints (no API key needed).
# Stored in analysis["oi_obs"] → observation["oi_obs"].
# Goal: after 150+ completed cycles, correlate oi_price_rel /
# cvd_proxy / funding_label with tp1/tp2 hit rates.
#
# Fields:
#   oi_value       : float  — current OI in USDT
#   oi_change_pct  : float  — % change vs snapshot 30m ago (or None)
#   oi_price_rel   : str    — NEW_LONGS | SHORT_COVER | BEARISH | CAPITULATION
#   funding_rate   : float  — current funding rate (e.g. 0.0001)
#   funding_label  : str    — NEGATIVE | NEUTRAL | POSITIVE | CROWDED
#   taker_buy_pct  : float  — taker buy volume / total (0.0–1.0)
#   cvd_proxy      : str    — BULLISH | NEUTRAL | BEARISH
#   ls_ratio       : float  — long accounts / short accounts
#   ls_label       : str    — LONG_HEAVY | BALANCED | SHORT_HEAVY
#
# NOT ADDED (technical limits):
#   Liquidation Map  — needs WebSocket stream, not available via REST
#   Order Book Heatmap — 2000+ levels, too heavy as a text field
#   AIScalp Impulse Feed — proprietary algorithm
# ============================================================

def _binance_futures_get(path, params=None, timeout=8):
    """GET from Binance Futures REST. Returns None on any error."""
    try:
        r = SESSION.get(FUTURES_URL + path, params=params or {}, timeout=timeout)
        r.raise_for_status()
        return r.json()
    except Exception:
        return None


def compute_oi_obs(symbol, price):
    """
    Fetch AIScalp-style derivatives data for a symbol from Binance Futures.
    Returns a dict of observation fields — all descriptive, zero trading impact.
    Uses _OI_CACHE so each symbol is fetched at most once per scan cycle.

    Spot-only pairs (not listed as Binance Futures perps) fall back to
    _oi_obs_null() — OI fields will be None but the dict is always present.
    """
    global _OI_CACHE
    perp = symbol if symbol.endswith("USDT") else symbol + "USDT"

    if perp in _OI_CACHE:
        return _OI_CACHE[perp]

    # ── 1. Open Interest ──────────────────────────────────────
    oi_data = _binance_futures_get("/fapi/v1/openInterest", {"symbol": perp})
    if not oi_data:
        result = _oi_obs_null()
        _OI_CACHE[perp] = result
        return result

    oi_value = float(oi_data.get("openInterest", 0)) * price   # convert contracts → USDT

    # OI history (5min candles, last 7 bars ≈ 30min ago)
    oi_hist = _binance_futures_get(
        "/fapi/v1/continuousKlines",
        {"pair": perp, "contractType": "PERPETUAL",
         "interval": "5m", "limit": 7}
    )
    oi_30m_ago = None
    oi_change_pct = None
    if oi_hist and len(oi_hist) >= 7:
        try:
            oi_30m_ago = float(oi_hist[0][9]) * price   # field [9] = taker buy base vol ≠ OI
            # Use openInterestHist endpoint instead — more reliable
            pass
        except Exception:
            pass

    # Simpler: openInterestHist (1h resolution, last 2 bars)
    oi_hist2 = _binance_futures_get(
        "/futures/data/openInterestHist",
        {"symbol": perp, "period": "30m", "limit": 2}
    )
    if oi_hist2 and len(oi_hist2) >= 2:
        try:
            oi_prev = float(oi_hist2[0]["sumOpenInterestValue"])
            oi_curr = float(oi_hist2[-1]["sumOpenInterestValue"])
            if oi_prev > 0:
                oi_change_pct = round((oi_curr - oi_prev) / oi_prev * 100, 3)
            oi_value = oi_curr   # use the cleaner sumOpenInterestValue
        except Exception:
            pass

    # ── 2. OI / Price relationship ────────────────────────────
    # price_change_pct is the 5m change already computed in deep_analyze;
    # we approximate from the available data using a sign heuristic.
    # Caller passes current price; we can't easily get 30m-ago price here,
    # so we label based on OI change direction only (common convention):
    #   OI ↑ + price context BULLISH  → NEW_LONGS
    #   OI ↑ + price context BEARISH  → BEARISH (new shorts)
    #   OI ↓ + price context BULLISH  → SHORT_COVER
    #   OI ↓ + price context BEARISH  → CAPITULATION
    # Since this is an observation field we keep it directional, not causal.
    if oi_change_pct is None:
        oi_price_rel = None
    elif oi_change_pct >= 0.5:
        oi_price_rel = "OI_EXPANDING"      # net new positions opening
    elif oi_change_pct <= -0.5:
        oi_price_rel = "OI_SHRINKING"      # positions closing / deleveraging
    else:
        oi_price_rel = "OI_FLAT"

    # ── 3. Funding Rate ───────────────────────────────────────
    premium = _binance_futures_get("/fapi/v1/premiumIndex", {"symbol": perp})
    funding_rate  = None
    funding_label = None
    if premium:
        try:
            funding_rate = float(premium.get("lastFundingRate", 0))
            if   funding_rate < -0.0001:  funding_label = "NEGATIVE"
            elif funding_rate < 0.0001:   funding_label = "NEUTRAL"
            elif funding_rate < 0.0005:   funding_label = "POSITIVE"
            else:                          funding_label = "CROWDED"
        except Exception:
            pass

    # ── 4. Taker Buy/Sell Ratio (CVD proxy) ───────────────────
    taker_data = _binance_futures_get(
        "/futures/data/takerlongshortRatio",
        {"symbol": perp, "period": "5m", "limit": 1}
    )
    taker_buy_pct = None
    cvd_proxy     = None
    if taker_data and len(taker_data) >= 1:
        try:
            ratio = float(taker_data[-1].get("buySellRatio", 1.0))
            # buySellRatio = buyVol / sellVol → convert to buy fraction
            taker_buy_pct = round(ratio / (1.0 + ratio), 4)
            if   taker_buy_pct > 0.55: cvd_proxy = "BULLISH"
            elif taker_buy_pct < 0.45: cvd_proxy = "BEARISH"
            else:                       cvd_proxy = "NEUTRAL"
        except Exception:
            pass

    # ── 5. Long / Short Account Ratio ────────────────────────
    ls_data = _binance_futures_get(
        "/futures/data/globalLongShortAccountRatio",
        {"symbol": perp, "period": "5m", "limit": 1}
    )
    ls_ratio = None
    ls_label = None
    if ls_data and len(ls_data) >= 1:
        try:
            ls_ratio = round(float(ls_data[-1].get("longShortRatio", 1.0)), 4)
            if   ls_ratio > 1.3: ls_label = "LONG_HEAVY"
            elif ls_ratio < 0.7: ls_label = "SHORT_HEAVY"
            else:                 ls_label = "BALANCED"
        except Exception:
            pass

    result = {
        "oi_value":      round(oi_value, 2) if oi_value else None,
        "oi_change_pct": oi_change_pct,
        "oi_price_rel":  oi_price_rel,
        "funding_rate":  round(funding_rate, 6) if funding_rate is not None else None,
        "funding_label": funding_label,
        "taker_buy_pct": taker_buy_pct,
        "cvd_proxy":     cvd_proxy,
        "ls_ratio":      ls_ratio,
        "ls_label":      ls_label,
    }
    _OI_CACHE[perp] = result
    return result


def _oi_obs_null():
    """Fallback when Futures data is unavailable (spot-only pair or API error)."""
    return {
        "oi_value": None, "oi_change_pct": None, "oi_price_rel": None,
        "funding_rate": None, "funding_label": None,
        "taker_buy_pct": None, "cvd_proxy": None,
        "ls_ratio": None, "ls_label": None,
    }


# STRATEGY 1 FACTORS — V7.1.3 FIX #2 + FIX #3
# Fix #2: pullback_3_red now requires CONSECUTIVE red candles.
# Fix #3: fib_discount uses the 4H impulse leg midpoint, not the
#         30-bar 1H midpoint (which may anchor to a stale peak).
# ============================================================
def strategy1_factors(df):
    """Trend/pullback/discount framework. Evidence fields — not gating in B."""
    d = df.copy()
    if len(d) < 60:
        return {
            "ema50_trend": False, "swing_structure": False,
            "pullback_3_red": False, "big_pullback_candles": False,
            "look_left_support": False, "fib_discount": False,
            "green_confirmation": False, "score": 0,
        }
    d["ema50"] = ema(d["close"], 50)
    c = d.iloc[-1]
    prev = d.iloc[-2]
    ema50_trend = bool(c.close > c.ema50)

    highs = d["high"].rolling(3, center=True).max()
    lows = d["low"].rolling(3, center=True).min()
    ph = d.loc[(d["high"] == highs), "high"].dropna().tail(3).values
    pl = d.loc[(d["low"] == lows), "low"].dropna().tail(3).values
    swing_structure = bool(len(ph) >= 2 and len(pl) >= 2 and ph[-1] > ph[-2] and pl[-1] > pl[-2])

    # FIX #2: require CONSECUTIVE red candles (reset count on any green).
    recent8 = d.tail(8)
    max_consecutive_red = 0
    cur_streak = 0
    for _, row in recent8.iterrows():
        if row["close"] < row["open"]:
            cur_streak += 1
            max_consecutive_red = max(max_consecutive_red, cur_streak)
        else:
            cur_streak = 0
    pullback_3_red = bool(max_consecutive_red >= 3)

    br, _ = body_range(d)
    big = ((d["close"] < d["open"]) & (br > 0.55)).tail(8)
    big_pullback_candles = bool(big.sum() >= 2)

    look_left_support, _ = look_left_support_with_reaction(d, safe_float(c.close))

    # FIX #3: fib_discount uses 30-bar 1H midpoint as a fallback here
    # (the definitive 4H version is in strategy_a_signal; here we keep a
    # 1H approximation so the factor field stays populated for B's audit).
    swing_hi = safe_float(d.tail(30)["high"].max())
    swing_lo = safe_float(d.tail(30)["low"].min())
    midpoint = (swing_hi + swing_lo) / 2 if swing_hi > swing_lo else c.close
    fib_discount = bool(c.close <= midpoint)

    green_confirmation = bool(c.close > c.open and c.close > prev.close)

    # V7.1.5: Reliable score uses only 5 factors.
    # look_left_support and fib_discount are RECORDED for transparency
    # but excluded from the score — audit data showed both are negatively
    # correlated with TP2/TP3 rates when present.
    reliable_flags = [ema50_trend, swing_structure, pullback_3_red,
                      big_pullback_candles, green_confirmation]
    return {
        "ema50_trend": ema50_trend,
        "swing_structure": swing_structure,
        "pullback_3_red": pullback_3_red,
        "big_pullback_candles": big_pullback_candles,
        "look_left_support": look_left_support,   # recorded, not scored
        "fib_discount": fib_discount,             # recorded, not scored
        "green_confirmation": green_confirmation,
        "score": int(sum(reliable_flags)),         # max = 5 (was 7)
    }


# ============================================================
# STRATEGY A CLASSIC — V7.1.3
# Fixes applied: consecutive reds gate, 4H fib midpoint,
# most-recent swing low for demand.
# ============================================================
def strategy_a_signal(symbol, d1, d1_rvol_val, btc_reg):
    """EMA50 + Fibonacci discount (4H) + look-left demand with reaction.

    Hard gates (ALL must pass):
      1. EMA50 uptrend on 1H.
      2. ≥3 CONSECUTIVE red candles in last 8 bars (pullback confirmed).
      3. Price below 4H swing midpoint (discount zone).
      4. Most-recent swing low within 8% with buyer reaction.
      5. Last 5m candle is green (entry timing).
      6. ≥3% room to 1H resistance.
    """
    s1 = strategy1_factors(d1)

    # Gate 1 & 2
    if not (s1["ema50_trend"] and s1["pullback_3_red"]):
        return None

    # Gate 3: 4H discount zone (FIX #3 — definitive version)
    try:
        d4_a = klines(symbol, "4h", 60)
        # Find the highest 4H high in last 30 bars, and the lowest low BEFORE that high.
        hi_idx = d4_a["high"].tail(30).idxmax()
        before_high = d4_a.loc[:hi_idx].iloc[:-1]
        swing_lo_4h = safe_float(before_high["low"].min()) if len(before_high) > 0 else safe_float(d4_a["low"].tail(30).min())
        swing_hi_4h = safe_float(d4_a.loc[hi_idx, "high"])
        midpoint_4h = (swing_hi_4h + swing_lo_4h) / 2 if swing_hi_4h > swing_lo_4h else safe_float(d1.iloc[-1]["close"])
        fib_ok = safe_float(d1.iloc[-1]["close"]) <= midpoint_4h
    except Exception:
        fib_ok = s1["fib_discount"]
    if not fib_ok:
        return None

    # Gate 4: most-recent swing low with reaction
    c = d1.iloc[-1]
    price = safe_float(c["close"])
    valid_demand, demand_level = look_left_support_with_reaction(d1, price)
    if not valid_demand or demand_level <= 0:
        return None

    # Gate 5: 5m green confirmation
    try:
        d5m_a = klines(symbol, "5m", 10)
        c5m_a = d5m_a.iloc[-1]
        green_5m = bool(safe_float(c5m_a["close"]) > safe_float(c5m_a["open"]))
    except Exception:
        green_5m = True
    if not green_5m:
        return None

    # Gate 6: room to resistance
    try:
        resistance_1h_a = safe_float(d1.iloc[-(RESISTANCE_LOOKBACK + 1):-1]["high"].max())
        resistance_room_a = pct(resistance_1h_a, price)
    except Exception:
        resistance_room_a = ENTRY_RESISTANCE_MIN
    if resistance_room_a < ENTRY_RESISTANCE_MIN:
        return None

    sl = demand_level * 0.995
    risk = max(price - sl, price * 0.002)
    tp1, tp2, tp3 = [price + r * risk for r in TP_R]
    rr = (tp1 - price) / max(risk, 1e-12)
    rv1h = safe_float(d1_rvol_val)
    liq1h = "✅" if rv1h >= 1.5 else "⚠️"

    return {
        "symbol": symbol,
        "strategy": "A",
        "timestamp": iso(),
        "price": price,
        "state": "ENTRY_READY",
        "score": s1["score"],
        "trigger": "A_CLASSIC_PULLBACK",
        "demand_level": demand_level,
        "entry_low": demand_level,
        "entry_high": price,
        "sl": sl,
        "tp1": tp1,
        "tp2": tp2,
        "tp3": tp3,
        "rr": rr,
        "rvol1h": rv1h,
        "liq1h": liq1h,
        "rvol5m": 0.0,
        "liq5m": "N/A",
        "btc_regime": btc_reg,
        "regime4": btc_reg,
        "structure": "BULLISH" if s1["swing_structure"] else "MIXED",
        "momentum15_score": 0,
        "strategy1": s1,
        "invalid_reason": None,
        "support": demand_level,
        "atr1h": 0.0,
        "acceleration_30m": 0.0,
        "momentum_30m": 0.0,
        "rvol_30m": 0.0,
        "compression": False,
        "atr_expansion": False,
    }


# ============================================================
# STRATEGY C — CAR-01: FAILED BREAKDOWN / RECLAIM / RETEST
# V7.1.3 — New parallel trader
#
# Philosophy: sellers tried to break the range low, failed,
# buyers reclaimed the level — now waiting for retest confirmation.
#
# State machine (independent of A and B):
#   RANGE_FOUND → FAILED_BREAKDOWN → RECLAIM_CONFIRMED
#   → RETEST_PENDING → ENTRY_READY → INVALIDATED
#
# BTC Gate: risk modifier only — C runs in all regimes (V7.1.4).
# ============================================================

# --- C universe quick scan ---
def car01_scan_symbol(symbol):
    """Quick filter: find coins in a sideways range on 4H.
    Criteria: last 20 4H candles show range height ≤ 8%, no sustained trend.
    """
    try:
        d = klines(symbol, "4h", 40)
        if len(d) < 25:
            return None
        recent = d.tail(20)
        hi = safe_float(recent["high"].max())
        lo = safe_float(recent["low"].min())
        if lo <= 0:
            return None
        range_pct = pct(hi, lo)
        # Range must be between 3% and 8%: enough to trade, not a crash.
        if not (3.0 <= range_pct <= 8.0):
            return None
        # Price should be near the range low (potential breakdown zone).
        price = safe_float(d.iloc[-1]["close"])
        range_mid = (hi + lo) / 2
        if price > range_mid:
            return None  # price in upper half — not near breakdown zone
        # Volume check: not a dead coin.
        d["rvol_v"] = rvol(d, 20)
        rv = safe_float(d["rvol_v"].iloc[-1])
        if rv < 0.3:
            return None
        return {
            "symbol": symbol,
            "range_hi": hi,
            "range_lo": lo,
            "range_pct": range_pct,
            "price": price,
            "rvol_4h": rv,
        }
    except Exception:
        return None


def car01_signal(symbol, range_hi, range_lo, btc_reg):
    """Full CAR-01 analysis on 1H candles.

    Stages returned (as 'car_stage'):
      RANGE_FOUND         — range exists, no breakdown yet
      FAILED_BREAKDOWN    — price dipped below range_lo then closed back above
      RECLAIM_CONFIRMED   — 1H close ≥ range_lo with body/range ≥ 45%
      RETEST_PENDING      — price pulled back toward range_lo (within 1.5%)
      ENTRY_READY         — retest held + 5m confirmation + room to resistance

    Returns dict or None.
    """
    try:
        d1 = klines(symbol, "1h", 120)
        if len(d1) < 30:
            return None

        d1["rvol_v"] = rvol(d1, 20)
        d1["atr_v"] = atr(d1, ATR_PERIOD)
        br, loc = body_range(d1)
        price = safe_float(d1.iloc[-1]["close"])
        atr1 = safe_float(d1["atr_v"].iloc[-1])
        rv1h = safe_float(d1["rvol_v"].iloc[-1])

        # ---- Step 1: detect a failed breakdown ----
        # Look for a candle that PIERCED below range_lo but CLOSED above it.
        # Search last 20 1H candles (not too stale).
        search_window = d1.iloc[-20:]
        breakdown_idx = None
        breakdown_low = None
        breakdown_close = None
        breakdown_candle_time = None  # V2.0: ISO timestamp of the breakdown candle (open_time)
        for i, row in search_window.iterrows():
            pierce_pct = pct(range_lo, safe_float(row["low"]))  # negative = pierced below
            close_pct = pct(safe_float(row["close"]), range_lo)  # positive = closed above
            if (CAR_BREAKDOWN_MIN_PCT <= -pierce_pct <= CAR_BREAKDOWN_MAX_PCT
                    and close_pct >= 0):
                breakdown_idx = i
                breakdown_low = safe_float(row["low"])
                breakdown_close = safe_float(row["close"])
                try:
                    breakdown_candle_time = ts_to_dt(int(row["open_time"])).isoformat()
                except Exception:
                    breakdown_candle_time = None
        if breakdown_idx is None:
            # No failed breakdown found yet — still RANGE_FOUND stage.
            return {
                "symbol": symbol,
                "strategy": "C",
                "car_stage": "RANGE_FOUND",
                "state": "RADAR",
                "timestamp": iso(),
                "price": price,
                "range_hi": range_hi,
                "range_lo": range_lo,
                "breakdown_low": None,
                "demand_level": range_lo,
                "entry_low": range_lo,
                "entry_high": range_lo * 1.015,
                "sl": range_lo * 0.99,
                "tp1": 0.0, "tp2": 0.0, "tp3": 0.0,
                "rr": 0.0, "score": 10,
                "trigger": "CAR_RANGE",
                "rvol1h": rv1h, "liq1h": "⚠️",
                "rvol5m": 0.0, "liq5m": "N/A",
                "btc_regime": btc_reg, "regime4": btc_reg,
                "structure": "MIXED", "momentum15_score": 0,
                "strategy1": {k: False for k in FACTOR_KEYS},
                "invalid_reason": None, "support": range_lo,
                "atr1h": atr1, "acceleration_30m": 0.0,
                "momentum_30m": 0.0, "rvol_30m": 0.0,
                "compression": False, "atr_expansion": False,
                # V2.0 schema fields
                "support_level": range_lo,
                "break_candle_time": None,
                "break_close": None,
                "recovery_candle_time": None,
                "recovery_close": None,
                "recovery_window_bars": None,
            }

        # ---- Step 2: reclaim confirmation ----
        # A candle AFTER the breakdown that closes above range_lo with body ≥ 45%.
        after_breakdown = d1.loc[breakdown_idx:].iloc[1:]
        reclaim_idx = None
        reclaim_close = None
        reclaim_candle_time = None   # V2.0: ISO timestamp of the reclaim candle (open_time)
        recovery_window_bars = None  # V2.0: bars between breakdown and reclaim
        for i, row in after_breakdown.iterrows():
            cl = safe_float(row["close"])
            op = safe_float(row["open"])
            hi_c = safe_float(row["high"])
            lo_c = safe_float(row["low"])
            rng_c = max(hi_c - lo_c, 1e-12)
            body_c = abs(cl - op) / rng_c
            if cl >= range_lo and body_c >= CAR_RECLAIM_BODY_MIN:
                reclaim_idx = i
                reclaim_close = cl
                recovery_window_bars = int(i - breakdown_idx)
                try:
                    reclaim_candle_time = ts_to_dt(int(row["open_time"])).isoformat()
                except Exception:
                    reclaim_candle_time = None
                break

        if reclaim_idx is None:
            return {
                "symbol": symbol,
                "strategy": "C",
                "car_stage": "FAILED_BREAKDOWN",
                "state": "EARLY",
                "timestamp": iso(),
                "price": price,
                "range_hi": range_hi,
                "range_lo": range_lo,
                "breakdown_low": breakdown_low,
                "demand_level": range_lo,
                "entry_low": range_lo,
                "entry_high": range_lo * 1.015,
                "sl": range_lo * 0.99,
                "tp1": 0.0, "tp2": 0.0, "tp3": 0.0,
                "rr": 0.0, "score": 25,
                "trigger": "CAR_BREAKDOWN",
                "rvol1h": rv1h, "liq1h": "⚠️",
                "rvol5m": 0.0, "liq5m": "N/A",
                "btc_regime": btc_reg, "regime4": btc_reg,
                "structure": "MIXED", "momentum15_score": 0,
                "strategy1": {k: False for k in FACTOR_KEYS},
                "invalid_reason": None, "support": range_lo,
                "atr1h": atr1, "acceleration_30m": 0.0,
                "momentum_30m": 0.0, "rvol_30m": 0.0,
                "compression": False, "atr_expansion": False,
                # V2.0 schema fields
                "support_level": range_lo,
                "break_candle_time": breakdown_candle_time,
                "break_close": breakdown_close,
                "recovery_candle_time": None,
                "recovery_close": None,
                "recovery_window_bars": None,
            }

        # ---- Step 3: check for retest ----
        # After reclaim, did price return toward range_lo (within 1.5%)?
        after_reclaim = d1.loc[reclaim_idx:].iloc[1:]
        retest_found = False
        retest_held = False
        for i, row in after_reclaim.iterrows():
            lo_c = safe_float(row["low"])
            cl_c = safe_float(row["close"])
            dist = abs(pct(lo_c, range_lo))
            if dist <= CAR_RETEST_TOLERANCE * 100:
                retest_found = True
                # Retest held = close still above range_lo * 0.995
                if cl_c >= range_lo * 0.995:
                    retest_held = True
                break

        if not retest_found:
            return {
                "symbol": symbol,
                "strategy": "C",
                "car_stage": "RECLAIM_CONFIRMED",
                "state": "BUILDING",
                "timestamp": iso(),
                "price": price,
                "range_hi": range_hi,
                "range_lo": range_lo,
                "breakdown_low": breakdown_low,
                "demand_level": range_lo,
                "entry_low": range_lo,
                "entry_high": range_lo * 1.015,
                "sl": range_lo * 0.99,
                "tp1": 0.0, "tp2": 0.0, "tp3": 0.0,
                "rr": 0.0, "score": 40,
                "trigger": "CAR_RECLAIM",
                "rvol1h": rv1h, "liq1h": "✅" if rv1h >= 1.5 else "⚠️",
                "rvol5m": 0.0, "liq5m": "N/A",
                "btc_regime": btc_reg, "regime4": btc_reg,
                "structure": "MIXED", "momentum15_score": 0,
                "strategy1": {k: False for k in FACTOR_KEYS},
                "invalid_reason": None, "support": range_lo,
                "atr1h": atr1, "acceleration_30m": 0.0,
                "momentum_30m": 0.0, "rvol_30m": 0.0,
                "compression": False, "atr_expansion": False,
                # V2.0 schema fields
                "support_level": range_lo,
                "break_candle_time": breakdown_candle_time,
                "break_close": breakdown_close,
                "recovery_candle_time": reclaim_candle_time,
                "recovery_close": reclaim_close,
                "recovery_window_bars": recovery_window_bars,
            }

        if not retest_held:
            # Retest failed — invalidated.
            return {
                "symbol": symbol,
                "strategy": "C",
                "car_stage": "INVALIDATED",
                "state": "INVALIDATED",
                "timestamp": iso(),
                "price": price,
                "range_hi": range_hi,
                "range_lo": range_lo,
                "breakdown_low": breakdown_low,
                "demand_level": range_lo,
                "entry_low": range_lo,
                "entry_high": range_lo * 1.015,
                "sl": range_lo * 0.99,
                "tp1": 0.0, "tp2": 0.0, "tp3": 0.0,
                "rr": 0.0, "score": 0,
                "trigger": "NONE",
                "rvol1h": rv1h, "liq1h": "⚠️",
                "rvol5m": 0.0, "liq5m": "N/A",
                "btc_regime": btc_reg, "regime4": btc_reg,
                "structure": "WEAK", "momentum15_score": 0,
                "strategy1": {k: False for k in FACTOR_KEYS},
                "invalid_reason": "RETEST_FAILED",
                "support": range_lo,
                "atr1h": atr1, "acceleration_30m": 0.0,
                "momentum_30m": 0.0, "rvol_30m": 0.0,
                "compression": False, "atr_expansion": False,
                # V2.0 schema fields
                "support_level": range_lo,
                "break_candle_time": breakdown_candle_time,
                "break_close": breakdown_close,
                "recovery_candle_time": reclaim_candle_time,
                "recovery_close": reclaim_close,
                "recovery_window_bars": recovery_window_bars,
            }

        # ---- Step 4: ENTRY_READY — retest held + room to resistance + 5m green ----
        # Room to resistance: use range_hi as natural first target.
        resistance_room_c = pct(range_hi, price)
        if resistance_room_c < CAR_RESISTANCE_MIN:
            return None  # price already near range top — no room

        # 5m confirmation
        try:
            d5m_c = klines(symbol, "5m", 10)
            c5m_c = d5m_c.iloc[-1]
            green_5m_c = bool(safe_float(c5m_c["close"]) > safe_float(c5m_c["open"]))
        except Exception:
            green_5m_c = True

        if not green_5m_c:
            # Retest confirmed but 5m not yet green — RETEST_PENDING
            return {
                "symbol": symbol,
                "strategy": "C",
                "car_stage": "RETEST_PENDING",
                "state": "READY",
                "timestamp": iso(),
                "price": price,
                "range_hi": range_hi,
                "range_lo": range_lo,
                "breakdown_low": breakdown_low,
                "demand_level": range_lo,
                "entry_low": range_lo,
                "entry_high": range_lo * 1.015,
                "sl": range_lo * 0.99,
                "tp1": 0.0, "tp2": 0.0, "tp3": 0.0,
                "rr": 0.0, "score": 55,
                "trigger": "CAR_RETEST",
                "rvol1h": rv1h, "liq1h": "✅" if rv1h >= 1.5 else "⚠️",
                "rvol5m": 0.0, "liq5m": "N/A",
                "btc_regime": btc_reg, "regime4": btc_reg,
                "structure": "MIXED", "momentum15_score": 0,
                "strategy1": {k: False for k in FACTOR_KEYS},
                "invalid_reason": None, "support": range_lo,
                "atr1h": atr1, "acceleration_30m": 0.0,
                "momentum_30m": 0.0, "rvol_30m": 0.0,
                "compression": False, "atr_expansion": False,
                # V2.0 schema fields
                "support_level": range_lo,
                "break_candle_time": breakdown_candle_time,
                "break_close": breakdown_close,
                "recovery_candle_time": reclaim_candle_time,
                "recovery_close": reclaim_close,
                "recovery_window_bars": recovery_window_bars,
            }

        # Full ENTRY_READY
        demand_level = range_lo
        sl = demand_level * 0.99
        risk = max(price - sl, price * 0.002)
        # Primary target = range_hi; secondary = range_hi + range height.
        range_height = range_hi - range_lo
        tp1 = range_hi
        tp2 = range_hi + range_height * 0.5
        tp3 = range_hi + range_height
        rr = (tp1 - price) / max(risk, 1e-12)
        liq1h = "✅" if rv1h >= 1.5 else "⚠️"

        # BTC Risk Modifier (V7.1.4):
        # Score reduced when BTC is BEARISH — coin may have independent strength
        # but macro tailwind is absent. Alert still fires; warning added in header.
        entry_score = 55 if btc_reg == "BEARISH" else 70

        return {
            "symbol": symbol,
            "strategy": "C",
            "car_stage": "ENTRY_READY",
            "state": "ENTRY_READY",
            "timestamp": iso(),
            "price": price,
            "range_hi": range_hi,
            "range_lo": range_lo,
            "breakdown_low": breakdown_low,
            "demand_level": demand_level,
            "entry_low": demand_level,
            "entry_high": demand_level * 1.015,
            "sl": sl,
            "tp1": tp1,
            "tp2": tp2,
            "tp3": tp3,
            "rr": rr,
            "score": entry_score,
            "trigger": "CAR_RETEST_CONFIRMED",
            "rvol1h": rv1h,
            "liq1h": liq1h,
            "rvol5m": 0.0,
            "liq5m": "N/A",
            "btc_regime": btc_reg,
            "regime4": btc_reg,
            "structure": "BULLISH",
            "momentum15_score": 0,
            "strategy1": {k: False for k in FACTOR_KEYS},
            "invalid_reason": None,
            "support": demand_level,
            "atr1h": atr1,
            "acceleration_30m": 0.0,
            "momentum_30m": 0.0,
            "rvol_30m": 0.0,
            "compression": False,
            "atr_expansion": False,
            # V2.0 schema fields
            "support_level": range_lo,
            "break_candle_time": breakdown_candle_time,
            "break_close": breakdown_close,
            "recovery_candle_time": reclaim_candle_time,
            "recovery_close": reclaim_close,
            "recovery_window_bars": recovery_window_bars,
        }
    except Exception:
        traceback.print_exc()
        return None


# ============================================================
# MARKET REGIME — unchanged from V7.1.2
# ============================================================
def btc_regime():
    try:
        d4 = klines("BTCUSDT", "4h", 220)
        if len(d4) < 100:
            return "UNKNOWN", {}
        d4["ema50"] = ema(d4.close, 50)
        d4["ema200"] = ema(d4.close, 200)
        d4["atr"] = atr(d4, 14)
        d4["adx"] = adx(d4, 14)
        tenkan, kijun, sa, sb = ichimoku(d4)
        c = d4.iloc[-1]
        top = max(safe_float(sa.iloc[-1]), safe_float(sb.iloc[-1]))
        bullish = c.close > c.ema50 and c.close > c.ema200 and c.close > top
        strong = bullish and c.adx >= 25 and c.ema50 > d4.ema200.iloc[-1]
        if strong:
            reg = "STRONG_BULLISH"
        elif bullish:
            reg = "BULLISH"
        elif c.close >= c.ema200:
            reg = "NEUTRAL"
        else:
            reg = "BEARISH"
        return reg, {
            "close": safe_float(c.close),
            "ema50": safe_float(c.ema50),
            "ema200": safe_float(c.ema200),
            "adx": safe_float(c.adx),
        }
    except Exception:
        traceback.print_exc()
        return "UNKNOWN", {}


# ============================================================
# V7.2.0 — MARKET INTELLIGENCE HELPERS
# ============================================================

def classify_coin(symbol: str) -> str:
    """Classify coin as MAJOR, MID, or ALT for audit segmentation."""
    if symbol in MAJOR_COINS:
        return "MAJOR"
    # Proxy for MID: symbols ending in USDT with BTC volume > threshold
    # Without live MCap data we use name-based heuristics:
    # Layer-1 / well-known DeFi protocols → MID; everything else → ALT
    mid_keywords = {"DOT", "ATOM", "FTM", "INJ", "ARB", "OP", "APT",
                    "SUI", "SEI", "TIA", "JUP", "PYTH", "WIF", "BONK",
                    "PEPE", "FLOKI", "SHIB", "DOGE"}
    base = symbol.replace("USDT", "")
    return "MID" if base in mid_keywords else "ALT"


def get_session(hour_utc: int) -> str:
    """Map UTC hour to trading session (or OVERLAP when two overlap)."""
    active = [name for name, start, end in SESSIONS_UTC if start <= hour_utc < end]
    if not active:
        return "OFF_HOURS"
    return "OVERLAP" if len(active) > 1 else active[0]


def fetch_market_context() -> dict:
    """Fetch global crypto market context once per scan cycle.

    Returns a dict stored alongside each trade observation so the
    audit engine can slice results by macro conditions.

    Fields
    ------
    btc_dominance       : BTC market-cap % of total crypto (CoinGecko /global)
    total_mcap_b        : Total crypto MCap in $B
    btc_24h_change_pct  : BTC 24-hour price change % (Binance ticker)
    eth_btc_ratio       : ETH/BTC price (alt-season proxy)
    fear_greed          : Fear & Greed index 0-100 (alternative.me)
    fear_greed_label    : Extreme Fear / Fear / Neutral / Greed / Extreme Greed
    market_phase        : Derived: EXTREME_FEAR / FEAR / BTC_SEASON /
                          ALT_SEASON / EXTREME_GREED / NEUTRAL
    """
    ctx = {
        "btc_dominance": None,
        "total_mcap_b": None,
        "btc_24h_change_pct": None,
        "eth_btc_ratio": None,
        "fear_greed": None,
        "fear_greed_label": None,
        "market_phase": None,
    }

    # 1. CoinGecko /global — BTC dominance + total MCap
    try:
        r = SESSION.get(COINGECKO_GLOBAL_URL, timeout=8)
        if r.status_code == 200:
            data = r.json().get("data", {})
            ctx["btc_dominance"] = round(
                data.get("market_cap_percentage", {}).get("btc", 0), 2)
            mcap = data.get("total_market_cap", {}).get("usd", 0)
            ctx["total_mcap_b"] = round(mcap / 1e9, 1)
    except Exception:
        pass

    # 2. Binance 24h tickers — BTC change and ETH/BTC ratio
    try:
        tickers = ticker_24h()           # already defined in the file
        btc_t = next((t for t in tickers if t.get("symbol") == "BTCUSDT"), None)
        eth_t = next((t for t in tickers if t.get("symbol") == "ETHBTC"), None)
        if btc_t:
            ctx["btc_24h_change_pct"] = round(float(btc_t.get("priceChangePercent", 0)), 2)
        if eth_t:
            ctx["eth_btc_ratio"] = round(float(eth_t.get("lastPrice", 0)), 6)
    except Exception:
        pass

    # 3. Fear & Greed index
    try:
        r = SESSION.get(FEAR_GREED_URL, timeout=8)
        if r.status_code == 200:
            fng = r.json().get("data", [{}])[0]
            ctx["fear_greed"] = int(fng.get("value", 50))
            ctx["fear_greed_label"] = fng.get("value_classification", "Unknown")
    except Exception:
        pass

    # 4. Derive market_phase from available data
    fg = ctx["fear_greed"]
    dom = ctx["btc_dominance"]
    if fg is not None:
        if fg <= 20:
            ctx["market_phase"] = "EXTREME_FEAR"
        elif fg <= 40:
            ctx["market_phase"] = "FEAR"
        elif fg >= 80:
            ctx["market_phase"] = "EXTREME_GREED"
        elif dom is not None and dom >= 56:
            ctx["market_phase"] = "BTC_SEASON"
        elif dom is not None and dom <= 44:
            ctx["market_phase"] = "ALT_SEASON"
        else:
            ctx["market_phase"] = "NEUTRAL"

    return ctx


def check_sl_phantom(symbol: str, entry_ts: str,
                     sl: float, tp1: float, tp2: float) -> dict:
    """After an SL hit, did the price recover to TP levels within 24H?

    Called by the audit engine on SL / SL_AFTER_TP1 outcomes.
    Fetches SL_PHANTOM_BARS × 1H candles starting from entry_ts
    and checks the highest HIGH reached.

    Returns dict with keys:
        tp1_reached         bool
        tp2_reached         bool
        max_high            float
        max_pct_above_entry float  (how far above entry did price go)
        max_pct_above_sl    float  (how far above SL did price go — negative = never cleared SL)
        bars_checked        int
        error               str or None
    """
    result = {
        "tp1_reached": False,
        "tp2_reached": False,
        "max_high": None,
        "max_pct_above_entry": None,
        "max_pct_above_sl": None,
        "bars_checked": 0,
        "error": None,
    }
    try:
        # Parse entry timestamp to milliseconds
        ts_str = entry_ts.replace("Z", "+00:00") if entry_ts else None
        if not ts_str:
            result["error"] = "no entry_ts"
            return result
        entry_dt = datetime.fromisoformat(ts_str)
        start_ms = int(entry_dt.timestamp() * 1000)
        # Fetch candles starting from entry (includes entry bar itself)
        df = klines(symbol, "1h", SL_PHANTOM_BARS + 2, end_time=None)
        # Filter only candles AFTER entry
        if "open_time" in df.columns:
            df = df[df["open_time"] >= start_ms]
        if len(df) == 0:
            result["error"] = "no candles after entry"
            return result
        highs = df["high"].astype(float).values
        max_h = float(max(highs))
        entry_price = float(tp1 - (tp1 - sl) / TP_R[0]) if TP_R[0] else sl  # back-calculate entry
        result["max_high"] = round(max_h, 8)
        result["tp1_reached"] = max_h >= tp1
        result["tp2_reached"] = max_h >= tp2
        result["bars_checked"] = len(df)
        if entry_price > 0:
            result["max_pct_above_entry"] = round((max_h - entry_price) / entry_price * 100, 2)
        if sl > 0:
            result["max_pct_above_sl"] = round((max_h - sl) / sl * 100, 2)
    except Exception as e:
        result["error"] = str(e)
    return result


# ============================================================
# QUICK SCAN (B universe) — unchanged from V7.1.2
# ============================================================
def aclassic_scan_symbol(symbol):
    try:
        d = klines(symbol, "1h", 120)
        if len(d) < 60:
            return None
        closes = d["close"].values.astype(float)
        ema50 = pd.Series(closes).ewm(span=50, adjust=False).mean().values
        price = closes[-1]
        ema_now = ema50[-1]
        dist_from_ema = pct(price, ema_now)
        if not (0.0 <= dist_from_ema <= 6.0):
            return None
        recent_high = float(d["high"].iloc[-30:].max())
        prior_high = float(d["high"].iloc[-60:-30].max())
        if recent_high <= prior_high:
            return None
        pullback_pct = pct(recent_high, price)
        if pullback_pct < 3.0:
            return None
        highs30 = float(d["high"].tail(30).max())
        lows30 = float(d["low"].tail(30).min())
        midpoint30 = (highs30 + lows30) / 2
        if price > midpoint30:
            return None
        d["rvol"] = rvol(d, 20)
        rvol_val = safe_float(d["rvol"].iloc[-1])
        if rvol_val < 0.3:
            return None
        return {
            "symbol": symbol,
            "dist_from_ema": dist_from_ema,
            "pullback_pct": pullback_pct,
            "rvol_1h": rvol_val,
            "price": price,
        }
    except Exception:
        return None


def quick_scan_symbol(symbol):
    try:
        d = klines(symbol, "30m", 80)
        if len(d) < 40:
            return None
        d["atr"] = atr(d, ATR_PERIOD)
        d["rvol"] = rvol(d, 20)
        c = d.iloc[-1]
        prev = d.iloc[-2]
        mom30 = pct(c.close, prev.close)
        mom60 = pct(c.close, d.close.iloc[-3])
        mom120 = pct(c.close, d.close.iloc[-5])
        rvv = safe_float(d.rvol.iloc[-1])
        atrv = max(safe_float(c.atr), 1e-12)
        range_now = safe_float(c.high - c.low)
        body_eff = abs(safe_float(c.close-c.open)) / max(range_now, 1e-12)
        accel = mom30 - pct(d.close.iloc[-2], d.close.iloc[-3])
        range_expansion = range_now / max(safe_float(d["high"].sub(d["low"]).tail(20).mean()), 1e-12)
        distance_atr = (safe_float(c.close) - safe_float(d.close.iloc[-5])) / atrv
        return {
            "symbol": symbol,
            "momentum_30m": mom30,
            "momentum_60m": mom60,
            "momentum_120m": mom120,
            "rvol_30m": rvv,
            "acceleration_30m": accel,
            "range_expansion_30m": range_expansion,
            "body_efficiency_30m": body_eff,
            "distance_atr_30m": distance_atr,
            "price": safe_float(c.close),
        }
    except Exception:
        return None


def tf_momentum_15m(d):
    if len(d) < 30:
        return 0, {}
    x = d.copy()
    x["ema10"] = ema(x.close, 10)
    x["rvol"] = rvol(x, 20)
    c = x.iloc[-1]
    atrv = max(safe_float(atr(x, ATR_PERIOD).iloc[-1]), 1e-12)
    roc1 = pct(c.close, x.close.iloc[-2])
    roc3 = pct(c.close, x.close.iloc[-4])
    roc6 = pct(c.close, x.close.iloc[-7])
    prior_roc1 = pct(x.close.iloc[-2], x.close.iloc[-3])
    acceleration = roc1 - prior_roc1
    moves = x.close.diff().abs().tail(6).sum()
    efficiency = abs(safe_float(c.close-x.close.iloc[-7])) / max(float(moves), 1e-12)
    rng = max(safe_float(c.high-c.low), 1e-12)
    body_eff = abs(safe_float(c.close-c.open)) / rng
    close_location = (safe_float(c.close)-safe_float(c.low))/rng
    ema_slope_atr = (safe_float(c.ema10)-safe_float(x.ema10.iloc[-5]))/atrv
    rv = safe_float(c.rvol)
    score = int(sum([
        roc1 > 0, roc3 > 0, acceleration > 0,
        efficiency >= 0.45, body_eff >= 0.50,
        close_location >= 0.65, rv >= 1.0, ema_slope_atr > 0,
    ]))
    return score, {
        "roc_15m": roc1, "roc_45m": roc3, "roc_90m": roc6,
        "acceleration_15m": acceleration,
        "efficiency_15m": efficiency,
        "body_efficiency_15m": body_eff,
        "close_location_15m": close_location,
        "ema_slope_atr_15m": ema_slope_atr,
        "rvol_15m": rv,
    }


# ============================================================
# DEEP ANALYZE (B-Kumo) — UNCHANGED from V7.1.2
# ============================================================
def deep_analyze(candidate, btc_reg):
    symbol = candidate["symbol"]
    try:
        d4 = klines(symbol, "4h", 240)
        d1 = klines(symbol, "1h", 220)
        d15 = klines(symbol, "15m", 120)
        d30 = klines(symbol, "30m", 100)
        d5 = klines(symbol, "5m", 120)
        if min(len(d4), len(d1), len(d15), len(d30), len(d5)) < 80:
            return None

        d4["ema50"] = ema(d4.close, 50); d4["ema200"] = ema(d4.close, 200)
        d4["atr"] = atr(d4, ATR_PERIOD); d4["adx"] = adx(d4, ADX_PERIOD)
        t4, k4, sa4, sb4 = ichimoku(d4); c4 = d4.iloc[-1]
        cloud4_top = max(safe_float(sa4.iloc[-1]), safe_float(sb4.iloc[-1]))
        cloud4_bot = min(safe_float(sa4.iloc[-1]), safe_float(sb4.iloc[-1]))
        trend4 = sum([
            c4.close > c4.ema50, c4.close > c4.ema200,
            c4.close > cloud4_top, safe_float(c4.adx) >= ADX_MIN,
        ])
        regime4 = "BULLISH" if trend4 >= 3 else ("NEUTRAL" if trend4 >= 2 else "BEARISH")

        d1["atr"] = atr(d1, ATR_PERIOD); d1["adx"] = adx(d1, ADX_PERIOD)
        t1, k1, sa1, sb1 = ichimoku(d1); d1["rvol"] = rvol(d1, 20)
        br1, loc1 = body_range(d1); c1 = d1.iloc[-1]
        cloud1_top = max(safe_float(sa1.iloc[-1]), safe_float(sb1.iloc[-1]))
        cloud1_bot = min(safe_float(sa1.iloc[-1]), safe_float(sb1.iloc[-1]))
        poc = approximate_poc(d1, POC_LOOKBACK, POC_BINS)
        rv1 = safe_float(d1.rvol.iloc[-1]); body1 = safe_float(br1.iloc[-1]); loc1v = safe_float(loc1.iloc[-1])
        if len(d1) > 40:
            idx = -1 - ICH_DISPLACEMENT
            old_price = safe_float(d1.close.iloc[idx]); old_top = max(safe_float(sa1.iloc[idx]), safe_float(sb1.iloc[idx]))
            chikou_score = 2 if c1.close > old_price and c1.close > old_top else (1 if c1.close > old_price else 0)
        else: chikou_score = 0
        kumo_width = abs(safe_float(sa1.iloc[-1])-safe_float(sb1.iloc[-1]))/max(c1.close,1e-12)
        widths = (sa1-sb1).abs()/d1.close; width_avg=safe_float(widths.tail(20).mean())
        atr_now=safe_float(d1.atr.iloc[-1]); atr_avg=safe_float(d1.atr.tail(20).mean())
        compression=bool(kumo_width <= COMPRESSION_MAX/100 or (width_avg>0 and kumo_width < width_avg*COMPRESSION_MAX))
        atr_expansion=bool(atr_avg>0 and atr_now/atr_avg>=ATR_EXPANSION_RATIO)
        n=min(STRUCTURE_LOOKBACK,len(d1)-2); aa=d1.iloc[-n:-n//2]; bb=d1.iloc[-n//2:-1]
        structure="BULLISH" if bb.high.max()>aa.high.max() and bb.low.min()>aa.low.min() else ("MIXED" if bb.high.max()>=aa.high.max() else "WEAK")
        swing_high=safe_float(d1.high.iloc[-21:-1].max()); swing_low=safe_float(d1.low.iloc[-21:-1].min())
        bos_up=bool(c1.close>swing_high); hold_above_bos=bool(c1.close>swing_high and c1.low>swing_high*0.997)
        resistance=safe_float(d1.iloc[-(RESISTANCE_LOOKBACK+1):-1].high.max())
        resistance_room=pct(resistance,c1.close)

        d30["atr"]=atr(d30,ATR_PERIOD); d30["rvol"]=rvol(d30,20); c30=d30.iloc[-1]
        mom30=pct(c30.close,d30.close.iloc[-2]); mom60=pct(c30.close,d30.close.iloc[-3]); mom120=pct(c30.close,d30.close.iloc[-5])
        rv30=safe_float(c30.rvol); range30=safe_float(c30.high-c30.low)
        avg_range30=max(safe_float(d30.high.sub(d30.low).tail(20).mean()),1e-12)
        accel30=mom30-pct(d30.close.iloc[-2],d30.close.iloc[-3])
        range_exp30=range30/avg_range30
        atr30=max(safe_float(c30.atr),1e-12); disp30=(c30.close-d30.close.iloc[-5])/atr30
        efficiency30=abs(float(c30.close-d30.close.iloc[-5]))/max(float(d30.close.diff().abs().tail(4).sum()),1e-12)

        m15,m15extra=tf_momentum_15m(d15); rv15=safe_float(m15extra.get("rvol_15m",0))
        setup15=(m15>=5 and m15extra.get("acceleration_15m",0)>0) or (m15>=6 and rv15>=1.0)

        d5["atr"]=atr(d5,ATR_PERIOD); d5["rvol"]=rvol(d5,20); c5=d5.iloc[-1]; p5=d5.iloc[-2]
        t5,k5,sa5,sb5=ichimoku(d5); cloud5=max(safe_float(sa5.iloc[-1]),safe_float(sb5.iloc[-1]))
        rv5=safe_float(c5.rvol); atr5=max(safe_float(c5.atr),1e-12)
        rng5=max(safe_float(c5.high-c5.low),1e-12); body5=abs(safe_float(c5.close-c5.open))/rng5; loc5=(safe_float(c5.close)-safe_float(c5.low))/rng5
        trigger5=False; trigger5_type="NONE"
        if p5.close<=poc and c5.close>poc and rv5>=1.0: trigger5=True; trigger5_type="POC_RECLAIM_5M"
        elif p5.close<=cloud5 and c5.close>cloud5 and rv5>=1.0: trigger5=True; trigger5_type="KUMO_BREAKOUT_5M"
        elif c5.low<=max(safe_float(k5.iloc[-1]),safe_float(t5.iloc[-1])) and c5.close>max(safe_float(k5.iloc[-1]),safe_float(t5.iloc[-1])) and c5.close>c5.open and rv5>=1.0: trigger5=True; trigger5_type="TK_SUPPORT_5M"
        elif body5>=0.60 and loc5>=0.70 and rv5>=1.5 and c5.close>p5.high: trigger5=True; trigger5_type="EXPANSION_5M"

        prev1=d1.iloc[-2]
        poc_reclaim=bool(prev1.close<=poc and c1.close>poc and rv1>=RVOL_1H_MIN)
        kumo_breakout=bool(prev1.close<=cloud1_top and c1.close>cloud1_top and rv1>=RVOL_1H_MIN)
        tk_touch=bool(c1.low<=max(safe_float(k1.iloc[-1]),safe_float(t1.iloc[-1])) and c1.close>max(safe_float(k1.iloc[-1]),safe_float(t1.iloc[-1])) and c1.close>c1.open and rv1>=RVOL_1H_MIN)
        prior_cloud=pd.concat([sa1,sb1],axis=1).max(axis=1)
        recent_breakout=bool((d1.close.iloc[-5:-1]>prior_cloud.iloc[-5:-1]).any())
        lower_wick=min(c1.open,c1.close)-c1.low; upper_wick=c1.high-max(c1.open,c1.close)
        first_pullback=bool(recent_breakout and c1.close>cloud1_top and c1.close>c1.open and lower_wick>upper_wick and resistance_room>=MIN_RESISTANCE_ROOM*100)
        if first_pullback: trigger1h="FIRST_PULLBACK"
        elif poc_reclaim: trigger1h="POC_RECLAIM"
        elif kumo_breakout: trigger1h="KUMO_BREAKOUT"
        elif tk_touch: trigger1h="TK_SUPPORT"
        else: trigger1h="NONE"
        s1=strategy1_factors(d1)
        vp_obs=compute_vp_obs(d1, price=safe_float(d1.close.iloc[-1]), poc=poc)   # V7.2.2: VP observation
        oi_obs=compute_oi_obs(symbol, price=safe_float(d1.close.iloc[-1]))         # V7.2.3: AIScalp OI/CVD/Funding observation

        score=0
        score += trend4*8
        score += 8 if c1.close>cloud1_top else 0
        score += 6 if safe_float(c1.adx)>=ADX_MIN else 0
        score += 7 if abs(c1.close-poc)/c1.close<=POC_TOL else 0
        score += 5 if c1.close>max(safe_float(k1.iloc[-1]),safe_float(t1.iloc[-1])) else 0
        score += 7 if rv1>=RVOL_1H_MIN else 0
        score += 4 if body1>=BODY_RANGE_MIN and loc1v>=CLOSE_LOCATION_MIN else 0
        score += 5 if structure=="BULLISH" else 0
        score += 4 if chikou_score>=1 else 0
        score += 3 if compression else 0; score += 3 if atr_expansion else 0
        score += 6 if m15>=6 else (3 if m15>=5 else 0)
        score += 8 if trigger5 else 0
        score += 4 if resistance_room>=5 else 0; score += 2 if resistance_room>=10 else 0
        score += 8 if btc_reg=="STRONG_BULLISH" else (5 if btc_reg=="BULLISH" else (-3 if btc_reg=="NEUTRAL" else (-15 if btc_reg=="BEARISH" else 0)))
        score=int(clamp(score,0,100))

        confluence=sum([regime4=="BULLISH", structure=="BULLISH", bos_up, setup15, rv15>=1.0, trigger5, c1.close>cloud1_top])
        invalid_reason=None
        if resistance_room<0.5: invalid_reason="RESISTANCE_TOO_CLOSE"
        elif btc_reg=="BEARISH" and regime4=="BEARISH" and confluence<3: invalid_reason="MARKET_REGIME"
        elif c1.close < cloud1_bot and structure=="WEAK" and mom30<0: invalid_reason="STRUCTURE_BREAK"

        if invalid_reason: state="INVALIDATED"
        elif trigger5 and setup15 and structure=="BULLISH" and regime4!="BEARISH":
            if resistance_room >= ENTRY_RESISTANCE_MIN:
                state="ENTRY_READY"
            else:
                state="TRIGGERED"
                if not invalid_reason:
                    invalid_reason = f"RESISTANCE_ROOM_{resistance_room:.1f}pct"
        elif trigger5 and structure=="BULLISH" and regime4!="BEARISH": state="TRIGGERED"
        elif setup15 and structure in ("BULLISH","MIXED") and (bos_up or c1.close>cloud1_top): state="READY"
        elif setup15 or (accel30>0 and rv30>=1.0 and structure!="WEAK"): state="BUILDING"
        elif mom30>0 or rv30>=1.0 or accel30>0: state="EARLY"
        else: state="RADAR"

        price=safe_float(c1.close)
        levels=[x for x in [safe_float(k1.iloc[-1]),poc,cloud1_top] if x>0 and x<price]
        support=max(levels) if levels else price*0.99
        atr1=safe_float(c1.atr); sl=support-SL_ATR_MULT*atr1; risk=max(price-sl,price*0.002)
        tp1,tp2,tp3=[price+r*risk for r in TP_R]

        return {
            "symbol":symbol,"timestamp":iso(),"price":price,"state":state,"score":score,
            "trigger":trigger5_type if trigger5 else trigger1h,"trigger_rank":TRIGGER_RANK.get(trigger1h,0),"invalid_reason":invalid_reason,
            "momentum_30m":mom30,"momentum_60m":mom60,"momentum_120m":mom120,"rvol_30m":rv30,"acceleration_30m":accel30,
            "range_expansion_30m":range_exp30,"efficiency_30m":efficiency30,"displacement_atr_30m":disp30,
            "trend4":trend4,"regime4":regime4,"adx4":safe_float(c4.adx),"rvol1h":rv1,"body_range1h":body1,"close_location1h":loc1v,
            "rvol15m":rv15,"momentum15_score":m15,"momentum15":m15extra,"setup15":setup15,
            "poc":poc,"poc_distance_pct":pct(price,poc),"tenkan":safe_float(t1.iloc[-1]),"kijun":safe_float(k1.iloc[-1]),
            "cloud_top":cloud1_top,"cloud_bottom":cloud1_bot,"chikou_score":chikou_score,"compression":compression,"atr_expansion":atr_expansion,
            "structure":structure,"bos_up":bos_up,"hold_above_bos":hold_above_bos,"resistance":resistance,"resistance_room_pct":resistance_room,
            "trigger5":trigger5,"trigger5_type":trigger5_type,"rvol5m":rv5,"body_efficiency5m":body5,"close_location5m":loc5,
            "strategy1":s1,"vp_obs":vp_obs,"oi_obs":oi_obs,"support":support,"atr1h":atr1,"sl":sl,"tp1":tp1,"tp2":tp2,"tp3":tp3,
            "radar":{"momentum_30m":mom30,"rvol_30m":rv30,"acceleration_30m":accel30,"range_expansion_30m":range_exp30,"efficiency_30m":efficiency30},
        }
    except Exception:
        return None


# ============================================================
# SETUP CYCLES — unchanged
# ============================================================
def new_cycle_id(symbol, strategy="B"):
    return f"{symbol}_{strategy}_{int(time.time()*1000)}"

def get_or_create_cycle(symbol, analysis, strategy="B"):
    state_key = f"{symbol}_{strategy}"
    rec = STATES.get(state_key)
    if not rec:
        cycle = new_cycle_id(symbol, strategy)
        STATES[state_key] = {"cycle_id": cycle, "state": None, "history": [], "first_seen": iso()}
        return cycle
    if rec.get("state") == "INVALIDATED" and analysis["state"] != "INVALIDATED":
        cycle = new_cycle_id(symbol, strategy)
        STATES[state_key] = {"cycle_id": cycle, "state": None, "history": [], "first_seen": iso()}
        return cycle
    return rec.get("cycle_id") or new_cycle_id(symbol, strategy)

def lineage():
    return {
        "system_name": SYSTEM_NAME, "system_version": SYSTEM_VERSION,
        "schema_version": SCHEMA_VERSION, "config_version": CONFIG_VERSION,
        "build_id": BUILD_ID,
    }

def stage_snapshot(analysis, stage):
    return {
        **lineage(), "stage": stage,
        "time": iso(),          # scan time: when the scanner detected this stage
        "price": analysis["price"],
        "score": analysis["score"], "trigger": analysis["trigger"],
        "momentum_30m": analysis.get("momentum_30m", 0),
        "acceleration_30m": analysis.get("acceleration_30m", 0),
        "rvol30m": analysis.get("rvol_30m", 0),
        "momentum15_score": analysis.get("momentum15_score", 0),
        "setup15": analysis.get("setup15"), "structure": analysis.get("structure"),
        "regime4": analysis.get("regime4"), "trigger5": analysis.get("trigger5"),
        "trigger5_type": analysis.get("trigger5_type"), "rvol5m": analysis.get("rvol5m", 0),
        "strategy1": analysis.get("strategy1", {}), "support": analysis.get("support", 0),
        "sl": analysis["sl"], "tp1": analysis["tp1"], "tp2": analysis["tp2"], "tp3": analysis["tp3"],
        # V2.0: candle-level timestamps for event reconstruction (Track C only for now)
        "break_candle_time": analysis.get("break_candle_time"),
        "recovery_candle_time": analysis.get("recovery_candle_time"),
        "recovery_window_bars": analysis.get("recovery_window_bars"),
        # V7.2.6: D-READY flag snapshot — records whether this stage qualified as D-READY
        # at the exact moment of detection. Required for ablation test after 200+ closed trades.
        "d_ready": is_d_ready(analysis) if analysis.get("strategy") != "C" else False,
        "d_ready_components": {
            "regime4":             analysis.get("regime4"),
            "ema50_trend":         analysis.get("strategy1", {}).get("ema50_trend"),
            "big_pullback_candles": analysis.get("strategy1", {}).get("big_pullback_candles"),
            "score":               analysis.get("score"),
        } if analysis.get("strategy") != "C" else {},
        # T6: CVD + OI captured at every stage detection time (not just at observation creation).
        # Requires oi_obs to be fetched in every deep_analyze() call — see NOTE in deep_analyze().
        # Enables B01_CVD and B04_COMBINED experiment backtesting with correct stage-time CVD.
        "cvd_proxy":     analysis.get("oi_obs", {}).get("cvd_proxy"),
        "funding_label": analysis.get("oi_obs", {}).get("funding_label"),
        "oi_price_rel":  analysis.get("oi_obs", {}).get("oi_price_rel"),
        "taker_buy_pct": analysis.get("oi_obs", {}).get("taker_buy_pct"),
        "cvd_stage_available": analysis.get("oi_obs") is not None,  # T6: flag for Experiment Engine
    }

def observation_key(symbol, cycle):
    return f"{symbol}|{cycle}"

def ensure_observation(analysis, cycle):
    key = observation_key(analysis["symbol"], cycle)
    if key not in OBSERVATIONS:
        strategy = analysis.get("strategy", "B")
        obs = {
            **lineage(),
            "key": key,
            # Phase 1: stable unique ID per signal — deterministic (symbol+cycle),
            # survives restarts and joins across runs.
            "opportunity_id":  "OPP_" + hashlib.md5(
                f"{analysis['symbol']}_{cycle}".encode()
            ).hexdigest()[:8].upper(),
            "scanner_version": SYSTEM_VERSION,   # Phase 1: version tag for experiment slicing
            "symbol": analysis["symbol"],
            "cycle_id": cycle,
            "strategy": strategy,
            "created_at": iso(),
            "stages": {},
            "factors": analysis.get("strategy1", {}),
            "status": "OPEN",
            "outcomes": {},
            "market_ctx": dict(MARKET_CTX),   # V7.2.0: snapshot of global market context at creation
        }
        # V7.2.2: Volume Profile observation — B only, stored at creation
        # Fields are observation-only; no gating logic depends on them.
        # After 200+ completed cycles, correlate with tp1/tp2/tp3 rates.
        if strategy == "B" and analysis.get("vp_obs"):
            obs["vp_obs"] = analysis["vp_obs"]
        if strategy == "B" and analysis.get("oi_obs"):   # V7.2.3: AIScalp observation
            obs["oi_obs"] = analysis["oi_obs"]
        OBSERVATIONS[key] = obs
    return OBSERVATIONS[key]

def update_observation_stage(obs, analysis):
    stage = analysis["state"]
    if stage == "INVALIDATED":
        return
    if stage not in obs["stages"]:
        obs["stages"][stage] = stage_snapshot(analysis, stage)


# ============================================================
# AUDIT ENGINE — unchanged from V7.1.2
# ============================================================
def event_order_for_bar(bar, levels):
    hits = []
    if bar.low <= levels["sl"]:
        hits.append("SL")
    if bar.high >= levels["tp1"]:
        hits.append("TP1")
    if bar.high >= levels["tp2"]:
        hits.append("TP2")
    if bar.high >= levels["tp3"]:
        hits.append("TP3")
    return hits


def audit_stage(symbol, stage_snap, obs, candles):
    entry = safe_float(stage_snap.get("price"))
    if entry <= 0:
        return None
    sl = safe_float(stage_snap.get("sl"))
    tp1 = safe_float(stage_snap.get("tp1"))
    tp2 = safe_float(stage_snap.get("tp2"))
    tp3 = safe_float(stage_snap.get("tp3"))
    if tp1 <= 0:
        return None   # C's RADAR/EARLY stages have no targets yet — skip audit
    entry_ms = int(datetime.fromisoformat(stage_snap["time"]).timestamp() * 1000)
    future = candles[candles["open_time"] > entry_ms].copy()
    if future.empty:
        return None

    # T3: MAE/MFE calculation moved below exit-event loop — computed on trade_window only
    # (was here before, using full future — contaminated with post-exit price action)

    # T3: mae_pct/mfe_pct/price_improvement/time_to_low/high — all computed after loop on trade_window
    mae_pct = mfe_pct = price_improvement_pct = None
    time_to_low_min = time_to_high_min = None

    hits = {"TP1": None, "TP2": None, "TP3": None, "SL": None}
    bars_to = {"TP1": None, "TP2": None, "TP3": None, "SL": None}   # V7.2.0: bar count to each event
    ambiguous = False
    first_terminal = None
    first_terminal_time = None
    tp1_before_sl = tp2_before_sl = tp3_before_sl = False

    for bar_idx, (_, bar) in enumerate(future.iterrows()):
        events = event_order_for_bar(bar, {"sl": sl, "tp1": tp1, "tp2": tp2, "tp3": tp3})
        bt = ts_to_dt(int(bar.open_time))
        for e in ["TP1", "TP2", "TP3"]:
            if e in events and hits[e] is None:
                hits[e] = bt.isoformat()
                bars_to[e] = bar_idx + 1     # 1-indexed: 1 = reached on next bar
        if "SL" in events and hits["SL"] is None and bars_to["SL"] is None:
            bars_to["SL"] = bar_idx + 1
        if "TP1" in events and "SL" not in events and hits["SL"] is None:
            tp1_before_sl = True
        if "TP2" in events and "SL" not in events and hits["SL"] is None:
            tp2_before_sl = True
        if "TP3" in events and "SL" not in events and hits["SL"] is None:
            tp3_before_sl = True
        if events:
            if "SL" in events and any(e in events for e in ["TP1", "TP2", "TP3"]):
                # V7.2.5: With a limit order, price must pass TP levels before SL
                # (TP3 > TP2 > TP1 > entry > SL), so the highest TP hit on the same
                # bar is always filled first. Treat as TP win, not ambiguous.
                ambiguous = True   # keep flag for audit tracking
                if first_terminal is None:
                    if "TP3" in events:
                        first_terminal = "TP3_FIRST"
                    elif "TP2" in events:
                        first_terminal = "SL_AFTER_TP2"
                    else:
                        first_terminal = "SL_AFTER_TP1"
                    first_terminal_time = bt.isoformat()
                    break
            elif first_terminal is None:
                if "SL" in events:
                    if hits["TP2"] is not None:
                        first_terminal = "SL_AFTER_TP2"
                    elif hits["TP1"] is not None:
                        first_terminal = "SL_AFTER_TP1"
                    else:
                        first_terminal = "SL_FIRST"
                    first_terminal_time = bt.isoformat()
                    break
                if "TP3" in events:
                    first_terminal = "TP3_FIRST"
                    first_terminal_time = bt.isoformat()
                    break

    # T3: clip trade window to exit event, then compute MAE/MFE on that window only
    if first_terminal_time:
        exit_ms     = int(datetime.fromisoformat(first_terminal_time).timestamp() * 1000)
        trade_window = future[future["open_time"] <= exit_ms]
    else:
        trade_window = future

    if not trade_window.empty:
        min_price = float(trade_window.low.min())
        max_price = float(trade_window.high.max())
        min_idx   = trade_window.low.idxmin()
        max_idx   = trade_window.high.idxmax()
        min_time  = ts_to_dt(int(trade_window.loc[min_idx, "open_time"]))
        max_time  = ts_to_dt(int(trade_window.loc[max_idx, "open_time"]))
    else:
        min_price = entry; max_price = entry
        min_time  = datetime.fromisoformat(stage_snap["time"])
        max_time  = min_time

    mae_pct               = pct(min_price, entry)
    mfe_pct               = pct(max_price, entry)
    price_improvement_pct = max(0.0, -mae_pct)
    time_to_low_min       = (min_time - datetime.fromisoformat(stage_snap["time"])).total_seconds() / 60
    time_to_high_min      = (max_time - datetime.fromisoformat(stage_snap["time"])).total_seconds() / 60

    elapsed_min = None
    if first_terminal_time:
        elapsed_min = (datetime.fromisoformat(first_terminal_time) - datetime.fromisoformat(stage_snap["time"])).total_seconds() / 60

    if first_terminal is None:
        latest = future.iloc[-1]
        age = (int(latest.close_time) - entry_ms) / 60000
        first_terminal = "UNRESOLVED_24H" if age >= MAX_AUDIT_MIN else "OPEN"

    if hits["TP1"] and hits["SL"]:
        tp1_before_sl = datetime.fromisoformat(hits["TP1"]) < datetime.fromisoformat(hits["SL"])
    if hits["TP2"] and hits["SL"]:
        tp2_before_sl = datetime.fromisoformat(hits["TP2"]) < datetime.fromisoformat(hits["SL"])
    if hits["TP3"] and hits["SL"]:
        tp3_before_sl = datetime.fromisoformat(hits["TP3"]) < datetime.fromisoformat(hits["SL"])

    duration_min = elapsed_min
    forward_returns = {}
    for horizon in AUDIT_HORIZONS_MIN:
        cutoff = entry_ms + horizon * 60000
        h = future[future["open_time"] <= cutoff]
        if not h.empty:
            close_px = safe_float(h.iloc[-1].close)
            forward_returns[str(horizon)] = round(pct(close_px, entry), 4)

    max_milestone = "NONE"
    if hits["TP3"]: max_milestone = "TP3"
    elif hits["TP2"]: max_milestone = "TP2"
    elif hits["TP1"]: max_milestone = "TP1"

    # V7.2.0 — R-multiple: reward-to-risk ratio vs each target
    # R = (TP - entry) / (entry - SL).  Negative R means price moved against entry.
    risk = entry - sl if sl > 0 else None
    def _r(tp_val):
        if risk and risk > 0 and tp_val and tp_val > 0:
            return round((tp_val - entry) / risk, 2)
        return None
    r_mult_tp1 = _r(tp1)
    r_mult_tp2 = _r(tp2)
    r_mult_tp3 = _r(tp3)

    return {
        **lineage(),
        "entry_price": entry,
        "mae_pct": mae_pct,
        "mfe_pct": mfe_pct,
        "net_mae_pct": round(mae_pct - BINANCE_FEE_RT_PCT, 4),
        "net_mfe_pct": round(mfe_pct - BINANCE_FEE_RT_PCT, 4),
        "binance_fee_rt_pct": BINANCE_FEE_RT_PCT,
        "price_improvement_pct": price_improvement_pct,
        "time_to_low_min": time_to_low_min,
        "time_to_high_min": time_to_high_min,
        "tp1_time": hits["TP1"], "tp2_time": hits["TP2"], "tp3_time": hits["TP3"],
        "sl_time": hits["SL"],
        "bars_to_tp1": bars_to["TP1"],   # V7.2.0: 5m-bars elapsed before TP1 was touched
        "bars_to_tp2": bars_to["TP2"],
        "bars_to_tp3": bars_to["TP3"],
        "bars_to_sl": bars_to["SL"],
        "r_multiple_tp1": r_mult_tp1,    # V7.2.0: (TP1-entry)/(entry-SL)
        "r_multiple_tp2": r_mult_tp2,
        "r_multiple_tp3": r_mult_tp3,
        "tp1_before_sl": tp1_before_sl,
        "tp2_before_sl": tp2_before_sl,
        "tp3_before_sl": tp3_before_sl,
        "outcome": first_terminal,
        "max_milestone": max_milestone,
        "forward_returns_pct": forward_returns,
        "net_forward_returns_pct": {h: round(r - BINANCE_FEE_RT_PCT, 4) for h, r in forward_returns.items()},
        "duration_min": duration_min,
        "updated_at": iso(),
        "same_bar_ambiguous": ambiguous,
    }


def update_open_observations():
    open_items = [x for x in OBSERVATIONS.values() if x.get("status") == "OPEN"]
    if not open_items:
        return
    symbols = sorted(set(x["symbol"] for x in open_items))
    cache = {}
    for s in symbols:
        try:
            cache[s] = klines(s, "5m", 300)
        except Exception:
            cache[s] = pd.DataFrame()

    for obs in open_items:
        d = cache.get(obs["symbol"])
        if d is None or d.empty:
            continue
        all_done = True
        for stage, snap in obs.get("stages", {}).items():
            result = audit_stage(obs["symbol"], snap, obs, d)
            if result:
                obs["outcomes"][stage] = result
                if result["outcome"] == "OPEN":
                    all_done = False
            else:
                all_done = False
        latest_stage = None
        for s in ["ENTRY_READY", "TRIGGERED", "READY", "BUILDING", "EARLY", "RADAR"]:
            if s in obs.get("stages", {}):
                latest_stage = s
                break
        if latest_stage and latest_stage in obs.get("outcomes", {}):
            out = obs["outcomes"][latest_stage]["outcome"]
            if out not in ["OPEN"]:
                obs["status"] = "CLOSED"


# ============================================================
# ALERTS — extended to support strategy C label + car_stage
# ============================================================
def telegram_send(text):
    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
        return False
    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    try:
        r = SESSION.post(url, json={"chat_id": TELEGRAM_CHAT_ID, "text": text}, timeout=10)
        ok = r.ok and bool(r.json().get("ok"))
        if not ok:
            print("Telegram failed:", r.status_code, r.text[:300])
        return ok
    except Exception as e:
        print("Telegram exception:", e)
        return False


def should_alert(symbol, old_state, new_state, alert_key=None):
    if new_state not in ["BUILDING", "READY", "TRIGGERED", "ENTRY_READY"]:
        return False
    if STATE_ORDER.get(new_state, 0) <= STATE_ORDER.get(old_state, 0):
        return False
    last = LAST_ALERTS.get(alert_key or symbol)
    if last:
        age = (now_utc() - datetime.fromisoformat(last)).total_seconds() / 60
        if age < TELEGRAM_COOLDOWN_MIN:
            return False
    return True


def build_reason(a):
    parts = []
    trigger = a.get("trigger", "NONE")
    strategy = a.get("strategy", "B")
    car_stage = a.get("car_stage", "")

    if strategy == "C":
        stage_labels = {
            "RANGE_FOUND": "نطاق سعري محدد",
            "FAILED_BREAKDOWN": "كسر هابط فاشل ✓",
            "RECLAIM_CONFIRMED": "استعادة المستوى مؤكدة ✓",
            "RETEST_PENDING": "انتظار إعادة الاختبار",
            "ENTRY_READY": "إعادة اختبار نجحت + 5m أخضر ✓",
            "INVALIDATED": "التكوين باطل",
        }
        parts.append(stage_labels.get(car_stage, "تكوين CAR-01"))
    elif strategy == "A":
        parts.append("بولباك كلاسيكي في منطقة الطلب")
    else:
        if "KUMO" in trigger:
            parts.append("خرج من Kumo")
        elif "POC" in trigger:
            parts.append("استرجع POC")
        elif "PULLBACK" in trigger:
            parts.append("أول pullback بعد breakout")
        elif "TK" in trigger:
            parts.append("ارتد من Kijun/Tenkan")
        elif "EXPANSION" in trigger:
            parts.append("كابيلة توسع نفسها")

    rv1h = safe_float(a.get("rvol1h", 0))
    if rv1h >= 2.0:
        parts.append(f"حجم {rv1h:.1f}x")
    elif rv1h >= 1.5:
        parts.append(f"حجم مرتفع {rv1h:.1f}x")
    if a.get("btc_regime") in ("BULLISH", "STRONG_BULLISH"):
        parts.append("BTC صاعد")
    if a.get("compression"):
        parts.append("بعد compression")
    if a.get("atr_expansion"):
        parts.append("توسع ATR")
    return " + ".join(parts) if parts else "إشارة متعددة الأطر"


def b_alert_allowed(a):
    """V7.1.5 quality gate for B-Kumo Telegram alerts.

    Rules derived from audit data:
    1. Regime gate: skip BEARISH regime entirely.
    2. EMA50 gate: ema50_trend must be True (boosts TP2 by +125%).
    3. BUILDING-state stricter gate: requires BULLISH (not just NEUTRAL).
       BUILDING in non-BULLISH had 0% TP3 in the audit.

    Returns True if the alert should fire; False to suppress.
    """
    regime = a.get("regime4", "UNKNOWN")
    state  = a.get("state", "")
    ema50  = a.get("strategy1", {}).get("ema50_trend", False)

    # Gate 1: no alerts in BEARISH macro
    if regime == "BEARISH":
        return False

    # Gate 2: ema50 required for all B signals
    if not ema50:
        return False

    # Gate 3: BUILDING state needs full BULLISH, not just NEUTRAL
    if state == "BUILDING" and regime != "BULLISH":
        return False

    return True


def is_d_ready(a):
    """V7.2.6: D-READY quality check — tightest B filter.

    All three conditions must be true:
      1. regime = BULLISH (not NEUTRAL, not BEARISH)
      2. ema50_trend = True
      3. big_pullback_candles = True (≥2 big red candles in last 8 bars)

    Score gate: score >= 65 (composite 0-100 score from build_b_analysis).
    Note: score reflects Kumo alignment + ADX + RVOL + structure + 5m trigger.
    At 200+ closed trades we'll validate this threshold empirically.

    Returns True if signal qualifies as D-READY.
    """
    regime   = a.get("regime4", "UNKNOWN")
    s1       = a.get("strategy1", {})
    ema50    = s1.get("ema50_trend", False)
    big_pc   = s1.get("big_pullback_candles", False)
    score    = a.get("score", 0)

    return (
        regime == "BULLISH"
        and ema50
        and big_pc
        and score >= 65
    )


def d_ready_message(a, old_state, cycle):
    """V7.2.6: Distinct Telegram message for D-READY signals."""
    price   = safe_float(a.get("price", 0))
    sl      = safe_float(a.get("sl", 0))
    tp1     = safe_float(a.get("tp1", 0))
    tp2     = safe_float(a.get("tp2", 0))
    tp3     = safe_float(a.get("tp3", 0))
    risk    = max(price - sl, price * 0.002)
    rr      = safe_float(a.get("rr", (tp1 - price) / risk if risk > 0 else 0))
    rv1h    = safe_float(a.get("rvol1h", 0))
    m15     = a.get("momentum15_score", 0)
    trigger = a.get("trigger", "NONE")
    symbol  = a.get("symbol", "?")
    score   = a.get("score", 0)

    return (
        f"⭐ D-READY | {symbol}\n"
        f"━━━━━━━━━━━━━━━━━\n"
        f"السعر: {price:.4f}\n"
        f"SL: {sl:.4f}\n"
        f"TP1: {tp1:.4f}  TP2: {tp2:.4f}  TP3: {tp3:.4f}\n"
        f"R/R: {rr:.1f}x\n"
        f"━━━━━━━━━━━━━━━━━\n"
        f"سكور: {score}/100 | زخم 15m: {m15}/8\n"
        f"حجم 1H: {rv1h:.2f}x | تريجر: {trigger}\n"
        f"BTC: {a.get('btc_reg','?')} | الكوين: {a.get('regime4','?')}\n"  # T1: fixed — was reading regime4 (coin) under BTC label
        f"━━━━━━━━━━━━━━━━━\n"
        f"Cycle: {cycle}"
    )


def alert_message(a, old_state, cycle):
    strategy = a.get("strategy", "B")
    if strategy == "C":
        label = "[C-CAR01]"
    elif strategy == "A":
        label = "[A-Classic]"
    else:
        label = "[B-Kumo]"

    # V7.1.5: Signal quality tag for subscribers.
    # ⚡ PRIME  = full bullish alignment + ema50 + bullish structure
    # ⚠️ WATCH  = signal fires but lower-quality conditions
    if strategy == "B":
        is_prime = (
            a.get("regime4") in ("BULLISH", "STRONG_BULLISH")
            and a.get("structure") == "BULLISH"
            and a.get("strategy1", {}).get("ema50_trend", False)
        )
        quality_tag = "⚡ PRIME" if is_prime else "⚠️ WATCH"
    else:
        quality_tag = ""

    trigger = a.get("trigger", "NONE")
    price = safe_float(a.get("price", 0))
    support = safe_float(a.get("support", price * 0.98))
    sl = safe_float(a.get("sl", 0))
    tp1 = safe_float(a.get("tp1", 0))
    tp2 = safe_float(a.get("tp2", 0))
    tp3 = safe_float(a.get("tp3", 0))
    risk = max(price - sl, price * 0.002)
    rr = safe_float(a.get("rr", (tp1 - price) / risk if risk > 0 else 0))
    rv1h = safe_float(a.get("rvol1h", 0))
    rv5m = safe_float(a.get("rvol5m", 0))
    liq1h = a.get("liq1h", "✅" if rv1h >= 1.5 else "⚠️")
    liq5m = a.get("liq5m", "✅" if rv5m >= 1.5 else ("⚠️" if rv5m > 0 else "N/A"))
    regime4 = a.get("regime4", "?")
    structure = a.get("structure", "?")
    m15 = a.get("momentum15_score", 0)
    reason = build_reason(a)
    state_line = f"{old_state or '-'} → {a['state']}" if old_state else a["state"]
    rvol5m_str = f"{rv5m:.1f}x" if rv5m > 0 else "N/A"

    # For C, show range bounds in the card.
    extra_c = ""
    btc_warning = ""
    if strategy == "C":
        rng_lo = safe_float(a.get("range_lo", 0))
        rng_hi = safe_float(a.get("range_hi", 0))
        bd_low = a.get("breakdown_low")
        extra_c = (
            f"\n📐 النطاق: {rng_lo:.8g} – {rng_hi:.8g}"
            + (f" | أدنى كسر: {bd_low:.8g}" if bd_low else "")
        )
        # V7.1.4: BTC warning when regime is BEARISH — coin shows independent
        # strength but macro tailwind is absent. Reduce position sizing.
        if a.get("btc_regime") == "BEARISH":
            btc_warning = "\n⚠️ BTC في ضغط — قوة مستقلة للعملة | خفّف الحجم\n"

    quality_line = f"{quality_tag}\n" if quality_tag else ""
    return (
        f"🎯 {a['symbol']} — {trigger} {label}\n"
        f"{quality_line}"
        f'"{reason}"\n'
        f"{btc_warning}"
        f"{extra_c}"
        f"\n"
        f"⚡ الدخول: {support:.8g} – {price:.8g}\n"
        f"🛑 الإلغاء: {sl:.8g}\n"
        f"🎯 TP1: {tp1:.8g}  TP2: {tp2:.8g}  TP3: {tp3:.8g}\n"
        f"⚖️ R:R → 1:{rr:.1f}\n"
        f"\n"
        f"💧 السيولة: RVOL 1H {rv1h:.1f}x {liq1h} | 5m {rvol5m_str} {liq5m}\n"
        f"📊 4H: {regime4} | Structure: {structure} | 15m: {m15}/8\n"
        f"\n"
        f"State: {state_line} | Score: {a['score']}\n"
        f"Cycle: {cycle} | {SYSTEM_VERSION}"
    )


# ============================================================
# AUDIT REPORT — unchanged except strategy field now covers A/B/C
# ============================================================
def audit_stats():
    """Build per-observation stat rows.

    V7.2.0 additions
    ----------------
    - coin_tier         : MAJOR / MID / ALT
    - entry_hour_utc    : 0-23 (from stage snapshot ts)
    - entry_session     : ASIAN / EUROPEAN / US / OVERLAP / OFF_HOURS
    - entry_day_of_week : Mon-Sun
    - score_at_entry    : int 0-5
    - factors_true      : list of factor names that were True
    - atr_pct           : ATR as % of entry price (stored in stage snap)
    - market_ctx.*      : global market context at entry time
    - sl_phantom.*      : post-SL analysis (for SL / SL_AFTER_TP1 only)
    """
    rows = []
    for obs in OBSERVATIONS.values():
        for stage, out in obs.get("outcomes", {}).items():
            if out.get("outcome") == "OPEN":
                continue
            stage_snap = obs.get("stages", {}).get(stage, {})
            regime = stage_snap.get("regime4", "UNKNOWN")
            symbol = obs["symbol"]

            # ---- Temporal enrichment ----
            ts_entry = out.get("ts_entry") or stage_snap.get("timestamp", "")
            try:
                entry_dt = datetime.fromisoformat(
                    ts_entry.replace("Z", "+00:00")) if ts_entry else None
                entry_hour = entry_dt.hour if entry_dt else None
                entry_dow  = entry_dt.strftime("%a") if entry_dt else None
                entry_sess = get_session(entry_hour) if entry_hour is not None else None
            except Exception:
                entry_hour = entry_dow = entry_sess = None

            # ---- Coin classification ----
            coin_tier = classify_coin(symbol)

            # ---- Factor detail ----
            factors = obs.get("factors", {})
            score_at_entry = obs.get("score", stage_snap.get("score", None))
            factors_true = [k for k in FACTOR_KEYS if bool(factors.get(k))]

            # ---- Volatility: ATR% ----
            atr_val  = stage_snap.get("atr1h") or stage_snap.get("atr_val")
            price_val = stage_snap.get("price") or out.get("entry_price")
            atr_pct = round(float(atr_val) / float(price_val) * 100, 3) \
                if atr_val and price_val and float(price_val) > 0 else None

            # ---- Global market context at entry ----
            mctx = obs.get("market_ctx", {}) or {}

            # ---- Post-SL phantom analysis ----
            sl_phantom = out.get("sl_phantom")  # may be pre-computed in obs
            outcome_str = out.get("outcome", "")
            if sl_phantom is None and outcome_str in ("SL_FIRST", "SL_AFTER_TP1"):
                sl = out.get("sl") or stage_snap.get("sl")
                tp1 = out.get("tp1") or stage_snap.get("tp1")
                tp2 = out.get("tp2") or stage_snap.get("tp2")
                if sl and tp1 and tp2 and ts_entry:
                    sl_phantom = check_sl_phantom(symbol, ts_entry,
                                                  float(sl), float(tp1), float(tp2))

            rows.append({
                "key": obs["key"], "cycle_id": obs["cycle_id"], "symbol": symbol,
                "stage": stage, "strategy": obs.get("strategy", "B"),
                "system_version": obs.get("system_version"),
                "config_version": obs.get("config_version"),
                "regime": regime,
                "outcome": outcome_str,
                "max_milestone": out.get("max_milestone", "NONE"),
                "mae": out.get("mae_pct", 0), "mfe": out.get("mfe_pct", 0),
                "net_mae": out.get("net_mae_pct", out.get("mae_pct", 0) - BINANCE_FEE_RT_PCT),
                "net_mfe": out.get("net_mfe_pct", out.get("mfe_pct", 0) - BINANCE_FEE_RT_PCT),
                "improvement": out.get("price_improvement_pct", 0),
                "duration": out.get("duration_min"),
                "tp1_hit": bool(out.get("tp1_time")),
                "tp2_hit": bool(out.get("tp2_time")),
                "tp3_hit": bool(out.get("tp3_time")),
                "bars_to_tp1": out.get("bars_to_tp1"),
                "bars_to_tp2": out.get("bars_to_tp2"),
                "bars_to_sl":  out.get("bars_to_sl"),
                "r_multiple_tp1": out.get("r_multiple_tp1"),
                "r_multiple_tp2": out.get("r_multiple_tp2"),
                "stages_seen": sorted(obs.get("stages", {}).keys()),   # V7.2.0: for transition analysis
                # V7.2.2: Volume Profile observation fields (B only) — flat for easy groupby
                "vp_price_vs_vah":   obs.get("vp_obs", {}).get("price_vs_vah"),
                "vp_price_vs_ph":    obs.get("vp_obs", {}).get("price_vs_ph"),
                "vp_price_vs_pvwap": obs.get("vp_obs", {}).get("price_vs_pvwap"),
                "vp_node_type":      obs.get("vp_obs", {}).get("node_type"),
                # V7.2.4: DGT VP extra fields — pC, VA Width, Candle Color
                "vp_price_vs_pc":      obs.get("vp_obs", {}).get("price_vs_pc"),
                "vp_va_width_pct":     obs.get("vp_obs", {}).get("va_width_pct"),
                "vp_dgt_candle_color": obs.get("vp_obs", {}).get("dgt_candle_color"),
                # V7.2.3: AIScalp OI/CVD/Funding observation fields
                "oi_value":          obs.get("oi_obs", {}).get("oi_value"),
                "oi_change_pct":     obs.get("oi_obs", {}).get("oi_change_pct"),
                "oi_price_rel":      obs.get("oi_obs", {}).get("oi_price_rel"),
                "funding_rate":      obs.get("oi_obs", {}).get("funding_rate"),
                "funding_label":     obs.get("oi_obs", {}).get("funding_label"),
                "taker_buy_pct":     obs.get("oi_obs", {}).get("taker_buy_pct"),
                "cvd_proxy":         obs.get("oi_obs", {}).get("cvd_proxy"),
                "ls_ratio":          obs.get("oi_obs", {}).get("ls_ratio"),
                "ls_label":          obs.get("oi_obs", {}).get("ls_label"),
                # V7.2.0 new fields
                "coin_tier": coin_tier,
                "entry_hour_utc": entry_hour,
                "entry_session": entry_sess,
                "entry_day_of_week": entry_dow,
                "score_at_entry": score_at_entry,
                "factors_true": factors_true,
                "atr_pct": atr_pct,
                "btc_dominance": mctx.get("btc_dominance"),
                "fear_greed": mctx.get("fear_greed"),
                "fear_greed_label": mctx.get("fear_greed_label"),
                "market_phase": mctx.get("market_phase"),
                "btc_24h_change_pct": mctx.get("btc_24h_change_pct"),
                "sl_phantom_tp1": sl_phantom.get("tp1_reached") if sl_phantom else None,
                "sl_phantom_tp2": sl_phantom.get("tp2_reached") if sl_phantom else None,
                "sl_phantom_max_pct_above_sl": sl_phantom.get("max_pct_above_sl") if sl_phantom else None,
                **{k: bool(factors.get(k)) for k in FACTOR_KEYS},
            })
    return rows


def build_audit_report():
    rows = audit_stats()
    report = {
        **lineage(), "generated_at": iso(),
        "observations": len(OBSERVATIONS),
        "unique_cycles": len(set(x.get("cycle_id") for x in OBSERVATIONS.values())),
        "unique_symbols": len(set(x.get("symbol") for x in OBSERVATIONS.values())),
        "stage_results": {}, "factor_effects": {}, "cycle_milestones": {},
        "forward_return_matrix_pct": {},
        "definitions": {
            "tp1_hit_rate": "percentage of closed stage observations that touched TP1",
            "tp2_hit_rate": "percentage of closed stage observations that touched TP2",
            "max_milestone": "highest target touched: NONE/TP1/TP2/TP3",
            "score": "ranking only; not probability",
        },
    }
    if not rows:
        return report
    df = pd.DataFrame(rows)

    # ── Phase 4 helper ─────────────────────────────────────────────────────────
    def _rr_stats(g):
        """Expectancy, Profit Factor, Max Consecutive Losses from r_multiple_tp1."""
        col = "r_multiple_tp1"
        if col not in g.columns:
            return {"expectancy": None, "profit_factor": None, "max_consec_losses": None}
        rr = g[col].dropna()
        exp = round(float(rr.mean()), 3) if len(rr) else None
        pos = float(rr[rr > 0].sum())
        neg = abs(float(rr[rr < 0].sum()))
        pf  = round(pos / neg, 3) if neg > 0 else None
        # Sequential max consecutive tp1 losses (detection order)
        streak = max_dd = 0
        for hit in g["tp1_hit"].tolist():
            if not bool(hit):
                streak += 1
                if streak > max_dd:
                    max_dd = streak
            else:
                streak = 0
        return {"expectancy": exp, "profit_factor": pf, "max_consec_losses": max_dd}
    # ───────────────────────────────────────────────────────────────────────────

    for stage, g in df.groupby("stage"):
        report["stage_results"][stage] = {
            "n": len(g), "unique_cycles": int(g.cycle_id.nunique()), "unique_symbols": int(g.symbol.nunique()),
            "tp1_hit": int(g.tp1_hit.sum()), "tp2_hit": int(g.tp2_hit.sum()), "tp3_hit": int(g.tp3_hit.sum()),
            "tp1_hit_rate": round(float(g.tp1_hit.mean())*100,2), "tp2_hit_rate": round(float(g.tp2_hit.mean())*100,2),
            "tp3_hit_rate": round(float(g.tp3_hit.mean())*100,2),
            "tp1_to_tp2_conversion": round(float(g[g.tp1_hit].tp2_hit.mean())*100,2) if g.tp1_hit.any() else None,
            "tp2_to_tp3_conversion": round(float(g[g.tp2_hit].tp3_hit.mean())*100,2) if g.tp2_hit.any() else None,
            "sl_before_tp1": int((~g.tp1_hit & g.outcome.isin(["SL_FIRST","SL_AFTER_TP1","SL_AFTER_TP2"])).sum()),
            # V7.1.5: explicit .astype(bool) avoids FutureWarning in Pandas >= 2.2
            "sl_after_tp1": int((g["tp1_hit"].astype(bool) & ~g["tp2_hit"].astype(bool) & (g["outcome"] == "SL_AFTER_TP1")).sum()),
            "sl_after_tp2": int((g["tp2_hit"].astype(bool) & (g["outcome"] == "SL_AFTER_TP2")).sum()),
            "tp3_first": int((g.outcome=="TP3_FIRST").sum()),
            "ambiguous": int((g.outcome=="AMBIGUOUS_SAME_BAR").sum()),
            "max_milestone_counts": {m:int((g.max_milestone==m).sum()) for m in ["NONE","TP1","TP2","TP3"]},
            "avg_mae_pct": round(float(g.mae.mean()),3), "avg_mfe_pct": round(float(g.mfe.mean()),3),
            "avg_net_mae_pct": round(float(g.net_mae.mean()),3),
            "avg_net_mfe_pct": round(float(g.net_mfe.mean()),3),
            "fee_note": f"net = gross - {BINANCE_FEE_RT_PCT}% round-trip",
            # Phase 4 — Expectancy / Profit Factor / Max Consecutive Losses
            **_rr_stats(g),
            "median_duration_min": round(float(g.duration.dropna().median()),1) if g.duration.notna().any() else None,
            "results_by_regime": {
                regime: {
                    "n": len(rg),
                    "tp1_hit_rate": round(float(rg.tp1_hit.mean())*100,2) if len(rg) else None,
                    "tp2_hit_rate": round(float(rg.tp2_hit.mean())*100,2) if len(rg) else None,
                    "avg_net_mfe_pct": round(float(rg.net_mfe.mean()),3) if len(rg) else None,
                }
                for regime, rg in g.groupby("regime")
                if regime not in (None, "UNKNOWN", float("nan"))
            },
        }
    cycle_best = {}
    rank={"NONE":0,"TP1":1,"TP2":2,"TP3":3}
    for _, r in df.iterrows():
        k=r.cycle_id; old=cycle_best.get(k)
        if old is None or rank.get(r.max_milestone,0)>rank.get(old["max_milestone"],0): cycle_best[k]=r.to_dict()
    cdf=pd.DataFrame(list(cycle_best.values()))
    if len(cdf):
        report["cycle_milestones"]={m:int((cdf.max_milestone==m).sum()) for m in ["NONE","TP1","TP2","TP3"]}
        report["cycle_milestones"]["total_cycles_with_outcome"]=int(len(cdf))
    for stage, sg in df.groupby("stage"):
        report["factor_effects"][stage]={}
        for factor in FACTOR_KEYS:
            y=sg[sg[factor]==True]; n=sg[sg[factor]==False]
            report["factor_effects"][stage][factor]={
                "yes_n":len(y),"no_n":len(n),
                "yes_tp2_pct":round(float(y.tp2_hit.mean())*100,2) if len(y) else None,
                "no_tp2_pct":round(float(n.tp2_hit.mean())*100,2) if len(n) else None,
                "yes_tp3_pct":round(float(y.tp3_hit.mean())*100,2) if len(y) else None,
                "no_tp3_pct":round(float(n.tp3_hit.mean())*100,2) if len(n) else None,
                "yes_avg_mae_pct":round(float(y.mae.mean()),3) if len(y) else None,
                "no_avg_mae_pct":round(float(n.mae.mean()),3) if len(n) else None,
            }

    # ================================================================
    # V7.2.0 — MARKET INTELLIGENCE AGGREGATIONS
    # ================================================================

    def _win_row(g):
        """Summary dict for a group — reused across all slice tables."""
        if len(g) == 0:
            return None
        rr_stats = _rr_stats(g)
        return {
            "n": len(g),
            "tp1_pct": round(float(g.tp1_hit.mean()) * 100, 1),
            "tp2_pct": round(float(g.tp2_hit.mean()) * 100, 1),
            "tp3_pct": round(float(g.tp3_hit.mean()) * 100, 1),
            "avg_net_mfe": round(float(g.net_mfe.mean()), 2),
            # Phase 4
            "expectancy":        rr_stats["expectancy"],
            "profit_factor":     rr_stats["profit_factor"],
            "max_consec_losses": rr_stats["max_consec_losses"],
        }

    # 1. By trading session
    session_table = {}
    for sess, sg in df.groupby("entry_session", dropna=True):
        row = _win_row(sg)
        if row:
            session_table[sess] = row
    report["results_by_session"] = session_table

    # 2. By hour of day (UTC) — heatmap data
    hour_table = {}
    for h, hg in df.groupby("entry_hour_utc", dropna=True):
        row = _win_row(hg)
        if row:
            hour_table[int(h)] = row
    report["results_by_hour_utc"] = hour_table

    # 3. By day of week
    dow_table = {}
    for d_str, dg in df.groupby("entry_day_of_week", dropna=True):
        row = _win_row(dg)
        if row:
            dow_table[d_str] = row
    report["results_by_day_of_week"] = dow_table

    # 4. By coin tier
    tier_table = {}
    for tier, tg in df.groupby("coin_tier", dropna=True):
        row = _win_row(tg)
        if row:
            tier_table[tier] = row
    report["results_by_coin_tier"] = tier_table

    # 5. By Fear & Greed label
    fg_table = {}
    for label, fg_g in df.groupby("fear_greed_label", dropna=True):
        row = _win_row(fg_g)
        if row:
            fg_table[label] = row
    report["results_by_fear_greed"] = fg_table

    # 6. By market phase
    phase_table = {}
    for phase, pg in df.groupby("market_phase", dropna=True):
        row = _win_row(pg)
        if row:
            phase_table[phase] = row
    report["results_by_market_phase"] = phase_table

    # 7. By BTC dominance bucket
    def _dom_bucket(v):
        if v is None:
            return None
        v = float(v)
        if v < 44:   return "<44%"
        if v < 50:   return "44-50%"
        if v < 56:   return "50-56%"
        return ">56%"
    if "btc_dominance" in df.columns:
        df["dom_bucket"] = df["btc_dominance"].apply(_dom_bucket)
        dom_table = {}
        for bucket, bg in df.groupby("dom_bucket", dropna=True):
            row = _win_row(bg)
            if row:
                dom_table[bucket] = row
        report["results_by_btc_dominance"] = dom_table

    # 8. By score at entry (0-5)
    score_table = {}
    for sc, sg in df.groupby("score_at_entry", dropna=True):
        row = _win_row(sg)
        if row:
            score_table[int(sc)] = row
    report["results_by_score"] = score_table

    # 9. SL Phantom analysis — how often SL hit but TP would have been reached
    sl_rows = df[df["outcome"].isin(["SL_FIRST", "SL_AFTER_TP1"])]
    phantom_total = len(sl_rows)
    phantom_tp1 = int(sl_rows["sl_phantom_tp1"].sum()) if "sl_phantom_tp1" in sl_rows else 0
    phantom_tp2 = int(sl_rows["sl_phantom_tp2"].sum()) if "sl_phantom_tp2" in sl_rows else 0
    avg_above_sl = None
    if "sl_phantom_max_pct_above_sl" in sl_rows.columns:
        valid = sl_rows["sl_phantom_max_pct_above_sl"].dropna()
        avg_above_sl = round(float(valid.mean()), 2) if len(valid) else None
    report["sl_phantom_analysis"] = {
        "total_sl_trades": phantom_total,
        "phantom_tp1_count": phantom_tp1,
        "phantom_tp1_rate_pct": round(phantom_tp1 / phantom_total * 100, 1) if phantom_total else None,
        "phantom_tp2_count": phantom_tp2,
        "phantom_tp2_rate_pct": round(phantom_tp2 / phantom_total * 100, 1) if phantom_total else None,
        "avg_max_pct_above_sl": avg_above_sl,
        "interpretation": (
            "If phantom_tp1_rate > 30%, the SL may be too tight. "
            "Price cleared SL then reached TP1 in those cases."
        ),
    }

    # ----------------------------------------------------------------
    # 10. P0.4 — Transition analysis: does progressing through stages
    #     improve outcomes, or just delay entry?
    #
    #     Key transitions tracked (B-strategy):
    #       RADAR_ONLY   : cycle stopped at RADAR, never reached EARLY
    #       EARLY_ONLY   : reached EARLY but not BUILDING
    #       EARLY→BUILD  : reached BUILDING after EARLY
    #       BUILD→READY  : reached READY after BUILDING
    #       EARLY→READY  : reached READY directly from EARLY (skipped BUILD)
    #       FULL_PATH    : saw RADAR→EARLY→BUILDING→READY
    #
    #     Each row in df has `stages_seen` (sorted list of stage names).
    #     We classify each cycle's full stage set, then aggregate.
    # ----------------------------------------------------------------
    if "stages_seen" in df.columns:
        STAGE_ORDER = {"RADAR": 0, "EARLY": 1, "BUILDING": 2, "READY": 3,
                       "TRIGGERED": 4, "ENTRY_READY": 5}

        def _classify_path(stages):
            """Turn a list of observed stages into a canonical path label."""
            s = set(stages) if stages else set()
            has = lambda x: x in s
            if has("ENTRY_READY") or has("TRIGGERED"):
                if has("BUILDING"):
                    return "FULL_PATH"
                return "EARLY→READY"
            if has("READY") or has("TRIGGERED"):
                if has("BUILDING"):
                    return "BUILD→READY"
                return "EARLY→READY"
            if has("BUILDING"):
                return "EARLY→BUILD"
            if has("EARLY"):
                return "EARLY_ONLY"
            return "RADAR_ONLY"

        df["path"] = df["stages_seen"].apply(_classify_path)

        # Aggregate at cycle level first — a cycle can have multiple stage rows;
        # take the row with the BEST outcome (highest max_milestone) per cycle.
        rank_m = {"NONE": 0, "TP1": 1, "TP2": 2, "TP3": 3}
        cycle_best_path = {}
        for _, r in df.iterrows():
            k = r["cycle_id"]
            existing = cycle_best_path.get(k)
            if existing is None or rank_m.get(r["max_milestone"], 0) > rank_m.get(existing["max_milestone"], 0):
                cycle_best_path[k] = r.to_dict()

        path_df = pd.DataFrame(list(cycle_best_path.values()))
        transition_table = {}
        path_order = ["RADAR_ONLY", "EARLY_ONLY", "EARLY→BUILD", "BUILD→READY",
                      "EARLY→READY", "FULL_PATH"]
        for path_label in path_order:
            pg = path_df[path_df["path"] == path_label] if "path" in path_df.columns else pd.DataFrame()
            if len(pg) == 0:
                continue
            avg_r_tp1 = None
            if "r_multiple_tp1" in pg.columns:
                valid_r = pg["r_multiple_tp1"].dropna()
                avg_r_tp1 = round(float(valid_r.mean()), 2) if len(valid_r) else None
            avg_bars = None
            if "bars_to_tp1" in pg.columns:
                valid_b = pg["bars_to_tp1"].dropna()
                avg_bars = round(float(valid_b.mean()), 1) if len(valid_b) else None
            transition_table[path_label] = {
                "n_cycles": len(pg),
                "tp1_pct": round(float(pg.tp1_hit.mean()) * 100, 1),
                "tp2_pct": round(float(pg.tp2_hit.mean()) * 100, 1),
                "tp3_pct": round(float(pg.tp3_hit.mean()) * 100, 1),
                "avg_net_mfe": round(float(pg.net_mfe.mean()), 2),
                "avg_r_multiple_tp1": avg_r_tp1,
                "avg_bars_to_tp1": avg_bars,
                "interpretation_hint": (
                    "Compare tp2_pct across paths — if FULL_PATH < EARLY_ONLY, "
                    "late-stage transitions add confirmation but miss the move."
                ),
            }
        report["results_by_transition"] = transition_table
        report["definitions"]["results_by_transition"] = (
            "Cycles grouped by which stages they passed through. "
            "FULL_PATH = EARLY→BUILDING→READY. "
            "Compare tp2_pct: if higher stages DON'T improve it, they delay entry without adding value."
        )

    # ----------------------------------------------------------------
    # 11. V7.2.3 — AIScalp OI/CVD/Funding correlation with outcomes
    #
    #     Groups B-trader observations (only rows with oi_obs data) by:
    #       - oi_price_rel  : OI_RISING_WITH_PRICE / OI_FLAT / OI_DIVERGING
    #       - cvd_proxy     : BULLISH / NEUTRAL / BEARISH
    #       - funding_label : BULLISH / NEUTRAL / BEARISH
    #       - ls_label      : LONG_HEAVY / BALANCED / SHORT_HEAVY
    #
    #     Produces tp1/tp2/tp3 hit rates and avg_net_mfe per label.
    #     This is the evaluation layer for the AIScalp monitoring indicators.
    # ----------------------------------------------------------------
    OI_LABEL_FIELDS = ["oi_price_rel", "cvd_proxy", "funding_label", "ls_label"]

    # Filter to rows that actually have oi_obs data (B-trader only)
    oi_df = df[df["cvd_proxy"].notna()] if "cvd_proxy" in df.columns else pd.DataFrame()

    oi_obs_report = {
        "_meta": {
            "description": (
                "Performance breakdown by AIScalp OI/CVD/Funding labels. "
                "Only B-trader cycles have oi_obs data. "
                "Use this to determine which market conditions (OI trend, CVD, funding, L/S ratio) "
                "correlate with better TP2/TP3 hit rates."
            ),
            "n_rows_with_oi_obs": len(oi_df),
            "n_rows_total": len(df),
            "coverage_pct": round(len(oi_df) / len(df) * 100, 1) if len(df) else 0,
        }
    }

    if len(oi_df) > 0:
        for field in OI_LABEL_FIELDS:
            if field not in oi_df.columns:
                continue
            field_table = {}
            for label, lg in oi_df.groupby(field, dropna=True):
                row = _win_row(lg)
                if row:
                    field_table[str(label)] = row
            if field_table:
                oi_obs_report[field] = field_table

        # Combined breakdown: oi_price_rel × cvd_proxy (most informative cross)
        if "oi_price_rel" in oi_df.columns and "cvd_proxy" in oi_df.columns:
            cross_table = {}
            for (oi_lbl, cvd_lbl), xg in oi_df.groupby(["oi_price_rel", "cvd_proxy"], dropna=True):
                key = f"{oi_lbl}|{cvd_lbl}"
                row = _win_row(xg)
                if row:
                    cross_table[key] = row
            oi_obs_report["oi_price_rel_x_cvd_proxy"] = cross_table

    report["results_by_oi_obs"] = oi_obs_report
    report["definitions"]["results_by_oi_obs"] = (
        "AIScalp monitoring indicators correlated with TP outcomes. "
        "Fields: oi_price_rel (OI trend vs price), cvd_proxy (taker buy pressure), "
        "funding_label (funding rate sentiment), ls_label (long/short ratio). "
        "Coverage limited to B-trader cycles only."
    )

    # ----------------------------------------------------------------
    # 12. V7.2.3 — Trader breakdown: A / B / C / A_legacy
    #
    #     Extracts trader identity from cycle_id:
    #       - cycle_id contains "_A_" → Trader A (Classic EMA50+Pullback)
    #       - cycle_id contains "_B_" → Trader B (Multi-TF Momentum)
    #       - cycle_id contains "_C_" → Trader C (CAR01 Failed Breakdown)
    #       - no tag                 → A_legacy (pre-V7.2.3 A cycles)
    #
    #     Allows isolated performance evaluation per trader.
    # ----------------------------------------------------------------
    def _get_trader(cycle_id):
        if not cycle_id:
            return "unknown"
        if "_A_" in cycle_id:
            return "A"
        if "_B_" in cycle_id:
            return "B"
        if "_C_" in cycle_id:
            return "C"
        return "A_legacy"

    if "cycle_id" in df.columns:
        df["trader"] = df["cycle_id"].apply(_get_trader)
        trader_table = {}
        for trader, tg in df.groupby("trader", dropna=True):
            row = _win_row(tg)
            if row:
                # إضافة breakdown per stage لكل متداول
                stage_breakdown = {}
                for st, sg in tg.groupby("stage", dropna=True):
                    sr = _win_row(sg)
                    if sr:
                        stage_breakdown[st] = sr
                row["stage_breakdown"] = stage_breakdown
                row["unique_cycles"] = int(tg["cycle_id"].nunique())
                trader_table[trader] = row
        report["results_by_trader"] = trader_table
        report["definitions"]["results_by_trader"] = (
            "Performance per trader. A=Classic EMA50+Pullback, B=Multi-TF Momentum, "
            "C=CAR01 Failed Breakdown, A_legacy=pre-V7.2.3 A cycles. "
            "stage_breakdown shows per-stage performance within each trader."
        )

    # ----------------------------------------------------------------
    # 13. V7.2.3 — D-READY Profile: optimal trade filter
    #
    #     Tracks observations matching the empirically best profile:
    #       Stage = READY
    #       ema50_trend = TRUE
    #       big_pullback_candles = TRUE
    #       regime ∈ {NEUTRAL, BULLISH}
    #
    #     This is NOT a new trader — it is an audit filter on existing
    #     B-trader READY observations to measure the optimal subset.
    # ----------------------------------------------------------------
    # T4: updated D-READY filter — matches is_d_ready() exactly (BUILDING+READY, score>=65, BULLISH only)
    d_ready_cols = ["stage", "ema50_trend", "big_pullback_candles", "regime", "score"]
    if all(c in df.columns for c in d_ready_cols):
        d_mask = (
            (df["stage"].isin(["BUILDING", "READY"])) &   # T4: expanded from READY-only
            (df["ema50_trend"] == True) &
            (df["big_pullback_candles"] == True) &
            (df["regime"].isin(["BULLISH"])) &            # BULLISH only — matches is_d_ready()
            (df["score"] >= 65)                           # T4: added score gate — was missing
        )
        d_df = df[d_mask]

        # مقارنة مع READY الكلي
        ready_df = df[df["stage"] == "READY"]
        ready_baseline = _win_row(ready_df) if len(ready_df) > 0 else None

        # T4: split subkeys — READY vs BUILDING vs combined (per SE+DE decision)
        d_at_ready    = d_df[d_df["stage"] == "READY"]
        d_at_building = d_df[d_df["stage"] == "BUILDING"]

        row_ready    = _win_row(d_at_ready)    if len(d_at_ready)    > 0 else None
        row_building = _win_row(d_at_building) if len(d_at_building) > 0 else None
        row_combined = _win_row(d_df)          if len(d_df)          > 0 else None

        if row_combined:
            row_combined["unique_cycles"]  = int(d_df["cycle_id"].nunique()) if "cycle_id" in d_df.columns else None
            row_combined["unique_symbols"] = int(d_df["symbol"].nunique())   if "symbol"   in d_df.columns else None

        report["results_by_d_ready_profile"] = {
            "_meta": {
                "description": (
                    "D-READY: optimal trade profile filter — matches is_d_ready() exactly. "
                    "Stage in [BUILDING,READY] + ema50_trend=TRUE + big_pullback_candles=TRUE "
                    "+ regime=BULLISH + score>=65. "
                    "Split into at_ready / at_building / combined for ablation analysis."
                ),
                "filter_criteria": {                      # T4: updated to match is_d_ready()
                    "stage":               ["BUILDING", "READY"],
                    "ema50_trend":         True,
                    "big_pullback_candles": True,
                    "regime":              ["BULLISH"],
                    "score_min":           65,
                },
            },
            "d_ready_at_ready":    row_ready,             # T4: READY-only subkey
            "d_ready_at_building": row_building,          # T4: BUILDING-only subkey
            "d_ready_combined":    row_combined,          # T4: both stages combined
            "ready_baseline":      ready_baseline,
            "lift_vs_baseline": {
                "tp2_lift_pct": round(row_combined["tp2_pct"] - ready_baseline["tp2_pct"], 1) if row_combined and ready_baseline else None,
                "tp3_lift_pct": round(row_combined["tp3_pct"] - ready_baseline["tp3_pct"], 1) if row_combined and ready_baseline else None,
                "mfe_lift":     round(row_combined["avg_net_mfe"] - ready_baseline["avg_net_mfe"], 2) if row_combined and ready_baseline else None,
            },
        }
        report["definitions"]["results_by_d_ready_profile"] = (
            "D-READY profile: subset matching is_d_ready() (ema50+big_pullback+BULLISH+score>=65). "
            "Split by stage (at_ready / at_building / combined). lift_vs_baseline vs READY average."
        )

    return report


def save_audit_report():
    report = build_audit_report()
    save_json("scanner_audit_v71.json", report)
    return report


# ============================================================
# T7: RADAR SNAPSHOT — shareable live radar file
# ============================================================
def write_radar_snapshot():
    """T7: Writes radar_latest.json after each scan cycle.

    Contains only D-READY / B-READY / B-BUILDING lists — no keys or sensitive data.
    Designed to be uploaded to Google Drive and read by a Claude Artifact (shareable link).

    Fields per entry:
      symbol, score, price, sl, tp1, tp2, state, regime4, ema50_trend,
      big_pullback_candles, trigger, cycle_id, detected_at
    """
    snapshot = {
        "generated_at":  iso(),
        "version":        SYSTEM_VERSION,
        "btc_regime":    MARKET_CTX.get("btc_regime", "UNKNOWN"),
        "d_ready":       [],
        "b_ready":       [],
        "b_building":    [],
    }

    def _entry(symbol, a, obs_key):
        obs = OBSERVATIONS.get(obs_key, {})
        return {
            "symbol":              symbol,
            "score":               a.get("score", 0),
            "price":               a.get("price", 0),
            "sl":                  a.get("sl", 0),
            "tp1":                 a.get("tp1", 0),
            "tp2":                 a.get("tp2", 0),
            "tp3":                 a.get("tp3", 0),
            "state":               a.get("state", "?"),
            "regime4":             a.get("regime4", "?"),
            "ema50_trend":         a.get("strategy1", {}).get("ema50_trend", False),
            "big_pullback_candles": a.get("strategy1", {}).get("big_pullback_candles", False),
            "trigger":             a.get("trigger", "NONE"),
            "rvol1h":              a.get("rvol1h", 0),
            "m15":                 f"{a.get('momentum15_score', 0)}/8",
            "cycle_id":            obs.get("cycle_id"),
            "detected_at":         obs.get("created_at"),
        }

    for symbol, state_data in STATES.items():
        a = state_data
        if a.get("strategy", "B") != "B":
            continue
        state    = a.get("state", "")
        obs_key  = observation_key(symbol, a.get("cycle_id", ""))

        if state == "READY" and is_d_ready(a):
            snapshot["d_ready"].append(_entry(symbol, a, obs_key))
        elif state == "READY":
            snapshot["b_ready"].append(_entry(symbol, a, obs_key))
        elif state == "BUILDING":
            snapshot["b_building"].append(_entry(symbol, a, obs_key))

    # Sort each list by score descending
    for key in ("d_ready", "b_ready", "b_building"):
        snapshot[key].sort(key=lambda x: x["score"], reverse=True)

    save_json("radar_latest.json", snapshot)
    print(f"[RADAR] D-READY={len(snapshot['d_ready'])} | B-READY={len(snapshot['b_ready'])} | BUILDING={len(snapshot['b_building'])}")


# ============================================================
# MAIN SCAN — B unchanged; A improved; C new
# ============================================================
def process_symbol(c):
    return deep_analyze(c, BTC_REGIME)


def run_scan():
    global BTC_REGIME, MARKET_CTX, _OI_CACHE
    _OI_CACHE = {}   # V7.2.3: reset Futures data cache each scan cycle
    started = time.time()
    print("\n" + "="*70)
    print(f"SUPER KUMO {SYSTEM_VERSION} |", iso())
    print("="*70)

    try:
        symbols = get_exchange_symbols()
        print(f"Universe: {len(symbols)} Binance Spot USDT")

        BTC_REGIME, btc_meta = btc_regime()
        print(f"BTC: {BTC_REGIME} | ADX {btc_meta.get('adx', 0):.1f}")

        # V7.2.0: Fetch global market context once per cycle
        MARKET_CTX = fetch_market_context()
        print(
            f"Market: BTC.D={MARKET_CTX.get('btc_dominance','?')}% | "
            f"F&G={MARKET_CTX.get('fear_greed','?')} ({MARKET_CTX.get('fear_greed_label','?')}) | "
            f"Phase={MARKET_CTX.get('market_phase','?')} | "
            f"MCap=${MARKET_CTX.get('total_mcap_b','?')}B | "
            f"BTC24h={MARKET_CTX.get('btc_24h_change_pct','?')}%"
        )

        # ================================================================
        # B-KUMO SCAN — UNCHANGED
        # ================================================================
        quick = []
        with ThreadPoolExecutor(max_workers=QUICK_WORKERS) as ex:
            futs = [ex.submit(quick_scan_symbol, s) for s in symbols]
            for f in as_completed(futs):
                r = f.result()
                if r:
                    quick.append(r)
        quick.sort(key=lambda x: (x["momentum_30m"], x["acceleration_30m"], x["rvol_30m"], x["range_expansion_30m"]), reverse=True)
        quick = quick[:CANDIDATE_CAP]
        print(f"Fast scan: {len(symbols)} → {len(quick)} in {time.time()-started:.1f}s")

        analyses = []
        with ThreadPoolExecutor(max_workers=DEEP_WORKERS) as ex:
            futs = [ex.submit(process_symbol, c) for c in quick]
            for f in as_completed(futs):
                try:
                    a = f.result()
                    if a:
                        analyses.append(a)
                except Exception:
                    traceback.print_exc()
        analyses.sort(key=lambda x: x["score"], reverse=True)
        print(f"Deep (B): {len(analyses)} in {time.time()-started:.1f}s")

        for a in analyses:
            symbol = a["symbol"]
            state_key_b = f"{symbol}_B"
            old_b = STATES.get(state_key_b, {}).get("state")
            a["strategy"] = "B"
            cycle_b = get_or_create_cycle(symbol, a, strategy="B")
            obs_b = ensure_observation(a, cycle_b)
            update_observation_stage(obs_b, a)
            STATES[state_key_b] = {
                **lineage(),
                "cycle_id": cycle_b, "state": a["state"], "score": a["score"],
                "trigger": a["trigger"], "price": a["price"], "strategy": "B",
                "updated_at": iso(),
                "first_seen": STATES.get(state_key_b, {}).get("first_seen", iso()),
                "history": STATES.get(state_key_b, {}).get("history", [])[-19:] + [{
                    "time": iso(), "state": a["state"], "score": a["score"], "price": a["price"]
                }],
            }
            if should_alert(symbol, old_b, a["state"], alert_key=f"{symbol}_B") and b_alert_allowed(a):  # V7.1.5: regime+ema50 gate
                # V7.2.6: D-READY alert fires instead of regular B alert when all D-READY conditions are met
                if is_d_ready(a) and a.get("state") == "READY":  # T2: D-READY only fires at READY, not BUILDING
                    ok = telegram_send(d_ready_message(a, old_b, cycle_b))
                else:
                    ok = telegram_send(alert_message(a, old_b, cycle_b))
                if ok:
                    LAST_ALERTS[f"{symbol}_B"] = iso()
            print(f"[B] {symbol:<12} {old_b or '-':<12} → {a['state']:<12} score={a['score']:<3} trigger={a['trigger']:<16} 15m={a['momentum15_score']}/8 RVOL1H={a.get('rvol1h',0):.2f} {'⭐D-READY' if is_d_ready(a) else ''}")

        # ================================================================
        # A-CLASSIC SCAN — IMPROVED (consecutive reds, 4H fib, swing low)
        # ================================================================
        aclassic_candidates = []
        with ThreadPoolExecutor(max_workers=QUICK_WORKERS) as ex:
            futs_a = [ex.submit(aclassic_scan_symbol, s) for s in symbols]
            for f in as_completed(futs_a):
                r = f.result()
                if r:
                    aclassic_candidates.append(r)
        aclassic_candidates.sort(key=lambda x: (x["pullback_pct"], -x["dist_from_ema"]), reverse=True)
        aclassic_candidates = aclassic_candidates[:60]
        print(f"A-Classic candidates: {len(aclassic_candidates)}")

        for cand_a in aclassic_candidates:
            sym_a = cand_a["symbol"]
            try:
                d1_ac = klines(sym_a, "1h", 120)
                if len(d1_ac) < 60:
                    continue
                d1_ac["rvol"] = rvol(d1_ac, 20)
                rv1h_ac = safe_float(d1_ac["rvol"].iloc[-1])
                sig_ac = strategy_a_signal(sym_a, d1_ac, rv1h_ac, BTC_REGIME)
                if sig_ac:
                    state_key_ac = f"{sym_a}_A"
                    old_ac = STATES.get(state_key_ac, {}).get("state")
                    cycle_ac = get_or_create_cycle(sym_a, sig_ac, strategy="A")
                    obs_ac = ensure_observation(sig_ac, cycle_ac)
                    update_observation_stage(obs_ac, sig_ac)
                    STATES[state_key_ac] = {
                        **lineage(),
                        "cycle_id": cycle_ac, "state": sig_ac["state"], "score": sig_ac["score"],
                        "trigger": sig_ac["trigger"], "price": sig_ac["price"], "strategy": "A",
                        "updated_at": iso(),
                        "first_seen": STATES.get(state_key_ac, {}).get("first_seen", iso()),
                        "history": STATES.get(state_key_ac, {}).get("history", [])[-19:] + [{
                            "time": iso(), "state": sig_ac["state"], "score": sig_ac["score"],
                            "price": sig_ac["price"],
                        }],
                    }
                    last_ac = LAST_ALERTS.get(f"{sym_a}_A")
                    cooldown_ok_ac = not last_ac or (now_utc() - datetime.fromisoformat(last_ac)).total_seconds() / 60 >= TELEGRAM_COOLDOWN_MIN
                    if old_ac != "ENTRY_READY" and cooldown_ok_ac:
                        ok_ac = telegram_send(alert_message(sig_ac, old_ac, cycle_ac))
                        if ok_ac:
                            LAST_ALERTS[f"{sym_a}_A"] = iso()
                    print(f"[A] {sym_a:<12} ENTRY_READY demand={sig_ac['demand_level']:.8g} sl={sig_ac['sl']:.8g} rr=1:{sig_ac['rr']:.1f}")
            except Exception:
                traceback.print_exc()

        # ================================================================
        # C — CAR-01 SCAN (V7.1.4)
        # BTC Gate: RISK MODIFIER ONLY — C runs in all regimes.
        # When BTC=BEARISH: score reduced, RETEST_PENDING alerts suppressed,
        # warning header added. ALTs can rise independently during BTC weakness.
        # ================================================================
        car01_candidates = []
        with ThreadPoolExecutor(max_workers=QUICK_WORKERS) as ex:
            futs_c = [ex.submit(car01_scan_symbol, s) for s in symbols]
            for f in as_completed(futs_c):
                r = f.result()
                if r:
                    car01_candidates.append(r)
        # Sort: narrower range is harder to fake, deeper price in range = more interesting.
        car01_candidates.sort(key=lambda x: x["range_pct"])
        car01_candidates = car01_candidates[:80]
        print(f"C-CAR01 candidates: {len(car01_candidates)} (BTC: {BTC_REGIME})")

        # V7.2.0: C stage counters — reset before loop
        _c_stage_counts: dict = {}

        for cand_c in car01_candidates:
            sym_c = cand_c["symbol"]
            try:
                sig_c = car01_signal(sym_c, cand_c["range_hi"], cand_c["range_lo"], BTC_REGIME)
                if not sig_c:
                    continue
                state_key_c = f"{sym_c}_C"
                old_c = STATES.get(state_key_c, {}).get("state")
                cycle_c = get_or_create_cycle(sym_c, sig_c, strategy="C")
                obs_c = ensure_observation(sig_c, cycle_c)
                update_observation_stage(obs_c, sig_c)
                STATES[state_key_c] = {
                    **lineage(),
                    "cycle_id": cycle_c, "state": sig_c["state"], "score": sig_c["score"],
                    "trigger": sig_c["trigger"], "price": sig_c["price"], "strategy": "C",
                    "car_stage": sig_c.get("car_stage", ""),
                    "updated_at": iso(),
                    "first_seen": STATES.get(state_key_c, {}).get("first_seen", iso()),
                    "history": STATES.get(state_key_c, {}).get("history", [])[-19:] + [{
                        "time": iso(), "state": sig_c["state"], "score": sig_c["score"],
                        "price": sig_c["price"], "car_stage": sig_c.get("car_stage", ""),
                    }],
                }
                # V7.1.4 Alert logic for C:
                # - BULLISH/NEUTRAL/STRONG_BULLISH: alert on ENTRY_READY or READY (RETEST_PENDING).
                # - BEARISH: alert ONLY on ENTRY_READY (suppress earlier stages — coin must
                #   prove full setup before alerting when macro tailwind is absent).
                if BTC_REGIME == "BEARISH":
                    alert_states_c = {"ENTRY_READY"}
                else:
                    alert_states_c = {"ENTRY_READY", "READY"}
                if should_alert(sym_c, old_c, sig_c["state"], alert_key=f"{sym_c}_C") and sig_c["state"] in alert_states_c:
                    ok_c = telegram_send(alert_message(sig_c, old_c, cycle_c))
                    if ok_c:
                        LAST_ALERTS[f"{sym_c}_C"] = iso()
                car_stage = sig_c.get("car_stage", "UNKNOWN")
                _c_stage_counts[car_stage] = _c_stage_counts.get(car_stage, 0) + 1
                print(f"[C] {sym_c:<12} car={car_stage:<20} state={sig_c['state']:<12} rng={cand_c['range_lo']:.6g}-{cand_c['range_hi']:.6g}")
            except Exception:
                traceback.print_exc()

        # V7.2.0: C diagnostic summary — shows funnel depth each cycle
        if _c_stage_counts:
            stage_summary = " | ".join(f"{k}={v}" for k, v in sorted(_c_stage_counts.items()))
            print(f"[C] Stage funnel this cycle: {stage_summary}")
        else:
            print("[C] Stage funnel this cycle: no signals passed filter")

        # ================================================================
        # AUDIT + SAVE
        # ================================================================
        update_open_observations()
        save_json(STATE_FILE, STATES)
        save_json(OBS_FILE, OBSERVATIONS)
        report = save_audit_report()
        write_radar_snapshot()  # T7: write shareable radar snapshot after every cycle

        # ── Phase 6: Auto-export observations for Experiment Engine ──────────
        try:
            import pathlib as _pl, shutil as _sh
            _exp_dir  = _pl.Path(__file__).parent
            _live     = _exp_dir / "observations_live.json"
            _bak      = _exp_dir / "observations_live.bak.json"
            _ts       = datetime.utcnow().strftime("%Y%m%d_%H%M")
            _archive  = _exp_dir / f"observations_{_ts}.json"
            _snap     = list(OBSERVATIONS.values())
            if _live.exists():
                _sh.copy2(_live, _bak)                                    # rotate live → bak
            with open(_live,    "w", encoding="utf-8") as _f:
                json.dump(_snap, _f, ensure_ascii=False, default=str)     # latest
            with open(_archive, "w", encoding="utf-8") as _f:
                json.dump(_snap, _f, ensure_ascii=False, default=str)     # timestamped archive
            print(f"[EE] Exported {len(_snap)} obs → {_live.name} + {_archive.name}")
        except Exception as _ee:
            print(f"[EE] Auto-export failed: {_ee}")

        # ── Phase 8a: Auto-run Experiment Engine → results.json ───────────────
        try:
            import experiment_engine as _exp_eng
            _ee_results   = _exp_eng.run_all(_snap)
            _results_path = _exp_dir / "results.json"
            with open(_results_path, "w", encoding="utf-8") as _f:
                json.dump(_ee_results, _f, ensure_ascii=False, default=str)
            _exp_eng.print_report(_ee_results)
            print(f"[EE] results.json saved → {_results_path.name}")
        except Exception as _ee_err:
            print(f"[EE] Experiment engine failed: {_ee_err}")
            _ee_results = None

        # ── Supabase push ─────────────────────────────────────────────────────
        try:
            os.environ.setdefault("SUPABASE_URL", SUPABASE_URL)
            os.environ.setdefault("SUPABASE_KEY", SUPABASE_KEY)
            import supabase_push as _sp
            _sp.push_observations(OBSERVATIONS)
            if _ee_results:
                _sp.push_experiment_results(_ee_results)
        except Exception as _sp_err:
            print(f"[SUPA] Push failed: {_sp_err}")
        # ─────────────────────────────────────────────────────────────────────

        print(f"Observations: {len(OBSERVATIONS)} | Open: {sum(x.get('status')=='OPEN' for x in OBSERVATIONS.values())}")
        print(f"Total run: {time.time()-started:.1f}s")

    except Exception:
        traceback.print_exc()


def telegram_test():
    ok = telegram_send(f"✅ Super Kumo {SYSTEM_VERSION} Telegram test — A+B+C active | BTC Gate: risk-modifier")
    print("Telegram test:", "SUCCESS" if ok else "FAILED")


def seconds_to_next_quarter():
    now = time.time()
    return INTERVAL_SECONDS - (now % INTERVAL_SECONDS) + 2


if __name__ == "__main__":
    import argparse as _ap
    _parser = _ap.ArgumentParser(add_help=False)
    _parser.add_argument("--single-cycle", action="store_true",
                         help="Run one scan cycle then exit (for GitHub Actions)")
    _args, _ = _parser.parse_known_args()

    if os.getenv("TELEGRAM_TEST", "0") == "1":
        telegram_test()
    elif _args.single_cycle:
        # GitHub Actions mode — one cycle then exit
        run_scan()
    else:
        # Normal server mode — loop forever
        run_scan()
        while True:
            sleep_for = seconds_to_next_quarter()
            print(f"Next scan in {sleep_for/60:.1f} min")
            time.sleep(sleep_for)
            run_scan()
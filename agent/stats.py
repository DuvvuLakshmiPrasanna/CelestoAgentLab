"""Summary statistics with the exact definitions the report contract uses."""

from __future__ import annotations

import math
from typing import Any, Sequence


def median(values: Sequence[float]) -> float:
    """Middle value; for an even count the mean of the two central values
    (for 20 rows: the mean of the 10th and 11th, 1-based)."""
    if not values:
        raise ValueError("median of empty sequence")
    ordered = sorted(values)
    n = len(ordered)
    mid = n // 2
    if n % 2:
        return float(ordered[mid])
    return (ordered[mid - 1] + ordered[mid]) / 2.0


def percentile_rank(values: Sequence[float], p: float) -> float:
    """Value at 1-based rank ceil(p * n) of the ascending sort (p90 of 20 rows: the 18th)."""
    if not values:
        raise ValueError("percentile of empty sequence")
    ordered = sorted(values)
    rank = max(1, math.ceil(p * len(ordered)))  # literally ceil(0.90 * n), as the contract states
    return float(ordered[min(rank, len(ordered)) - 1])


def summarize_runs(runs: Sequence[dict[str, Any]]) -> dict[str, Any]:
    n = len(runs)
    if n == 0:
        raise ValueError("no runs to summarize")
    successes = sum(1 for r in runs if r["success"] is True)
    return {
        "run_count": n,
        "success_rate": round(successes / n, 6),
        "median_wall_clock_s": round(median([r["wall_clock_s"] for r in runs]), 6),
        "p90_wall_clock_s": round(percentile_rank([r["wall_clock_s"] for r in runs], 0.90), 6),
        "median_boot_to_ready_s": round(median([r["boot_to_ready_s"] for r in runs]), 6),
        "total_cost_usd": round(sum(r["cost_usd"] for r in runs), 6),
    }

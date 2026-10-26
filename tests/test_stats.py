from __future__ import annotations

import pytest

from agent.stats import median, percentile_rank, summarize_runs


def test_median_even_is_mean_of_central_pair():
    values = list(range(1, 21))  # 1..20
    assert median(values) == 10.5  # mean of the 10th and 11th
    assert median([5, 1, 3]) == 3


def test_p90_of_20_is_the_18th():
    assert percentile_rank(list(range(1, 21)), 0.90) == 18
    assert percentile_rank([3, 1, 2], 0.90) == 3
    assert percentile_rank([7], 0.90) == 7


def test_p90_is_not_interpolated():
    assert percentile_rank([1, 2, 3, 4, 5, 6, 7, 8, 9, 100], 0.90) == 9


def test_summarize_runs():
    runs = [{"success": i % 4 != 0, "wall_clock_s": float(i), "boot_to_ready_s": 0.1 * i, "cost_usd": 0.5}
            for i in range(1, 21)]
    s = summarize_runs(runs)
    assert s["run_count"] == 20 and s["success_rate"] == 0.75
    assert s["median_wall_clock_s"] == 10.5 and s["p90_wall_clock_s"] == 18
    assert s["total_cost_usd"] == 10.0
    assert s["median_boot_to_ready_s"] == pytest.approx(1.05)


def test_empty_is_an_error():
    with pytest.raises(ValueError):
        summarize_runs([])

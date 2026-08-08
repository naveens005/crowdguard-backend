"""
Automated tests for CROWD GUARD 2.0's rule-based decision logic.
----------------------------------------------------------------
These cover the three pure functions that decide what the dashboard tells
an operator to actually DO - compute_risk(), compute_growth_rate(), and
recommend_police() - since a silent bug in any of these would produce a
wrong risk level, a wrong officer count, or a wrong SMS, with nothing in
the UI to indicate the number is wrong. They're also the cheapest part of
the system to test: pure functions, no Flask request context, no network,
no camera, no database (compute_growth_rate/recommend_police take a plain
dict for `cam` - they don't need a real camera object from app.py's
CAMERAS store).

Run with:
    python -m unittest discover tests
or, for just this file:
    python -m unittest tests.test_logic -v

Requires the same dependencies as app.py itself (flask, flask-socketio,
etc. - see requirements.txt) since importing app.py to reach these
functions also imports those. Importing app.py does NOT touch the
database, start the server, or bootstrap any accounts - all of that is
inside `if __name__ == "__main__":` in app.py, which only runs when app.py
is executed directly, not when it's imported as a module (as this test
file does).
"""

import math
import os
import sys
import unittest

# Make "import app" work when running this file directly (python
# tests/test_logic.py) as well as via discovery from the project root
# (python -m unittest discover tests).
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import app as crowdguard  # noqa: E402  (import after sys.path fix, on purpose)


def make_cam(history_points=None):
    """Builds a minimal fake camera dict - just enough for
    compute_growth_rate/recommend_police to read `cam["history"]`. Real
    camera dicts (see get_or_create_camera in app.py) carry a lot more
    fields, but these two functions only ever look at "history".
    history_points is a list of (timestamp, count) tuples."""
    points = history_points or []
    return {"history": [{"t": t, "count": c} for t, c in points]}


class ComputeRiskTests(unittest.TestCase):
    """compute_risk(count, max_capacity) -> "SAFE" | "WARNING" | "CRITICAL",
    using STATE["warning_pct"]/STATE["critical_pct"] as the two thresholds.
    Pinning both thresholds explicitly in setUp means these tests don't
    depend on whatever STATE happens to hold from elsewhere - important
    since STATE is a plain module-level dict shared with the rest of
    app.py, and could be left mutated by a previous test or a previous
    import elsewhere in a larger test run."""

    def setUp(self):
        crowdguard.STATE["warning_pct"] = 60
        crowdguard.STATE["critical_pct"] = 85

    def test_well_below_warning_is_safe(self):
        self.assertEqual(crowdguard.compute_risk(10, 100), "SAFE")

    def test_zero_count_is_safe(self):
        self.assertEqual(crowdguard.compute_risk(0, 100), "SAFE")

    def test_just_below_warning_threshold_is_safe(self):
        self.assertEqual(crowdguard.compute_risk(59, 100), "SAFE")

    def test_exactly_at_warning_threshold_is_warning(self):
        # Boundary is inclusive (>=), matching app.py's own comparison.
        self.assertEqual(crowdguard.compute_risk(60, 100), "WARNING")

    def test_between_warning_and_critical_is_warning(self):
        self.assertEqual(crowdguard.compute_risk(75, 100), "WARNING")

    def test_just_below_critical_threshold_is_warning(self):
        self.assertEqual(crowdguard.compute_risk(84, 100), "WARNING")

    def test_exactly_at_critical_threshold_is_critical(self):
        self.assertEqual(crowdguard.compute_risk(85, 100), "CRITICAL")

    def test_above_capacity_is_critical(self):
        self.assertEqual(crowdguard.compute_risk(150, 100), "CRITICAL")

    def test_zero_capacity_does_not_crash(self):
        # max_capacity=0 must not raise ZeroDivisionError - app.py guards
        # this with `if max_capacity else 0`.
        self.assertEqual(crowdguard.compute_risk(10, 0), "SAFE")

    def test_scales_with_capacity_not_absolute_count(self):
        # 60/100 and 6/10 are both exactly the 60% warning threshold -
        # risk should depend on the percentage, not the raw headcount.
        self.assertEqual(crowdguard.compute_risk(60, 100), "WARNING")
        self.assertEqual(crowdguard.compute_risk(6, 10), "WARNING")

    def test_warning_unreachable_if_misconfigured_critical_lower(self):
        # api_config() rejects warning_pct >= critical_pct at the API
        # layer, but compute_risk() itself has no such guard - this
        # documents what actually happens if STATE ends up that way
        # anyway (critical's check runs first, so it wins): a caller
        # relying on compute_risk() directly (bypassing api_config's
        # validation) would silently never see WARNING.
        crowdguard.STATE["warning_pct"] = 90
        crowdguard.STATE["critical_pct"] = 50
        self.assertEqual(crowdguard.compute_risk(60, 100), "CRITICAL")


class ComputeGrowthRateTests(unittest.TestCase):
    """compute_growth_rate(cam) -> people-per-second over the last 5
    history points. Used by recommend_police's surge buffer and by the
    clearance-plan/predictive-alert logic elsewhere in app.py."""

    def test_no_history_is_zero(self):
        cam = make_cam([])
        self.assertEqual(crowdguard.compute_growth_rate(cam), 0.0)

    def test_single_point_is_zero(self):
        # Need at least 2 points to compute a rate.
        cam = make_cam([(0, 10)])
        self.assertEqual(crowdguard.compute_growth_rate(cam), 0.0)

    def test_growing_crowd_is_positive(self):
        # +20 people over 10 seconds = 2.0 people/sec
        cam = make_cam([(0, 10), (10, 30)])
        self.assertAlmostEqual(crowdguard.compute_growth_rate(cam), 2.0)

    def test_shrinking_crowd_is_negative(self):
        cam = make_cam([(0, 50), (10, 30)])
        self.assertAlmostEqual(crowdguard.compute_growth_rate(cam), -2.0)

    def test_flat_crowd_is_zero(self):
        cam = make_cam([(0, 40), (10, 40)])
        self.assertEqual(crowdguard.compute_growth_rate(cam), 0.0)

    def test_only_last_five_points_are_considered(self):
        # A big jump in the older, now-excluded points (0 -> 1000 people)
        # should NOT influence the rate - only the most recent 5 points
        # (indices 1..5) do, matching app.py's `list(cam["history"])[-5:]`.
        points = [(0, 1000), (10, 10), (20, 20), (30, 30), (40, 40), (50, 50)]
        cam = make_cam(points)
        # last five points: (10,10) .. (50,50) -> +40 over 40s = 1.0/s
        self.assertAlmostEqual(crowdguard.compute_growth_rate(cam), 1.0)

    def test_identical_timestamps_do_not_divide_by_zero(self):
        # dt == 0 must not raise ZeroDivisionError.
        cam = make_cam([(5, 10), (5, 40)])
        self.assertEqual(crowdguard.compute_growth_rate(cam), 0.0)


class RecommendPoliceTests(unittest.TestCase):
    """recommend_police(count, risk, cam) -> (recommended_count, reason).
    Pinning every STATE field it reads in setUp for the same isolation
    reason as ComputeRiskTests above."""

    def setUp(self):
        crowdguard.STATE["ratio_safe"] = 40
        crowdguard.STATE["ratio_warning"] = 25
        crowdguard.STATE["ratio_critical"] = 12
        crowdguard.STATE["min_officers"] = 2

    def test_zero_count_needs_no_officers(self):
        recommended, reason = crowdguard.recommend_police(0, "SAFE", make_cam())
        self.assertEqual(recommended, 0)
        self.assertIn("No crowd", reason)

    def test_safe_uses_safe_ratio(self):
        # 80 people / 40:1 = 2 officers, flat history so no surge buffer.
        recommended, reason = crowdguard.recommend_police(80, "SAFE", make_cam())
        self.assertEqual(recommended, 2)
        self.assertIn("40:1", reason)

    def test_warning_uses_tighter_ratio_than_safe(self):
        # Same headcount, worse risk tier -> should need MORE officers,
        # not the same or fewer - this is the core "risk actually matters"
        # behaviour a regression here would break silently.
        safe_count, _ = crowdguard.recommend_police(200, "SAFE", make_cam())
        warn_count, _ = crowdguard.recommend_police(200, "WARNING", make_cam())
        self.assertGreater(warn_count, safe_count)

    def test_critical_uses_tightest_ratio(self):
        # 120 people / 12:1 CRITICAL ratio = 10 officers.
        recommended, _ = crowdguard.recommend_police(120, "CRITICAL", make_cam())
        self.assertEqual(recommended, 10)

    def test_recommendation_never_below_minimum(self):
        # 5 people / 40:1 rounds up to 1 officer, but min_officers=2 floors it.
        recommended, _ = crowdguard.recommend_police(5, "SAFE", make_cam())
        self.assertEqual(recommended, 2)

    def test_fast_growth_adds_surge_buffer(self):
        # Growth rate > 0.5/s (see app.py) should add a 20% surge on top
        # of the base recommendation.
        fast_growth_cam = make_cam([(0, 10), (10, 30)])  # 2.0 people/sec
        recommended, reason = crowdguard.recommend_police(80, "SAFE", fast_growth_cam)
        base = math.ceil(80 / 40)  # 2
        self.assertEqual(recommended, math.ceil(base * 1.2))
        self.assertIn("surge", reason.lower())

    def test_slow_growth_does_not_add_surge_buffer(self):
        slow_growth_cam = make_cam([(0, 10), (100, 11)])  # 0.01 people/sec
        recommended, reason = crowdguard.recommend_police(80, "SAFE", slow_growth_cam)
        self.assertEqual(recommended, 2)
        self.assertNotIn("surge", reason.lower())

    def test_unknown_risk_falls_back_to_safe_ratio(self):
        # recommend_police uses .get(risk, STATE["ratio_safe"]) - an
        # unrecognised risk string shouldn't crash, it should behave like
        # SAFE.
        recommended, _ = crowdguard.recommend_police(80, "SOMETHING_UNEXPECTED", make_cam())
        self.assertEqual(recommended, 2)


if __name__ == "__main__":
    unittest.main()

from backend.app.risk_engine import AdaptiveRiskScorer, RiskInput, RiskLevel


def test_risk_scoring_is_deterministic_and_explainable() -> None:
    scorer = AdaptiveRiskScorer()
    signal = RiskInput(
        phone_confidence=0.9,
        unauthorized_observer_confidence=0.8,
        persistence_ms=3_000,
        recent_incident_count=2,
        consecutive_frames=8,
    )
    first = scorer.score(signal)
    second = scorer.score(signal)
    assert first == second
    assert first.score >= 60
    assert first.level in {RiskLevel.WARNING, RiskLevel.LOCKDOWN}
    assert {factor.name for factor in first.factors} >= {"phone_signal", "unauthorized_observer", "duration", "recent_risk_history"}


def test_no_single_frame_lockdown_even_with_strong_signal() -> None:
    assessment = AdaptiveRiskScorer().score(
        RiskInput(
            phone_confidence=1.0,
            unauthorized_observer_confidence=1.0,
            gaze_intersection_confidence=1.0,
            persistence_ms=3_000,
            recent_incident_count=3,
            monitoring_interrupted=True,
            consecutive_frames=1,
        )
    )
    assert assessment.score == 59
    assert assessment.level is RiskLevel.OBSERVE


def test_risk_decay_and_hysteresis_prevent_oscillation() -> None:
    scorer = AdaptiveRiskScorer()
    assessment = scorer.score(
        RiskInput(
            previous_score=62,
            previous_level=RiskLevel.WARNING,
            elapsed_ms_since_previous=500,
            consecutive_frames=3,
        )
    )
    assert assessment.level is RiskLevel.WARNING
    assert assessment.score == 58

    cleared = scorer.score(
        RiskInput(
            previous_score=62,
            previous_level=RiskLevel.WARNING,
            elapsed_ms_since_previous=2_000,
            consecutive_frames=3,
        )
    )
    assert cleared.level is RiskLevel.OBSERVE

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum


class RiskLevel(StrEnum):
    SECURE = "SECURE"
    OBSERVE = "OBSERVE"
    WARNING = "WARNING"
    LOCKDOWN = "LOCKDOWN"


@dataclass(frozen=True, slots=True)
class RiskWeights:
    phone_signal: int = 35
    unauthorized_observer: int = 25
    gaze_intersection: int = 20
    duration: int = 10
    recent_risk_history: int = 10


@dataclass(frozen=True, slots=True)
class RiskInput:
    phone_confidence: float = 0.0
    unauthorized_observer_confidence: float = 0.0
    gaze_intersection_confidence: float = 0.0
    persistence_ms: int = 0
    recent_incident_count: int = 0
    workspace_sensitivity: float = 1.0
    monitoring_interrupted: bool = False
    backend_unavailable: bool = False
    consecutive_frames: int = 0
    previous_score: float = 0.0
    elapsed_ms_since_previous: int = 0
    previous_level: RiskLevel = RiskLevel.SECURE


@dataclass(frozen=True, slots=True)
class RiskFactor:
    name: str
    contribution: float
    reason: str


@dataclass(frozen=True, slots=True)
class RiskAssessment:
    score: int
    raw_score: int
    level: RiskLevel
    factors: list[RiskFactor] = field(default_factory=list)


class AdaptiveRiskScorer:
    """Deterministic, explainable risk scorer for optical-DLP signals."""

    def __init__(self, weights: RiskWeights | None = None, decay_per_second: float = 8.0) -> None:
        self.weights = weights or RiskWeights()
        self.decay_per_second = decay_per_second

    def score(self, signal: RiskInput) -> RiskAssessment:
        factors = self._factors(signal)
        raw = min(100, round(sum(item.contribution for item in factors) * self._sensitivity(signal.workspace_sensitivity)))
        decayed_previous = max(0.0, signal.previous_score - (signal.elapsed_ms_since_previous / 1000) * self.decay_per_second)
        blended = max(raw, decayed_previous if raw < signal.previous_score else raw)
        score = min(100, round(blended))

        if signal.consecutive_frames < 3:
            score = min(score, 59)
            if raw >= 60:
                factors.append(RiskFactor("single_frame_guard", 0, "Risk capped below Warning until at least three consecutive frames confirm the signal."))
        elif signal.consecutive_frames < 6:
            score = min(score, 79)
            if raw >= 80:
                factors.append(RiskFactor("lockdown_guard", 0, "Risk capped below Lockdown until evidence persists beyond a short burst."))

        level = self._level_with_hysteresis(score, signal.previous_level)
        return RiskAssessment(score=score, raw_score=raw, level=level, factors=factors)

    def _factors(self, signal: RiskInput) -> list[RiskFactor]:
        factors: list[RiskFactor] = []
        if signal.phone_confidence > 0:
            value = self.weights.phone_signal * self._clamp(signal.phone_confidence)
            factors.append(RiskFactor("phone_signal", value, f"Phone detector confidence {signal.phone_confidence:.2f}."))
        if signal.unauthorized_observer_confidence > 0:
            value = self.weights.unauthorized_observer * self._clamp(signal.unauthorized_observer_confidence)
            factors.append(RiskFactor("unauthorized_observer", value, f"Additional observer confidence {signal.unauthorized_observer_confidence:.2f}."))
        if signal.gaze_intersection_confidence > 0:
            value = self.weights.gaze_intersection * self._clamp(signal.gaze_intersection_confidence)
            factors.append(RiskFactor("gaze_intersection", value, f"Gaze/protected-zone intersection confidence {signal.gaze_intersection_confidence:.2f}."))
        if signal.persistence_ms > 0:
            value = self.weights.duration * min(signal.persistence_ms / 3000, 1.0)
            factors.append(RiskFactor("duration", value, f"Signal persisted for {signal.persistence_ms} ms."))
        if signal.recent_incident_count > 0:
            value = self.weights.recent_risk_history * min(signal.recent_incident_count / 3, 1.0)
            factors.append(RiskFactor("recent_risk_history", value, f"{signal.recent_incident_count} recent incident(s) in this tenant context."))
        if signal.monitoring_interrupted:
            factors.append(RiskFactor("monitoring_interruption", 15, "Endpoint monitoring is interrupted."))
        if signal.backend_unavailable:
            factors.append(RiskFactor("backend_unavailable", 5, "Face-analysis backend is unavailable."))
        return factors

    @staticmethod
    def _level_with_hysteresis(score: int, previous: RiskLevel) -> RiskLevel:
        if previous is RiskLevel.LOCKDOWN and score >= 75:
            return RiskLevel.LOCKDOWN
        if previous is RiskLevel.WARNING and score >= 55:
            return RiskLevel.WARNING
        if score >= 80:
            return RiskLevel.LOCKDOWN
        if score >= 60:
            return RiskLevel.WARNING
        if score >= 30:
            return RiskLevel.OBSERVE
        return RiskLevel.SECURE

    @staticmethod
    def _clamp(value: float) -> float:
        return min(1.0, max(0.0, value))

    @staticmethod
    def _sensitivity(value: float) -> float:
        return min(1.25, max(0.75, value))

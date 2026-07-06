from backend.app.schemas import Detection, SecurityState
from backend.app.threat_engine import TemporalThreatEngine


FACE = Detection(type="FACE", confidence=0.9, bbox=(0, 0, 40, 40))
SECOND_FACE = Detection(type="FACE", confidence=0.8, bbox=(50, 0, 40, 40))


def test_single_face_remains_secure() -> None:
    engine = TemporalThreatEngine()
    assert engine.evaluate([FACE], 0).state is SecurityState.SECURE
    assert engine.evaluate([FACE], 10_000).state is SecurityState.SECURE


def test_second_face_requires_persistence() -> None:
    engine = TemporalThreatEngine()
    pair = [FACE, SECOND_FACE]
    assert engine.evaluate(pair, 0).state is SecurityState.SECURE
    assert engine.evaluate(pair, 1499).state is SecurityState.SECURE
    assert engine.evaluate(pair, 1500).state is SecurityState.WARNING
    assert engine.evaluate(pair, 3000).state is SecurityState.LOCKDOWN


def test_brief_second_face_does_not_accumulate() -> None:
    engine = TemporalThreatEngine()
    pair = [FACE, SECOND_FACE]
    engine.evaluate(pair, 0)
    engine.evaluate([FACE], 500)
    assert engine.evaluate(pair, 2000).state is SecurityState.SECURE


def test_reset_clears_buffers_and_adds_cooldown() -> None:
    engine = TemporalThreatEngine()
    pair = [FACE, SECOND_FACE]
    engine.evaluate(pair, 0)
    assert engine.evaluate(pair, 3000).state is SecurityState.LOCKDOWN
    engine.reset(3100)
    assert engine.evaluate(pair, 5000).state is SecurityState.SECURE
    assert engine.evaluate(pair, 6100).state is SecurityState.SECURE
    assert engine.evaluate(pair, 7600).state is SecurityState.WARNING

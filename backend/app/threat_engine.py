from __future__ import annotations

from dataclasses import dataclass

from .schemas import AnalysisResponse, Detection, SecurityState


@dataclass(slots=True)
class TemporalThreatEngine:
    """Per-camera temporal policy; timestamps are client epoch milliseconds."""

    second_face_since: int | None = None
    phone_since: int | None = None
    clear_since: int | None = None
    cooldown_until: int = 0
    state: SecurityState = SecurityState.SECURE

    def reset(self, timestamp: int, cooldown_ms: int = 3000) -> None:
        self.second_face_since = None
        self.phone_since = None
        self.clear_since = None
        self.cooldown_until = timestamp + cooldown_ms
        self.state = SecurityState.SECURE

    def evaluate(self, detections: list[Detection], timestamp: int, frame_id: int | None = None) -> AnalysisResponse:
        faces = [item for item in detections if item.type == "FACE"]
        phones = [item for item in detections if item.type in {"PHONE", "CAMERA"}]
        has_second_face = len(faces) > 1
        has_phone = bool(phones)

        if timestamp < self.cooldown_until:
            self.second_face_since = None
            self.phone_since = None
            return self._response(detections, timestamp, None, frame_id)

        self.second_face_since = self._update_start(self.second_face_since, has_second_face, timestamp)
        self.phone_since = self._update_start(self.phone_since, has_phone, timestamp)
        second_face_ms = timestamp - self.second_face_since if self.second_face_since is not None else 0
        phone_ms = timestamp - self.phone_since if self.phone_since is not None else 0

        next_state = SecurityState.SECURE
        reason: str | None = None
        if second_face_ms >= 3000:
            next_state, reason = SecurityState.LOCKDOWN, "Second face persisted for 3.0 seconds"
        elif phone_ms >= 2000:
            next_state, reason = SecurityState.LOCKDOWN, "Phone persisted for 2.0 seconds"
        elif second_face_ms >= 1500:
            next_state, reason = SecurityState.WARNING, "Second face persisted for 1.5 seconds"
        elif phone_ms >= 1000:
            next_state, reason = SecurityState.WARNING, "Phone persisted for 1.0 second"

        if not has_second_face and not has_phone:
            self.clear_since = self.clear_since or timestamp
            # Avoid flicker: retain a prior threat for up to two clear seconds.
            if self.state != SecurityState.SECURE and timestamp - self.clear_since < 2000:
                next_state = self.state
                reason = "Waiting for clear-scene confirmation"
        else:
            self.clear_since = None

        self.state = next_state
        return self._response(detections, timestamp, reason, frame_id)

    @staticmethod
    def _update_start(current: int | None, active: bool, timestamp: int) -> int | None:
        if not active:
            return None
        return current if current is not None else timestamp

    def _response(
        self, detections: list[Detection], timestamp: int, reason: str | None, frame_id: int | None = None
    ) -> AnalysisResponse:
        action = {
            SecurityState.SECURE: "NONE",
            SecurityState.WARNING: "BLUR",
            SecurityState.LOCKDOWN: "LOCKDOWN",
        }[self.state]
        return AnalysisResponse(
            state=self.state,
            detections=detections,
            faces_count=sum(item.type == "FACE" for item in detections),
            phone_detected=any(item.type in {"PHONE", "CAMERA"} for item in detections),
            threat_reason=reason,
            action=action,
            timestamp=timestamp,
            frame_id=frame_id,
        )

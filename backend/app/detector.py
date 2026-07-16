from __future__ import annotations

import base64
import binascii
import math

import cv2
import numpy as np

from .schemas import Detection


class InvalidFrameError(ValueError):
    """Raised when a websocket payload is not a decodable image."""


class FrameDetector:
    """CPU-only face detector using OpenCV's bundled frontal-face cascade.

    Haar level weights are converted to a bounded display score. This is a
    detector score, not a calibrated identity or recognition probability.
    """

    def __init__(self) -> None:
        cascade_path = cv2.data.haarcascades + "haarcascade_frontalface_default.xml"
        self._face_cascade = cv2.CascadeClassifier(cascade_path)
        if self._face_cascade.empty():
            raise RuntimeError(f"Unable to load OpenCV face cascade: {cascade_path}")

    @staticmethod
    def decode_frame(encoded: str) -> np.ndarray:
        if "," in encoded:
            encoded = encoded.split(",", 1)[1]
        try:
            raw = base64.b64decode(encoded, validate=True)
        except (binascii.Error, ValueError) as exc:
            raise InvalidFrameError("frame must be valid base64 JPEG data") from exc
        if not raw:
            raise InvalidFrameError("frame is empty")
        if len(raw) > 2_000_000:
            raise InvalidFrameError("frame exceeds maximum encoded size")
        image = cv2.imdecode(np.frombuffer(raw, dtype=np.uint8), cv2.IMREAD_COLOR)
        if image is None:
            raise InvalidFrameError("frame is not a supported encoded image")
        height, width = image.shape[:2]
        if width > 1920 or height > 1080:
            raise InvalidFrameError("frame dimensions exceed maximum supported size")
        return image

    def analyze(self, encoded: str) -> list[Detection]:
        image = self.decode_frame(encoded)
        gray = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY)
        gray = cv2.equalizeHist(gray)
        min_size = max(36, min(gray.shape[:2]) // 10)

        try:
            boxes, _reject, weights = self._face_cascade.detectMultiScale3(
                gray,
                scaleFactor=1.1,
                minNeighbors=5,
                minSize=(min_size, min_size),
                outputRejectLevels=True,
            )
            scores = [1.0 / (1.0 + math.exp(-float(weight) / 2.0)) for weight in weights]
        except AttributeError:  # pragma: no cover - compatibility with older OpenCV
            boxes = self._face_cascade.detectMultiScale(
                gray, scaleFactor=1.1, minNeighbors=5, minSize=(min_size, min_size)
            )
            scores = [0.75] * len(boxes)

        return [
            Detection(type="FACE", confidence=max(0.5, min(0.99, score)), bbox=tuple(map(int, box)))
            for box, score in zip(boxes, scores, strict=True)
        ]

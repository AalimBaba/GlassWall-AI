import type { FaceInferenceResult, FusedDetectionFrame, PhoneInferenceResult } from './types'

export class DetectionFusion {
  constructor(private readonly toleranceMs = 900) {}

  fuse(phone: PhoneInferenceResult | null, face: FaceInferenceResult | null, fallbackFrameId = 0, fallbackTimestamp = Date.now()): FusedDetectionFrame {
    const frameId = Math.max(phone?.frameId ?? fallbackFrameId, face?.frameId ?? fallbackFrameId)
    const timestamp = phone?.capturedAt ?? face?.capturedAt ?? fallbackTimestamp
    const faceIsFresh = Boolean(face && Math.abs((phone?.capturedAt ?? face.capturedAt) - face.capturedAt) <= this.toleranceMs)
    const phones = phone?.detections ?? []
    const phoneConfidence = Math.max(0, ...phones.map(item => item.score))
    const facesCount = face && faceIsFresh ? face.facesCount : null
    return {
      frameId,
      timestamp,
      phoneDetected: phones.length > 0,
      phoneConfidence,
      facesCount,
      unauthorizedObserver: facesCount !== null ? facesCount > 1 : false,
      phoneLatencyMs: phone?.latencyMs ?? null,
      faceLatencyMs: faceIsFresh ? face?.latencyMs ?? null : null,
      backendAvailable: Boolean(face?.backendConnected),
      backendStale: Boolean(face && !faceIsFresh),
      evidence: [
        ...phones.map(item => ({ source: 'phone' as const, label: item.class, confidence: item.score })),
        ...(facesCount !== null ? [{ source: 'face' as const, label: `${facesCount} face${facesCount === 1 ? '' : 's'}` }] : []),
        ...(face && !faceIsFresh ? [{ source: 'health' as const, label: 'Backend face result stale' }] : []),
      ],
    }
  }
}

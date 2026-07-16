import type { DetectedObject } from '@tensorflow-models/coco-ssd'

export type CapturedFrame = {
  frameId: number
  capturedAt: number
  width: number
  height: number
}

export type PhoneDetection = Pick<DetectedObject, 'bbox' | 'class' | 'score'>

export type PhoneInferenceResult = {
  frameId: number
  capturedAt: number
  completedAt: number
  latencyMs: number
  modelLoaded: boolean
  detections: PhoneDetection[]
}

export type FaceDetection = { type: 'FACE' | 'PHONE' | 'CAMERA'; confidence: number; bbox: [number, number, number, number] }

export type FaceInferenceResult = {
  frameId: number
  capturedAt: number
  completedAt: number
  latencyMs: number
  backendConnected: boolean
  facesCount: number
  detections: FaceDetection[]
  state: 'SECURE' | 'WARNING' | 'LOCKDOWN'
  threatReason: string | null
  action: 'NONE' | 'BLUR' | 'LOCKDOWN'
}

export type FusedDetectionFrame = {
  frameId: number
  timestamp: number
  phoneDetected: boolean
  phoneConfidence: number
  facesCount: number | null
  unauthorizedObserver: boolean
  phoneLatencyMs: number | null
  faceLatencyMs: number | null
  backendAvailable: boolean
  backendStale: boolean
  evidence: Array<{ source: 'phone' | 'face' | 'health'; label: string; confidence?: number }>
}

export type PipelineMetricsSnapshot = {
  captureFps: number
  phoneInferenceFps: number
  backendInferenceFps: number
  averagePhoneLatencyMs: number
  averageFaceLatencyMs: number
  queueDepth: number
  droppedFrames: number
  staleResultsDiscarded: number
  latestProcessedFrameId: number
}

import type { ObjectDetection } from '@tensorflow-models/coco-ssd'
import { PHONE_POLICY } from '../phoneThreatTracker'
import type { CapturedFrame, PhoneInferenceResult } from './types'

export class PhoneInferenceWorker {
  private busy = false
  private cancelled = false

  constructor(private readonly getModel: () => Promise<ObjectDetection>) {}

  cancel() {
    this.cancelled = true
  }

  reset() {
    this.cancelled = false
  }

  isBusy() {
    return this.busy
  }

  async infer(frame: CapturedFrame, source: HTMLImageElement | HTMLVideoElement | HTMLCanvasElement | ImageData): Promise<PhoneInferenceResult | null> {
    if (this.busy || this.cancelled) return null
    this.busy = true
    const startedAt = performance.now()
    try {
      const model = await this.getModel()
      if (this.cancelled) return null
      const predictions = await model.detect(source, 20, PHONE_POLICY.confidenceThreshold)
      const detections = predictions.filter(item => /cell phone|smartphone|mobile phone|phone/i.test(item.class))
      const completedAt = Date.now()
      return {
        frameId: frame.frameId,
        capturedAt: frame.capturedAt,
        completedAt,
        latencyMs: performance.now() - startedAt,
        modelLoaded: true,
        detections,
      }
    } finally {
      this.busy = false
    }
  }
}

import type { PipelineMetricsSnapshot } from './types'

export class PipelineMetrics {
  private captureTimes: number[] = []
  private phoneTimes: number[] = []
  private faceTimes: number[] = []
  private phoneLatencies: number[] = []
  private faceLatencies: number[] = []
  private stale = 0
  private latestFrame = 0

  markCapture(frameId: number, at = performance.now()) {
    this.latestFrame = Math.max(this.latestFrame, frameId)
    this.captureTimes = this.keepRecent([...this.captureTimes, at], at)
  }

  markPhoneInference(latencyMs: number, at = performance.now()) {
    this.phoneTimes = this.keepRecent([...this.phoneTimes, at], at)
    this.phoneLatencies = this.keepSamples([...this.phoneLatencies, latencyMs])
  }

  markFaceInference(latencyMs: number, at = performance.now()) {
    this.faceTimes = this.keepRecent([...this.faceTimes, at], at)
    this.faceLatencies = this.keepSamples([...this.faceLatencies, latencyMs])
  }

  markStaleResult() {
    this.stale += 1
  }

  reset() {
    this.captureTimes = []
    this.phoneTimes = []
    this.faceTimes = []
    this.phoneLatencies = []
    this.faceLatencies = []
    this.stale = 0
    this.latestFrame = 0
  }

  snapshot(queueDepth: number, droppedFrames: number): PipelineMetricsSnapshot {
    return {
      captureFps: this.rate(this.captureTimes),
      phoneInferenceFps: this.rate(this.phoneTimes),
      backendInferenceFps: this.rate(this.faceTimes),
      averagePhoneLatencyMs: this.average(this.phoneLatencies),
      averageFaceLatencyMs: this.average(this.faceLatencies),
      queueDepth,
      droppedFrames,
      staleResultsDiscarded: this.stale,
      latestProcessedFrameId: this.latestFrame,
    }
  }

  private keepRecent(values: number[], now: number) {
    return values.filter(item => now - item <= 1000)
  }

  private keepSamples(values: number[]) {
    return values.slice(-20)
  }

  private rate(values: number[]) {
    return Math.round(values.length * 10) / 10
  }

  private average(values: number[]) {
    if (!values.length) return 0
    return Math.round(values.reduce((sum, item) => sum + item, 0) / values.length)
  }
}

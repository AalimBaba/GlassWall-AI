import { describe, expect, it, vi } from 'vitest'
import { DetectionFusion } from './DetectionFusion'
import { LatestFrameQueue } from './LatestFrameQueue'
import { PhoneInferenceWorker } from './PhoneInferenceWorker'
import { PipelineMetrics } from './PipelineMetrics'
import { StateCoordinator } from './StateCoordinator'

describe('LatestFrameQueue', () => {
  it('drops the oldest pending frame and enforces capacity', async () => {
    const queue = new LatestFrameQueue<number>(2)
    queue.push(1)
    queue.push(2)
    queue.push(3)
    expect(queue.size()).toBe(2)
    expect(queue.droppedCount()).toBe(1)
    expect(await queue.take()).toBe(3)
  })

  it('closes cleanly', async () => {
    const queue = new LatestFrameQueue<number>(1)
    const pending = queue.take()
    queue.close()
    await expect(pending).rejects.toThrow('closed')
  })
})

describe('pipeline workers and coordinators', () => {
  it('keeps phone inference single-flight', async () => {
    const detect = vi.fn(async () => {
      await new Promise(resolve => setTimeout(resolve, 10))
      return [{ class: 'cell phone', score: .9, bbox: [1, 2, 3, 4] }]
    })
    const worker = new PhoneInferenceWorker(async () => ({ detect }) as never)
    const first = worker.infer({ frameId: 1, capturedAt: 1, width: 10, height: 10 }, {} as HTMLVideoElement)
    const second = await worker.infer({ frameId: 2, capturedAt: 2, width: 10, height: 10 }, {} as HTMLVideoElement)
    expect(second).toBeNull()
    expect((await first)?.detections).toHaveLength(1)
  })

  it('rejects stale transitions', () => {
    const coordinator = new StateCoordinator()
    expect(coordinator.apply('WARNING', 10, 'fresh').changed).toBe(true)
    const stale = coordinator.apply('SECURE', 9, 'old clear')
    expect(stale.changed).toBe(false)
    expect(stale.state).toBe('WARNING')
  })

  it('marks stale backend fusion without creating positive face evidence', () => {
    const fused = new DetectionFusion(100).fuse(
      { frameId: 5, capturedAt: 1000, completedAt: 1050, latencyMs: 50, modelLoaded: true, detections: [] },
      { frameId: 1, capturedAt: 100, completedAt: 200, latencyMs: 100, backendConnected: true, facesCount: 2, detections: [], state: 'LOCKDOWN', threatReason: 'old', action: 'LOCKDOWN' },
    )
    expect(fused.backendStale).toBe(true)
    expect(fused.facesCount).toBeNull()
    expect(fused.unauthorizedObserver).toBe(false)
  })

  it('diagnostics use real counters', () => {
    const metrics = new PipelineMetrics()
    metrics.markCapture(1, 100)
    metrics.markPhoneInference(33, 120)
    metrics.markFaceInference(80, 140)
    metrics.markStaleResult()
    expect(metrics.snapshot(1, 2)).toMatchObject({
      queueDepth: 1,
      droppedFrames: 2,
      staleResultsDiscarded: 1,
      latestProcessedFrameId: 1,
      averagePhoneLatencyMs: 33,
      averageFaceLatencyMs: 80,
    })
  })
})

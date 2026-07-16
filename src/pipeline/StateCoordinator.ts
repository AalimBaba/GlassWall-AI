export type PipelineState = 'SECURE' | 'OBSERVE' | 'WARNING' | 'LOCKDOWN' | 'RECOVERY'

export type StateTransition = {
  state: PipelineState
  reason: string
  frameId: number
  changed: boolean
}

export class StateCoordinator {
  private state: PipelineState = 'SECURE'
  private latestFrameId = 0

  apply(next: PipelineState, frameId: number, reason: string): StateTransition {
    if (frameId < this.latestFrameId) {
      return { state: this.state, reason: 'stale transition rejected', frameId, changed: false }
    }
    this.latestFrameId = frameId
    const changed = next !== this.state
    this.state = next
    return { state: this.state, reason, frameId, changed }
  }

  reset() {
    this.state = 'SECURE'
    this.latestFrameId = 0
  }

  current() {
    return this.state
  }
}

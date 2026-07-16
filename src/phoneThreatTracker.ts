export type PhoneSecurityState = 'SECURE' | 'SUSPICIOUS' | 'WARNING' | 'LOCKDOWN' | 'RECOVERY'

export const PHONE_POLICY = {
  confidenceThreshold: 0.45,
  consecutiveFrames: 3,
  warningMs: 1500,
  lockdownMs: 3000,
  recoveryMs: 2000,
} as const

export type PhoneTrackerSnapshot = {
  state: PhoneSecurityState
  durationMs: number
  confidence: number
  confirmed: boolean
}

export class PhoneThreatTracker {
  private detectedSince: number | null = null
  private clearSince: number | null = null
  private consecutive = 0
  private lastThreatState: PhoneSecurityState = 'SECURE'

  reset(): PhoneTrackerSnapshot {
    this.detectedSince = null
    this.clearSince = null
    this.consecutive = 0
    this.lastThreatState = 'SECURE'
    return { state: 'SECURE', durationMs: 0, confidence: 0, confirmed: false }
  }

  update(detected: boolean, confidence: number, timestamp: number): PhoneTrackerSnapshot {
    const qualifies = detected && confidence >= PHONE_POLICY.confidenceThreshold
    if (qualifies) {
      this.consecutive += 1
      this.clearSince = null
      if (this.consecutive >= PHONE_POLICY.consecutiveFrames && this.detectedSince === null) {
        this.detectedSince = timestamp
      }
      const durationMs = this.detectedSince === null ? 0 : timestamp - this.detectedSince
      let state: PhoneSecurityState = 'SUSPICIOUS'
      if (this.detectedSince === null) state = 'SECURE'
      else if (durationMs >= PHONE_POLICY.lockdownMs) state = 'LOCKDOWN'
      else if (durationMs >= PHONE_POLICY.warningMs) state = 'WARNING'
      this.lastThreatState = state
      return { state, durationMs, confidence, confirmed: this.detectedSince !== null }
    }

    this.consecutive = 0
    this.detectedSince = null
    if (this.lastThreatState !== 'SECURE' && this.lastThreatState !== 'SUSPICIOUS') {
      this.clearSince ??= timestamp
      const clearDuration = timestamp - this.clearSince
      if (clearDuration < PHONE_POLICY.recoveryMs) {
        return { state: 'RECOVERY', durationMs: clearDuration, confidence: 0, confirmed: false }
      }
    }
    this.clearSince = null
    this.lastThreatState = 'SECURE'
    return { state: 'SECURE', durationMs: 0, confidence: 0, confirmed: false }
  }
}

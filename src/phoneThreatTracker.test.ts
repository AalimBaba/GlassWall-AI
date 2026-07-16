import { describe, expect, it } from 'vitest'
import { PhoneThreatTracker } from './phoneThreatTracker'

describe('PhoneThreatTracker', () => {
  it('rejects one-frame and low-confidence detections', () => {
    const tracker = new PhoneThreatTracker()
    expect(tracker.update(true, .9, 0).state).toBe('SECURE')
    expect(tracker.update(false, 0, 400).state).toBe('SECURE')
    expect(tracker.update(true, .44, 800).state).toBe('SECURE')
  })

  it('progresses through suspicious, warning, lockdown, recovery, secure', () => {
    const tracker = new PhoneThreatTracker()
    expect(tracker.update(true, .8, 0).state).toBe('SECURE')
    expect(tracker.update(true, .8, 400).state).toBe('SECURE')
    expect(tracker.update(true, .8, 800).state).toBe('SUSPICIOUS')
    expect(tracker.update(true, .8, 2300).state).toBe('WARNING')
    expect(tracker.update(true, .8, 3800).state).toBe('LOCKDOWN')
    expect(tracker.update(false, 0, 4000).state).toBe('RECOVERY')
    expect(tracker.update(false, 0, 5999).state).toBe('RECOVERY')
    expect(tracker.update(false, 0, 6000).state).toBe('SECURE')
  })

  it('reset clears all accumulated evidence', () => {
    const tracker = new PhoneThreatTracker()
    tracker.update(true, .8, 0)
    tracker.update(true, .8, 400)
    tracker.update(true, .8, 800)
    tracker.reset()
    expect(tracker.update(true, .8, 4000).state).toBe('SECURE')
  })
})

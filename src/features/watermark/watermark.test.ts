import { describe, expect, it } from 'vitest'
import { buildWatermarkText, maskIdentifier, watermarkOpacity } from './watermark'

describe('forensic watermark helpers', () => {
  it('masks identifiers before rendering them', () => {
    expect(maskIdentifier('browser-session-91c4', 'SESSION')).toBe('SESSION-91C4')
  })

  it('raises opacity as threat state escalates', () => {
    expect(watermarkOpacity('SECURE')).toBeLessThan(watermarkOpacity('WARNING'))
    expect(watermarkOpacity('WARNING')).toBeLessThan(watermarkOpacity('LOCKDOWN'))
  })

  it('builds safe watermark text without raw identifiers', () => {
    const text = buildWatermarkText({ organizationId: 'organization-secret-name', deviceId: 'device-7f2a', sessionId: 'session-91c4', timestamp: new Date('2026-07-16T10:42:00Z') })
    expect(text).toContain('CONFIDENTIAL')
    expect(text).toContain('DEVICE-7F2A')
    expect(text).toContain('SESSION-91C4')
    expect(text).not.toContain('organization-secret-name')
  })
})

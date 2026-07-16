import { describe, expect, it } from 'vitest'
import type { ProtectedZone } from '../../api/types'
import { hasProtectedFallback, moveZone, normalizeRect, resizeZone, zoneProtectionDecision } from './zoneMath'

const zone = (overrides: Partial<ProtectedZone> = {}): ProtectedZone => ({
  id: 'z1',
  organization_id: 'org',
  workspace_id: 'workspace',
  name: 'Salary column',
  description: '',
  relative_x: 0.1,
  relative_y: 0.1,
  relative_width: 0.2,
  relative_height: 0.2,
  sensitivity: 'HIGH',
  protection_action: 'BLUR',
  enabled: true,
  created_at: '',
  updated_at: '',
  ...overrides,
})

describe('protected zone decisions', () => {
  it('normalizes drawn rectangles', () => {
    expect(normalizeRect({ x: 0.7, y: 0.6 }, { x: 0.2, y: 0.1 })).toEqual({ relative_x: 0.2, relative_y: 0.1, relative_width: 0.5, relative_height: 0.5 })
  })

  it('moves and resizes zones without leaving normalized bounds', () => {
    expect(moveZone(zone(), 0.9, 0).relative_x).toBe(0.8)
    expect(resizeZone(zone({ relative_x: 0.9 }), 0.3, 0).relative_width).toBe(0.1)
  })

  it('protects high and critical zones during warning only', () => {
    const decisions = zoneProtectionDecision([zone({ sensitivity: 'LOW' }), zone({ id: 'z2', sensitivity: 'CRITICAL', protection_action: 'REDACT' })], 'WARNING')
    expect(decisions.map(item => item.active)).toEqual([false, true])
    expect(decisions[1].action).toBe('REDACT')
  })

  it('protects all enabled zones during lockdown and ignores disabled zones', () => {
    const decisions = zoneProtectionDecision([zone({ sensitivity: 'LOW' }), zone({ id: 'z2', enabled: false })], 'LOCKDOWN')
    expect(decisions.map(item => item.active)).toEqual([true, false])
  })

  it('uses full-dashboard fallback when no enabled zones exist', () => {
    expect(hasProtectedFallback([], 'WARNING')).toBe(true)
    expect(hasProtectedFallback([zone({ enabled: false })], 'LOCKDOWN')).toBe(true)
    expect(hasProtectedFallback([zone()], 'LOCKDOWN')).toBe(false)
  })
})

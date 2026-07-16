import { describe, expect, it } from 'vitest'
import type { ProtectedZone, ProtectionPolicy } from '../../api/types'
import { evaluateProtectionPolicy } from './policyDecision'

const policy: ProtectionPolicy = { id: 'p', organization_id: 'o', workspace_id: 'w', name: 'Standard Office', enabled: true, warning_threshold: 60, lockdown_threshold: 80, recovery_seconds: 2, monitoring_required: true, watermark_mode: 'ON_THREAT', warning_default_action: 'BLUR', lockdown_default_action: 'HIDE', protect_high_zones_on_warning: true, protect_all_zones_on_lockdown: true, require_reauthentication_after_lockdown: true, created_at: '', updated_at: '' }
const zone = (id: string, sensitivity: ProtectedZone['sensitivity']): ProtectedZone => ({ id, organization_id: 'o', workspace_id: 'w', name: id, description: '', relative_x: 0, relative_y: 0, relative_width: 0.2, relative_height: 0.2, sensitivity, protection_action: 'BLUR', enabled: true, created_at: '', updated_at: '' })

describe('policy decision engine', () => {
  it('protects only high and critical zones during warning', () => {
    const decision = evaluateProtectionPolicy({ policy, zones: [zone('low', 'LOW'), zone('high', 'HIGH')], state: 'WARNING', riskScore: 65, monitoringHealthy: true })
    expect(decision.zones_to_blur).toEqual(['high'])
  })
  it('hides critical zones and requires reauth during lockdown', () => {
    const decision = evaluateProtectionPolicy({ policy, zones: [zone('critical', 'CRITICAL')], state: 'LOCKDOWN', riskScore: 90, monitoringHealthy: true })
    expect(decision.zones_to_hide).toContain('critical')
    expect(decision.require_reauthentication).toBe(true)
    expect(decision.watermark_level).toBe('HIGH')
  })
})

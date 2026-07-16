import type { ProtectedZone, ProtectionPolicy, ZoneProtectionAction } from '../../api/types'
import type { ThreatState } from '../zones/zoneMath'

export type ProtectionDecision = {
  zones_to_blur: string[]
  zones_to_redact: string[]
  zones_to_hide: string[]
  zones_to_watermark: string[]
  blur_entire_workspace: boolean
  hide_entire_workspace: boolean
  watermark_level: 'NONE' | 'LOW' | 'MEDIUM' | 'HIGH'
  require_reauthentication: boolean
  create_incident_event: boolean
  reason: string
}

export function evaluateProtectionPolicy(input: { state: ThreatState; riskScore: number; zones: ProtectedZone[]; policy: ProtectionPolicy | null; monitoringHealthy: boolean }): ProtectionDecision {
  const activeZones = input.zones.filter(zone => zone.enabled)
  const policy = input.policy
  const decision: ProtectionDecision = { zones_to_blur: [], zones_to_redact: [], zones_to_hide: [], zones_to_watermark: [], blur_entire_workspace: false, hide_entire_workspace: false, watermark_level: 'NONE', require_reauthentication: false, create_incident_event: false, reason: 'No enabled policy.' }
  if (!policy || !policy.enabled) return decision
  const apply = (zone: ProtectedZone, action: ZoneProtectionAction) => {
    if (action === 'BLUR') decision.zones_to_blur.push(zone.id)
    if (action === 'REDACT') decision.zones_to_redact.push(zone.id)
    if (action === 'HIDE') decision.zones_to_hide.push(zone.id)
    if (action === 'WATERMARK') decision.zones_to_watermark.push(zone.id)
  }
  if (policy.watermark_mode === 'ALWAYS') decision.watermark_level = 'LOW'
  if (!input.monitoringHealthy && policy.monitoring_required) {
    decision.blur_entire_workspace = activeZones.length === 0
    decision.create_incident_event = true
    decision.reason = 'Monitoring is required by policy but endpoint health is degraded.'
  }
  if (input.state === 'WARNING' || input.riskScore >= policy.warning_threshold) {
    activeZones.filter(zone => policy.protect_high_zones_on_warning && ['HIGH', 'CRITICAL'].includes(zone.sensitivity)).forEach(zone => apply(zone, zone.protection_action || policy.warning_default_action))
    decision.watermark_level = 'MEDIUM'
    decision.create_incident_event = true
    decision.reason = `Risk reached warning threshold ${policy.warning_threshold}.`
  }
  if (input.state === 'LOCKDOWN' || input.riskScore >= policy.lockdown_threshold) {
    if (policy.protect_all_zones_on_lockdown) activeZones.forEach(zone => apply(zone, zone.sensitivity === 'CRITICAL' ? 'HIDE' : (zone.protection_action || policy.lockdown_default_action)))
    decision.hide_entire_workspace = activeZones.length === 0
    decision.watermark_level = 'HIGH'
    decision.require_reauthentication = policy.require_reauthentication_after_lockdown
    decision.create_incident_event = true
    decision.reason = `Risk reached lockdown threshold ${policy.lockdown_threshold}.`
  }
  return decision
}

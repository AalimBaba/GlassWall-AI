import type { ProtectedZone, ZoneProtectionAction } from '../../api/types'

export type ThreatState = 'SECURE' | 'OBSERVE' | 'WARNING' | 'LOCKDOWN' | 'RECOVERY'
export type ZoneProtection = { zone: ProtectedZone; action: ZoneProtectionAction; active: boolean; reason: string }

export function normalizeRect(start: { x: number; y: number }, end: { x: number; y: number }) {
  const x = Math.max(0, Math.min(start.x, end.x))
  const y = Math.max(0, Math.min(start.y, end.y))
  const width = Math.min(1 - x, Math.abs(end.x - start.x))
  const height = Math.min(1 - y, Math.abs(end.y - start.y))
  return { relative_x: round(x), relative_y: round(y), relative_width: round(width), relative_height: round(height) }
}

export function clampZone(zone: ProtectedZone): ProtectedZone {
  const x = Math.max(0, Math.min(1 - zone.relative_width, zone.relative_x))
  const y = Math.max(0, Math.min(1 - zone.relative_height, zone.relative_y))
  const width = Math.max(0.02, Math.min(zone.relative_width, 1 - x))
  const height = Math.max(0.02, Math.min(zone.relative_height, 1 - y))
  return { ...zone, relative_x: round(x), relative_y: round(y), relative_width: round(width), relative_height: round(height) }
}

export function resizeZone(zone: ProtectedZone, deltaWidth: number, deltaHeight: number): ProtectedZone {
  return {
    ...zone,
    relative_width: round(Math.max(0.02, Math.min(zone.relative_width + deltaWidth, 1 - zone.relative_x))),
    relative_height: round(Math.max(0.02, Math.min(zone.relative_height + deltaHeight, 1 - zone.relative_y))),
  }
}

export function moveZone(zone: ProtectedZone, deltaX: number, deltaY: number): ProtectedZone {
  return {
    ...zone,
    relative_x: round(Math.max(0, Math.min(1 - zone.relative_width, zone.relative_x + deltaX))),
    relative_y: round(Math.max(0, Math.min(1 - zone.relative_height, zone.relative_y + deltaY))),
  }
}

export function shouldProtectZone(zone: ProtectedZone, state: ThreatState) {
  if (!zone.enabled) return false
  if (state === 'LOCKDOWN') return true
  if (state === 'RECOVERY') return zone.sensitivity === 'HIGH' || zone.sensitivity === 'CRITICAL'
  if (state === 'WARNING') return zone.sensitivity === 'HIGH' || zone.sensitivity === 'CRITICAL'
  if (state === 'OBSERVE') return zone.protection_action === 'WATERMARK'
  return false
}

export function zoneProtectionDecision(zones: ProtectedZone[], state: ThreatState): ZoneProtection[] {
  return zones.map(zone => {
    const active = shouldProtectZone(zone, state)
    const action = state === 'LOCKDOWN' && zone.sensitivity === 'CRITICAL' && zone.protection_action === 'BLUR' ? 'HIDE' : zone.protection_action
    return {
      zone,
      active,
      action,
      reason: !zone.enabled ? 'Zone disabled' : active ? `${state} policy applies ${action}` : 'No protection in current state',
    }
  })
}

export function hasProtectedFallback(zones: ProtectedZone[], state: ThreatState) {
  return zones.filter(zone => zone.enabled).length === 0 && (state === 'WARNING' || state === 'LOCKDOWN' || state === 'RECOVERY')
}

function round(value: number) {
  return Math.round(value * 10_000) / 10_000
}

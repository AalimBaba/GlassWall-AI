import type { ThreatState } from '../zones/zoneMath'

export function maskIdentifier(value: string, prefix: string) {
  const clean = (value || 'unknown').replace(/[^a-z0-9]/gi, '').toUpperCase()
  return `${prefix}-${clean.slice(-4).padStart(4, '0')}`
}

export function watermarkOpacity(state: ThreatState) {
  if (state === 'LOCKDOWN') return 0.3
  if (state === 'WARNING' || state === 'RECOVERY') return 0.2
  if (state === 'OBSERVE') return 0.14
  return 0.07
}

export function buildWatermarkText(input: { organizationId: string; deviceId: string; sessionId: string; timestamp: Date }) {
  const stamp = input.timestamp.toLocaleString([], { day: '2-digit', month: 'short', year: 'numeric', hour: '2-digit', minute: '2-digit' }).toUpperCase()
  return `CONFIDENTIAL · ${maskIdentifier(input.deviceId, 'DEVICE')} · ${maskIdentifier(input.sessionId, 'SESSION')} · ${maskIdentifier(input.organizationId, 'ORG')} · ${stamp}`
}

import type { AdminOverview, DeviceInventoryItem, EndpointHeartbeatPayload, EndpointHealth } from './types'

export type AdminMetric = { label: string; value: number; tone: 'secure' | 'warning' | 'danger' | 'neutral' }

export function buildOverviewMetrics(overview: AdminOverview | null): AdminMetric[] {
  const health = overview?.health_counts
  const states = overview?.state_counts
  return [
    { label: 'Total Registered Devices', value: overview?.endpoint_count ?? 0, tone: 'neutral' },
    { label: 'Online Devices', value: health?.Online ?? 0, tone: 'secure' },
    { label: 'Degraded Devices', value: health?.Degraded ?? 0, tone: 'warning' },
    { label: 'Offline Devices', value: health?.Offline ?? 0, tone: 'danger' },
    { label: 'Secure Sessions', value: states?.SECURE ?? 0, tone: 'secure' },
    { label: 'Warning Sessions', value: states?.WARNING ?? 0, tone: 'warning' },
    { label: 'Lockdown Sessions', value: states?.LOCKDOWN ?? 0, tone: 'danger' },
    { label: 'Open Incidents', value: overview?.open_incident_count ?? 0, tone: 'danger' },
  ]
}

export function riskLabel(score: number) {
  if (score >= 80) return 'LOCKDOWN'
  if (score >= 60) return 'WARNING'
  if (score >= 30) return 'OBSERVE'
  return 'SECURE'
}

export function healthTone(health: EndpointHealth): 'secure' | 'warning' | 'danger' | 'neutral' {
  if (health === 'Online') return 'secure'
  if (health === 'Degraded' || health === 'Monitoring Interrupted') return 'warning'
  if (health === 'Offline') return 'danger'
  return 'neutral'
}

export function formatReported(value: string | number | boolean | null | undefined) {
  if (value === null || value === undefined || value === '') return 'Not reported'
  if (typeof value === 'boolean') return value ? 'Available' : 'Unavailable'
  return String(value)
}

export function buildHeartbeatPayload(input: {
  sessionId: string
  workspaceId: string
  deviceId: string
  userId?: string
  state: string
  cameraPermission: boolean
  backendConnected: boolean
  modelLoaded: boolean
  inferenceLatencyMs: number
  latestRiskScore: number
  lastDetectionTimestamp: number | null
  applicationVersion: string
}): EndpointHeartbeatPayload {
  return {
    session_id: input.sessionId,
    workspace_id: input.workspaceId,
    device_id: input.deviceId,
    user_id: input.userId || null,
    session_state: input.state,
    camera_permission: input.cameraPermission,
    backend_connected: input.backendConnected,
    model_loaded: input.modelLoaded,
    inference_latency_ms: Math.max(0, Math.round(input.inferenceLatencyMs)),
    latest_risk_score: Math.max(0, Math.min(100, Math.round(input.latestRiskScore))),
    last_detection_timestamp: input.lastDetectionTimestamp,
    application_version: input.applicationVersion,
  }
}

export function hasRandomLookingData(devices: DeviceInventoryItem[]) {
  return devices.some(item => /random|fake|lorem/i.test(`${item.device_name} ${item.workspace_name}`))
}

export type EndpointHealth = 'Online' | 'Degraded' | 'Monitoring Interrupted' | 'Offline'
export type SessionState = 'SECURE' | 'WARNING' | 'LOCKDOWN' | 'MONITORING_INTERRUPTED' | string

export type AdminOverview = {
  organization_id: string
  endpoint_count: number
  health_counts: Record<EndpointHealth, number>
  state_counts: Record<'SECURE' | 'WARNING' | 'LOCKDOWN', number>
  incident_count: number
  open_incident_count: number
  sample_data: boolean
}

export type DeviceInventoryItem = {
  session_id: string
  workspace_id: string
  workspace_name: string | null
  device_id: string
  device_name: string | null
  state: SessionState
  health: EndpointHealth
  latest_risk_score: number
  camera_permission: boolean
  backend_connected: boolean
  model_loaded: boolean
  inference_latency_ms: number
  last_detection_at: string | null
  last_heartbeat_at: string | null
  application_version: string
}

export type DeviceInventory = {
  organization_id: string
  devices: DeviceInventoryItem[]
  sample_data: boolean
}

export type EndpointHeartbeatPayload = {
  session_id: string
  workspace_id: string
  device_id: string
  user_id?: string | null
  session_state: SessionState
  camera_permission: boolean
  backend_connected: boolean
  model_loaded: boolean
  inference_latency_ms: number
  latest_risk_score: number
  last_detection_timestamp?: number | null
  application_version: string
}

export type EndpointHeartbeatResponse = DeviceInventoryItem

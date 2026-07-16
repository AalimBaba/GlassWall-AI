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

export type IncidentStatus = 'OPEN' | 'INVESTIGATING' | 'RESOLVED' | 'FALSE_POSITIVE' | 'DISMISSED'
export type IncidentSeverity = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'

export type IncidentSummary = {
  id: string
  organization_id: string
  workspace_id: string
  device_id: string
  session_id: string
  state: string
  status: IncidentStatus
  severity: IncidentSeverity
  threat_type: string
  started_at: string
  ended_at: string | null
  duration_ms: number | null
  peak_risk_score: number
  current_risk_score: number
  phone_confidence: number | null
  face_count: number | null
  backend_connected: boolean
  model_loaded: boolean
  assigned_analyst_id: string | null
  resolution_reason: string | null
  created_at: string
  updated_at: string
}

export type IncidentEvent = {
  id: string
  event_type: string
  source: string
  message: string
  risk_score: number | null
  confidence: number | null
  frame_id: number | null
  metadata: Record<string, unknown>
  occurred_at: string
}

export type IncidentSignal = {
  id: string
  signal_type: string
  confidence: number | null
  frame_id: number | null
  bbox: unknown[]
  frame_hash: string | null
  metadata: Record<string, unknown>
  observed_at: string
}

export type RemediationAction = {
  id: string
  action_type: string
  status: string
  requested_by_user_id: string | null
  created_at: string
}

export type AnalystNote = {
  id: string
  analyst_id: string | null
  note: string
  created_at: string
}

export type IncidentDetail = IncidentSummary & {
  events: IncidentEvent[]
  signals: IncidentSignal[]
  remediation_actions: RemediationAction[]
  analyst_notes: AnalystNote[]
}

export type IncidentList = {
  organization_id: string
  incidents: IncidentSummary[]
  total: number
  limit: number
  offset: number
  sample_data: boolean
}

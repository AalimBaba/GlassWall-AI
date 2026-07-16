import { describe, expect, it } from 'vitest'
import { buildHeartbeatPayload, buildOverviewMetrics, formatReported, hasRandomIncidentData, hasRandomLookingData, healthTone, riskLabel } from './adminModel'
import { getRuntimeConfig } from './config'

describe('admin console view models', () => {
  it('renders backend-not-configured production state without localhost', () => {
    const config = getRuntimeConfig({ PROD: true, DEV: false })
    expect(config.controlPlaneConfigured).toBe(false)
    expect(config.apiBaseUrl).toBe('')
    expect(config.wsBaseUrl).toBe('')
    expect(config.backendWsUrl).toBe('')
    expect(JSON.stringify(config)).not.toContain('localhost')
    expect(JSON.stringify(config)).not.toContain('127.0.0.1')
  })

  it('derives the face-analysis websocket URL from the configured public WSS base URL', () => {
    const config = getRuntimeConfig({
      PROD: true,
      DEV: false,
      VITE_API_BASE_URL: 'https://glasswall-api.example.test/',
      VITE_WS_BASE_URL: 'wss://glasswall-api.example.test/',
    })
    expect(config.apiBaseUrl).toBe('https://glasswall-api.example.test')
    expect(config.wsBaseUrl).toBe('wss://glasswall-api.example.test')
    expect(config.backendWsUrl).toBe('wss://glasswall-api.example.test/ws/analyze')
  })

  it('builds empty and populated overview metrics from API data', () => {
    expect(buildOverviewMetrics(null).map(item => item.value)).toEqual([0, 0, 0, 0, 0, 0, 0, 0])
    const metrics = buildOverviewMetrics({
      organization_id: 'org',
      endpoint_count: 3,
      health_counts: { Online: 1, Degraded: 1, 'Monitoring Interrupted': 0, Offline: 1 },
      state_counts: { SECURE: 1, WARNING: 1, LOCKDOWN: 1 },
      incident_count: 2,
      open_incident_count: 1,
      sample_data: false,
    })
    expect(metrics.map(item => item.value)).toEqual([3, 1, 1, 1, 1, 1, 1, 1])
  })

  it('maps health badges and risk labels deterministically', () => {
    expect(healthTone('Online')).toBe('secure')
    expect(healthTone('Degraded')).toBe('warning')
    expect(healthTone('Offline')).toBe('danger')
    expect(riskLabel(0)).toBe('SECURE')
    expect(riskLabel(35)).toBe('OBSERVE')
    expect(riskLabel(65)).toBe('WARNING')
    expect(riskLabel(92)).toBe('LOCKDOWN')
  })

  it('constructs heartbeat payloads from real endpoint state', () => {
    const payload = buildHeartbeatPayload({
      sessionId: 'session-1',
      workspaceId: 'workspace-1',
      deviceId: 'device-1',
      state: 'WARNING',
      cameraPermission: true,
      backendConnected: false,
      modelLoaded: true,
      inferenceLatencyMs: 24.6,
      latestRiskScore: 64.4,
      lastDetectionTimestamp: 1234,
      applicationVersion: 'test',
    })
    expect(payload).toMatchObject({
      session_id: 'session-1',
      workspace_id: 'workspace-1',
      device_id: 'device-1',
      session_state: 'WARNING',
      camera_permission: true,
      backend_connected: false,
      model_loaded: true,
      inference_latency_ms: 25,
      latest_risk_score: 64,
      last_detection_timestamp: 1234,
    })
  })

  it('uses Not reported for unavailable fields and does not flag real endpoint names as random data', () => {
    expect(formatReported(null)).toBe('Not reported')
    expect(formatReported(false)).toBe('Unavailable')
    expect(hasRandomLookingData([{
      session_id: 's',
      workspace_id: 'w',
      workspace_name: 'Finance Workspace',
      device_id: 'd',
      device_name: 'Aalim Laptop',
      state: 'SECURE',
      health: 'Online',
      latest_risk_score: 10,
      camera_permission: true,
      backend_connected: true,
      model_loaded: true,
      inference_latency_ms: 20,
      last_detection_at: null,
      last_heartbeat_at: null,
      application_version: 'test',
    }])).toBe(false)
  })

  it('does not classify real persisted incident metadata as random sample data', () => {
    expect(hasRandomIncidentData([{
      id: 'incident-001',
      organization_id: 'org',
      workspace_id: 'finance-workspace',
      device_id: 'aalim-laptop',
      session_id: 'session-1',
      state: 'WARNING',
      status: 'OPEN',
      severity: 'HIGH',
      threat_type: 'OPTICAL_THREAT',
      started_at: '2026-07-16T00:00:00Z',
      ended_at: null,
      duration_ms: null,
      peak_risk_score: 67,
      current_risk_score: 67,
      phone_confidence: null,
      face_count: null,
      backend_connected: true,
      model_loaded: true,
      assigned_analyst_id: null,
      resolution_reason: null,
      created_at: '2026-07-16T00:00:00Z',
      updated_at: '2026-07-16T00:00:00Z',
    }])).toBe(false)
  })
})

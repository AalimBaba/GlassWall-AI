import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { buildHeartbeatPayload } from '../api/adminModel'
import { createApiClient } from '../api/client'
import type { RuntimeConfig } from '../api/config'

export type HeartbeatInputState = {
  state: string
  cameraPermission: boolean
  backendConnected: boolean
  modelLoaded: boolean
  inferenceLatencyMs: number
  latestRiskScore: number
  lastDetectionTimestamp: number | null
  enabled: boolean
}

export function useEndpointHeartbeat(config: RuntimeConfig, heartbeat: HeartbeatInputState) {
  const [status, setStatus] = useState<'disabled' | 'ready' | 'sent' | 'error'>('disabled')
  const [error, setError] = useState('')
  const [lastSentAt, setLastSentAt] = useState<Date | null>(null)
  const client = useMemo(() => createApiClient({ baseUrl: config.apiBaseUrl }), [config.apiBaseUrl])
  const abortRef = useRef<AbortController | null>(null)
  const heartbeatRef = useRef(heartbeat)
  heartbeatRef.current = heartbeat

  const send = useCallback(async () => {
    if (!config.controlPlaneConfigured || !config.endpointIdentityConfigured || !heartbeatRef.current.enabled) {
      setStatus('disabled')
      return
    }
    abortRef.current?.abort()
    const controller = new AbortController()
    abortRef.current = controller
    try {
      await client.sendHeartbeat(
        config.organizationId,
        buildHeartbeatPayload({
          sessionId: config.sessionId,
          workspaceId: config.workspaceId,
          deviceId: config.deviceId,
          userId: config.userId,
          state: heartbeatRef.current.state,
          cameraPermission: heartbeatRef.current.cameraPermission,
          backendConnected: heartbeatRef.current.backendConnected,
          modelLoaded: heartbeatRef.current.modelLoaded,
          inferenceLatencyMs: heartbeatRef.current.inferenceLatencyMs,
          latestRiskScore: heartbeatRef.current.latestRiskScore,
          lastDetectionTimestamp: heartbeatRef.current.lastDetectionTimestamp,
          applicationVersion: config.applicationVersion,
        }),
        controller.signal,
      )
      setStatus('sent')
      setError('')
      setLastSentAt(new Date())
    } catch (err) {
      setStatus('error')
      setError(err instanceof Error ? err.message : 'Unable to send endpoint heartbeat')
    }
  }, [client, config])

  useEffect(() => {
    if (!config.controlPlaneConfigured || !config.endpointIdentityConfigured || !heartbeat.enabled) {
      setStatus(config.controlPlaneConfigured ? 'ready' : 'disabled')
      return
    }
    void send()
    const interval = window.setInterval(() => {
      if (document.visibilityState === 'visible') void send()
    }, config.heartbeatIntervalMs)
    return () => {
      window.clearInterval(interval)
      abortRef.current?.abort()
    }
  }, [config.controlPlaneConfigured, config.endpointIdentityConfigured, config.heartbeatIntervalMs, heartbeat.enabled, send])

  useEffect(() => {
    if (heartbeat.enabled) void send()
  }, [heartbeat.state, heartbeat.cameraPermission, heartbeat.backendConnected, heartbeat.modelLoaded, heartbeat.latestRiskScore, send])

  return { status, error, lastSentAt, send }
}

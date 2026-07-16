import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { createApiClient } from '../api/client'
import type { DeviceInventoryItem } from '../api/types'
import type { RuntimeConfig } from '../api/config'

export function useDevices(config: RuntimeConfig) {
  const [devices, setDevices] = useState<DeviceInventoryItem[]>([])
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const [lastUpdatedAt, setLastUpdatedAt] = useState<Date | null>(null)
  const client = useMemo(() => createApiClient({ baseUrl: config.apiBaseUrl }), [config.apiBaseUrl])
  const abortRef = useRef<AbortController | null>(null)

  const refresh = useCallback(async () => {
    if (!config.controlPlaneConfigured || !config.organizationId) return
    abortRef.current?.abort()
    const controller = new AbortController()
    abortRef.current = controller
    setLoading(true)
    setError('')
    try {
      const inventory = await client.getDevices(config.organizationId, controller.signal)
      setDevices(inventory.devices)
      setLastUpdatedAt(new Date())
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Unable to load endpoint inventory')
    } finally {
      setLoading(false)
    }
  }, [client, config.controlPlaneConfigured, config.organizationId])

  useEffect(() => {
    if (!config.controlPlaneConfigured || !config.organizationId) return
    void refresh()
    const interval = window.setInterval(() => {
      if (document.visibilityState === 'visible') void refresh()
    }, config.pollIntervalMs)
    const visible = () => { if (document.visibilityState === 'visible') void refresh() }
    document.addEventListener('visibilitychange', visible)
    return () => {
      window.clearInterval(interval)
      document.removeEventListener('visibilitychange', visible)
      abortRef.current?.abort()
    }
  }, [config.controlPlaneConfigured, config.organizationId, config.pollIntervalMs, refresh])

  return { devices, loading, error, lastUpdatedAt, refresh }
}

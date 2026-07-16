import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { createApiClient } from '../api/client'
import type { AdminOverview } from '../api/types'
import type { RuntimeConfig } from '../api/config'

export function useAdminOverview(config: RuntimeConfig) {
  const [data, setData] = useState<AdminOverview | null>(null)
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
      const overview = await client.getAdminOverview(config.organizationId, controller.signal)
      setData(overview)
      setLastUpdatedAt(new Date())
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Unable to load admin overview')
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

  return { data, loading, error, lastUpdatedAt, refresh }
}

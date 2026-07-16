import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { createApiClient } from '../api/client'
import type { ProtectedZone, ProtectedZoneInput } from '../api/types'
import type { RuntimeConfig } from '../api/config'

export function useProtectedZones(config: RuntimeConfig) {
  const [zones, setZones] = useState<ProtectedZone[]>([])
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const [lastUpdatedAt, setLastUpdatedAt] = useState<Date | null>(null)
  const client = useMemo(() => createApiClient({ baseUrl: config.apiBaseUrl }), [config.apiBaseUrl])
  const abortRef = useRef<AbortController | null>(null)

  const refresh = useCallback(async () => {
    if (!config.controlPlaneConfigured || !config.organizationId || !config.workspaceId) return
    abortRef.current?.abort()
    const controller = new AbortController()
    abortRef.current = controller
    setLoading(true)
    setError('')
    try {
      const response = await client.getProtectedZones(config.organizationId, config.workspaceId, controller.signal)
      setZones(response.zones)
      setLastUpdatedAt(new Date())
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Unable to load protected zones')
    } finally {
      setLoading(false)
    }
  }, [client, config.controlPlaneConfigured, config.organizationId, config.workspaceId])

  const createZone = useCallback(async (zone: ProtectedZoneInput) => {
    if (!config.organizationId || !config.workspaceId) return
    const created = await client.createProtectedZone(config.organizationId, config.workspaceId, zone)
    setZones(current => [...current, created])
  }, [client, config.organizationId, config.workspaceId])

  const updateZone = useCallback(async (zoneId: string, updates: Partial<ProtectedZoneInput>) => {
    if (!config.organizationId || !config.workspaceId) return
    const updated = await client.updateProtectedZone(config.organizationId, config.workspaceId, zoneId, updates)
    setZones(current => current.map(item => item.id === zoneId ? updated : item))
  }, [client, config.organizationId, config.workspaceId])

  const deleteZone = useCallback(async (zoneId: string) => {
    if (!config.organizationId || !config.workspaceId) return
    await client.deleteProtectedZone(config.organizationId, config.workspaceId, zoneId)
    setZones(current => current.filter(item => item.id !== zoneId))
  }, [client, config.organizationId, config.workspaceId])

  useEffect(() => {
    void refresh()
    return () => abortRef.current?.abort()
  }, [refresh])

  return { zones, loading, error, lastUpdatedAt, refresh, createZone, updateZone, deleteZone }
}

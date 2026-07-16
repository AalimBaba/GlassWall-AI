import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { createApiClient } from '../api/client'
import type { IncidentDetail, IncidentList, IncidentSeverity, IncidentStatus, IncidentSummary } from '../api/types'
import type { RuntimeConfig } from '../api/config'

export function useIncidents(config: RuntimeConfig) {
  const [data, setData] = useState<IncidentList | null>(null)
  const [selected, setSelected] = useState<IncidentDetail | null>(null)
  const [statusFilter, setStatusFilter] = useState<IncidentStatus | ''>('')
  const [severityFilter, setSeverityFilter] = useState<IncidentSeverity | ''>('')
  const [search, setSearch] = useState('')
  const [loading, setLoading] = useState(false)
  const [detailLoading, setDetailLoading] = useState(false)
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
      const incidents = await client.getIncidents(config.organizationId, { status: statusFilter, severity: severityFilter }, controller.signal)
      setData(incidents)
      setLastUpdatedAt(new Date())
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Unable to load incidents')
    } finally {
      setLoading(false)
    }
  }, [client, config.controlPlaneConfigured, config.organizationId, severityFilter, statusFilter])

  const openIncident = useCallback(async (incident: IncidentSummary) => {
    if (!config.controlPlaneConfigured || !config.organizationId) return
    setDetailLoading(true)
    setError('')
    try {
      setSelected(await client.getIncident(config.organizationId, incident.id))
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Unable to load incident details')
    } finally {
      setDetailLoading(false)
    }
  }, [client, config.controlPlaneConfigured, config.organizationId])

  const updateStatus = useCallback(async (status: IncidentStatus) => {
    if (!config.organizationId || !selected) return
    setDetailLoading(true)
    try {
      setSelected(await client.updateIncidentStatus(config.organizationId, selected.id, status, status === 'FALSE_POSITIVE' ? 'Marked false positive by analyst.' : undefined))
      await refresh()
    } finally {
      setDetailLoading(false)
    }
  }, [client, config.organizationId, refresh, selected])

  const addNote = useCallback(async (note: string) => {
    if (!config.organizationId || !selected || !note.trim()) return
    setDetailLoading(true)
    try {
      setSelected(await client.addIncidentNote(config.organizationId, selected.id, note.trim()))
    } finally {
      setDetailLoading(false)
    }
  }, [client, config.organizationId, selected])

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

  const visibleIncidents = (data?.incidents ?? []).filter(item => {
    const term = search.trim().toLowerCase()
    if (!term) return true
    return `${item.id} ${item.device_id} ${item.workspace_id} ${item.threat_type} ${item.status} ${item.severity}`.toLowerCase().includes(term)
  })

  return {
    data,
    incidents: visibleIncidents,
    selected,
    statusFilter,
    severityFilter,
    search,
    loading,
    detailLoading,
    error,
    lastUpdatedAt,
    setStatusFilter,
    setSeverityFilter,
    setSearch,
    openIncident,
    closeIncident: () => setSelected(null),
    updateStatus,
    addNote,
    refresh,
  }
}

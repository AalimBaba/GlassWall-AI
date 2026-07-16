import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { createApiClient } from '../api/client'
import type { ProtectionPolicy } from '../api/types'
import type { RuntimeConfig } from '../api/config'

export function useProtectionPolicies(config: RuntimeConfig) {
  const [policies, setPolicies] = useState<ProtectionPolicy[]>([])
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const client = useMemo(() => createApiClient({ baseUrl: config.apiBaseUrl }), [config.apiBaseUrl])
  const abortRef = useRef<AbortController | null>(null)
  const refresh = useCallback(async () => {
    if (!config.controlPlaneConfigured || !config.organizationId) return
    abortRef.current?.abort()
    const controller = new AbortController()
    abortRef.current = controller
    setLoading(true); setError('')
    try { setPolicies((await client.getPolicies(config.organizationId, config.workspaceId, controller.signal)).policies) }
    catch (err) { setError(err instanceof Error ? err.message : 'Unable to load policies') }
    finally { setLoading(false) }
  }, [client, config.controlPlaneConfigured, config.organizationId, config.workspaceId])
  const createPreset = useCallback(async (preset: string) => {
    if (!config.organizationId || !config.workspaceId) return
    const created = await client.createPolicyPreset(config.organizationId, config.workspaceId, preset)
    setPolicies(current => [created, ...current])
  }, [client, config.organizationId, config.workspaceId])
  const updatePolicy = useCallback(async (policyId: string, updates: Partial<ProtectionPolicy>) => {
    if (!config.organizationId) return
    const updated = await client.updatePolicy(config.organizationId, policyId, updates)
    setPolicies(current => current.map(item => item.id === policyId ? updated : item))
  }, [client, config.organizationId])
  useEffect(() => { void refresh(); return () => abortRef.current?.abort() }, [refresh])
  return { policies, activePolicy: policies.find(item => item.enabled) || null, loading, error, refresh, createPreset, updatePolicy }
}

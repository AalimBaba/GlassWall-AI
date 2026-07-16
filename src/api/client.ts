import type { AdminOverview, DeviceInventory, EndpointHeartbeatPayload, EndpointHeartbeatResponse, IncidentDetail, IncidentList, IncidentStatus, ProtectedZone, ProtectedZoneInput, ProtectedZoneList } from './types'

export class ApiError extends Error {
  constructor(message: string, readonly status?: number) {
    super(message)
    this.name = 'ApiError'
  }
}

export type ApiClientOptions = {
  baseUrl: string
  timeoutMs?: number
}

async function request<T>(baseUrl: string, path: string, init: RequestInit = {}, timeoutMs = 8_000): Promise<T> {
  if (!baseUrl) throw new ApiError('Control-plane backend is not configured')
  const controller = new AbortController()
  const timeout = globalThis.setTimeout(() => controller.abort(), timeoutMs)
  const externalSignal = init.signal
  if (externalSignal) {
    if (externalSignal.aborted) controller.abort()
    else externalSignal.addEventListener('abort', () => controller.abort(), { once: true })
  }
  try {
    const response = await fetch(`${baseUrl}${path}`, {
      ...init,
      headers: { 'Content-Type': 'application/json', ...(init.headers || {}) },
      signal: controller.signal,
    })
    if (!response.ok) {
      let detail = response.statusText
      try {
        const body = await response.json()
        detail = body.detail || detail
      } catch {
        // ignore non-JSON API errors
      }
      throw new ApiError(detail, response.status)
    }
    return await response.json() as T
  } catch (error) {
    if (error instanceof ApiError) throw error
    if (error instanceof DOMException && error.name === 'AbortError') throw new ApiError('Request timed out or was cancelled')
    throw new ApiError(error instanceof Error ? error.message : 'Network request failed')
  } finally {
    globalThis.clearTimeout(timeout)
  }
}

export function createApiClient({ baseUrl, timeoutMs }: ApiClientOptions) {
  return {
    getAdminOverview(organizationId: string, signal?: AbortSignal) {
      return request<AdminOverview>(baseUrl, `/api/organizations/${organizationId}/admin/overview`, { signal }, timeoutMs)
    },
    getDevices(organizationId: string, signal?: AbortSignal) {
      return request<DeviceInventory>(baseUrl, `/api/organizations/${organizationId}/devices`, { signal }, timeoutMs)
    },
    sendHeartbeat(organizationId: string, payload: EndpointHeartbeatPayload, signal?: AbortSignal) {
      return request<EndpointHeartbeatResponse>(
        baseUrl,
        `/api/organizations/${organizationId}/heartbeats`,
        { method: 'POST', body: JSON.stringify(payload), signal },
        timeoutMs,
      )
    },
    getIncidents(organizationId: string, filters: { status?: string; severity?: string; search?: string } = {}, signal?: AbortSignal) {
      const params = new URLSearchParams()
      if (filters.status) params.set('status', filters.status)
      if (filters.severity) params.set('severity', filters.severity)
      const query = params.toString()
      return request<IncidentList>(baseUrl, `/api/organizations/${organizationId}/incidents${query ? `?${query}` : ''}`, { signal }, timeoutMs)
    },
    getIncident(organizationId: string, incidentId: string, signal?: AbortSignal) {
      return request<IncidentDetail>(baseUrl, `/api/organizations/${organizationId}/incidents/${incidentId}`, { signal }, timeoutMs)
    },
    updateIncidentStatus(organizationId: string, incidentId: string, status: IncidentStatus, reason?: string, signal?: AbortSignal) {
      return request<IncidentDetail>(
        baseUrl,
        `/api/organizations/${organizationId}/incidents/${incidentId}/status`,
        { method: 'POST', body: JSON.stringify({ status, reason }), signal },
        timeoutMs,
      )
    },
    addIncidentNote(organizationId: string, incidentId: string, note: string, signal?: AbortSignal) {
      return request<IncidentDetail>(
        baseUrl,
        `/api/organizations/${organizationId}/incidents/${incidentId}/notes`,
        { method: 'POST', body: JSON.stringify({ note }), signal },
        timeoutMs,
      )
    },
    getProtectedZones(organizationId: string, workspaceId: string, signal?: AbortSignal) {
      return request<ProtectedZoneList>(baseUrl, `/api/organizations/${organizationId}/workspaces/${workspaceId}/zones`, { signal }, timeoutMs)
    },
    createProtectedZone(organizationId: string, workspaceId: string, payload: ProtectedZoneInput, signal?: AbortSignal) {
      return request<ProtectedZone>(
        baseUrl,
        `/api/organizations/${organizationId}/workspaces/${workspaceId}/zones`,
        { method: 'POST', body: JSON.stringify(payload), signal },
        timeoutMs,
      )
    },
    updateProtectedZone(organizationId: string, workspaceId: string, zoneId: string, payload: Partial<ProtectedZoneInput>, signal?: AbortSignal) {
      return request<ProtectedZone>(
        baseUrl,
        `/api/organizations/${organizationId}/workspaces/${workspaceId}/zones/${zoneId}`,
        { method: 'PATCH', body: JSON.stringify(payload), signal },
        timeoutMs,
      )
    },
    deleteProtectedZone(organizationId: string, workspaceId: string, zoneId: string, signal?: AbortSignal) {
      return request<{ deleted: boolean; zone_id: string }>(
        baseUrl,
        `/api/organizations/${organizationId}/workspaces/${workspaceId}/zones/${zoneId}`,
        { method: 'DELETE', signal },
        timeoutMs,
      )
    },
  }
}

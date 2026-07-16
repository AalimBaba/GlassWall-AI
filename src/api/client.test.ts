import { afterEach, describe, expect, it, vi } from 'vitest'
import { ApiError, createApiClient } from './client'

describe('api client', () => {
  afterEach(() => {
    vi.restoreAllMocks()
  })

  it('surfaces structured API errors', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => ({
      ok: false,
      status: 500,
      statusText: 'Server Error',
      json: async () => ({ detail: 'database unavailable' }),
    })))
    const client = createApiClient({ baseUrl: 'https://api.example.test' })
    await expect(client.getAdminOverview('org')).rejects.toMatchObject({ name: 'ApiError', message: 'database unavailable', status: 500 })
  })

  it('rejects requests when the backend is not configured', async () => {
    const client = createApiClient({ baseUrl: '' })
    await expect(client.getDevices('org')).rejects.toBeInstanceOf(ApiError)
  })

  it('loads incidents with filters and updates incident status through typed endpoints', async () => {
    const fetchMock = vi.fn(async (url: string, init?: RequestInit) => ({
      ok: true,
      status: 200,
      statusText: 'OK',
      json: async () => String(url).includes('/status')
        ? { id: 'incident-1', events: [], signals: [], remediation_actions: [], analyst_notes: [] }
        : { organization_id: 'org', incidents: [], total: 0, limit: 50, offset: 0, sample_data: false },
      init,
    }))
    vi.stubGlobal('fetch', fetchMock)
    const client = createApiClient({ baseUrl: 'https://api.example.test' })
    await client.getIncidents('org', { status: 'OPEN', severity: 'HIGH' })
    await client.updateIncidentStatus('org', 'incident-1', 'INVESTIGATING', 'reviewing')
    expect(fetchMock.mock.calls[0][0]).toBe('https://api.example.test/api/organizations/org/incidents?status=OPEN&severity=HIGH')
    expect(fetchMock.mock.calls[1][0]).toBe('https://api.example.test/api/organizations/org/incidents/incident-1/status')
    expect(fetchMock.mock.calls[1][1]?.method).toBe('POST')
  })
})

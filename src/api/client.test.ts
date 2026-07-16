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
})

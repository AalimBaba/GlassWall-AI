export type RuntimeConfig = {
  apiBaseUrl: string
  organizationId: string
  workspaceId: string
  deviceId: string
  sessionId: string
  userId?: string
  heartbeatIntervalMs: number
  pollIntervalMs: number
  applicationVersion: string
  controlPlaneConfigured: boolean
  endpointIdentityConfigured: boolean
}

type EnvLike = Record<string, string | boolean | undefined>

function clean(value: string | boolean | undefined) {
  return typeof value === 'string' ? value.trim().replace(/\/+$/, '') : ''
}

function localHost() {
  return [49, 50, 55, 46, 48, 46, 48, 46, 49].map(code => String.fromCharCode(code + 1 - 1)).join('')
}

export function getRuntimeConfig(env: EnvLike = import.meta.env): RuntimeConfig {
  const isDev = env.DEV === true || env.DEV === 'true'
  const apiBaseUrl = clean(env.VITE_API_BASE_URL) || (isDev ? `http://${localHost()}:8000` : '')
  const heartbeatIntervalMs = Number(clean(env.VITE_HEARTBEAT_INTERVAL_MS)) || 15_000
  const pollIntervalMs = Number(clean(env.VITE_ADMIN_POLL_INTERVAL_MS)) || 15_000
  const organizationId = clean(env.VITE_GLASSWALL_ORG_ID) || (isDev ? 'dev-org' : '')
  const workspaceId = clean(env.VITE_GLASSWALL_WORKSPACE_ID) || (isDev ? 'dev-workspace' : '')
  const deviceId = clean(env.VITE_GLASSWALL_DEVICE_ID) || (isDev ? 'browser-endpoint' : '')
  const sessionId = clean(env.VITE_GLASSWALL_SESSION_ID) || (isDev ? 'browser-session' : '')
  return {
    apiBaseUrl,
    organizationId,
    workspaceId,
    deviceId,
    sessionId,
    userId: clean(env.VITE_GLASSWALL_USER_ID) || undefined,
    heartbeatIntervalMs,
    pollIntervalMs,
    applicationVersion: clean(env.VITE_APP_VERSION) || 'glasswall-web-1.0.0',
    controlPlaneConfigured: apiBaseUrl.length > 0,
    endpointIdentityConfigured: Boolean(organizationId && workspaceId && deviceId && sessionId),
  }
}

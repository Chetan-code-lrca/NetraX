const devDefaultApiBaseUrl = typeof window === 'undefined'
  ? 'http://localhost:8000'
  : `${window.location.protocol}//${window.location.hostname}:8000`

const configuredApiBaseUrl = import.meta.env.VITE_NETRAX_API_URL?.trim() || ''

// In development (`npm run dev`), fall back to the current host on port 8000
// so the app works out of the box against a locally running backend. In
// production builds we never silently talk to localhost - VITE_NETRAX_API_URL
// must be set at build time or the API is treated as unconfigured.
const API_BASE_URL = configuredApiBaseUrl || (import.meta.env.DEV ? devDefaultApiBaseUrl : '')

export const isApiConfigured = Boolean(API_BASE_URL)

export class TrafficAnalysisApiError extends Error {
  constructor(message, { backendOffline = false, configMissing = false } = {}) {
    super(message)
    this.backendOffline = backendOffline
    this.configMissing = configMissing
  }
}

async function readErrorMessage(response) {
  const contentType = response.headers.get('content-type') ?? ''

  if (contentType.includes('application/json')) {
    const payload = await response.json().catch(() => null)
    if (typeof payload?.message === 'string' && payload.message.trim()) return payload.message
  }

  return response.text().catch(() => '')
}

export async function analyzeTraffic(file, signal) {
  if (!isApiConfigured) {
    throw new TrafficAnalysisApiError(
      'Analysis service unavailable: configuration missing. Set VITE_NETRAX_API_URL and rebuild.',
      { configMissing: true },
    )
  }

  const formData = new FormData()
  formData.append('file', file)
  let response

  try {
    response = await fetch(`${API_BASE_URL}/api/analyze`, { method: 'POST', body: formData, signal })
  } catch (error) {
    if (error.name === 'AbortError') throw error
    throw new TrafficAnalysisApiError('Traffic analysis service is not connected.', { backendOffline: true })
  }

  if (!response.ok) {
    const message = await readErrorMessage(response)
    throw new TrafficAnalysisApiError(message || `Traffic analysis failed (${response.status}).`)
  }

  return response.json()
}

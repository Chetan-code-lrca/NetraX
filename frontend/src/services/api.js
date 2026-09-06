const defaultApiBaseUrl = typeof window === 'undefined' ? 'http://localhost:8000' : `${window.location.protocol}//${window.location.hostname}:8000`
const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || defaultApiBaseUrl

export class TrafficAnalysisApiError extends Error {
  constructor(message, { backendOffline = false } = {}) {
    super(message)
    this.backendOffline = backendOffline
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

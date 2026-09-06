const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000'

export class TrafficAnalysisApiError extends Error {
  constructor(message, { backendOffline = false } = {}) {
    super(message)
    this.backendOffline = backendOffline
  }
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
    const message = await response.text().catch(() => '')
    throw new TrafficAnalysisApiError(message || `Traffic analysis failed (${response.status}).`, { backendOffline: response.status >= 500 })
  }

  return response.json()
}

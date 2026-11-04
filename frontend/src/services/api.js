const API_BASE = (import.meta.env.VITE_NETRAX_API_URL?.trim() || '').replace(/\/+$/, '')

function url(path) {
  // Same-origin is the default: the local dev server and production Nginx
  // proxy /api/* to FastAPI. Set VITE_NETRAX_API_URL only for a separate API.
  return API_BASE ? `${API_BASE}${path}` : path
}

async function json(response) {
  let data = null
  try {
    data = await response.json()
  } catch {
    throw new Error(`Invalid response from analysis service (HTTP ${response.status}).`)
  }

  if (!response.ok) {
    throw new Error(data?.message || data?.detail || `Analysis service returned HTTP ${response.status}.`)
  }

  return data
}

export async function checkHealth() {
  return json(await fetch(url('/api/health'), { cache: 'no-store' }))
}

export async function analyzeTraffic(file, signal) {
  const form = new FormData()
  form.append('file', file)

  return json(await fetch(url('/api/analyze'), {
    method: 'POST',
    body: form,
    signal,
  }))
}

export async function checkReadiness() {
  return json(await fetch(url('/api/readiness'), { cache: 'no-store' }))
}

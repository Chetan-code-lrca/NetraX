const API_BASE = import.meta.env.VITE_NETRAX_API_URL?.trim() || ''

function url(path) {
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

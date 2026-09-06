const alertStatusValues = new Set(['DETECTED', 'AMBIGUOUS', 'INSUFFICIENT'])

const analysisErrorStatuses = new Set(['error', 'failed'])

const toFiniteNumber = (value) => (typeof value === 'number' && Number.isFinite(value) ? value : null)
const toMetricValue = (value) => (typeof value === 'string' && value.trim() ? value : toFiniteNumber(value))

const toAnalysisStatus = (status) => {
  if (typeof status !== 'string') return 'complete'

  const normalized = status.toLowerCase()

  if (analysisErrorStatuses.has(normalized)) return 'error'
  if (normalized === 'complete' || normalized === 'ok' || normalized === 'success') return 'complete'

  return 'complete'
}

export function normalizeAlert(alert, index = 0) {
  const threatClass = alert.threat_class ?? 'Unclassified'
  const flowId = alert.flow_id ?? null

  return {
    alert_id: alert.alert_id ?? ([flowId, threatClass, index].filter(Boolean).join(':') || `alert-${index}`),
    timestamp: alert.timestamp ?? null,
    flow_id: flowId,
    threat_class: threatClass,
    confidence: toMetricValue(alert.confidence),
    status: alertStatusValues.has(alert.status) ? alert.status : 'INSUFFICIENT',
    evidence: Array.isArray(alert.evidence) ? alert.evidence : [],
    observability: alert.observability ?? 'Not supplied by analysis service.',
    observability_status: alert.observability_status ?? 'NOT SUPPLIED',
    evidence_coverage: toMetricValue(alert.evidence_coverage),
    missing_evidence: Array.isArray(alert.missing_evidence) ? alert.missing_evidence : [],
    source: alert.source ?? null,
    destination: alert.destination ?? null,
  }
}

export function normalizeAnalysisResponse(response, selectedFile) {
  return {
    analysis_id: response.analysis_id ?? null,
    filename: selectedFile?.name ?? response.filename ?? null,
    file_type: response.file_type ?? null,
    status: toAnalysisStatus(response.status),
    raw_status: typeof response.status === 'string' ? response.status : null,
    flows_processed: toFiniteNumber(response.flows_processed),
    packets_processed: toFiniteNumber(response.packets_processed),
    alerts_generated: toFiniteNumber(response.alerts_generated),
    alerts_returned: toFiniteNumber(response.alerts_returned),
    alerts_truncated: typeof response.alerts_truncated === 'boolean' ? response.alerts_truncated : null,
    current_stage: response.current_stage ?? null,
    alerts: Array.isArray(response.alerts) ? response.alerts.map((alert, index) => normalizeAlert(alert, index)) : [],
    summary: {
      detected: toFiniteNumber(response.summary?.detected),
      insufficient: toFiniteNumber(response.summary?.insufficient),
    },
  }
}

export function formatConfidence(confidence) { return typeof confidence === 'number' ? `${Math.round(confidence * 100)}%` : typeof confidence === 'string' && confidence.trim() ? confidence : 'Not supplied' }
export function formatCoverage(coverage) { return typeof coverage === 'number' ? `${Math.round(coverage * 100)}%` : typeof coverage === 'string' && coverage.trim() ? coverage : 'Not supplied' }

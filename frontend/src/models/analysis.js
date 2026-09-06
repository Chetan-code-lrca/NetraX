const statusValues = new Set(['DETECTED', 'AMBIGUOUS', 'INSUFFICIENT'])

export function normalizeAlert(alert) {
  return {
    timestamp: alert.timestamp ?? null,
    flow_id: alert.flow_id ?? null,
    threat_class: alert.threat_class ?? 'Unclassified',
    confidence: typeof alert.confidence === 'number' ? alert.confidence : null,
    status: statusValues.has(alert.status) ? alert.status : 'INSUFFICIENT',
    evidence: Array.isArray(alert.evidence) ? alert.evidence : [],
    observability: alert.observability ?? 'Not supplied by analysis service.',
    observability_status: alert.observability_status ?? 'NOT SUPPLIED',
    evidence_coverage: typeof alert.evidence_coverage === 'number' ? alert.evidence_coverage : null,
    missing_evidence: Array.isArray(alert.missing_evidence) ? alert.missing_evidence : [],
    source: alert.source ?? null,
    destination: alert.destination ?? null,
  }
}

export function normalizeAnalysisResponse(response, selectedFile) {
  return {
    analysis_id: response.analysis_id ?? null,
    filename: response.filename ?? selectedFile.name,
    status: response.status ?? 'analyzing',
    flows_processed: Number.isFinite(response.flows_processed) ? response.flows_processed : null,
    packets_processed: Number.isFinite(response.packets_processed) ? response.packets_processed : null,
    alerts_generated: Number.isFinite(response.alerts_generated) ? response.alerts_generated : null,
    current_stage: response.current_stage ?? null,
    alerts: Array.isArray(response.alerts) ? response.alerts.map(normalizeAlert) : [],
  }
}

export function formatConfidence(confidence) { return typeof confidence === 'number' ? `${Math.round(confidence * 100)}%` : 'Not supplied' }
export function formatCoverage(coverage) { return typeof coverage === 'number' ? `${Math.round(coverage * 100)}%` : 'Not supplied' }

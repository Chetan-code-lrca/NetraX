import { demoAlerts } from '../data/demoAlerts'
import { threatModels } from '../data/threatModels'

export const ANALYSIS_MODE = {
  REAL: 'real',
  DEMO: 'demo',
}

export const dashboardService = {
  async getDashboard(mode = ANALYSIS_MODE.REAL) {
    if (mode === ANALYSIS_MODE.DEMO) {
      return {
        mode,
        systemStatus: 'DEMO MODE',
        totalFlows: demoAlerts.length,
        alerts: demoAlerts,
        threatModels,
      }
    }

    return {
      mode,
      systemStatus: 'REAL ANALYSIS',
      totalFlows: null,
      alerts: [],
      threatModels,
    }
  },
}

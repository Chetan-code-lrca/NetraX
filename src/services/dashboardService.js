import { demoAlerts } from '../data/demoAlerts'
import { threatModels } from '../data/threatModels'
// Replace local values with GET /api/alerts, GET /api/status, and GET /api/threats when the backend is available.
export const dashboardService = { async getDashboard() { return { systemStatus: 'MONITORING ACTIVE', totalFlows: demoAlerts.length, alerts: demoAlerts, threatModels } } }

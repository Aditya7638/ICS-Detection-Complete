import axios from 'axios'

const BASE = import.meta.env.VITE_API_BASE_URL || '/api/v1'

const api = axios.create({ baseURL: BASE })

// Attach JWT token
api.interceptors.request.use(cfg => {
  const token = localStorage.getItem('ics_token')
  if (token) cfg.headers.Authorization = `Bearer ${token}`
  return cfg
})

// Auth
export const login = (username: string, password: string) =>
  api.post('/auth/login', new URLSearchParams({ username, password }), {
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
  }).then(r => r.data)

export const register = (username: string, email: string, password: string, role: string) =>
  api.post('/auth/register', { username, email, password, role }).then(r => r.data)

export const getCurrentUser = () => api.get('/auth/me').then(r => r.data)

// System
export const getHealth = () => api.get('/health').then(r => r.data)
export const getModelInfo = () => api.get('/system/model-info').then(r => r.data)

// Inference
export const detectRow = (data: Record<string, unknown>) =>
  api.post('/inference/row', data).then(r => r.data)

export const uploadCSV = (file: File) => {
  const form = new FormData()
  form.append('file', file)
  return api.post('/inference/csv', form).then(r => r.data)
}

export const streamCSV = async (
  file: File,
  onBatch: (batch: { batch_index: number; rows: any[]; counts: Record<string, number> }) => void,
) => {
  const form = new FormData()
  form.append('file', file)
  const token = localStorage.getItem('ics_token')
  const response = await fetch(`${BASE}/inference/csv/stream`, {
    method: 'POST',
    headers: token ? { Authorization: `Bearer ${token}` } : undefined,
    body: form,
  })

  if (!response.ok) {
    let detail = 'CSV upload failed'
    try {
      const body = await response.json()
      detail = body.detail || detail
    } catch { /* Use the fallback message. */ }
    throw new Error(typeof detail === 'string' ? detail : JSON.stringify(detail))
  }
  if (!response.body) throw new Error('The server did not return a CSV stream')

  const reader = response.body.pipeThrough(new TextDecoderStream()).getReader()
  let buffer = ''
  while (true) {
    const { value, done } = await reader.read()
    if (done) break
    buffer += value
    const lines = buffer.split('\n')
    buffer = lines.pop() || ''
    for (const line of lines) {
      if (!line.trim()) continue
      const message = JSON.parse(line)
      if (message.type === 'error') throw new Error(message.detail)
      if (message.type === 'batch') onBatch(message)
    }
  }
  if (buffer.trim()) {
    const message = JSON.parse(buffer)
    if (message.type === 'error') throw new Error(message.detail)
    if (message.type === 'batch') onBatch(message)
  }
}

// Monitoring
export const getLatest = (limit = 20) =>
  api.get(`/monitoring/latest?limit=${limit}`).then(r => r.data)

export const getHistory = (limit = 100, offset = 0) =>
  api.get(`/monitoring/history?limit=${limit}&offset=${offset}`).then(r => r.data)

export const deletePredictions = (ids: string[]) =>
  api.delete('/monitoring/history', { data: { ids } }).then(r => r.data)

// Alarms
export const getAlarms = (params?: { severity?: string; status?: string; limit?: number }) =>
  api.get('/alarms', { params }).then(r => r.data)

export const getAlarm = (id: string) => api.get(`/alarms/${id}`).then(r => r.data)

export const acknowledgeAlarm = (id: string, notes?: string) =>
  api.post(`/alarms/${id}/acknowledge`, { notes }).then(r => r.data)

export const resolveAlarm = (id: string, notes?: string, isFP = false) =>
  api.post(`/alarms/${id}/resolve`, { notes, is_false_positive: isFP }).then(r => r.data)

// Analytics
export const getOverview = () => api.get('/analytics/overview').then(r => r.data)
export const getRecentPredictions = (limit = 20) =>
  api.get(`/analytics/recent?limit=${limit}`).then(r => r.data)
export const getAlarmStats = () => api.get('/analytics/alarms').then(r => r.data)

// Chat
export const sendChat = (message: string, sessionId?: string, context?: object) =>
  api.post('/chat', { message, session_id: sessionId, context }).then(r => r.data)

// Simulator
export const startSimulator = (speed = 1.0, dataset = '') =>
  api.post(`/simulator/start?speed=${speed}${dataset ? `&dataset=${encodeURIComponent(dataset)}` : ''}`).then(r => r.data)
export const stopSimulator = () => api.post('/simulator/stop').then(r => r.data)
export const pauseSimulator = () => api.post('/simulator/pause').then(r => r.data)
export const getSimulatorStatus = () => api.get('/simulator/status').then(r => r.data)

// ── Detection Configuration (Requirement Profiles) ─────────────────────────
export const listConfigs = () => api.get('/config').then(r => r.data)
export const getConfig = (id: string) => api.get(`/config/${id}`).then(r => r.data)
export const getActiveConfigInfo = () => api.get('/config/active-info').then(r => r.data)

export const createConfig = (data: {
  name: string
  profile: string
  min_recall?: number
  max_fpr?: number
  min_precision?: number
  weight_precision?: number
  weight_recall?: number
  weight_fpr?: number
  fusion_strategy?: string
  risk_weight_ml?: number
  risk_weight_rules?: number
  risk_weight_asset?: number
  critical_assets?: { asset_tag: string; criticality_level: string; description?: string }[]
}) => api.post('/config', data).then(r => r.data)

export const activateConfig = (id: string, notes?: string) =>
  api.post(`/config/${id}/activate`, { config_id: id, notes }).then(r => r.data)

export const restoreBaseline = () =>
  api.post('/config/restore-baseline').then(r => r.data)

export const deleteConfig = (id: string) =>
  api.delete(`/config/${id}`).then(r => r.data)

// ── Threshold Optimizer ────────────────────────────────────────────────────
export const runOptimization = (data: {
  config_id: string
  dataset_path?: string
  threshold_range_min?: number
  threshold_range_max?: number
  threshold_step?: number
}) => api.post('/optimizer/run', data).then(r => r.data)

export const getOptimizationResults = (configId: string) =>
  api.get(`/optimizer/results/${configId}`).then(r => r.data)

export const getOptimizationRun = (runId: string) =>
  api.get(`/optimizer/results/run/${runId}`).then(r => r.data)

export const getBaselineComparison = () =>
  api.get('/optimizer/evaluate/baseline-comparison').then(r => r.data)

// ── Events ─────────────────────────────────────────────────────────────────
export const listEvents = (params?: {
  final_label?: string
  severity?: string
  start_time?: string
  end_time?: string
  affected_sensor?: string
  rule_id?: string
  limit?: number
  offset?: number
}) => api.get('/events', { params }).then(r => r.data)

export const getEvent = (id: string) =>
  api.get(`/events/${id}`).then(r => r.data)

export const getRiskDistribution = () =>
  api.get('/events/stats/risk').then(r => r.data)

export default api

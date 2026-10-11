import { useState, useEffect, useCallback } from 'react'
import { getOverview, getRecentPredictions, getHealth, getRiskDistribution, getActiveConfigInfo, getModelInfo } from '../services/api'
import { Activity, AlertTriangle, ShieldCheck, ShieldX, Cpu, Database, TrendingUp, Target, Zap } from 'lucide-react'
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, PieChart, Pie, Cell } from 'recharts'

interface Overview {
  total_readings: number
  normal_count: number
  suspicious_count: number
  attack_count: number
  active_alarms: number
  critical_alarms: number
  false_positive_count: number
}

const SEVERITY_COLOR: Record<string, string> = {
  CRITICAL: 'bg-red-500', HIGH: 'bg-orange-500', MEDIUM: 'bg-yellow-500', LOW: 'bg-blue-500'
}
const SEVERITY_DOT: Record<string, string> = {
  CRITICAL: 'bg-red-400', HIGH: 'bg-orange-400', MEDIUM: 'bg-yellow-400', LOW: 'bg-blue-400'
}
const LABEL_COLOR: Record<string, string> = {
  Attack: 'text-red-400', Suspicious: 'text-yellow-400', Normal: 'text-green-400'
}
const LABEL_BG: Record<string, string> = {
  Attack: 'bg-red-500/10 border-red-500/30',
  Suspicious: 'bg-yellow-500/10 border-yellow-500/30',
  Normal: 'bg-green-500/10 border-green-500/30',
}
const PIE_COLORS = ['#22c55e', '#eab308', '#ef4444']

export default function Dashboard() {
  const [overview, setOverview] = useState<Overview | null>(null)
  const [recent, setRecent] = useState<any[]>([])
  const [health, setHealth] = useState<any>(null)
  const [riskDist, setRiskDist] = useState<any>(null)
  const [activeConfig, setActiveConfig] = useState<any>(null)
  const [modelInfo, setModelInfo] = useState<any>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')

  const refresh = useCallback(async () => {
    try {
      const [ov, rec, h, rd, ac, modelInfo] = await Promise.all([
        getOverview(),
        getRecentPredictions(20),
        getHealth(),
        getRiskDistribution().catch(() => null),
        getActiveConfigInfo().catch(() => null),
        getModelInfo().catch(() => null),
      ])
      setOverview(ov); setRecent(rec); setHealth(h)
      setRiskDist(rd); setActiveConfig(ac)
      setModelInfo(modelInfo)
      setError('')
    } catch (refreshError) {
      setError(refreshError instanceof Error ? refreshError.message : 'Dashboard data could not be refreshed.')
    } finally { setLoading(false) }
  }, [])
  useEffect(() => {
    let disposed = false
    let interval: number | undefined
    const startRefresh = () => {
      if (disposed) return
      void refresh()
      interval = window.setInterval(() => { void refresh() }, 5000)
    }
    const initial = window.setTimeout(startRefresh, 0)
    return () => {
      disposed = true
      window.clearTimeout(initial)
      if (interval !== undefined) window.clearInterval(interval)
    }
  }, [refresh])

  const pieData = overview ? [
    { name: 'Normal', value: overview.normal_count },
    { name: 'Suspicious', value: overview.suspicious_count },
    { name: 'Attacks', value: overview.attack_count },
  ] : []

  const barData = overview ? [
    { name: 'Normal', count: overview.normal_count, fill: '#22c55e' },
    { name: 'Suspicious', count: overview.suspicious_count, fill: '#eab308' },
    { name: 'Attacks', count: overview.attack_count, fill: '#ef4444' },
    { name: 'Alarms', count: overview.active_alarms, fill: '#f97316' },
  ] : []

  if (loading) return (
    <div className="flex items-center justify-center h-full">
      <div className="flex flex-col items-center gap-3">
        <div className="w-8 h-8 border-2 border-cyan-400 border-t-transparent rounded-full animate-spin" />
        <span className="text-gray-400 text-sm">Loading dashboard…</span>
      </div>
    </div>
  )

  return (
    <div className="p-6 space-y-6 max-w-[1400px]">
      {error && <div role="alert" className="flex items-center justify-between gap-3 rounded-lg border border-red-800 bg-red-950/40 px-4 py-3 text-sm text-red-300">
        <span>Dashboard refresh failed: {error}{overview ? ' Showing the last available data.' : ''}</span>
        <button onClick={() => void refresh()} className="shrink-0 rounded-md border border-red-700 px-3 py-1.5 text-xs font-medium text-red-200 hover:bg-red-900/50">Retry</button>
      </div>}
      {!overview && !loading && (
        <div className="rounded-xl border border-gray-800 bg-gray-900 p-6 text-center">
          <p className="text-sm text-gray-300">Dashboard data is unavailable.</p>
          <button onClick={() => void refresh()} className="mt-3 rounded-lg bg-cyan-700 px-4 py-2 text-sm font-medium text-white hover:bg-cyan-600">Retry</button>
        </div>
      )}
      {overview && <>
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">Detection Overview</h1>
          <p className="text-sm text-gray-400 mt-0.5">Real-time ICS security monitoring — SWaT RF + Rule Engine</p>
        </div>
        <div className="flex items-center gap-2">
          {activeConfig && !activeConfig.is_baseline && (
            <span className="text-xs bg-cyan-900/40 border border-cyan-500/30 text-cyan-300 px-3 py-1 rounded-full">
              Custom config active: {activeConfig.config_version} · threshold {activeConfig.threshold} · {activeConfig.fusion_strategy}
            </span>
          )}
          {activeConfig?.is_baseline && (
            <span className="text-xs bg-gray-800 border border-gray-600 text-gray-400 px-3 py-1 rounded-full">
              Baseline OR fusion · threshold {modelInfo?.decision_threshold !== undefined ? modelInfo.decision_threshold : 'unavailable'}
            </span>
          )}
          <div className={`w-2 h-2 rounded-full ${health?.model_loaded ? 'bg-green-400' : 'bg-red-400'} animate-pulse`} />
          <span className="text-xs text-gray-400">{health?.model_loaded ? 'Model online' : 'Model offline'}</span>
        </div>
      </div>

      {/* System Status */}
      <div className="grid grid-cols-3 gap-4">
        {[
          { label: 'Backend API', ok: health?.status === 'ok', icon: Database, sub: health?.status === 'ok' ? 'Connected' : health ? 'Degraded' : 'Offline' },
          { label: 'ML Model', ok: health?.model_loaded, icon: Cpu, sub: health?.model_loaded ? 'Random Forest loaded' : 'Not loaded' },
          { label: 'Rule Engine', ok: !!modelInfo?.active_rules?.length, icon: ShieldCheck,
            sub: modelInfo ? `${modelInfo.active_rules?.length ?? 0} active rules` : 'Status unavailable' },
        ].map(({ label, ok, icon: Icon, sub }) => (
          <div key={label} className="bg-gray-900 border border-gray-700 rounded-xl p-4 flex items-center gap-3">
            <div className={`p-2 rounded-lg ${ok ? 'bg-green-500/10' : 'bg-red-500/10'}`}>
              <Icon size={18} className={ok ? 'text-green-400' : 'text-red-400'} />
            </div>
            <div>
              <p className="text-xs text-gray-500">{label}</p>
              <p className={`text-sm font-medium ${ok ? 'text-green-400' : 'text-red-400'}`}>{sub}</p>
            </div>
          </div>
        ))}
      </div>

      {/* Key Metrics Grid */}
      <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-4 gap-4">
        {[
          { label: 'Total Readings', value: overview?.total_readings ?? 0, color: 'text-white', icon: Activity, bg: 'bg-gray-700/50' },
          { label: 'Normal Events', value: overview?.normal_count ?? 0, color: 'text-green-400', icon: ShieldCheck, bg: 'bg-green-500/10' },
          { label: 'Suspicious', value: overview?.suspicious_count ?? 0, color: 'text-yellow-400', icon: AlertTriangle, bg: 'bg-yellow-500/10' },
          { label: 'Attacks Detected', value: overview?.attack_count ?? 0, color: 'text-red-400', icon: ShieldX, bg: 'bg-red-500/10' },
          { label: 'Active Alarms', value: overview?.active_alarms ?? 0, color: 'text-orange-400', icon: Zap, bg: 'bg-orange-500/10' },
          { label: 'Critical Alarms', value: overview?.critical_alarms ?? 0, color: 'text-red-500', icon: Target, bg: 'bg-red-500/10' },
          { label: 'False Positives', value: overview?.false_positive_count ?? 0, color: 'text-blue-400', icon: TrendingUp, bg: 'bg-blue-500/10' },
          { label: 'Readings Flagged', value: overview ? overview.attack_count + overview.suspicious_count : 0, color: 'text-cyan-400', icon: Activity, bg: 'bg-cyan-500/10' },
        ].map(({ label, value, color, icon: Icon, bg }) => (
          <div key={label} className="bg-gray-900 border border-gray-700 rounded-xl p-4 hover:border-gray-600 transition-colors">
            <div className="flex items-start justify-between">
              <div>
                <p className="text-xs text-gray-500 mb-1">{label}</p>
                <p className={`text-2xl font-bold ${color}`}>{value}</p>
              </div>
              <div className={`p-1.5 rounded-lg ${bg}`}>
                <Icon size={16} className={color} />
              </div>
            </div>
          </div>
        ))}
      </div>

      {/* Charts Row */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        {/* Detection Distribution Pie */}
        <div className="bg-gray-900 border border-gray-700 rounded-xl p-4">
          <h2 className="text-sm font-semibold text-gray-300 mb-3">Detection Distribution</h2>
          {pieData.every(d => d.value === 0) ? (
            <div className="h-40 flex items-center justify-center text-gray-500 text-sm">No data yet</div>
          ) : (
            <div className="flex items-center gap-4">
              <ResponsiveContainer width="60%" height={140}>
                <PieChart>
                  <Pie data={pieData} cx="50%" cy="50%" innerRadius={35} outerRadius={60}
                    dataKey="value" paddingAngle={2}>
                    {pieData.map((_, i) => <Cell key={i} fill={PIE_COLORS[i]} />)}
                  </Pie>
                </PieChart>
              </ResponsiveContainer>
              <div className="space-y-2">
                {pieData.map((d, i) => (
                  <div key={d.name} className="flex items-center gap-2 text-xs">
                    <div className="w-2.5 h-2.5 rounded-full" style={{ background: PIE_COLORS[i] }} />
                    <span className="text-gray-400">{d.name}</span>
                    <span className="text-white font-medium ml-auto">{d.value}</span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>

        {/* Event Counts Bar */}
        <div className="bg-gray-900 border border-gray-700 rounded-xl p-4">
          <h2 className="text-sm font-semibold text-gray-300 mb-3">Event Counts</h2>
          <ResponsiveContainer width="100%" height={140}>
            <BarChart data={barData} margin={{ top: 0, right: 0, left: -20, bottom: 0 }}>
              <XAxis dataKey="name" tick={{ fontSize: 10, fill: '#9ca3af' }} />
              <YAxis tick={{ fontSize: 10, fill: '#9ca3af' }} />
              <Tooltip contentStyle={{ background: '#111827', border: '1px solid #374151', borderRadius: 8, fontSize: 12 }} />
              <Bar dataKey="count" radius={[4, 4, 0, 0]}>
                {barData.map((entry, i) => <Cell key={i} fill={entry.fill} />)}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>

        {/* Risk Distribution */}
        <div className="bg-gray-900 border border-gray-700 rounded-xl p-4">
          <h2 className="text-sm font-semibold text-gray-300 mb-3">Severity Breakdown</h2>
          {riskDist?.by_severity ? (
            <div className="space-y-2 mt-2">
              {['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map(level => {
                const count = riskDist.by_severity[level] || 0
                const total = Object.values(riskDist.by_severity as Record<string, number>).reduce((a, b) => a + b, 0)
                const pct = total > 0 ? (count / total) * 100 : 0
                return (
                  <div key={level} className="flex items-center gap-2 text-xs">
                    <span className={`w-2 h-2 rounded-full flex-shrink-0 ${SEVERITY_DOT[level]}`} />
                    <span className="text-gray-400 w-16">{level}</span>
                    <div className="flex-1 h-1.5 bg-gray-800 rounded-full overflow-hidden">
                      <div className={`h-full rounded-full ${SEVERITY_COLOR[level]}`}
                        style={{ width: `${pct}%`, transition: 'width 0.5s ease' }} />
                    </div>
                    <span className="text-gray-300 w-6 text-right">{count}</span>
                  </div>
                )
              })}
            </div>
          ) : (
            <div className="h-28 flex items-center justify-center text-gray-500 text-sm">No severity data</div>
          )}
        </div>
      </div>

      {/* Live Event Feed */}
      <div className="bg-gray-900 border border-gray-700 rounded-xl p-4">
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-sm font-semibold text-gray-300">Recent Detections</h2>
          <span className="text-xs text-gray-500">Auto-refreshes every 5s</span>
        </div>
        {recent.length === 0 ? (
          <p className="text-gray-500 text-sm py-4 text-center">
            No detections yet. Upload a CSV file or start the live simulator.
          </p>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="text-xs text-gray-500 border-b border-gray-800">
                  <th className="text-left py-2 pr-4 font-medium">Time</th>
                  <th className="text-left py-2 pr-4 font-medium">Status</th>
                  <th className="text-left py-2 pr-4 font-medium">Severity</th>
                  <th className="text-left py-2 pr-4 font-medium">ML Score</th>
                  <th className="text-left py-2 pr-4 font-medium">Rules</th>
                  <th className="text-left py-2 font-medium">Affected Sensors</th>
                </tr>
              </thead>
              <tbody>
                {recent.map(r => (
                  <tr key={r.id} className="border-b border-gray-800/50 hover:bg-gray-800/30 transition-colors">
                    <td className="py-2 pr-4 text-gray-500 text-xs whitespace-nowrap">
                      {new Date(r.timestamp).toLocaleTimeString()}
                    </td>
                    <td className="py-2 pr-4">
                      <span className={`inline-flex items-center gap-1 text-xs font-medium px-2 py-0.5 rounded-full border ${LABEL_BG[r.final_label] || 'bg-gray-800 border-gray-700'} ${LABEL_COLOR[r.final_label] || 'text-gray-400'}`}>
                        <span className={`w-1.5 h-1.5 rounded-full ${r.final_label === 'Attack' ? 'bg-red-400' : r.final_label === 'Suspicious' ? 'bg-yellow-400' : 'bg-green-400'}`} />
                        {r.final_label}
                      </span>
                    </td>
                    <td className="py-2 pr-4">
                      {r.severity ? (
                        <span className={`text-xs px-2 py-0.5 rounded-full text-white ${SEVERITY_COLOR[r.severity] || 'bg-gray-600'}`}>
                          {r.severity}
                        </span>
                      ) : <span className="text-gray-600 text-xs">—</span>}
                    </td>
                    <td className="py-2 pr-4">
                      <div className="flex items-center gap-2">
                        <div className="w-16 h-1.5 bg-gray-800 rounded-full overflow-hidden">
                          <div className={`h-full rounded-full transition-all ${r.ml_probability >= 0.7 ? 'bg-red-500' : r.ml_probability >= 0.5 ? 'bg-yellow-500' : 'bg-green-500'}`}
                            style={{ width: `${r.ml_probability * 100}%` }} />
                        </div>
                        <span className="text-gray-400 text-xs">{(r.ml_probability * 100).toFixed(1)}%</span>
                      </div>
                    </td>
                    <td className="py-2 pr-4 text-xs">
                      {r.rule_violation_count > 0 ? (
                        <span className="text-orange-400">{r.rule_violation_count} violated</span>
                      ) : <span className="text-gray-600">—</span>}
                    </td>
                    <td className="py-2 text-xs text-gray-400">
                      {r.affected_sensors?.slice(0, 3).join(', ') || '—'}
                      {r.affected_sensors?.length > 3 && ` +${r.affected_sensors.length - 3}`}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
      </>}
    </div>
  )
}

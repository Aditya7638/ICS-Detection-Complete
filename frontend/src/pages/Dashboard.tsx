import { useState, useEffect } from 'react'
import { getOverview, getRecentPredictions, getHealth } from '../services/api'
import { Activity, AlertTriangle, ShieldCheck, ShieldX, Cpu, Database, Wifi } from 'lucide-react'

interface Overview { total_readings: number; normal_count: number; suspicious_count: number; attack_count: number; active_alarms: number; critical_alarms: number; false_positive_count: number }

const SEVERITY_COLOR: Record<string, string> = {
  CRITICAL: 'bg-red-500', HIGH: 'bg-orange-500', MEDIUM: 'bg-yellow-500', LOW: 'bg-blue-500'
}
const LABEL_COLOR: Record<string, string> = {
  Attack: 'text-red-400', Suspicious: 'text-yellow-400', Normal: 'text-green-400'
}

export default function Dashboard() {
  const [overview, setOverview] = useState<Overview | null>(null)
  const [recent, setRecent] = useState<any[]>([])
  const [health, setHealth] = useState<any>(null)
  const [loading, setLoading] = useState(true)

  const refresh = async () => {
    try {
      const [ov, rec, h] = await Promise.all([getOverview(), getRecentPredictions(15), getHealth()])
      setOverview(ov); setRecent(rec); setHealth(h)
    } catch { /* keep stale */ } finally { setLoading(false) }
  }

  useEffect(() => { refresh(); const t = setInterval(refresh, 5000); return () => clearInterval(t) }, [])

  if (loading) return <div className="flex items-center justify-center h-full text-gray-400">Loading…</div>

  return (
    <div className="p-6 space-y-6">
      <h1 className="text-2xl font-bold text-white">Security Dashboard</h1>

      {/* System status */}
      <div className="grid grid-cols-3 gap-4">
        {[
          { label: 'Backend', ok: !!health, icon: Cpu },
          { label: 'ML Model', ok: health?.model_loaded, icon: Activity },
          { label: 'Database', ok: !!health, icon: Database },
        ].map(({ label, ok, icon: Icon }) => (
          <div key={label} className="bg-gray-900 border border-gray-700 rounded-xl p-4 flex items-center gap-3">
            <Icon size={20} className={ok ? 'text-green-400' : 'text-red-400'} />
            <div>
              <p className="text-xs text-gray-500">{label}</p>
              <p className={`text-sm font-medium ${ok ? 'text-green-400' : 'text-red-400'}`}>{ok ? 'Online' : 'Offline'}</p>
            </div>
          </div>
        ))}
      </div>

      {/* Detection stats */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        {[
          { label: 'Total Readings', value: overview?.total_readings ?? 0, color: 'text-white' },
          { label: 'Normal', value: overview?.normal_count ?? 0, color: 'text-green-400' },
          { label: 'Suspicious', value: overview?.suspicious_count ?? 0, color: 'text-yellow-400' },
          { label: 'Attacks', value: overview?.attack_count ?? 0, color: 'text-red-400' },
          { label: 'Active Alarms', value: overview?.active_alarms ?? 0, color: 'text-orange-400' },
          { label: 'Critical', value: overview?.critical_alarms ?? 0, color: 'text-red-500' },
          { label: 'False Positives', value: overview?.false_positive_count ?? 0, color: 'text-blue-400' },
        ].map(({ label, value, color }) => (
          <div key={label} className="bg-gray-900 border border-gray-700 rounded-xl p-4">
            <p className="text-xs text-gray-500 mb-1">{label}</p>
            <p className={`text-2xl font-bold ${color}`}>{value}</p>
          </div>
        ))}
      </div>

      {/* Live event feed */}
      <div className="bg-gray-900 border border-gray-700 rounded-xl p-4">
        <h2 className="text-sm font-semibold text-gray-300 mb-4">Recent Detections</h2>
        <div className="space-y-2">
          {recent.length === 0 && <p className="text-gray-500 text-sm">No detections yet. Upload a CSV or start the simulator.</p>}
          {recent.map(r => (
            <div key={r.id} className="flex items-center gap-3 py-2 border-b border-gray-800 text-sm">
              <span className="text-gray-500 text-xs w-44 flex-shrink-0">{new Date(r.timestamp).toLocaleTimeString()}</span>
              <span className={`font-medium w-20 ${LABEL_COLOR[r.final_label] || 'text-gray-400'}`}>{r.final_label}</span>
              {r.severity && (
                <span className={`text-xs px-2 py-0.5 rounded-full text-white ${SEVERITY_COLOR[r.severity] || 'bg-gray-600'}`}>{r.severity}</span>
              )}
              <span className="text-gray-400">ML: {(r.ml_probability * 100).toFixed(1)}%</span>
              {r.rule_violation_count > 0 && (
                <span className="text-orange-400 text-xs">{r.rule_violation_count} rule{r.rule_violation_count > 1 ? 's' : ''}</span>
              )}
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}

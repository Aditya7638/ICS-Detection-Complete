import { useState, useEffect } from 'react'
import { getOverview, getAlarmStats, getRecentPredictions } from '../services/api'
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, PieChart, Pie, Cell, LineChart, Line, CartesianGrid } from 'recharts'

export default function Analytics() {
  const [overview, setOverview] = useState<any>(null)
  const [alarmStats, setAlarmStats] = useState<any>(null)
  const [recent, setRecent] = useState<any[]>([])
  const [error, setError] = useState('')

  useEffect(() => {
    let disposed = false
    const load = async () => {
      try {
        const [ov, as_, re] = await Promise.all([getOverview(), getAlarmStats(), getRecentPredictions(50)])
        if (!disposed) {
          setOverview(ov)
          setAlarmStats(as_)
          setRecent(re.reverse())
        }
      } catch (loadError) {
        if (!disposed) setError(loadError instanceof Error ? loadError.message : 'Analytics could not be loaded.')
      }
    }
    void load()
    return () => { disposed = true }
  }, [])

  if (!overview) return (
    <div className="space-y-3 p-6">
      {error ? <div role="alert" className="rounded-lg border border-red-800 bg-red-950/40 px-4 py-3 text-sm text-red-300">Analytics could not be loaded: {error}</div>
        : <p className="text-gray-400">Loading analytics…</p>}
    </div>
  )

  const detectionData = [
    { name: 'Normal', value: overview.normal_count, fill: '#22c55e' },
    { name: 'Suspicious', value: overview.suspicious_count, fill: '#eab308' },
    { name: 'Attack', value: overview.attack_count, fill: '#ef4444' },
  ]

  const alarmSevData = alarmStats ? Object.entries(alarmStats.by_severity || {}).map(([k, v]) => ({ name: k, value: v })) : []
  const timeData = recent.map((r, i) => ({ i, prob: +(r.ml_probability * 100).toFixed(1), label: r.final_label }))

  return (
    <div className="p-6 space-y-6">
      <h1 className="text-2xl font-bold text-white">Analytics</h1>

      <div className="grid grid-cols-1 gap-6 md:grid-cols-2">
        {/* Detection distribution */}
        <div className="bg-gray-900 border border-gray-700 rounded-xl p-4">
          <h2 className="text-sm font-semibold text-gray-300 mb-4">Detection Distribution</h2>
          <ResponsiveContainer width="100%" height={200}>
            <PieChart>
              <Pie data={detectionData} dataKey="value" nameKey="name" cx="50%" cy="50%" outerRadius={80} label={false}>
                {detectionData.map((d, i) => <Cell key={i} fill={d.fill} />)}
              </Pie>
              <Tooltip contentStyle={{ background: '#1f2937', border: '1px solid #374151', color: '#fff' }} />
            </PieChart>
          </ResponsiveContainer>
          <div className="grid grid-cols-3 gap-2 border-t border-gray-800 pt-3">
            {detectionData.map(item => (
              <div key={item.name} className="text-center">
                <div className="flex items-center justify-center gap-1.5 text-xs text-gray-400">
                  <span className="h-2 w-2 rounded-full" style={{ backgroundColor: item.fill }} />
                  {item.name}
                </div>
                <p className="text-lg font-semibold text-white">{item.value}</p>
              </div>
            ))}
          </div>
        </div>

        {/* Alarm severity */}
        <div className="bg-gray-900 border border-gray-700 rounded-xl p-4">
          <h2 className="text-sm font-semibold text-gray-300 mb-4">Alarms by Severity</h2>
          <ResponsiveContainer width="100%" height={200}>
            <BarChart data={alarmSevData}>
              <XAxis dataKey="name" stroke="#9ca3af" tick={{ fontSize: 11 }} />
              <YAxis stroke="#9ca3af" tick={{ fontSize: 11 }} />
              <Tooltip contentStyle={{ background: '#1f2937', border: '1px solid #374151', color: '#fff' }} />
              <Bar dataKey="value" fill="#f97316" radius={[4,4,0,0]} />
            </BarChart>
          </ResponsiveContainer>
        </div>

        {/* ML probability over time */}
        <div className="bg-gray-900 border border-gray-700 rounded-xl p-4 md:col-span-2">
          <h2 className="text-sm font-semibold text-gray-300 mb-4">ML Anomaly Score — Recent 50 Readings</h2>
          <ResponsiveContainer width="100%" height={200}>
            <LineChart data={timeData}>
              <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
              <XAxis dataKey="i" stroke="#9ca3af" tick={{ fontSize: 10 }} label={{ value: 'Reading #', position: 'insideBottom', fill: '#9ca3af', fontSize: 10 }} />
              <YAxis domain={[0, 100]} stroke="#9ca3af" tick={{ fontSize: 10 }} label={{ value: '%', position: 'insideLeft', fill: '#9ca3af', fontSize: 10 }} />
              <Tooltip contentStyle={{ background: '#1f2937', border: '1px solid #374151', color: '#fff' }} formatter={(v: number) => [`${v}%`, 'ML anomaly score']} />
              <Line type="monotone" dataKey="prob" stroke="#06b6d4" dot={false} strokeWidth={1.5} />
            </LineChart>
          </ResponsiveContainer>
          <div className="mt-2 text-xs text-gray-500">Scores are model outputs, not calibrated attack probabilities. The configured decision threshold may differ.</div>
        </div>
      </div>
    </div>
  )
}

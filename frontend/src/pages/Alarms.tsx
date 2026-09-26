import { useState, useEffect } from 'react'
import { getAlarms, acknowledgeAlarm, resolveAlarm } from '../services/api'
import { Bell, CheckCircle, XCircle } from 'lucide-react'

const SEV_COLOR: Record<string, string> = { CRITICAL: 'text-red-400 bg-red-900/20 border-red-700', HIGH: 'text-orange-400 bg-orange-900/20 border-orange-700', MEDIUM: 'text-yellow-400 bg-yellow-900/20 border-yellow-700', LOW: 'text-blue-400 bg-blue-900/20 border-blue-700' }
const STATUS_COLOR: Record<string, string> = { NEW: 'text-red-400', ACKNOWLEDGED: 'text-yellow-400', INVESTIGATING: 'text-blue-400', RESOLVED: 'text-green-400', FALSE_POSITIVE: 'text-gray-400' }

export default function Alarms() {
  const [alarms, setAlarms] = useState<any[]>([])
  const [filter, setFilter] = useState({ severity: '', status: '' })
  const [loading, setLoading] = useState(true)

  const load = async () => {
    try {
      const data = await getAlarms({ ...filter, limit: 100 })
      setAlarms(data)
    } finally { setLoading(false) }
  }

  useEffect(() => { load() }, [filter])

  const handleAck = async (id: string) => { await acknowledgeAlarm(id); load() }
  const handleResolve = async (id: string, fp = false) => { await resolveAlarm(id, '', fp); load() }

  return (
    <div className="p-6 space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold text-white flex items-center gap-2"><Bell size={24} /> Alarm Center</h1>
        <span className="text-gray-400 text-sm">{alarms.length} alarms</span>
      </div>

      {/* Filters */}
      <div className="flex gap-3">
        {[['severity', ['', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW']],
          ['status', ['', 'NEW', 'ACKNOWLEDGED', 'RESOLVED', 'FALSE_POSITIVE']]].map(([key, opts]) => (
          <select key={key as string} value={(filter as any)[key as string]}
            onChange={e => setFilter(f => ({ ...f, [key as string]: e.target.value }))}
            className="bg-gray-800 border border-gray-600 text-gray-200 rounded-lg px-3 py-2 text-sm">
            {(opts as string[]).map(o => <option key={o} value={o}>{o || `All ${key}`}</option>)}
          </select>
        ))}
        <button onClick={load} className="px-4 py-2 bg-cyan-700 hover:bg-cyan-600 text-white rounded-lg text-sm">Refresh</button>
      </div>

      {/* Alarm list */}
      {loading ? <p className="text-gray-400">Loading…</p> : (
        <div className="space-y-3">
          {alarms.length === 0 && <p className="text-gray-500">No alarms match the filter.</p>}
          {alarms.map(alarm => (
            <div key={alarm.id} className={`border rounded-xl p-4 ${SEV_COLOR[alarm.severity] || 'bg-gray-800 border-gray-700'}`}>
              <div className="flex items-start justify-between gap-4">
                <div className="flex-1">
                  <div className="flex items-center gap-3 mb-1">
                    <span className="font-semibold text-white">{alarm.title}</span>
                    <span className={`text-xs font-medium ${STATUS_COLOR[alarm.status]}`}>{alarm.status}</span>
                  </div>
                  <p className="text-sm text-gray-400 mb-2">{alarm.description?.slice(0, 150)}</p>
                  <div className="text-xs text-gray-500 space-x-4">
                    <span>{new Date(alarm.timestamp).toLocaleString()}</span>
                    {alarm.acknowledged_by && <span>Ack: {alarm.acknowledged_by}</span>}
                    {alarm.is_false_positive && <span className="text-blue-400">False Positive</span>}
                  </div>
                </div>
                <div className="flex gap-2 flex-shrink-0">
                  {alarm.status === 'NEW' && (
                    <button onClick={() => handleAck(alarm.id)}
                      className="flex items-center gap-1 px-3 py-1 bg-yellow-800 hover:bg-yellow-700 text-white rounded text-xs">
                      <CheckCircle size={12} /> Ack
                    </button>
                  )}
                  {['NEW','ACKNOWLEDGED','INVESTIGATING'].includes(alarm.status) && (
                    <>
                      <button onClick={() => handleResolve(alarm.id, false)}
                        className="px-3 py-1 bg-green-800 hover:bg-green-700 text-white rounded text-xs">Resolve</button>
                      <button onClick={() => handleResolve(alarm.id, true)}
                        className="flex items-center gap-1 px-3 py-1 bg-gray-700 hover:bg-gray-600 text-white rounded text-xs">
                        <XCircle size={12} /> FP
                      </button>
                    </>
                  )}
                </div>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}

import { useState, useEffect } from 'react'
import { getModelInfo } from '../services/api'
import { Cpu, CheckCircle } from 'lucide-react'

export default function ModelInfo() {
  const [info, setInfo] = useState<any>(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    getModelInfo().then(setInfo).finally(() => setLoading(false))
  }, [])

  if (loading) return <div className="p-6 text-gray-400">Loading model info…</div>
  if (!info) return <div className="p-6 text-red-400">Failed to load model info.</div>

  return (
    <div className="p-6 space-y-6">
      <h1 className="text-2xl font-bold text-white flex items-center gap-2"><Cpu size={24} /> ML Model Information</h1>

      <div className="grid grid-cols-2 gap-4">
        {[
          ['Model Type', 'RandomForestClassifier'],
          ['Artifact', info.model_version],
          ['Total Features', info.feature_count],
          ['Raw Sensor Columns', info.raw_feature_count],
          ['Rolling Window', info.rolling_window + ' rows'],
          ['Classes', info.classes?.join(' / ') + '  (0=Normal, 1=Attack)'],
          ['Decision Threshold', (info.decision_threshold * 100).toFixed(0) + '%'],
          ['Fusion Logic', info.fusion_logic],
          ['Preprocessing', 'Rolling mean/std/diff computed at inference (no embedded scaler)'],
          ['predict_proba()', info.probability_supported ? 'Yes' : 'No'],
        ].map(([k, v]) => (
          <div key={k as string} className="bg-gray-900 border border-gray-700 rounded-xl p-4">
            <p className="text-xs text-gray-500 mb-1">{k}</p>
            <p className="text-white text-sm font-medium">{v}</p>
          </div>
        ))}
      </div>

      {info.validated_performance && (
        <div className="bg-gray-900 border border-gray-700 rounded-xl p-4">
          <h2 className="text-sm font-semibold text-gray-300 mb-3">Validated Performance (fusion_config.json)</h2>
          <div className="grid grid-cols-4 gap-4 text-center">
            {[
              ['Precision', (info.validated_performance.precision * 100).toFixed(1) + '%', 'text-green-400'],
              ['Recall', (info.validated_performance.recall * 100).toFixed(1) + '%', 'text-cyan-400'],
              ['F1', (info.validated_performance.f1 * 100).toFixed(1) + '%', 'text-blue-400'],
              ['FPR', (info.validated_performance.fpr * 100).toFixed(2) + '%', 'text-yellow-400'],
            ].map(([k, v, c]) => (
              <div key={k as string}>
                <p className={`text-2xl font-bold ${c}`}>{v}</p>
                <p className="text-gray-500 text-xs">{k}</p>
              </div>
            ))}
          </div>
          <p className="text-xs text-gray-600 mt-3">Source: RF (t=0.70) OR Rule Engine (16 rules) — validated on 20k-row SWaT sample</p>
        </div>
      )}

      <div className="bg-gray-900 border border-gray-700 rounded-xl p-4">
        <h2 className="text-sm font-semibold text-gray-300 mb-3">Active Rules ({info.active_rules?.length})</h2>
        <div className="flex flex-wrap gap-2">
          {info.active_rules?.map((r: string) => (
            <span key={r} className="bg-cyan-900/30 border border-cyan-700 text-cyan-300 px-2 py-1 rounded text-xs flex items-center gap-1">
              <CheckCircle size={10} /> {r}
            </span>
          ))}
        </div>
      </div>

      <div className="bg-gray-900 border border-gray-700 rounded-xl p-4">
        <h2 className="text-sm font-semibold text-gray-300 mb-3">All 168 Model Features</h2>
        <div className="text-xs text-gray-500 mb-2">42 raw sensor/actuator columns + 126 rolling features (roll_mean5, roll_std5, diff5 for each)</div>
        <div className="grid grid-cols-4 gap-1 max-h-64 overflow-y-auto">
          {info.features?.map((f: string, i: number) => (
            <span key={f} className={`text-xs px-1 py-0.5 rounded ${f.includes('_roll_') || f.includes('_diff') ? 'text-gray-500' : 'text-gray-300 font-medium'}`}>
              {i + 1}. {f}
            </span>
          ))}
        </div>
      </div>
    </div>
  )
}

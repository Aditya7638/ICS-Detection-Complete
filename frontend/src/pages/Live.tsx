import { useState, useCallback, useEffect, useRef } from 'react'
import { useNavigate } from 'react-router-dom'
import { useWebSocket } from '../hooks/useWebSocket'
import { getRecentPredictions, deletePredictions, streamCSV, startSimulator, stopSimulator, pauseSimulator, getSimulatorStatus } from '../services/api'
import { Wifi, WifiOff, Play, Pause, Square, Upload, ListFilter, X, MessageSquare, Trash2, RotateCw } from 'lucide-react'

interface Event { event_id: string; timestamp: string; final_label: string; ml_probability: number; severity: string | null; rule_violation_count: number; affected_sensors: string[]; rule_violations?: { rule_id?: string; message?: string; evidence?: Record<string, unknown> }[]; recommendations?: string[]; explanation?: string | null; source?: 'simulator' | 'csv_upload'; simulator?: boolean; true_label?: string }
interface CsvRow { row_index: number; valid: boolean; errors: { message: string }[]; detection?: Event; true_label?: string }
interface CsvBatch { batch_index: number; rows: CsvRow[]; counts: Record<string, number> }
type EventFilter = 'All' | 'Normal' | 'Suspicious' | 'Attack'
type SourceFilter = 'All' | 'simulator' | 'csv_upload'
type SavedFilter = 'All' | 'Normal' | 'Suspicious' | 'Attack'

const MAX_VISIBLE_EVENTS = 100
const MAX_VISIBLE_BATCHES = 20

const LABEL_BG: Record<string, string> = { Attack: 'bg-red-900/30 border-red-700', Suspicious: 'bg-yellow-900/30 border-yellow-700', Normal: 'bg-green-900/30 border-green-700' }
const LABEL_TEXT: Record<string, string> = { Attack: 'text-red-400', Suspicious: 'text-yellow-400', Normal: 'text-green-400' }

export default function Live() {
  const navigate = useNavigate()
  const [events, setEvents] = useState<Event[]>([])
  const [simRunning, setSimRunning] = useState(false)
  const [simPaused, setSimPaused] = useState(false)
  const [simError, setSimError] = useState('')
  const [speed, setSpeed] = useState(5)
  const [csvLoading, setCsvLoading] = useState(false)
  const [csvBatches, setCsvBatches] = useState<CsvBatch[]>([])
  const [csvCounts, setCsvCounts] = useState({ total: 0, valid: 0, invalid: 0, attack: 0, suspicious: 0, normal: 0 })
  const [csvFilename, setCsvFilename] = useState('')
  const [eventFilter, setEventFilter] = useState<EventFilter>('All')
  const [sourceFilter, setSourceFilter] = useState<SourceFilter>('All')
  const [savedPredictions, setSavedPredictions] = useState<any[]>([])
  const [savedFilter, setSavedFilter] = useState<SavedFilter>('All')
  const [selectedPredictionIds, setSelectedPredictionIds] = useState<Set<string>>(new Set())
  const [selectedEvent, setSelectedEvent] = useState<Event | null>(null)
  const fileRef = useRef<HTMLInputElement>(null)

  useEffect(() => {
    let cancelled = false
    getSimulatorStatus().then(status => {
      if (cancelled) return
      setSimRunning(status.running)
      setSimPaused(status.paused)
      setSpeed(status.speed)
    }).catch(() => {
      if (!cancelled) setSimError('Could not retrieve simulator status.')
    })
    return () => { cancelled = true }
  }, [])

  useEffect(() => {
    getRecentPredictions(200).then(predictions => {
      setSavedPredictions(predictions)
      setEvents(predictions.slice(0, MAX_VISIBLE_EVENTS).map((prediction: any) => ({
        event_id: prediction.id,
        timestamp: prediction.timestamp,
        final_label: prediction.final_label,
        ml_probability: prediction.ml_probability,
        severity: prediction.severity,
        rule_violation_count: prediction.rule_violation_count,
        affected_sensors: prediction.affected_sensors || [],
        rule_violations: prediction.rule_violations || [],
        recommendations: prediction.recommendations || [],
        explanation: prediction.explanation,
        source: prediction.source,
        simulator: prediction.source === 'simulator',
      })))
    }).catch(() => setSimError('Could not load saved detections. New WebSocket events may still appear.'))
  }, [])

  const onMessage = useCallback((data: any) => {
    if (data.type === 'detection') {
      setEvents(prev => [{ ...data, source: 'simulator', simulator: true }, ...prev].slice(0, MAX_VISIBLE_EVENTS))
    }
  }, [])

  const { connected } = useWebSocket(onMessage)

  const handleStartSim = async () => {
    setSimError('')
    try {
      await startSimulator(speed)
      setSimRunning(true)
      setSimPaused(false)
    } catch (error: any) {
      setSimError(error.response?.data?.detail || 'Failed to start the simulator.')
    }
  }
  const handleStopSim = async () => {
    setSimError('')
    try {
      await stopSimulator()
      setSimRunning(false)
      setSimPaused(false)
    } catch (error: any) {
      setSimError(error.response?.data?.detail || 'Failed to stop the simulator.')
    }
  }
  const handlePauseSim = async () => {
    setSimError('')
    try {
      const status = await pauseSimulator()
      setSimPaused(status.paused)
    } catch (error: any) {
      setSimError(error.response?.data?.detail || 'Failed to update simulator state.')
    }
  }

  const handleCSV = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0]
    if (!file) return
    setCsvFilename(file.name)
    setCsvBatches([])
    setCsvCounts({ total: 0, valid: 0, invalid: 0, attack: 0, suspicious: 0, normal: 0 })
    setCsvLoading(true)
    try {
      await streamCSV(file, batch => {
        setCsvBatches(prev => [...prev, batch].slice(-MAX_VISIBLE_BATCHES))
        setCsvCounts(prev => ({
          total: prev.total + batch.rows.length,
          valid: prev.valid + (batch.counts.valid || 0),
          invalid: prev.invalid + (batch.counts.invalid || 0),
          attack: prev.attack + (batch.counts.attack || 0),
          suspicious: prev.suspicious + (batch.counts.suspicious || 0),
          normal: prev.normal + (batch.counts.normal || 0),
        }))
        const detections = batch.rows.flatMap(row => row.detection ? [{ ...row.detection, source: 'csv_upload' as const, true_label: row.true_label }] : [])
        setEvents(prev => [...detections, ...prev].slice(0, MAX_VISIBLE_EVENTS))
      })
    } catch (err: any) {
      setSimError(`CSV upload failed: ${err.message}`)
    } finally {
      setCsvLoading(false)
      if (fileRef.current) fileRef.current.value = ''
    }
  }

  const eventCounts = events.reduce((counts, event) => {
    if (event.final_label in counts) counts[event.final_label as keyof typeof counts] += 1
    return counts
  }, { Normal: 0, Suspicious: 0, Attack: 0 })
  const filteredEvents = events.filter(event =>
    (sourceFilter === 'All' || event.source === sourceFilter) &&
    (eventFilter === 'All' || event.final_label === eventFilter)
  )
  const visibleSavedPredictions = savedPredictions.filter(prediction =>
    savedFilter === 'All' || prediction.final_label === savedFilter
  )
  const allVisibleSelected = visibleSavedPredictions.length > 0 &&
    visibleSavedPredictions.every(prediction => selectedPredictionIds.has(prediction.id))

  const togglePrediction = (id: string) => {
    setSelectedPredictionIds(previous => {
      const next = new Set(previous)
      if (next.has(id)) next.delete(id)
      else next.add(id)
      return next
    })
  }

  const toggleVisiblePredictions = () => {
    setSelectedPredictionIds(previous => {
      const next = new Set(previous)
      if (allVisibleSelected) visibleSavedPredictions.forEach(prediction => next.delete(prediction.id))
      else visibleSavedPredictions.forEach(prediction => next.add(prediction.id))
      return next
    })
  }

  const refreshSavedPredictions = async () => {
    try {
      setSavedPredictions(await getRecentPredictions(200))
    } catch {
      setSimError('Could not refresh saved detections.')
    }
  }

  const handleDeletePredictions = async () => {
    const ids = [...selectedPredictionIds]
    if (!ids.length || !window.confirm(`Permanently delete ${ids.length} selected detections and their linked alarms? This cannot be undone.`)) return
    try {
      await deletePredictions(ids)
      setSavedPredictions(previous => previous.filter(prediction => !selectedPredictionIds.has(prediction.id)))
      setEvents(previous => previous.filter(event => !selectedPredictionIds.has(event.event_id)))
      setSelectedPredictionIds(new Set())
    } catch (error: any) {
      setSimError(error.response?.data?.detail || 'Could not delete the selected detections.')
    }
  }

  return (
    <div className="p-6 space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold text-white">Live Monitor</h1>
        <div className="flex items-center gap-2 text-sm">
          {connected ? <><Wifi size={16} className="text-green-400" /><span className="text-green-400">WebSocket Connected</span></>
            : <><WifiOff size={16} className="text-red-400" /><span className="text-red-400">Disconnected</span></>}
        </div>
      </div>

      {simError && <div role="alert" className="rounded-lg border border-red-800 bg-red-950/40 px-4 py-3 text-sm text-red-300">{simError}</div>}

      {/* Controls */}
      <div className="bg-gray-900 border border-gray-700 rounded-xl p-4 space-y-4">
        <div className="flex items-center gap-4 flex-wrap">
          <div className="flex items-center gap-2">
            <label className="text-sm text-gray-400">Speed:</label>
            {[1, 5, 10].map(s => (
              <button key={s} onClick={() => setSpeed(s)}
                className={`px-3 py-1 rounded text-sm ${speed === s ? 'bg-cyan-600 text-white' : 'bg-gray-800 text-gray-400'}`}>{s}x</button>
            ))}
          </div>
          <button onClick={handleStartSim} disabled={simRunning || csvLoading}
            className="flex items-center gap-2 px-4 py-2 bg-green-700 hover:bg-green-600 disabled:bg-gray-700 text-white rounded-lg text-sm">
            <Play size={14} /> Start Simulator
          </button>
          <button onClick={handlePauseSim} disabled={!simRunning || csvLoading}
            className="flex items-center gap-2 px-4 py-2 bg-yellow-700 hover:bg-yellow-600 disabled:bg-gray-700 text-white rounded-lg text-sm">
            <Pause size={14} /> {simPaused ? 'Resume' : 'Pause'}
          </button>
          <button onClick={handleStopSim} disabled={!simRunning || csvLoading}
            className="flex items-center gap-2 px-4 py-2 bg-red-800 hover:bg-red-700 disabled:bg-gray-700 text-white rounded-lg text-sm">
            <Square size={14} /> Stop
          </button>
        </div>

        {simRunning && (
          <div className="text-xs text-amber-400 bg-amber-900/20 border border-amber-700 rounded px-3 py-2">
            ⚠ REPLAY / DEMO MODE — replaying CSV dataset through the actual ML model and rule engine.
          </div>
        )}

        <div className="border-t border-gray-800 pt-4">
          <p className="text-sm text-gray-400 mb-2">Or upload a CSV for batch analysis:</p>
          <button onClick={() => fileRef.current?.click()} disabled={csvLoading || simRunning}
            title={simRunning ? 'Stop the simulator before uploading a CSV.' : 'Upload a CSV for batch analysis'}
            className="flex items-center gap-2 px-4 py-2 bg-cyan-700 hover:bg-cyan-600 disabled:cursor-not-allowed disabled:opacity-50 text-white rounded-lg text-sm">
            <Upload size={14} /> {csvLoading ? 'Processing…' : 'Upload CSV'}
          </button>
          <input ref={fileRef} type="file" accept=".csv" onChange={handleCSV} className="hidden" />
        </div>
      </div>

      <section className="bg-gray-900 border border-gray-700 rounded-xl p-4">
        <div className="flex items-start justify-between gap-4 flex-wrap mb-4">
          <div>
            <h2 className="text-sm font-semibold text-gray-200">Saved detections</h2>
            <p className="text-xs text-gray-500 mt-1">Latest {savedPredictions.length} persisted records. CSV preview-only rows are not included.</p>
          </div>
          <div className="flex items-center gap-2 flex-wrap">
            {(['All', 'Normal', 'Suspicious', 'Attack'] as SavedFilter[]).map(filter => (
              <button key={filter} onClick={() => setSavedFilter(filter)}
                className={`px-2.5 py-1 rounded border text-xs ${savedFilter === filter ? 'border-cyan-500 bg-cyan-900/40 text-cyan-300' : 'border-gray-700 text-gray-400 hover:border-gray-500'}`}>
                {filter}
              </button>
            ))}
              <button onClick={refreshSavedPredictions} title="Refresh saved detections" aria-label="Refresh saved detections"
                className="p-1.5 rounded border border-gray-700 text-gray-400 hover:text-white hover:border-gray-500">
                <RotateCw size={14} />
              </button>
          </div>
        </div>
        <div className="flex items-center justify-between gap-4 border-y border-gray-800 py-3 mb-2">
          <label className="flex items-center gap-2 text-xs text-gray-400">
            <input type="checkbox" checked={allVisibleSelected} onChange={toggleVisiblePredictions} />
            Select visible ({visibleSavedPredictions.length})
          </label>
          <button onClick={handleDeletePredictions} disabled={selectedPredictionIds.size === 0}
            className="inline-flex items-center gap-2 px-3 py-1.5 rounded bg-red-900/50 hover:bg-red-800 disabled:opacity-40 disabled:cursor-not-allowed text-red-200 text-xs">
            <Trash2 size={13} /> Delete selected ({selectedPredictionIds.size})
          </button>
        </div>
        <div className="max-h-72 overflow-y-auto divide-y divide-gray-800">
          {visibleSavedPredictions.length === 0 && <p className="py-4 text-sm text-gray-500">No saved detections match this filter.</p>}
          {visibleSavedPredictions.map(prediction => (
            <label key={prediction.id} className="flex items-center gap-3 py-2.5 text-sm cursor-pointer">
              <input type="checkbox" checked={selectedPredictionIds.has(prediction.id)} onChange={() => togglePrediction(prediction.id)} />
              <span className={`w-20 font-medium ${LABEL_TEXT[prediction.final_label] || 'text-gray-300'}`}>{prediction.final_label}</span>
              <span className="text-gray-400">{new Date(prediction.timestamp).toLocaleString()}</span>
              <span className="ml-auto text-xs text-gray-500">ML {(prediction.ml_probability * 100).toFixed(1)}%</span>
              {prediction.source && <span className="hidden sm:inline text-xs text-gray-600">{prediction.source}</span>}
            </label>
          ))}
        </div>
      </section>

      {/* CSV result summary */}
      {csvBatches.length > 0 && (
        <div className="bg-gray-900 border border-gray-700 rounded-xl p-4 text-sm">
          <h2 className="font-semibold text-white mb-2">CSV Analysis: {csvFilename}</h2>
          <div className="grid grid-cols-4 gap-4">
            {[['Processed', csvCounts.total, 'text-white'],
              ['Valid', csvCounts.valid, 'text-green-400'],
              ['Attacks', csvCounts.attack, 'text-red-400'],
              ['Normal', csvCounts.normal, 'text-green-300']].map(([l, v, c]) => (
              <div key={String(l)}>
                <p className="text-gray-500">{l}</p>
                <p className={`text-xl font-bold ${c}`}>{v}</p>
              </div>
            ))}
          </div>
          <p className="text-xs text-gray-500 mt-3">Processed in batches of five. Earlier batches remain available while the next batch is analyzed.</p>

          <div className="grid gap-4 lg:grid-cols-3 mt-5">
            {[
              ['Attacks', 'Attack', 'border-red-800', 'text-red-400'],
              ['Suspicious', 'Suspicious', 'border-yellow-800', 'text-yellow-400'],
              ['Normal', 'Normal', 'border-green-800', 'text-green-400'],
            ].map(([title, category, border, text]) => {
              const rows = csvBatches.flatMap(batch => batch.rows.filter(row => row.detection?.final_label === category))
              return (
                <div key={category} className={`border ${border} rounded-lg p-3`}>
                  <h3 className={`font-semibold ${text} mb-2`}>{title} ({rows.length})</h3>
                  <div className="space-y-1 max-h-48 overflow-y-auto">
                    {rows.length === 0 && <p className="text-gray-600 text-xs">No rows yet</p>}
                    {rows.map(row => (
                      <div key={row.row_index} className="flex justify-between text-xs text-gray-400">
                        <span>Row {row.row_index + 1}</span>
                        <span>{row.detection && `${(row.detection.ml_probability * 100).toFixed(1)}%`}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )
            })}
          </div>

          <div className="mt-5 space-y-3">
            <p className="text-xs text-gray-500">Showing the latest {MAX_VISIBLE_BATCHES} batches to keep the monitor responsive. Totals above include the complete upload.</p>
            {csvBatches.map(batch => (
              <div key={batch.batch_index} className="border border-gray-800 rounded-lg p-3">
                <h3 className="text-gray-300 font-medium mb-2">Batch {batch.batch_index} ({batch.rows.length} rows)</h3>
                <div className="space-y-1">
                  {batch.rows.map(row => (
                    <div key={row.row_index} className="flex items-center gap-3 text-xs text-gray-400">
                      <span className="w-16">Row {row.row_index + 1}</span>
                      <span className={row.detection ? LABEL_TEXT[row.detection.final_label] : 'text-red-400'}>
                        {row.detection?.final_label || 'Invalid'}
                      </span>
                      <span>{row.detection ? `${(row.detection.ml_probability * 100).toFixed(1)}% attack probability` : row.errors[0]?.message}</span>
                    </div>
                  ))}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Live event feed */}
      <div className="bg-gray-900 border border-gray-700 rounded-xl p-4">
        <div className="flex items-center justify-between gap-4 mb-4 flex-wrap">
          <h2 className="text-sm font-semibold text-gray-300">
            Event Feed <span className="text-gray-500">({events.length} recent events)</span>
          </h2>
          <div className="flex items-center gap-2 text-xs text-gray-400">
            <ListFilter size={14} />
            {(['All', 'simulator', 'csv_upload'] as SourceFilter[]).map(filter => (
              <button key={filter} onClick={() => setSourceFilter(filter)}
                className={`px-2.5 py-1 rounded border ${sourceFilter === filter ? 'border-cyan-500 bg-cyan-900/40 text-cyan-300' : 'border-gray-700 hover:border-gray-500'}`}>
                {filter === 'All' ? 'All sources' : filter === 'simulator' ? 'Simulator' : 'CSV upload'} ({filter === 'All' ? events.length : events.filter(event => event.source === filter).length})
              </button>
            ))}
          </div>
          <div className="flex items-center gap-2 text-xs text-gray-400">
            {(['All', 'Normal', 'Suspicious', 'Attack'] as EventFilter[]).map(filter => (
              <button key={filter} onClick={() => setEventFilter(filter)}
                className={`px-2.5 py-1 rounded border ${eventFilter === filter ? 'border-cyan-500 bg-cyan-900/40 text-cyan-300' : 'border-gray-700 hover:border-gray-500'}`}>
                {filter} ({filter === 'All' ? events.length : eventCounts[filter]})
              </button>
            ))}
          </div>
        </div>
        <div className="space-y-2 max-h-96 overflow-y-auto">
          {events.length === 0 && <p className="text-gray-500 text-sm">Start the simulator or upload a CSV to see live events.</p>}
          {events.length > 0 && filteredEvents.length === 0 && <p className="text-gray-500 text-sm">No events match the selected evaluation.</p>}
          {filteredEvents.map(e => (
            <button key={e.event_id} onClick={() => setSelectedEvent(e)}
              className={`w-full text-left border rounded-lg p-3 text-sm ${LABEL_BG[e.final_label] || 'bg-gray-800 border-gray-700'}`}>
              <div className="flex items-center gap-3 flex-wrap">
                <span className="text-gray-400 text-xs">{new Date(e.timestamp).toLocaleTimeString()}</span>
                <span className={`font-bold ${LABEL_TEXT[e.final_label]}`}>{e.final_label}</span>
                {e.severity && <span className="text-xs bg-gray-800 px-2 py-0.5 rounded-full">{e.severity}</span>}
                <span className="text-gray-400">ML: {(e.ml_probability * 100).toFixed(1)}%</span>
                {e.rule_violation_count > 0 && <span className="text-orange-400">{e.rule_violation_count} rule{e.rule_violation_count > 1 ? 's' : ''}</span>}
                {e.affected_sensors?.length > 0 && <span className="text-gray-500 text-xs">{e.affected_sensors.slice(0, 3).join(', ')}</span>}
                <span className="text-xs text-cyan-300">{e.source === 'simulator' ? 'Simulator' : 'CSV upload'}</span>
              </div>
              <span className="text-xs text-gray-500">Select for evaluation details</span>
            </button>
          ))}
        </div>
      </div>

      {selectedEvent && (
        <div className="bg-gray-900 border border-cyan-800 rounded-xl p-5 space-y-4">
          <div className="flex items-start justify-between gap-4">
            <div>
              <p className="text-xs text-cyan-300 uppercase">{selectedEvent.source === 'simulator' ? 'Simulator evaluation' : 'CSV upload evaluation'}</p>
              <h2 className="text-lg font-semibold text-white">{selectedEvent.final_label} detection details</h2>
              <p className="text-xs text-gray-500">{new Date(selectedEvent.timestamp).toLocaleString()}</p>
            </div>
            <button onClick={() => setSelectedEvent(null)} aria-label="Close details" title="Close details"
              className="p-1 text-gray-400 hover:text-white"><X size={18} /></button>
          </div>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3 text-sm">
            <div><p className="text-gray-500">Evaluation</p><p className="text-white">{selectedEvent.source === 'simulator' ? 'Replay' : 'Uploaded CSV'}</p></div>
            <div><p className="text-gray-500">ML probability</p><p className="text-white">{(selectedEvent.ml_probability * 100).toFixed(1)}%</p></div>
            <div><p className="text-gray-500">Severity</p><p className="text-white">{selectedEvent.severity || 'None'}</p></div>
            <div><p className="text-gray-500">Rule violations</p><p className="text-white">{selectedEvent.rule_violation_count}</p></div>
          </div>
          <div>
            <p className="text-gray-500 text-sm mb-1">What is happening</p>
            <p className="text-gray-200 text-sm">{selectedEvent.explanation || 'No explanation was stored for this older evaluation.'}</p>
          </div>
          <button onClick={() => navigate('/chat', { state: { detection: selectedEvent } })}
            className="flex items-center gap-2 bg-cyan-700 hover:bg-cyan-600 text-white rounded-lg px-4 py-2 text-sm">
            <MessageSquare size={15} /> Ask AI Assistant about this evaluation
          </button>
          <div className="grid md:grid-cols-2 gap-4 text-sm">
            <div><p className="text-gray-500 mb-1">Affected sensors</p><p className="text-gray-300">{selectedEvent.affected_sensors?.join(', ') || 'None reported'}</p></div>
            <div><p className="text-gray-500 mb-1">Recommended action</p><ul className="list-disc list-inside text-gray-300">{(selectedEvent.recommendations || []).map(item => <li key={item}>{item}</li>)}</ul></div>
          </div>
          {(selectedEvent.rule_violations || []).length > 0 && (
            <div><p className="text-gray-500 text-sm mb-1">Detected rule evidence</p><ul className="list-disc list-inside text-orange-300 text-sm">{selectedEvent.rule_violations?.map((rule, index) => <li key={`${rule.rule_id}-${index}`}>{rule.rule_id ? `${rule.rule_id}: ` : ''}{rule.message}</li>)}</ul></div>
          )}
        </div>
      )}
    </div>
  )
}

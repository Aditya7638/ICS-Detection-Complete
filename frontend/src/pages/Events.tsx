import { useCallback, useEffect, useRef, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { AlertTriangle, CalendarClock, ChevronLeft, ChevronRight, Clock3, LoaderCircle, RotateCw, Search, ShieldAlert, ScrollText, MessageSquare } from 'lucide-react'
import { getEvent, listEvents } from '../services/api'

interface DetectionEvent {
  id: string
  timestamp: string
  final_label: string
  severity: string | null
  ml_probability: number
  rule_violation_count: number
  rule_violations: { rule_id?: string; message?: string; evidence?: Record<string, unknown> }[]
  affected_sensors: string[]
  explanation: string | null
  recommendations: string[]
  source: string | null
}

interface EventDetail extends DetectionEvent {
  event_id: string
  ml_prediction: number
  ml_label: string | null
  rule_violated: boolean
  sensor_values: Record<string, unknown>
  alarm: { id: string; title: string; status: string; severity: string } | null
}

interface EventFilters {
  final_label: string
  severity: string
  start_time: string
  end_time: string
  affected_sensor: string
  rule_id: string
}

interface ApiErrorShape { response?: { data?: { detail?: unknown } } }

function errorMessage(error: unknown): string {
  const detail = (error as ApiErrorShape)?.response?.data?.detail
  if (typeof detail === 'string') return detail
  if (detail !== undefined && detail !== null) return JSON.stringify(detail) || 'Request failed.'
  return error instanceof Error ? error.message : 'Request failed.'
}

const LIMIT = 30
const EMPTY_FILTERS: EventFilters = {
  final_label: '', severity: '', start_time: '', end_time: '', affected_sensor: '', rule_id: '',
}
const AUTO_REFRESH_MS = 15_000
interface EventListResponse { results: DetectionEvent[]; total: number; offset: number }

function loadEvents(filters: EventFilters, offset: number): Promise<EventListResponse> {
  return listEvents({
    final_label: filters.final_label || undefined,
    severity: filters.severity || undefined,
    start_time: filters.start_time ? new Date(filters.start_time).toISOString() : undefined,
    end_time: filters.end_time ? new Date(filters.end_time).toISOString() : undefined,
    affected_sensor: filters.affected_sensor.trim() || undefined,
    rule_id: filters.rule_id.trim() || undefined,
    limit: LIMIT,
    offset,
  }) as Promise<EventListResponse>
}

const inputClass = 'rounded-lg border border-gray-700 bg-gray-950 px-3 py-2 text-sm text-gray-200 outline-none focus:border-cyan-500'
const labelColor: Record<string, string> = {
  Attack: 'border-red-800 bg-red-950/30 text-red-300',
  Suspicious: 'border-amber-800 bg-amber-950/30 text-amber-300',
  Normal: 'border-green-800 bg-green-950/30 text-green-300',
}

function openDatePicker(input: HTMLInputElement | null) {
  if (!input) return
  if (typeof input.showPicker !== 'function') {
    input.focus()
    return
  }
  try {
    input.showPicker()
  } catch {
    input.focus()
  }
}

export default function Events() {
  const navigate = useNavigate()
  const fromInputRef = useRef<HTMLInputElement>(null)
  const toInputRef = useRef<HTMLInputElement>(null)
  const [filters, setFilters] = useState<EventFilters>(EMPTY_FILTERS)
  const [events, setEvents] = useState<DetectionEvent[]>([])
  const [total, setTotal] = useState(0)
  const [offset, setOffset] = useState(0)
  const [detail, setDetail] = useState<EventDetail | null>(null)
  const [loading, setLoading] = useState(true)
  const [detailLoading, setDetailLoading] = useState(false)
  const [error, setError] = useState('')
  const [lastUpdated, setLastUpdated] = useState<Date | null>(null)
  const appliedSearchRef = useRef({ filters: EMPTY_FILTERS, offset: 0 })
  const requestIdRef = useRef(0)

  const fetchEvents = useCallback(async (
    selectedFilters: EventFilters,
    nextOffset: number,
    showLoading: boolean,
    clearDetail: boolean,
  ) => {
    const requestId = ++requestIdRef.current
    if (showLoading) setLoading(true)
    setError('')
    if (clearDetail) setDetail(null)
    try {
      const result = await loadEvents(selectedFilters, nextOffset)
      if (requestId !== requestIdRef.current) return
      setEvents(result.results)
      setTotal(result.total)
      setOffset(result.offset)
      setLastUpdated(new Date())
    } catch (searchError) {
      if (requestId === requestIdRef.current) setError(errorMessage(searchError))
    } finally {
      if (requestId === requestIdRef.current) setLoading(false)
    }
  }, [])

  const search = (selectedFilters: EventFilters, nextOffset = 0) => {
    appliedSearchRef.current = { filters: selectedFilters, offset: nextOffset }
    void fetchEvents(selectedFilters, nextOffset, true, true)
  }

  const refreshCurrentResults = useCallback(() => {
    const { filters: appliedFilters, offset: appliedOffset } = appliedSearchRef.current
    void fetchEvents(appliedFilters, appliedOffset, false, false)
  }, [fetchEvents])

  useEffect(() => {
    const refreshIfVisible = () => {
      if (document.visibilityState === 'visible') refreshCurrentResults()
    }
    const initialRefresh = window.setTimeout(refreshCurrentResults, 0)
    const interval = window.setInterval(refreshIfVisible, AUTO_REFRESH_MS)
    window.addEventListener('focus', refreshIfVisible)
    document.addEventListener('visibilitychange', refreshIfVisible)

    return () => {
      window.clearTimeout(initialRefresh)
      window.clearInterval(interval)
      window.removeEventListener('focus', refreshIfVisible)
      document.removeEventListener('visibilitychange', refreshIfVisible)
      requestIdRef.current += 1
    }
  }, [fetchEvents, refreshCurrentResults])

  const openDetail = async (id: string) => {
    setDetailLoading(true)
    setError('')
    try {
      setDetail(await getEvent(id) as EventDetail)
    } catch (detailError) {
      setError(errorMessage(detailError))
    } finally {
      setDetailLoading(false)
    }
  }

  const changeFilter = (key: keyof EventFilters, value: string) => {
    setFilters(current => ({ ...current, [key]: value }))
  }

  return (
    <div className="mx-auto max-w-[1400px] space-y-6 p-6">
      <header>
        <h1 className="flex items-center gap-2 text-2xl font-bold text-white">
          <ScrollText className="text-cyan-400" size={25} /> Event History
        </h1>
        <p className="mt-1 text-sm text-gray-400">Search saved detections and inspect sensor evidence, rule violations, and linked alarms.</p>
      </header>

      {error && <div role="alert" className="rounded-lg border border-red-800 bg-red-950/40 px-4 py-3 text-sm text-red-300">{error}</div>}

      <form onSubmit={event => { event.preventDefault(); void search(filters) }} className="grid gap-3 rounded-xl border border-gray-800 bg-gray-900 p-4 sm:grid-cols-2 xl:grid-cols-3">
        <label className="space-y-1 text-xs text-gray-400">
          Detection
          <select value={filters.final_label} onChange={event => changeFilter('final_label', event.target.value)} className={`${inputClass} w-full`}>
            <option value="">All detections</option><option>Attack</option><option>Suspicious</option><option>Normal</option>
          </select>
        </label>
        <label className="space-y-1 text-xs text-gray-400">
          Severity
          <select value={filters.severity} onChange={event => changeFilter('severity', event.target.value)} className={`${inputClass} w-full`}>
            <option value="">All severities</option><option>CRITICAL</option><option>HIGH</option><option>MEDIUM</option><option>LOW</option>
          </select>
        </label>
        <label className="space-y-1 text-xs text-gray-400">
          Affected sensor
          <input value={filters.affected_sensor} onChange={event => changeFilter('affected_sensor', event.target.value)}
            placeholder="e.g. LIT101" className={`${inputClass} w-full`} />
        </label>
        <label className="space-y-1 text-xs text-gray-400">
          Rule ID
          <input value={filters.rule_id} onChange={event => changeFilter('rule_id', event.target.value)}
            placeholder="e.g. R-01" className={`${inputClass} w-full`} />
        </label>
        <label className="space-y-1 text-xs text-gray-400">
          From
          <span className="relative block">
            <input ref={fromInputRef} type="datetime-local" value={filters.start_time}
              onClick={() => openDatePicker(fromInputRef.current)}
              onChange={event => changeFilter('start_time', event.target.value)}
              className={`${inputClass} w-full cursor-pointer pr-11`} />
            <button type="button" onClick={() => openDatePicker(fromInputRef.current)}
              aria-label="Open From date and time picker" title="Choose start date and time"
              className="absolute inset-y-0 right-0 inline-flex w-10 items-center justify-center rounded-r-lg border-l border-gray-700 bg-gray-800 text-cyan-200 transition-colors hover:bg-cyan-900 hover:text-white focus-visible:z-10 focus-visible:outline focus-visible:outline-2 focus-visible:outline-cyan-400">
              <CalendarClock size={17} />
            </button>
          </span>
        </label>
        <label className="space-y-1 text-xs text-gray-400">
          To
          <span className="relative block">
            <input ref={toInputRef} type="datetime-local" value={filters.end_time}
              onClick={() => openDatePicker(toInputRef.current)}
              onChange={event => changeFilter('end_time', event.target.value)}
              className={`${inputClass} w-full cursor-pointer pr-11`} />
            <button type="button" onClick={() => openDatePicker(toInputRef.current)}
              aria-label="Open To date and time picker" title="Choose end date and time"
              className="absolute inset-y-0 right-0 inline-flex w-10 items-center justify-center rounded-r-lg border-l border-gray-700 bg-gray-800 text-cyan-200 transition-colors hover:bg-cyan-900 hover:text-white focus-visible:z-10 focus-visible:outline focus-visible:outline-2 focus-visible:outline-cyan-400">
              <CalendarClock size={17} />
            </button>
          </span>
        </label>
        <button type="submit" disabled={loading} className="inline-flex items-center justify-center gap-2 rounded-lg bg-cyan-700 px-4 py-2 text-sm font-medium text-white hover:bg-cyan-600 disabled:opacity-50 sm:col-span-2 xl:col-span-3">
          {loading ? <LoaderCircle size={16} className="animate-spin" /> : <Search size={16} />} Search events
        </button>
      </form>

      <div className="grid items-start gap-5 xl:grid-cols-[minmax(0,1fr)_minmax(340px,0.75fr)]">
        <section className="space-y-3">
          <div className="flex items-center justify-between text-sm">
            <h2 className="font-semibold text-white">Results</h2>
            <div className="flex items-center gap-3">
              <span className="text-gray-500">{total.toLocaleString()} events</span>
              <button type="button" onClick={refreshCurrentResults} disabled={loading}
                className="inline-flex items-center gap-1.5 rounded-lg border border-gray-700 bg-gray-800 px-2.5 py-1.5 text-xs text-gray-300 transition-colors hover:border-cyan-700 hover:text-cyan-200 disabled:opacity-50"
                title="Refresh event results">
                <RotateCw size={13} className={loading ? 'animate-spin' : ''} /> Refresh
              </button>
            </div>
          </div>
          <p className="text-[11px] text-gray-600">
            Auto-refreshes every 15 seconds{lastUpdated ? ` · Updated ${lastUpdated.toLocaleTimeString()}` : ''}
          </p>
          {loading ? <p className="text-sm text-gray-500">Loading events…</p>
            : events.length === 0 ? <p className="rounded-xl border border-gray-800 bg-gray-900 p-5 text-sm text-gray-500">No saved detections match these filters.</p>
              : events.map(item => (
                <button key={item.id} onClick={() => void openDetail(item.id)}
                  className="w-full rounded-xl border border-gray-800 bg-gray-900 p-4 text-left transition-colors hover:border-gray-600">
                  <div className="flex flex-wrap items-start justify-between gap-3">
                    <div>
                      <span className={`rounded border px-2 py-1 text-xs font-semibold ${labelColor[item.final_label] ?? 'border-gray-700 text-gray-300'}`}>{item.final_label}</span>
                      {item.severity && <span className="ml-2 text-xs text-gray-400">{item.severity}</span>}
                    </div>
                    <span className="flex items-center gap-1 text-xs text-gray-500"><Clock3 size={13} />{new Date(item.timestamp).toLocaleString()}</span>
                  </div>
                  <div className="mt-3 flex flex-wrap gap-x-5 gap-y-1 text-xs text-gray-400">
                    <span>ML anomaly score: {(item.ml_probability * 100).toFixed(1)}%</span>
                    <span>Rule violations: {item.rule_violation_count}</span>
                    <span>Source: {item.source ?? 'unknown'}</span>
                  </div>
                  {!!item.affected_sensors.length && <p className="mt-2 truncate text-xs text-gray-500">Sensors: {item.affected_sensors.join(', ')}</p>}
                  {item.explanation && <p className="mt-2 line-clamp-2 text-sm text-gray-300">{item.explanation}</p>}
                </button>
              ))}
          <div className="flex items-center justify-between pt-1">
            <button type="button" onClick={() => void search(filters, Math.max(0, offset - LIMIT))}
              disabled={loading || offset === 0} className="inline-flex items-center gap-1 rounded-lg bg-gray-800 px-3 py-2 text-xs text-gray-300 disabled:opacity-40">
              <ChevronLeft size={14} /> Previous
            </button>
            <span className="text-xs text-gray-600">{total ? `${offset + 1}–${Math.min(offset + events.length, total)} of ${total}` : 'No results'}</span>
            <button type="button" onClick={() => void search(filters, offset + LIMIT)}
              disabled={loading || offset + LIMIT >= total} className="inline-flex items-center gap-1 rounded-lg bg-gray-800 px-3 py-2 text-xs text-gray-300 disabled:opacity-40">
              Next <ChevronRight size={14} />
            </button>
          </div>
        </section>

        <aside className="min-h-44 rounded-xl border border-gray-800 bg-gray-900 p-5">
          <h2 className="mb-4 flex items-center gap-2 font-semibold text-white"><ShieldAlert size={16} className="text-amber-400" /> Event detail</h2>
          {detailLoading ? <div className="flex items-center gap-2 text-sm text-gray-400"><LoaderCircle size={15} className="animate-spin" />Loading detail…</div>
            : !detail ? <p className="text-sm text-gray-500">Select a result to inspect its full record.</p>
              : (
                <div className="space-y-4 text-sm">
                  <div>
                    <p className="font-medium text-white">{detail.final_label} · {detail.severity ?? 'No severity'}</p>
                    <p className="mt-1 text-xs text-gray-500">{new Date(detail.timestamp).toLocaleString()} · {detail.source ?? 'unknown source'}</p>
                  </div>
                  <div className="grid grid-cols-2 gap-2 text-xs">
                    <p className="rounded bg-gray-950 p-2 text-gray-400">ML anomaly score <span className="block pt-1 text-white">{(detail.ml_probability * 100).toFixed(2)}%</span></p>
                    <p className="rounded bg-gray-950 p-2 text-gray-400">ML label <span className="block pt-1 text-white">{detail.ml_label ?? '—'}</span></p>
                  </div>
                  {detail.explanation && <p className="text-gray-300">{detail.explanation}</p>}
                  <button onClick={() => navigate('/chat', { state: { detection: detail } })}
                    className="inline-flex items-center gap-2 rounded-lg bg-cyan-800 px-3 py-2 text-xs font-medium text-cyan-100 hover:bg-cyan-700">
                    <MessageSquare size={14} /> Investigate with AI Assistant
                  </button>
                  {!!detail.rule_violations.length && (
                    <div>
                      <h3 className="mb-2 flex items-center gap-2 text-xs font-semibold uppercase tracking-wide text-amber-300"><AlertTriangle size={13} /> Rule violations</h3>
                      <ul className="space-y-2">
                        {detail.rule_violations.map((violation, index) => (
                          <li key={`${violation.rule_id ?? 'rule'}-${index}`} className="rounded-lg border border-gray-800 bg-gray-950 p-3 text-xs text-gray-300">
                            <span className="font-mono text-cyan-300">{violation.rule_id ?? 'Rule'}</span>
                            {violation.message && <p className="mt-1">{violation.message}</p>}
                          </li>
                        ))}
                      </ul>
                    </div>
                  )}
                  {!!detail.recommendations.length && (
                    <div><h3 className="mb-1 text-xs font-semibold uppercase tracking-wide text-gray-500">Recommendations</h3>
                      <ul className="list-inside list-disc space-y-1 text-xs text-gray-300">
                        {detail.recommendations.map((recommendation, index) => <li key={`${index}-${recommendation}`}>{recommendation}</li>)}
                      </ul>
                    </div>
                  )}
                  {detail.alarm && <div className="rounded-lg border border-amber-900 bg-amber-950/20 p-3 text-xs text-amber-200">
                    Linked alarm: {detail.alarm.title} · {detail.alarm.status} · {detail.alarm.severity}
                  </div>}
                  {!!Object.keys(detail.sensor_values ?? {}).length && (
                    <details>
                      <summary className="cursor-pointer text-xs text-gray-400">Sensor values</summary>
                      <pre className="mt-2 max-h-64 overflow-auto rounded-lg bg-gray-950 p-3 text-[10px] text-gray-400">
                        {JSON.stringify(detail.sensor_values, null, 2)}
                      </pre>
                    </details>
                  )}
                </div>
              )}
        </aside>
      </div>
    </div>
  )
}

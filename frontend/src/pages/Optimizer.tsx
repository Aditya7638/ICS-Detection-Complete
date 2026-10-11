import { useCallback, useEffect, useMemo, useState, type FormEvent } from 'react'
import {
  Activity, Check, CircleAlert, Gauge, LoaderCircle, Play, RotateCcw,
  ShieldCheck, Trash2, WandSparkles,
} from 'lucide-react'
import {
  activateConfig, createConfig, deleteConfig, getBaselineComparison,
  getOptimizationResults, listConfigs, restoreBaseline, runOptimization,
} from '../services/api'
import { useAuth } from '../hooks/useAuth'
import {
  CartesianGrid, Line, LineChart, ResponsiveContainer, Tooltip, XAxis, YAxis,
} from 'recharts'

interface DetectionConfig {
  id: string
  version: number
  name: string
  profile: string
  min_recall: number | null
  max_fpr: number | null
  min_precision: number | null
  threshold: number | null
  fusion_strategy: string
  is_active: boolean
  is_baseline: boolean
  created_at: string
}

interface Metrics {
  threshold?: number
  precision?: number
  recall?: number
  f1?: number
  fpr?: number
  fnr?: number
}

interface MetricBundle {
  selected?: Metrics
  baseline?: Metrics | Record<string, Metrics>
  methodology?: string
}

interface SweepPoint {
  threshold: number
  rf_only?: Metrics
  rf_or_rules?: Metrics
}

interface OptimizationRun {
  id: string
  config_id: string
  run_at: string
  selected_threshold: number | null
  selected_fusion: string | null
  constraints_satisfied: boolean | null
  infeasible_reason: string | null
  val_metrics: MetricBundle | Metrics | null
  test_metrics: MetricBundle | Metrics | null
  sweep_results: SweepPoint[] | null
  alternatives: { threshold: number; fusion: string; score: number; metrics: Metrics }[] | null
  methodology_note: string | null
  n_val: number | null
  n_test: number | null
}

interface ComparisonEntry {
  run_id: string
  config_id: string
  config_name: string
  profile: string
  run_at: string | null
  selected_threshold: number | null
  selected_fusion: string | null
  constraints_satisfied: boolean | null
  val_metrics: MetricBundle | Metrics | null
  test_metrics: MetricBundle | Metrics | null
}

type ApiErrorShape = { response?: { data?: { detail?: unknown } } }
const EMPTY_SWEEP: SweepPoint[] = []

function errorMessage(error: unknown): string {
  const detail = (error as ApiErrorShape)?.response?.data?.detail
  if (typeof detail === 'string') return detail
  if (detail !== undefined && detail !== null) return JSON.stringify(detail) || 'Request failed.'
  return error instanceof Error ? error.message : 'Request failed.'
}

function selectedMetrics(bundle: MetricBundle | Metrics | null | undefined): Metrics | null {
  if (!bundle) return null
  if ('selected' in bundle) return bundle.selected ?? null
  return bundle as Metrics
}

function baselineMetrics(bundle: MetricBundle | Metrics | null | undefined): Metrics | null {
  if (!bundle || !('baseline' in bundle)) return null
  const baseline = bundle.baseline
  if (!baseline) return null
  if ('rf_or_rules' in baseline) return baseline.rf_or_rules ?? null
  return baseline as Metrics
}

function formatPercent(value: number | undefined): string {
  return value === undefined ? '—' : `${(value * 100).toFixed(1)}%`
}

const inputClass = 'w-full rounded-lg border border-gray-700 bg-gray-950 px-3 py-2 text-sm text-gray-100 outline-none focus:border-cyan-500'
const buttonClass = 'inline-flex items-center justify-center gap-2 rounded-lg px-3 py-2 text-sm font-medium transition-colors disabled:cursor-not-allowed disabled:opacity-50'

export default function Optimizer() {
  const { user } = useAuth()
  const canEdit = user?.role === 'ADMIN' || user?.role === 'SECURITY_ANALYST'
  const [configs, setConfigs] = useState<DetectionConfig[]>([])
  const [selectedId, setSelectedId] = useState('')
  const [runs, setRuns] = useState<OptimizationRun[]>([])
  const [comparison, setComparison] = useState<ComparisonEntry[]>([])
  const [loading, setLoading] = useState(true)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [notice, setNotice] = useState('')
  const [showCreate, setShowCreate] = useState(false)
  const [configName, setConfigName] = useState('')
  const [profile, setProfile] = useState('BALANCED')
  const [minRecall, setMinRecall] = useState('')
  const [maxFpr, setMaxFpr] = useState('')
  const [minPrecision, setMinPrecision] = useState('')
  const [thresholdMin, setThresholdMin] = useState('0.30')
  const [thresholdMax, setThresholdMax] = useState('0.95')
  const [thresholdStep, setThresholdStep] = useState('0.01')
  const [datasetPath, setDatasetPath] = useState('')

  const selectedConfig = configs.find(config => config.id === selectedId) ?? null
  const latestRun = runs[0] ?? null
  const latestMetrics = selectedMetrics(latestRun?.test_metrics)
  const latestSweep = latestRun?.sweep_results ?? EMPTY_SWEEP
  const activeSweep = useMemo(() => latestSweep.map(point => {
    const metrics = latestRun?.selected_fusion === 'RF_ONLY' ? point.rf_only : point.rf_or_rules
    return {
      threshold: point.threshold,
      precision: (metrics?.precision ?? 0) * 100,
      recall: (metrics?.recall ?? 0) * 100,
      fpr: (metrics?.fpr ?? 0) * 100,
    }
  }), [latestRun?.selected_fusion, latestSweep])
  const running = runs.some(run => run.constraints_satisfied === null)
  const selectConfig = (id: string) => {
    setRuns([])
    setSelectedId(id)
  }

  const refreshConfigs = useCallback(async () => {
    const nextConfigs = await listConfigs() as DetectionConfig[]
    setConfigs(nextConfigs)
    setSelectedId(current => current && nextConfigs.some(config => config.id === current)
      ? current
      : nextConfigs.find(config => config.is_active)?.id ?? nextConfigs[0]?.id ?? '')
  }, [])

  const refreshComparison = useCallback(async () => {
    const result = await getBaselineComparison() as { comparison?: ComparisonEntry[] }
    setComparison(result.comparison ?? [])
  }, [])

  useEffect(() => {
    let disposed = false
    const load = async () => {
      try {
        const [configResult, comparisonResult] = await Promise.all([
          listConfigs() as Promise<DetectionConfig[]>,
          getBaselineComparison() as Promise<{ comparison?: ComparisonEntry[] }>,
        ])
        if (disposed) return
        setConfigs(configResult)
        setSelectedId(configResult.find(config => config.is_active)?.id ?? configResult[0]?.id ?? '')
        setComparison(comparisonResult.comparison ?? [])
      } catch (loadError) {
        if (!disposed) setError(errorMessage(loadError))
      } finally {
        if (!disposed) setLoading(false)
      }
    }
    void load()
    return () => { disposed = true }
  }, [])

  useEffect(() => {
    if (!selectedId) return
    let disposed = false
    const loadRuns = async () => {
      try {
        const result = await getOptimizationResults(selectedId) as OptimizationRun[]
        if (!disposed) setRuns(result)
      } catch (loadError) {
        if (!disposed) setError(errorMessage(loadError))
      }
    }
    void loadRuns()
    if (!running) return () => { disposed = true }
    const timer = window.setInterval(loadRuns, 4000)
    return () => {
      disposed = true
      window.clearInterval(timer)
    }
  }, [selectedId, running])

  const handleCreateConfig = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault()
    setBusy(true)
    setError('')
    setNotice('')
    try {
      const percent = (value: string) => value.trim() === '' ? undefined : Number(value) / 100
      const created = await createConfig({
        name: configName.trim(),
        profile,
        min_recall: percent(minRecall),
        max_fpr: percent(maxFpr),
        min_precision: percent(minPrecision),
      }) as DetectionConfig
      await refreshConfigs()
      setRuns([])
      setSelectedId(created.id)
      setConfigName('')
      setShowCreate(false)
      setNotice(`Profile "${created.name}" created. Run optimization to resolve its threshold.`)
    } catch (createError) {
      setError(errorMessage(createError))
    } finally {
      setBusy(false)
    }
  }

  const handleRun = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault()
    if (!selectedConfig) return
    if (Number(thresholdMin) > Number(thresholdMax)) {
      setError('Minimum threshold must not be greater than maximum threshold.')
      return
    }
    setBusy(true)
    setError('')
    setNotice('')
    try {
      const run = await runOptimization({
        config_id: selectedConfig.id,
        dataset_path: datasetPath.trim() || undefined,
        threshold_range_min: Number(thresholdMin),
        threshold_range_max: Number(thresholdMax),
        threshold_step: Number(thresholdStep),
      }) as OptimizationRun
      setRuns(previous => [run, ...previous.filter(existing => existing.id !== run.id)])
      setNotice('Optimization started. This page refreshes the run status automatically.')
    } catch (runError) {
      setError(errorMessage(runError))
    } finally {
      setBusy(false)
    }
  }

  const handleActivate = async (config: DetectionConfig) => {
    if (!window.confirm(`Activate "${config.name}" for production detection?`)) return
    setBusy(true)
    setError('')
    setNotice('')
    try {
      await activateConfig(config.id)
      await refreshConfigs()
      setNotice(`"${config.name}" is now active. Detection uses the new configuration immediately.`)
    } catch (activateError) {
      setError(errorMessage(activateError))
    } finally {
      setBusy(false)
    }
  }

  const handleRestoreBaseline = async () => {
    if (!window.confirm('Restore the original baseline configuration (threshold 0.70, OR fusion)?')) return
    setBusy(true)
    setError('')
    setNotice('')
    try {
      await restoreBaseline()
      await refreshConfigs()
      await refreshComparison()
      setNotice('Baseline configuration restored.')
    } catch (restoreError) {
      setError(errorMessage(restoreError))
    } finally {
      setBusy(false)
    }
  }

  const handleDelete = async (config: DetectionConfig) => {
    if (!window.confirm(`Delete the profile "${config.name}" and its optimization history?`)) return
    setBusy(true)
    setError('')
    setNotice('')
    try {
      await deleteConfig(config.id)
      setRuns([])
      await refreshConfigs()
      setNotice(`"${config.name}" deleted.`)
    } catch (deleteError) {
      setError(errorMessage(deleteError))
    } finally {
      setBusy(false)
    }
  }

  if (loading) return <div className="p-6 text-gray-400">Loading optimizer…</div>

  return (
    <div className="mx-auto max-w-[1400px] space-y-6 p-6">
      <header className="flex flex-wrap items-start justify-between gap-4">
        <div>
          <h1 className="flex items-center gap-2 text-2xl font-bold text-white">
            <Gauge className="text-cyan-400" size={25} /> Threshold Optimizer
          </h1>
          <p className="mt-1 max-w-3xl text-sm text-gray-400">
            Evaluate detection thresholds against the labeled dataset, compare with the preserved baseline,
            then explicitly activate a feasible profile.
          </p>
        </div>
        <div className="flex gap-2">
          {canEdit && (
            <button onClick={() => setShowCreate(value => !value)}
              className={`${buttonClass} bg-gray-800 text-gray-100 hover:bg-gray-700`}>
              <WandSparkles size={16} /> {showCreate ? 'Cancel' : 'New profile'}
            </button>
          )}
          {canEdit && (
            <button onClick={handleRestoreBaseline} disabled={busy}
              className={`${buttonClass} border border-amber-700/70 bg-amber-950/40 text-amber-300 hover:bg-amber-900/50`}>
              <RotateCcw size={16} /> Restore baseline
            </button>
          )}
        </div>
      </header>

      {error && <div role="alert" className="rounded-lg border border-red-800 bg-red-950/40 px-4 py-3 text-sm text-red-300">{error}</div>}
      {notice && <div role="status" className="rounded-lg border border-green-800 bg-green-950/30 px-4 py-3 text-sm text-green-300">{notice}</div>}

      {!canEdit && (
        <div className="rounded-lg border border-blue-800 bg-blue-950/30 px-4 py-3 text-sm text-blue-200">
          Read-only access. Creating profiles, running optimization, and activating configurations require the
          SECURITY_ANALYST or ADMIN role.
        </div>
      )}

      {showCreate && canEdit && (
        <form onSubmit={handleCreateConfig} className="space-y-4 rounded-xl border border-gray-700 bg-gray-900 p-5">
          <div>
            <h2 className="font-semibold text-white">Create a requirement profile</h2>
            <p className="mt-1 text-xs text-gray-500">Optional bounds are hard constraints. Leave a bound empty to skip it.</p>
          </div>
          <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
            <label className="space-y-1 text-xs text-gray-400">
              Profile name
              <input required minLength={2} maxLength={128} value={configName} onChange={event => setConfigName(event.target.value)}
                placeholder="e.g. High recall for SWaT" className={inputClass} />
            </label>
            <label className="space-y-1 text-xs text-gray-400">
              Optimization objective
              <select value={profile} onChange={event => setProfile(event.target.value)} className={inputClass}>
                <option value="BALANCED">Balanced</option>
                <option value="HIGH_RECALL">High recall</option>
                <option value="LOW_FP">Low false positives</option>
                <option value="CRITICAL_ASSET">Critical asset</option>
              </select>
            </label>
            {[
              ['Minimum recall (%)', minRecall, setMinRecall],
              ['Maximum false positive rate (%)', maxFpr, setMaxFpr],
              ['Minimum precision (%)', minPrecision, setMinPrecision],
            ].map(([label, value, setter]) => (
              <label key={label as string} className="space-y-1 text-xs text-gray-400">
                {label as string}
                <input type="number" min="0" max="100" step="0.1" value={value as string}
                  onChange={event => (setter as (value: string) => void)(event.target.value)}
                  placeholder="No limit" className={inputClass} />
              </label>
            ))}
          </div>
          <button type="submit" disabled={busy || !configName.trim()}
            className={`${buttonClass} bg-cyan-700 text-white hover:bg-cyan-600`}>
            {busy ? <LoaderCircle size={16} className="animate-spin" /> : <Check size={16} />}
            Create profile
          </button>
        </form>
      )}

      <section className="grid gap-6 xl:grid-cols-[minmax(0,1fr)_minmax(360px,0.85fr)]">
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <h2 className="text-lg font-semibold text-white">Detection profiles</h2>
            <span className="text-xs text-gray-500">{configs.length} profiles</span>
          </div>
          {!configs.length && <p className="rounded-xl border border-gray-800 p-5 text-sm text-gray-500">No detection profiles are available.</p>}
          {configs.map(config => (
            <article key={config.id}
              className={`rounded-xl border p-4 transition-colors ${
                selectedId === config.id ? 'border-cyan-600 bg-cyan-950/20' : 'border-gray-800 bg-gray-900 hover:border-gray-700'
              }`}>
              <div className="flex flex-wrap items-start justify-between gap-3">
                <div>
                  <div className="flex flex-wrap items-center gap-2">
                    <h3 className="font-semibold text-white">{config.name}</h3>
                    {config.is_baseline && <span className="rounded-full border border-gray-700 px-2 py-0.5 text-[10px] text-gray-300">BASELINE</span>}
                    {config.is_active && <span className="rounded-full border border-green-800 bg-green-950/40 px-2 py-0.5 text-[10px] text-green-300">ACTIVE</span>}
                  </div>
                  <p className="mt-1 text-xs text-gray-500">v{config.version} · {config.profile.replace(/_/g, ' ')} objective</p>
                </div>
                <div className="flex items-center gap-2">
                  <button onClick={() => selectConfig(config.id)} aria-pressed={selectedId === config.id}
                    className={`${buttonClass} ${selectedId === config.id ? 'bg-cyan-900/60 text-cyan-200' : 'bg-gray-800 text-gray-300 hover:bg-gray-700'}`}>
                    {selectedId === config.id ? 'Selected' : 'Use profile'}
                  </button>
                  <div className="text-right">
                    <p className="text-[10px] uppercase tracking-wide text-gray-500">Threshold</p>
                    <p className="font-mono text-sm text-cyan-300">{config.threshold === null ? 'Not optimized' : config.threshold.toFixed(3)}</p>
                  </div>
                  {canEdit && !config.is_baseline && !config.is_active && (
                    <button title="Delete profile" onClick={() => void handleDelete(config)}
                      disabled={busy} className="rounded-lg p-2 text-gray-500 hover:bg-red-950/50 hover:text-red-300">
                      <Trash2 size={15} />
                    </button>
                  )}
                </div>
              </div>
              <div className="mt-3 flex flex-wrap gap-2 text-xs text-gray-400">
                {config.min_recall !== null && <span className="rounded bg-gray-800 px-2 py-1">Recall ≥ {formatPercent(config.min_recall)}</span>}
                {config.max_fpr !== null && <span className="rounded bg-gray-800 px-2 py-1">FPR ≤ {formatPercent(config.max_fpr)}</span>}
                {config.min_precision !== null && <span className="rounded bg-gray-800 px-2 py-1">Precision ≥ {formatPercent(config.min_precision)}</span>}
                {config.min_recall === null && config.max_fpr === null && config.min_precision === null &&
                  <span className="rounded bg-gray-800 px-2 py-1">No hard metric constraints</span>}
                <span className="rounded bg-gray-800 px-2 py-1">Fusion: {config.fusion_strategy}</span>
              </div>
            </article>
          ))}
        </div>

        <div className="space-y-4">
          <form onSubmit={handleRun} className="space-y-4 rounded-xl border border-gray-700 bg-gray-900 p-5">
            <div>
              <h2 className="font-semibold text-white">Run threshold search</h2>
              <p className="mt-1 text-xs text-gray-500">
                {selectedConfig ? `Selected: ${selectedConfig.name}` : 'Create or select a profile first.'}
              </p>
            </div>
            <label className="block space-y-1 text-xs text-gray-400">
              Evaluation dataset path (optional)
              <input value={datasetPath} onChange={event => setDatasetPath(event.target.value)}
                placeholder="Default: data/NewTestData.csv (or data/ne_data.csv)" className={inputClass} />
              <span className="block text-[11px] text-gray-600">Path is relative to the project root. Dataset needs a Normal/Attack label column.</span>
            </label>
            <div className="grid grid-cols-3 gap-3">
              {[
                ['Minimum', thresholdMin, setThresholdMin, '0', '1', '0.01'],
                ['Maximum', thresholdMax, setThresholdMax, '0', '1', '0.01'],
                ['Step', thresholdStep, setThresholdStep, '0.001', '0.1', '0.001'],
              ].map(([label, value, setter, min, max, step]) => (
                <label key={label as string} className="space-y-1 text-xs text-gray-400">
                  {label as string}
                  <input required type="number" min={min as string} max={max as string} step={step as string}
                    value={value as string} onChange={event => (setter as (value: string) => void)(event.target.value)}
                    className={inputClass} />
                </label>
              ))}
            </div>
            <button type="submit" disabled={!canEdit || busy || !selectedConfig || selectedConfig.is_baseline || running}
              className={`${buttonClass} w-full bg-cyan-700 text-white hover:bg-cyan-600`}>
              {busy || running ? <LoaderCircle size={16} className="animate-spin" /> : <Play size={16} />}
              {running ? 'Optimization running…' : 'Run optimization'}
            </button>
            {selectedConfig?.is_baseline && <p className="text-xs text-amber-400">The preserved baseline cannot be optimized.</p>}
          </form>

          <div className="rounded-xl border border-gray-800 bg-gray-900 p-5">
            <h2 className="mb-3 flex items-center gap-2 font-semibold text-white">
              <Activity size={16} className="text-cyan-400" /> Latest run
            </h2>
            {!latestRun ? (
              <p className="text-sm text-gray-500">No optimization runs for this profile yet. Select a non-baseline profile and run the search.</p>
            ) : (
              <div className="space-y-4">
                <div className={`flex items-start gap-2 rounded-lg border px-3 py-2 text-sm ${
                  latestRun.constraints_satisfied === null ? 'border-blue-800 bg-blue-950/30 text-blue-200'
                    : latestRun.constraints_satisfied ? 'border-green-800 bg-green-950/30 text-green-200'
                      : 'border-amber-800 bg-amber-950/30 text-amber-200'
                }`}>
                  {latestRun.constraints_satisfied === null ? <LoaderCircle size={17} className="mt-0.5 animate-spin" />
                    : latestRun.constraints_satisfied ? <Check size={17} className="mt-0.5" />
                      : <CircleAlert size={17} className="mt-0.5" />}
                  <span>{latestRun.constraints_satisfied === null ? 'Evaluation is running.'
                    : latestRun.constraints_satisfied ? 'Constraints satisfied. Review held-out test metrics before activation.'
                      : latestRun.infeasible_reason || 'No feasible threshold was found.'}</span>
                </div>
                {latestRun.constraints_satisfied === true && (
                  <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
                    {[
                      ['Threshold', latestRun.selected_threshold?.toFixed(3) ?? '—'],
                      ['Fusion', latestRun.selected_fusion ?? '—'],
                      ['Precision', formatPercent(latestMetrics?.precision)],
                      ['Recall', formatPercent(latestMetrics?.recall)],
                      ['F1', formatPercent(latestMetrics?.f1)],
                      ['FPR', formatPercent(latestMetrics?.fpr)],
                      ['Validation rows', latestRun.n_val?.toLocaleString() ?? '—'],
                      ['Test rows', latestRun.n_test?.toLocaleString() ?? '—'],
                    ].map(([label, value]) => (
                      <div key={label} className="rounded-lg bg-gray-950 p-3">
                        <p className="text-[10px] uppercase tracking-wide text-gray-500">{label}</p>
                        <p className="mt-1 font-semibold text-white">{value}</p>
                      </div>
                    ))}
                  </div>
                )}
                {activeSweep.length > 0 && (
                  <div>
                    <p className="mb-2 text-xs text-gray-400">Validation sweep · {latestRun.selected_fusion === 'RF_ONLY' ? 'RF only' : 'RF + rule OR'}</p>
                    <ResponsiveContainer width="100%" height={190}>
                      <LineChart data={activeSweep}>
                        <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
                        <XAxis dataKey="threshold" type="number" domain={['dataMin', 'dataMax']} stroke="#9ca3af" tick={{ fontSize: 10 }} />
                        <YAxis domain={[0, 100]} stroke="#9ca3af" tick={{ fontSize: 10 }} />
                        <Tooltip contentStyle={{ background: '#111827', border: '1px solid #374151', color: '#fff' }}
                          formatter={(value: number) => [`${value.toFixed(1)}%`]} />
                        <Line type="monotone" dataKey="precision" stroke="#22d3ee" dot={false} strokeWidth={2} />
                        <Line type="monotone" dataKey="recall" stroke="#4ade80" dot={false} strokeWidth={2} />
                        <Line type="monotone" dataKey="fpr" stroke="#fb7185" dot={false} strokeWidth={2} />
                      </LineChart>
                    </ResponsiveContainer>
                    <div className="flex gap-4 text-[11px] text-gray-500">
                      <span className="text-cyan-300">Precision</span><span className="text-green-300">Recall</span><span className="text-rose-300">FPR</span>
                    </div>
                  </div>
                )}
                {latestRun.constraints_satisfied === false && !!latestRun.alternatives?.length && (
                  <div className="text-xs text-gray-400">
                    Best alternatives: {latestRun.alternatives.map(option =>
                      `t=${option.threshold.toFixed(2)} (${option.fusion}, score ${option.score.toFixed(3)})`
                    ).join(' · ')}
                  </div>
                )}
                <p className="text-[11px] text-gray-600">
                  Run {new Date(latestRun.run_at).toLocaleString()} · Results use a chronological 70/15/15 split; the held-out test period is reported separately.
                </p>
                {canEdit && latestRun.constraints_satisfied === true && selectedConfig && !selectedConfig.is_active && (
                  <button onClick={() => void handleActivate(selectedConfig)} disabled={busy}
                    className={`${buttonClass} bg-green-900/60 text-green-200 hover:bg-green-800`}>
                    <ShieldCheck size={15} /> Activate this profile
                  </button>
                )}
              </div>
            )}
          </div>
        </div>
      </section>

      <section className="rounded-xl border border-gray-800 bg-gray-900 p-5">
        <h2 className="mb-3 text-lg font-semibold text-white">Baseline comparison</h2>
        <p className="mb-4 text-xs text-gray-500">Completed evaluations compared with their baseline threshold (0.70, OR fusion).</p>
        {!comparison.length ? <p className="text-sm text-gray-500">No completed comparisons yet.</p> : (
          <div className="overflow-x-auto">
            <table className="w-full min-w-[760px] text-left text-sm">
              <thead className="text-xs uppercase text-gray-500">
                <tr>
                  <th className="pb-3 pr-4">Profile</th><th className="pb-3 pr-4">Threshold</th>
                  <th className="pb-3 pr-4">Fusion</th><th className="pb-3 pr-4">Test F1 (selected / baseline)</th>
                  <th className="pb-3 pr-4">Recall (selected / baseline)</th><th className="pb-3 pr-4">FPR (selected / baseline)</th>
                  <th className="pb-3">Status</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-800">
                {comparison.map(entry => {
                  const metrics = selectedMetrics(entry.test_metrics)
                  const baseline = baselineMetrics(entry.test_metrics)
                  return (
                    <tr key={entry.run_id} className="text-gray-300">
                      <td className="py-3 pr-4">{entry.config_name}<span className="ml-2 text-xs text-gray-600">{entry.profile}</span></td>
                      <td className="py-3 pr-4 font-mono">{entry.selected_threshold?.toFixed(3) ?? '—'}</td>
                      <td className="py-3 pr-4">{entry.selected_fusion ?? '—'}</td>
                      <td className="py-3 pr-4">{formatPercent(metrics?.f1)} / {formatPercent(baseline?.f1)}</td>
                      <td className="py-3 pr-4">{formatPercent(metrics?.recall)} / {formatPercent(baseline?.recall)}</td>
                      <td className="py-3 pr-4">{formatPercent(metrics?.fpr)} / {formatPercent(baseline?.fpr)}</td>
                      <td className="py-3">{entry.constraints_satisfied ? 'Feasible' : 'Infeasible'}</td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>
        )}
      </section>

      <p className="text-xs leading-relaxed text-gray-600">
        The optimizer only evaluates candidate thresholds and the RF-only / RF-plus-rules OR strategies using the
        available labeled CSV; it does not retrain the model. Production behavior changes only after an authorized
        user explicitly activates a feasible profile. Restore baseline to roll back.
      </p>
    </div>
  )
}

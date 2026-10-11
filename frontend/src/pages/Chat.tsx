import { useState, useRef, useEffect } from 'react'
import { useLocation } from 'react-router-dom'
import { sendChat } from '../services/api'
import {
  Send, Bot, User, AlertCircle, RotateCw, Trash2, Sparkles,
  Activity, SearchCheck, ClipboardList, ShieldQuestion, CircleHelp, AlertTriangle,
} from 'lucide-react'

interface Message { role: 'user' | 'assistant'; content: string }
type DetectionContext = Record<string, unknown>

const SUGGESTIONS = [
  'Why was the last detection classified as an attack?',
  'Which rules were triggered most recently?',
  'What should I investigate after a HIGH severity alarm?',
  'Explain the fusion logic used in this system.',
  'What sensors are involved in P2 chemical dosing anomalies?',
]

const FOLLOW_UPS = [
  'Explain the strongest evidence first.',
  'What should I investigate first?',
  'What would distinguish this from a normal reading?',
]

const WELCOME_MESSAGE = 'Hello! I am the ICS Security Assistant. I can help you investigate detections, understand rule violations, and recommend next steps. What would you like to know?\n\nSafety notice: I am an advisory tool only. I cannot and will not control any ICS equipment, PLCs, or actuators.'

const SECTION_ICONS = [Activity, SearchCheck, ClipboardList, AlertTriangle, ShieldQuestion]
const SECTION_COLORS = [
  'border-cyan-800/70 bg-cyan-950/20',
  'border-amber-800/60 bg-amber-950/15',
  'border-sky-900/70 bg-sky-950/15',
  'border-emerald-900/70 bg-emerald-950/15',
  'border-violet-900/70 bg-violet-950/15',
]

function parseSections(content: string): { title: string; body: string }[] {
  const sections: { title: string; body: string[] }[] = []
  for (const line of content.split('\n')) {
    const heading = line.trim().replace(/^#{1,4}\s*/, '').replace(/\*/g, '').replace(/:$/, '')
      .match(/^[1-5]\.\s*(Incident Summary|Suspected Problem|Evidence|Recommended Next Steps|Confidence\s*&\s*Limitations)$/i)
    if (heading) sections.push({ title: heading[1], body: [] })
    else if (sections.length) sections[sections.length - 1].body.push(line)
  }
  return sections.length === 5
    ? sections.map(section => ({ title: section.title, body: section.body.join('\n').trim() }))
    : []
}

function MessageLines({ content }: { content: string }) {
  return (
    <div className="space-y-1.5">
      {content.split('\n').map((line, index) => {
        const trimmed = line.trim()
        if (!trimmed) return null
        if (/^[-*]\s/.test(trimmed)) return (
          <div key={index} className="flex gap-2 pl-1"><span className="text-cyan-400">•</span><span>{trimmed.slice(2).replace(/\*\*/g, '')}</span></div>
        )
        if (/^\d+\.\s/.test(trimmed)) return (
          <div key={index} className="flex gap-2 pl-1"><span className="font-semibold text-cyan-300">{trimmed.match(/^\d+/)?.[0]}.</span><span>{trimmed.replace(/^\d+\.\s/, '').replace(/\*\*/g, '')}</span></div>
        )
        return <p key={index}>{trimmed.replace(/\*\*/g, '')}</p>
      })}
    </div>
  )
}

function AssistantContent({ content }: { content: string }) {
  const sections = parseSections(content)
  if (!sections.length) return <MessageLines content={content} />

  return (
    <div className="space-y-2.5">
      {sections.map((section, index) => {
        const Icon = SECTION_ICONS[index] ?? CircleHelp
        const severity = index === 0 ? section.body.match(/severity:\s*(CRITICAL|HIGH|MEDIUM|LOW)/i)?.[1]?.toUpperCase() : undefined
        const severityColor = severity === 'CRITICAL' || severity === 'HIGH' ? 'text-red-300 border-red-800 bg-red-950/50'
          : severity === 'MEDIUM' ? 'text-amber-300 border-amber-800 bg-amber-950/40'
            : 'text-blue-300 border-blue-800 bg-blue-950/40'
        return (
          <section key={section.title} className={`rounded-xl border px-3 py-2.5 ${SECTION_COLORS[index]}`}>
            <h3 className="mb-1.5 flex flex-wrap items-center gap-2 text-xs font-semibold uppercase tracking-wide text-gray-200">
              <Icon size={14} className="text-cyan-300" /> {section.title}
              {severity && <span className={`rounded-full border px-2 py-0.5 text-[10px] ${severityColor}`}>{severity}</span>}
            </h3>
            <div className="text-[13px] leading-5 text-gray-300"><MessageLines content={section.body} /></div>
          </section>
        )
      })}
    </div>
  )
}

export default function Chat() {
  const location = useLocation()
  const initialDetection = (location.state as { detection?: DetectionContext } | null)?.detection
  const [messages, setMessages] = useState<Message[]>([
    { role: 'assistant', content: WELCOME_MESSAGE }
  ])
  const [input, setInput] = useState(initialDetection
    ? 'Investigate this selected detection using the recorded evidence.'
    : '')
  const [sessionId, setSessionId] = useState<string | undefined>()
  const [loading, setLoading] = useState(false)
  const [errorMessage, setErrorMessage] = useState('')
  const [lastRequest, setLastRequest] = useState('')
  const [detectionContext, setDetectionContext] = useState<DetectionContext | undefined>(initialDetection)
  const bottomRef = useRef<HTMLDivElement>(null)

  useEffect(() => { bottomRef.current?.scrollIntoView({ behavior: 'smooth' }) }, [messages])

  useEffect(() => {
    if (initialDetection) {
      window.history.replaceState({}, document.title, window.location.pathname)
    }
  }, [initialDetection, location.key])

  const send = async (text?: string) => {
    const msg = text || input.trim()
    if (!msg || loading) return
    setErrorMessage('')
    setLastRequest(msg)
    setInput('')
    setMessages(prev => [...prev, { role: 'user', content: msg }])
    setLoading(true)
    try {
      const resp = await sendChat(msg, sessionId, detectionContext)
      setSessionId(resp.session_id)
      setMessages(prev => [...prev, { role: 'assistant', content: resp.reply }])
    } catch (e: any) {
      setErrorMessage(e.response?.data?.detail || 'The assistant could not be reached. Check the backend and try again.')
    } finally {
      setLoading(false)
    }
  }

  const clearConversation = () => {
    setMessages([{ role: 'assistant', content: WELCOME_MESSAGE }])
    setInput('')
    setSessionId(undefined)
    setDetectionContext(undefined)
    setErrorMessage('')
    setLastRequest('')
  }

  return (
    <div className="flex flex-col h-full p-4 md:p-6 max-w-6xl mx-auto w-full">
      <div className="flex items-center justify-between gap-4 mb-5">
        <div>
          <div className="flex items-center gap-3">
            <div className="h-10 w-10 rounded-xl bg-cyan-950/70 border border-cyan-800 flex items-center justify-center">
              <Sparkles size={19} className="text-cyan-300" />
            </div>
            <div>
              <h1 className="text-xl md:text-2xl font-semibold tracking-tight text-white">AI Security Assistant</h1>
              <p className="text-xs text-gray-500 mt-0.5">Investigation support for detections and alarms</p>
            </div>
          </div>
        </div>
        <div className="flex items-center gap-3">
          <span className="hidden sm:flex items-center gap-2 text-xs text-emerald-400"><span className="h-1.5 w-1.5 rounded-full bg-emerald-400" />Ready</span>
          <button onClick={clearConversation} title="Clear conversation" aria-label="Clear conversation"
            className="p-2 text-gray-400 hover:text-white hover:bg-gray-800 border border-transparent hover:border-gray-700 rounded-lg"><Trash2 size={17} /></button>
        </div>
      </div>

      <div className="flex-1 bg-gray-900/80 border border-gray-700/80 rounded-2xl flex flex-col min-h-0 shadow-2xl shadow-black/20 overflow-hidden">
        {detectionContext && (
          <div className="px-5 py-3 border-b border-cyan-900/60 bg-cyan-950/20 flex items-center gap-3">
            <div className="h-7 w-7 rounded-lg bg-cyan-900/70 flex items-center justify-center"><Sparkles size={14} className="text-cyan-300" /></div>
            <div className="min-w-0">
              <p className="text-xs font-medium text-cyan-200">Selected event attached</p>
              <p className="truncate text-xs text-gray-500">
                ID {String(detectionContext.event_id ?? detectionContext.id ?? 'Unavailable')}
                {' · '}{String(detectionContext.final_label ?? 'Detection status unavailable')}
                {' · '}{String(detectionContext.severity ?? 'Severity unavailable')}
              </p>
            </div>
          </div>
        )}
        {/* Messages */}
        <div className="flex-1 overflow-y-auto p-4 md:p-6 space-y-5">
          {messages.map((m, i) => (
            <div key={i} className={`flex gap-3 items-end ${m.role === 'user' ? 'flex-row-reverse' : ''}`}>
              <div className={`w-8 h-8 rounded-xl flex items-center justify-center flex-shrink-0 border ${m.role === 'assistant' ? 'bg-cyan-950 border-cyan-800' : 'bg-gray-800 border-gray-700'}`}>
                {m.role === 'assistant' ? <Bot size={14} className="text-cyan-400" /> : <User size={14} className="text-gray-300" />}
              </div>
              <div className={`${m.role === 'assistant' ? 'w-full max-w-4xl' : 'max-w-3xl'} rounded-2xl px-4 py-3 text-sm leading-6 border ${
                m.role === 'assistant' ? 'bg-gray-800/90 border-gray-700 text-gray-200 rounded-bl-md' : 'bg-cyan-900/40 border-cyan-800/70 text-white rounded-br-md'
              }`}>
                {m.role === 'assistant' ? <AssistantContent content={m.content} /> : m.content}
              </div>
            </div>
          ))}
          {loading && (
            <div className="flex gap-3">
              <div className="w-7 h-7 rounded-full bg-cyan-900 flex items-center justify-center"><Bot size={14} className="text-cyan-400" /></div>
              <div className="bg-gray-800/90 border border-gray-700 rounded-2xl rounded-bl-md px-4 py-3 text-sm text-gray-400"><span className="inline-flex gap-1"><span className="animate-pulse">Thinking</span><span className="animate-pulse">.</span><span className="animate-pulse">.</span><span className="animate-pulse">.</span></span></div>
            </div>
          )}
          {errorMessage && (
            <div className="ml-10 max-w-2xl rounded-lg border border-red-800 bg-red-950/40 px-3 py-2 text-sm text-red-200">
              <p>{errorMessage}</p>
              {lastRequest && <button onClick={() => send(lastRequest)} className="mt-2 inline-flex items-center gap-2 text-red-300 hover:text-white"><RotateCw size={14} /> Try again</button>}
            </div>
          )}
          <div ref={bottomRef} />
        </div>

        {/* Suggestions */}
        {messages.length <= 1 && (
          <div className="px-4 pb-2">
            <p className="text-xs text-gray-500 mb-2">Suggested questions:</p>
            <div className="flex flex-wrap gap-2">
              {SUGGESTIONS.map(s => (
                <button key={s} onClick={() => send(s)}
                  className="text-xs bg-gray-800 hover:bg-gray-700 border border-gray-600 text-gray-300 px-3 py-1.5 rounded-full transition-colors">
                  {s}
                </button>
              ))}
            </div>
          </div>
        )}

        {detectionContext && !loading && messages.length > 1 && (
          <div className="px-4 pb-3">
            <div className="mb-2 flex items-center gap-2 text-xs text-cyan-300"><Sparkles size={13} /> Follow up on the selected event</div>
            <div className="flex flex-wrap gap-2">
            {FOLLOW_UPS.map(question => (
              <button key={question} onClick={() => send(question)}
                className="text-xs bg-cyan-950/50 hover:bg-cyan-900 border border-cyan-800 text-cyan-200 px-3 py-1.5 rounded-full">
                {question}
              </button>
            ))}
            </div>
          </div>
        )}

        {/* Input */}
        <div className="border-t border-gray-700/80 bg-gray-950/30 p-4 md:p-5">
          <div className="flex gap-3">
          <input
            value={input}
            onChange={e => setInput(e.target.value)}
            onKeyDown={e => e.key === 'Enter' && send()}
            placeholder="Ask about a detection, alarm, or investigation…"
            className="flex-1 bg-gray-800/90 border border-gray-700 rounded-xl px-4 py-3 text-white text-sm focus:outline-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500/30 placeholder:text-gray-600"
          />
          <button onClick={() => send()} disabled={loading || !input.trim()}
            title="Send message" aria-label="Send message"
            className="bg-cyan-600 hover:bg-cyan-500 disabled:bg-gray-800 disabled:text-gray-600 text-white rounded-xl px-4 transition-colors">
            <Send size={16} />
          </button>
          </div>
          <p className="text-[11px] text-gray-600 mt-2">Press Enter to send · Responses are advisory and should be verified against authorized procedures.</p>
        </div>
      </div>

      <div className="mt-3 flex items-center gap-2 text-xs text-gray-600">
        <AlertCircle size={12} />
        This assistant is advisory only. Never take operational actions based solely on AI recommendations.
        {!sessionId ? ' Connect an LLM provider in .env for full AI responses.' : ''}
      </div>
    </div>
  )
}

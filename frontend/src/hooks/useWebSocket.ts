import { useEffect, useRef, useState, useCallback } from 'react'

const WS_URL = import.meta.env.VITE_WS_URL || `ws://${window.location.host}/api/v1/ws/monitor`

export function useWebSocket(onMessage: (data: unknown) => void) {
  const ws = useRef<WebSocket | null>(null)
  const [connected, setConnected] = useState(false)

  const connect = useCallback(() => {
    const token = localStorage.getItem('ics_token')
    const url = token ? `${WS_URL}?token=${token}` : WS_URL
    const socket = new WebSocket(url)
    ws.current = socket

    socket.onopen = () => setConnected(true)
    socket.onclose = () => { setConnected(false); setTimeout(connect, 3000) }
    socket.onerror = () => socket.close()
    socket.onmessage = e => { try { onMessage(JSON.parse(e.data)) } catch {} }
  }, [onMessage])

  useEffect(() => {
    connect()
    return () => { ws.current?.close() }
  }, [connect])

  return { connected }
}

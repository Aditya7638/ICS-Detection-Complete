import { useEffect, useRef, useState, useCallback } from 'react'

const WS_URL = import.meta.env.VITE_WS_URL || `ws://${window.location.host}/api/v1/ws/monitor`

export function useWebSocket(onMessage: (data: unknown) => void) {
  const ws = useRef<WebSocket | null>(null)
  const reconnectTimer = useRef<number | null>(null)
  const onMessageRef = useRef(onMessage)
  const active = useRef(false)
  const [connected, setConnected] = useState(false)

  useEffect(() => {
    onMessageRef.current = onMessage
  }, [onMessage])

  const connect = useCallback(function connectSocket() {
    if (!active.current) return
    const token = localStorage.getItem('ics_token')
    const url = token ? `${WS_URL}?token=${token}` : WS_URL
    const socket = new WebSocket(url)
    ws.current = socket

    socket.onopen = () => {
      if (active.current && ws.current === socket) setConnected(true)
    }
    socket.onclose = () => {
      if (!active.current || ws.current !== socket) return
      setConnected(false)
      reconnectTimer.current = window.setTimeout(connectSocket, 3000)
    }
    socket.onerror = () => socket.close()
    socket.onmessage = event => {
      let data: unknown
      try {
        data = JSON.parse(event.data)
      } catch (error) {
        console.error('Received invalid WebSocket message.', error)
        return
      }
      onMessageRef.current(data)
    }
  }, [])

  useEffect(() => {
    active.current = true
    connect()
    return () => {
      active.current = false
      if (reconnectTimer.current !== null) window.clearTimeout(reconnectTimer.current)
      ws.current?.close()
      ws.current = null
    }
  }, [connect])

  return { connected }
}

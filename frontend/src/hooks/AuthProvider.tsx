import { useEffect, useState, type ReactNode } from 'react'
import { login as apiLogin, getCurrentUser } from '../services/api'
import { AuthContext, type User } from './authContext'

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<User | null>(null)
  const [token, setToken] = useState<string | null>(() => localStorage.getItem('ics_token'))
  const [loading, setLoading] = useState(() => Boolean(localStorage.getItem('ics_token')))

  useEffect(() => {
    const storedToken = localStorage.getItem('ics_token')
    if (!storedToken) return

    let active = true
    getCurrentUser()
      .then(currentUser => {
        if (active) setUser(currentUser)
      })
      .catch(() => {
        if (!active) return
        localStorage.removeItem('ics_token')
        setToken(null)
      })
      .finally(() => {
        if (active) setLoading(false)
      })

    return () => { active = false }
  }, [])

  const login = async (username: string, password: string) => {
    setLoading(true)
    try {
      const data = await apiLogin(username, password)
      localStorage.setItem('ics_token', data.access_token)
      const currentUser = await getCurrentUser()
      setUser(currentUser)
      setToken(data.access_token)
    } catch (error) {
      localStorage.removeItem('ics_token')
      setToken(null)
      setUser(null)
      throw error
    } finally {
      setLoading(false)
    }
  }

  const logout = () => {
    localStorage.removeItem('ics_token')
    setToken(null)
    setUser(null)
  }

  return <AuthContext.Provider value={{ user, token, login, logout, loading }}>{children}</AuthContext.Provider>
}

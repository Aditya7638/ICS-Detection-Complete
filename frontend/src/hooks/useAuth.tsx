import { createContext, useContext, useState, useEffect, ReactNode } from 'react'
import { login as apiLogin, getCurrentUser } from '../services/api'

interface User { id: string; username: string; role: string; email: string }
interface AuthCtx { user: User | null; token: string | null; login: (u: string, p: string) => Promise<void>; logout: () => void; loading: boolean }

const Ctx = createContext<AuthCtx>({} as AuthCtx)

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<User | null>(null)
  const [token, setToken] = useState<string | null>(localStorage.getItem('ics_token'))
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    if (token) {
      getCurrentUser().then(setUser).catch(() => { setToken(null); localStorage.removeItem('ics_token') }).finally(() => setLoading(false))
    } else {
      setLoading(false)
    }
  }, [token])

  const login = async (username: string, password: string) => {
    const data = await apiLogin(username, password)
    localStorage.setItem('ics_token', data.access_token)
    setToken(data.access_token)
    const me = await getCurrentUser()
    setUser(me)
  }

  const logout = () => {
    localStorage.removeItem('ics_token')
    setToken(null)
    setUser(null)
  }

  return <Ctx.Provider value={{ user, token, login, logout, loading }}>{children}</Ctx.Provider>
}

export const useAuth = () => useContext(Ctx)

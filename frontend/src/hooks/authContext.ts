import { createContext } from 'react'

export interface User {
  id: string
  username: string
  role: string
  email: string
}

export interface AuthContextValue {
  user: User | null
  token: string | null
  login: (username: string, password: string) => Promise<void>
  logout: () => void
  loading: boolean
}

export const AuthContext = createContext<AuthContextValue | undefined>(undefined)

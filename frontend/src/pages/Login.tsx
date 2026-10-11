import { useState } from 'react'
import { useAuth } from '../hooks/useAuth.ts'
import { Link, useNavigate, useSearchParams } from 'react-router-dom'
import { Shield, AlertCircle } from 'lucide-react'

export default function Login() {
  const { login } = useAuth()
  const navigate = useNavigate()
  const [searchParams] = useSearchParams()
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)
  const registered = searchParams.get('registered') === '1'

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setError('')
    setLoading(true)
    try {
      await login(username, password)
      navigate('/dashboard')
    } catch {
      setError('Invalid username or password.')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="min-h-screen bg-gray-950 flex items-center justify-center">
      <div className="bg-gray-900 border border-gray-700 rounded-xl p-8 w-full max-w-md shadow-2xl">
        <div className="flex items-center gap-3 mb-8">
          <Shield className="text-cyan-400" size={32} />
          <div>
            <h1 className="text-xl font-bold text-white">ICS Detection Platform</h1>
            <p className="text-gray-400 text-sm">Industrial Control System Security</p>
          </div>
        </div>

        {error && (
          <div className="flex items-center gap-2 bg-red-900/30 border border-red-700 rounded-lg p-3 mb-4 text-red-300 text-sm">
            <AlertCircle size={16} /> {error}
          </div>
        )}

        {registered && !error && (
          <div className="bg-emerald-900/30 border border-emerald-700 rounded-lg p-3 mb-4 text-emerald-300 text-sm">
            Account created successfully. Sign in to continue.
          </div>
        )}

        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label className="block text-gray-400 text-sm mb-1">Username</label>
            <input value={username} onChange={e => setUsername(e.target.value)}
              className="w-full bg-gray-800 border border-gray-600 rounded-lg px-3 py-2 text-white focus:outline-none focus:border-cyan-500"
              placeholder="admin" autoComplete="username" required />
          </div>
          <div>
            <label className="block text-gray-400 text-sm mb-1">Password</label>
            <input type="password" value={password} onChange={e => setPassword(e.target.value)}
              className="w-full bg-gray-800 border border-gray-600 rounded-lg px-3 py-2 text-white focus:outline-none focus:border-cyan-500"
              placeholder="••••••••" autoComplete="current-password" required />
          </div>
          <button type="submit" disabled={loading}
            className="w-full bg-cyan-600 hover:bg-cyan-500 disabled:bg-gray-700 text-white rounded-lg py-2 font-medium transition-colors">
            {loading ? 'Signing in…' : 'Sign In'}
          </button>
        </form>

        <p className="mt-6 text-center text-sm text-gray-400">
          New to the platform?{' '}
          <Link to="/register" className="text-cyan-400 hover:text-cyan-300">Create an account</Link>
        </p>

      </div>
    </div>
  )
}

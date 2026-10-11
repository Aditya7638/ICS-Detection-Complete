import { useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { AlertCircle, Shield } from 'lucide-react'
import { register } from '../services/api'

interface ApiErrorShape {
  message?: string
  response?: { data?: { detail?: unknown } }
}

function registrationErrorMessage(error: unknown): string {
  const apiError = error as ApiErrorShape
  const detail = apiError.response?.data?.detail
  if (typeof detail === 'string') return detail
  if (Array.isArray(detail)) {
    return detail.map(item => {
      if (typeof item === 'string') return item
      if (item && typeof item === 'object' && 'msg' in item) return String(item.msg)
      return JSON.stringify(item)
    }).join(' ')
  }
  if (!apiError.response) return 'Unable to reach the server. Check that the backend is running and try again.'
  return apiError.message || 'Unable to create account. Please try again.'
}

export default function Register() {
  const navigate = useNavigate()
  const [username, setUsername] = useState('')
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [confirmPassword, setConfirmPassword] = useState('')
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)

  const handleSubmit = async (event: React.FormEvent) => {
    event.preventDefault()
    setError('')

    if (password !== confirmPassword) {
      setError('Passwords do not match.')
      return
    }
    if (password.length < 9 || !/[^A-Za-z0-9]/.test(password)) {
      setError('Password must be at least 9 characters and contain a special character.')
      return
    }

    setLoading(true)
    try {
      await register(username, email, password)
      navigate('/login?registered=1')
    } catch (requestError) {
      setError(registrationErrorMessage(requestError))
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="min-h-screen bg-gray-950 flex items-center justify-center px-4 py-8">
      <div className="bg-gray-900 border border-gray-700 rounded-xl p-8 w-full max-w-md shadow-2xl">
        <div className="flex items-center gap-3 mb-8">
          <Shield className="text-cyan-400" size={32} />
          <div>
            <h1 className="text-xl font-bold text-white">Create your account</h1>
            <p className="text-gray-400 text-sm">Join the ICS Detection Platform</p>
          </div>
        </div>

        {error && (
          <div className="flex items-center gap-2 bg-red-900/30 border border-red-700 rounded-lg p-3 mb-4 text-red-300 text-sm">
            <AlertCircle size={16} /> {error}
          </div>
        )}

        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label className="block text-gray-400 text-sm mb-1">Username</label>
            <input value={username} onChange={event => setUsername(event.target.value)}
              className="w-full bg-gray-800 border border-gray-600 rounded-lg px-3 py-2 text-white focus:outline-none focus:border-cyan-500"
              autoComplete="username" required />
          </div>
          <div>
            <label className="block text-gray-400 text-sm mb-1">Email</label>
            <input type="email" value={email} onChange={event => setEmail(event.target.value)}
              className="w-full bg-gray-800 border border-gray-600 rounded-lg px-3 py-2 text-white focus:outline-none focus:border-cyan-500"
              autoComplete="email" required />
          </div>
          <div>
            <p className="text-xs leading-5 text-gray-500">
              New accounts receive Operator access. Elevated roles must be provisioned by an administrator.
            </p>
          </div>
          <div>
            <label className="block text-gray-400 text-sm mb-1">Password</label>
            <input type="password" value={password} onChange={event => setPassword(event.target.value)}
              className="w-full bg-gray-800 border border-gray-600 rounded-lg px-3 py-2 text-white focus:outline-none focus:border-cyan-500"
              autoComplete="new-password" minLength={9} pattern=".*[^A-Za-z0-9].*"
              title="Use at least 9 characters and one special character" required />
          </div>
          <div>
            <label className="block text-gray-400 text-sm mb-1">Confirm password</label>
            <input type="password" value={confirmPassword} onChange={event => setConfirmPassword(event.target.value)}
              className="w-full bg-gray-800 border border-gray-600 rounded-lg px-3 py-2 text-white focus:outline-none focus:border-cyan-500"
              autoComplete="new-password" minLength={9} pattern=".*[^A-Za-z0-9].*"
              title="Use at least 9 characters and one special character" required />
          </div>
          <button type="submit" disabled={loading}
            className="w-full bg-cyan-600 hover:bg-cyan-500 disabled:bg-gray-700 text-white rounded-lg py-2 font-medium transition-colors">
            {loading ? 'Creating account…' : 'Create account'}
          </button>
        </form>

        <p className="mt-6 text-center text-sm text-gray-400">
          Already have an account?{' '}
          <Link to="/login" className="text-cyan-400 hover:text-cyan-300">Sign in</Link>
        </p>
      </div>
    </div>
  )
}
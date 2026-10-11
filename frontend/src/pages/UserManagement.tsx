import { useCallback, useEffect, useState } from 'react'
import { ShieldCheck, Users } from 'lucide-react'
import { getUsers, updateUserRole } from '../services/api'
import { useAuth } from '../hooks/useAuth'

type UserRole = 'ADMIN' | 'SECURITY_ANALYST' | 'OPERATOR'

interface ManagedUser {
  id: string
  username: string
  email: string
  role: UserRole
  is_active: boolean
  created_at: string
}

interface ApiErrorShape { response?: { data?: { detail?: unknown } } }

function errorMessage(error: unknown): string {
  const detail = (error as ApiErrorShape)?.response?.data?.detail
  if (typeof detail === 'string') return detail
  if (detail !== undefined && detail !== null) return JSON.stringify(detail) || 'Request failed.'
  return error instanceof Error ? error.message : 'Request failed.'
}

const roles: UserRole[] = ['OPERATOR', 'SECURITY_ANALYST', 'ADMIN']

export default function UserManagement() {
  const { user: currentUser } = useAuth()
  const [users, setUsers] = useState<ManagedUser[]>([])
  const [selectedRoles, setSelectedRoles] = useState<Record<string, UserRole>>({})
  const [loading, setLoading] = useState(true)
  const [savingId, setSavingId] = useState('')
  const [error, setError] = useState('')
  const [notice, setNotice] = useState('')

  const loadUsers = useCallback(async () => {
    const result = await getUsers() as ManagedUser[]
    setUsers(result)
    setSelectedRoles(Object.fromEntries(result.map(item => [item.id, item.role])))
  }, [])

  useEffect(() => {
    let active = true
    getUsers()
      .then((result: ManagedUser[]) => {
        if (!active) return
        setUsers(result)
        setSelectedRoles(Object.fromEntries(result.map(item => [item.id, item.role])))
      })
      .catch(loadError => {
        if (active) setError(errorMessage(loadError))
      })
      .finally(() => {
        if (active) setLoading(false)
      })
    return () => { active = false }
  }, [])

  const saveRole = async (target: ManagedUser) => {
    const role = selectedRoles[target.id]
    if (!role || role === target.role || target.id === currentUser?.id) return
    setSavingId(target.id)
    setError('')
    setNotice('')
    try {
      await updateUserRole(target.id, role)
      await loadUsers()
      setNotice(`${target.username}'s role was updated to ${role}.`)
    } catch (saveError) {
      setError(errorMessage(saveError))
    } finally {
      setSavingId('')
    }
  }

  if (currentUser?.role !== 'ADMIN') {
    return <div className="mx-auto max-w-3xl p-6 text-sm text-gray-300">Administrator access is required to manage user roles.</div>
  }

  return (
    <div className="mx-auto max-w-5xl space-y-6 p-6">
      <header>
        <h1 className="flex items-center gap-2 text-2xl font-bold text-white">
          <Users className="text-cyan-400" size={25} /> User Management
        </h1>
        <p className="mt-1 text-sm text-gray-400">Review accounts and assign roles. New registrations remain Operators until an administrator changes their role.</p>
      </header>

      {error && <div role="alert" className="rounded-lg border border-red-800 bg-red-950/40 px-4 py-3 text-sm text-red-300">{error}</div>}
      {notice && <div role="status" className="rounded-lg border border-green-800 bg-green-950/30 px-4 py-3 text-sm text-green-300">{notice}</div>}

      <section className="overflow-hidden rounded-xl border border-gray-800 bg-gray-900">
        <div className="border-b border-gray-800 px-5 py-4">
          <h2 className="flex items-center gap-2 font-semibold text-white"><ShieldCheck size={16} className="text-cyan-300" /> Registered accounts</h2>
        </div>
        {loading ? <p className="p-5 text-sm text-gray-400">Loading accounts…</p>
          : !users.length ? <p className="p-5 text-sm text-gray-400">No user accounts found.</p>
            : <div className="divide-y divide-gray-800">
              {users.map(account => {
                const isSelf = account.id === currentUser.id
                const changed = selectedRoles[account.id] !== account.role
                return (
                  <div key={account.id} className="flex flex-col gap-4 p-5 md:flex-row md:items-center md:justify-between">
                    <div className="min-w-0">
                      <p className="truncate font-medium text-white">{account.username}{isSelf ? ' (you)' : ''}</p>
                      <p className="truncate text-xs text-gray-500">{account.email}</p>
                      <p className="mt-1 text-[11px] text-gray-600">Registered {new Date(account.created_at).toLocaleString()}</p>
                    </div>
                    <div className="flex items-center gap-2">
                      <select value={selectedRoles[account.id] ?? account.role}
                        disabled={isSelf || savingId === account.id}
                        onChange={event => setSelectedRoles(current => ({
                          ...current,
                          [account.id]: event.target.value as UserRole,
                        }))}
                        aria-label={`Role for ${account.username}`}
                        className="rounded-lg border border-gray-700 bg-gray-950 px-3 py-2 text-sm text-gray-100 outline-none focus:border-cyan-500 disabled:opacity-60">
                        {roles.map(role => <option key={role} value={role}>{role.replace(/_/g, ' ')}</option>)}
                      </select>
                      <button type="button" onClick={() => void saveRole(account)}
                        disabled={isSelf || !changed || savingId === account.id}
                        className="rounded-lg bg-cyan-700 px-3 py-2 text-sm font-medium text-white transition-colors hover:bg-cyan-600 disabled:cursor-not-allowed disabled:opacity-40">
                        {savingId === account.id ? 'Saving…' : 'Save role'}
                      </button>
                    </div>
                  </div>
                )
              })}
            </div>}
      </section>

      <p className="text-xs leading-relaxed text-gray-600">
        Role changes are authorized and recorded by the backend. Self-promotion and demotion of the last active administrator are blocked.
      </p>
    </div>
  )
}

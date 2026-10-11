import { useEffect, useState } from 'react'
import { NavLink, Outlet, useNavigate } from 'react-router-dom'
import { Shield, LayoutDashboard, Radio, Bell, BarChart2, Cpu, MessageSquare, LogOut, SlidersHorizontal, ScrollText, Moon, Sun, Menu, X, Users } from 'lucide-react'
import { useAuth } from '../hooks/useAuth'

type Theme = 'dark' | 'light'

function getSavedTheme(): Theme {
  return localStorage.getItem('ics_theme') === 'light' ? 'light' : 'dark'
}

const NAV = [
  { to: '/dashboard', icon: LayoutDashboard, label: 'Dashboard' },
  { to: '/live', icon: Radio, label: 'Live Monitor' },
  { to: '/events', icon: ScrollText, label: 'Event History' },
  { to: '/alarms', icon: Bell, label: 'Alarms' },
  { to: '/analytics', icon: BarChart2, label: 'Analytics' },
  { to: '/model', icon: Cpu, label: 'Model Info' },
  { to: '/optimizer', icon: SlidersHorizontal, label: 'Optimizer' },
  { to: '/users', icon: Users, label: 'User Management', adminOnly: true },
  { to: '/chat', icon: MessageSquare, label: 'AI Assistant' },
]

export default function AppLayout() {
  const { user, logout } = useAuth()
  const navigate = useNavigate()
  const [theme, setTheme] = useState<Theme>(getSavedTheme)
  const [mobileNavOpen, setMobileNavOpen] = useState(false)

  useEffect(() => {
    document.documentElement.dataset.theme = theme
    localStorage.setItem('ics_theme', theme)
  }, [theme])

  const handleLogout = () => { logout(); navigate('/login') }
  const toggleTheme = () => setTheme(current => current === 'dark' ? 'light' : 'dark')

  const roleColor: Record<string, string> = {
    ADMIN: 'text-red-400', SECURITY_ANALYST: 'text-amber-400', OPERATOR: 'text-cyan-400'
  }

  return (
    <div className="flex h-screen overflow-hidden bg-gray-950 text-white">
      {mobileNavOpen && (
        <button type="button" aria-label="Close navigation menu" onClick={() => setMobileNavOpen(false)}
          className="fixed inset-0 z-40 bg-black/60 md:hidden" />
      )}
      {/* Sidebar */}
      <aside className={`fixed inset-y-0 left-0 z-50 flex w-56 flex-shrink-0 flex-col border-r border-gray-800 bg-gray-900 transition-transform md:static md:z-auto md:translate-x-0 ${
        mobileNavOpen ? 'translate-x-0' : '-translate-x-full'
      }`}>
        <div className="p-4 border-b border-gray-800 flex items-center gap-2">
          <Shield className="text-cyan-400" size={22} />
          <span className="font-bold text-sm">ICS Detection</span>
          <button type="button" onClick={() => setMobileNavOpen(false)} aria-label="Close navigation menu"
            className="ml-auto rounded p-1 text-gray-400 hover:bg-gray-800 hover:text-white md:hidden">
            <X size={18} />
          </button>
        </div>

        <nav className="min-h-0 flex-1 space-y-1 overflow-y-auto p-3">
          {NAV.filter(item => !item.adminOnly || user?.role === 'ADMIN').map(({ to, icon: Icon, label }) => (
            <NavLink key={to} to={to}
              className={({ isActive }) =>
                `flex items-center gap-3 px-3 py-2 rounded-lg text-sm transition-colors ${
                  isActive ? 'bg-cyan-900/40 text-cyan-300' : 'text-gray-400 hover:bg-gray-800 hover:text-white'
                }`}
              onClick={() => setMobileNavOpen(false)}>
              <Icon size={16} />
              {label}
            </NavLink>
          ))}
        </nav>

        <div className="shrink-0 space-y-2 border-t border-gray-800 p-3">
          <button type="button" onClick={toggleTheme} aria-label={`Switch to ${theme === 'dark' ? 'light' : 'dark'} theme`}
            aria-pressed={theme === 'light'} title={`Switch to ${theme === 'dark' ? 'light' : 'dark'} theme`}
            className="flex w-full items-center justify-between gap-3 rounded-lg border border-gray-700 bg-gray-800 px-3 py-2.5 text-sm font-medium text-gray-100 transition-colors hover:border-cyan-600 hover:bg-gray-700 focus-visible:outline focus-visible:outline-2 focus-visible:outline-cyan-400">
            <span className="flex items-center gap-2">
              {theme === 'dark' ? <Sun size={16} className="text-amber-300" /> : <Moon size={16} className="text-cyan-300" />}
              {theme === 'dark' ? 'Light theme' : 'Dark theme'}
            </span>
          </button>
          <div className="px-3 py-2 text-xs text-gray-500">
            <p className="text-white text-sm font-medium">{user?.username}</p>
            <p className={roleColor[user?.role || ''] || 'text-gray-400'}>{user?.role}</p>
          </div>
          <button onClick={handleLogout}
            className="flex w-full items-center gap-2 rounded-lg border border-transparent px-3 py-2 text-sm text-gray-300 transition-colors hover:border-red-800 hover:bg-red-950/30 hover:text-red-300 focus-visible:outline focus-visible:outline-2 focus-visible:outline-red-400">
            <LogOut size={16} /> Sign out
          </button>
        </div>
      </aside>

      {/* Main content */}
      <main className="min-w-0 flex-1 overflow-auto bg-gray-950">
        <div className="sticky top-0 z-30 flex items-center gap-3 border-b border-gray-800 bg-gray-900 px-4 py-3 md:hidden">
          <button type="button" onClick={() => setMobileNavOpen(true)} aria-label="Open navigation menu"
            aria-expanded={mobileNavOpen}
            className="rounded-lg border border-gray-700 bg-gray-800 p-2 text-gray-200 hover:border-cyan-600 hover:text-white">
            <Menu size={18} />
          </button>
          <span className="text-sm font-semibold text-white">ICS Detection</span>
        </div>
        <Outlet />
      </main>
    </div>
  )
}

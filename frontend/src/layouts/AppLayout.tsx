import { NavLink, Outlet, useNavigate } from 'react-router-dom'
import { Shield, LayoutDashboard, Radio, Bell, BarChart2, Cpu, MessageSquare, LogOut, SlidersHorizontal, ScrollText } from 'lucide-react'
import { useAuth } from '../hooks/useAuth'

const NAV = [
  { to: '/dashboard', icon: LayoutDashboard, label: 'Dashboard' },
  { to: '/live', icon: Radio, label: 'Live Monitor' },
  { to: '/events', icon: ScrollText, label: 'Event History' },
  { to: '/alarms', icon: Bell, label: 'Alarms' },
  { to: '/analytics', icon: BarChart2, label: 'Analytics' },
  { to: '/model', icon: Cpu, label: 'Model Info' },
  { to: '/optimizer', icon: SlidersHorizontal, label: 'Optimizer' },
  { to: '/chat', icon: MessageSquare, label: 'AI Assistant' },
]

export default function AppLayout() {
  const { user, logout } = useAuth()
  const navigate = useNavigate()

  const handleLogout = () => { logout(); navigate('/login') }

  const roleColor: Record<string, string> = {
    ADMIN: 'text-red-400', SECURITY_ANALYST: 'text-amber-400', OPERATOR: 'text-cyan-400'
  }

  return (
    <div className="flex h-screen bg-gray-950 text-white overflow-hidden">
      {/* Sidebar */}
      <aside className="w-56 flex-shrink-0 bg-gray-900 border-r border-gray-800 flex flex-col">
        <div className="p-4 border-b border-gray-800 flex items-center gap-2">
          <Shield className="text-cyan-400" size={22} />
          <span className="font-bold text-sm">ICS Detection</span>
        </div>

        <nav className="flex-1 p-3 space-y-1">
          {NAV.map(({ to, icon: Icon, label }) => (
            <NavLink key={to} to={to}
              className={({ isActive }) =>
                `flex items-center gap-3 px-3 py-2 rounded-lg text-sm transition-colors ${
                  isActive ? 'bg-cyan-900/40 text-cyan-300' : 'text-gray-400 hover:bg-gray-800 hover:text-white'
                }`}>
              <Icon size={16} />
              {label}
            </NavLink>
          ))}
        </nav>

        <div className="p-3 border-t border-gray-800">
          <div className="px-3 py-2 text-xs text-gray-500">
            <p className="text-white text-sm font-medium">{user?.username}</p>
            <p className={roleColor[user?.role || ''] || 'text-gray-400'}>{user?.role}</p>
          </div>
          <button onClick={handleLogout}
            className="w-full flex items-center gap-2 px-3 py-2 text-sm text-gray-400 hover:text-red-400 hover:bg-gray-800 rounded-lg transition-colors">
            <LogOut size={16} /> Sign out
          </button>
        </div>
      </aside>

      {/* Main content */}
      <main className="flex-1 overflow-auto bg-gray-950">
        <Outlet />
      </main>
    </div>
  )
}

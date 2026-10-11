import { lazy, Suspense } from 'react'
import { BrowserRouter, Routes, Route, Navigate, Link } from 'react-router-dom'
import { AuthProvider } from './hooks/AuthProvider'
import { useAuth } from './hooks/useAuth'
import AppLayout from './layouts/AppLayout'

const Login = lazy(() => import('./pages/Login'))
const Register = lazy(() => import('./pages/Register'))
const Dashboard = lazy(() => import('./pages/Dashboard'))
const Live = lazy(() => import('./pages/Live'))
const Alarms = lazy(() => import('./pages/Alarms'))
const Analytics = lazy(() => import('./pages/Analytics'))
const ModelInfo = lazy(() => import('./pages/ModelInfo'))
const Chat = lazy(() => import('./pages/Chat'))
const Optimizer = lazy(() => import('./pages/Optimizer'))
const Events = lazy(() => import('./pages/Events'))

function ProtectedRoute({ children }: { children: React.ReactNode }) {
  const { user, loading } = useAuth()
  if (loading) return <div className="min-h-screen bg-gray-950 flex items-center justify-center text-gray-400">Loading…</div>
  if (!user) return <Navigate to="/login" replace />
  return <>{children}</>
}

function NotFound() {
  return (
    <main className="flex min-h-screen flex-col items-center justify-center gap-3 bg-gray-950 px-4 text-center text-white">
      <h1 className="text-3xl font-bold">Page not found</h1>
      <p className="text-sm text-gray-400">The address may be incorrect or the page may have moved.</p>
      <Link to="/dashboard" className="rounded-lg bg-cyan-700 px-4 py-2 text-sm font-medium text-white hover:bg-cyan-600">
        Return to dashboard
      </Link>
    </main>
  )
}

function AppRoutes() {
  const { user } = useAuth()
  return (
    <Suspense fallback={<div className="flex min-h-screen items-center justify-center bg-gray-950 text-sm text-gray-400">Loading page…</div>}>
      <Routes>
        <Route path="/login" element={user ? <Navigate to="/dashboard" replace /> : <Login />} />
        <Route path="/register" element={user ? <Navigate to="/dashboard" replace /> : <Register />} />
        <Route path="/" element={<ProtectedRoute><AppLayout /></ProtectedRoute>}>
          <Route index element={<Navigate to="/dashboard" replace />} />
          <Route path="dashboard" element={<Dashboard />} />
          <Route path="live" element={<Live />} />
          <Route path="events" element={<Events />} />
          <Route path="alarms" element={<Alarms />} />
          <Route path="analytics" element={<Analytics />} />
          <Route path="model" element={<ModelInfo />} />
          <Route path="chat" element={<Chat />} />
          <Route path="optimizer" element={<Optimizer />} />
        </Route>
        <Route path="*" element={<NotFound />} />
      </Routes>
    </Suspense>
  )
}

export default function App() {
  return (
    <BrowserRouter>
      <AuthProvider>
        <AppRoutes />
      </AuthProvider>
    </BrowserRouter>
  )
}

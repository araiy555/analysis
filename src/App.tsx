import React, { useState, useEffect } from 'react'
import { Routes, Route, NavLink, useNavigate } from 'react-router-dom'
import {
  LayoutDashboard, FileSearch, Globe, Cpu, Brain, FileText,
  Settings, Shield, ChevronRight, Circle, Code2
} from 'lucide-react'
import Dashboard from './components/Dashboard'
import StaticAnalysis from './components/StaticAnalysis'
import NetworkAnalysis from './components/NetworkAnalysis'
import MemoryAnalysis from './components/MemoryAnalysis'
import AIAnalysis from './components/AIAnalysis'
import GhidraAnalysis from './components/GhidraAnalysis'
import ReportView from './components/ReportView'
import SettingsPage from './components/Settings'
import axios from 'axios'

const API_BASE = 'http://localhost:8765'

const navItems = [
  { path: '/', icon: LayoutDashboard, label: 'ダッシュボード', exact: true },
  { path: '/static', icon: FileSearch, label: '静的解析' },
  { path: '/ghidra', icon: Code2, label: 'Ghidra 逆コンパイル' },
  { path: '/network', icon: Globe, label: 'ネットワーク解析' },
  { path: '/memory', icon: Cpu, label: 'メモリ解析' },
  { path: '/ai', icon: Brain, label: 'AI解析' },
  { path: '/reports', icon: FileText, label: 'レポート' },
]

export default function App() {
  const [backendStatus, setBackendStatus] = useState<'connecting' | 'online' | 'offline'>('connecting')
  const [collapsed, setCollapsed] = useState(false)

  useEffect(() => {
    const checkBackend = async () => {
      try {
        await axios.get(`${API_BASE}/health`, { timeout: 3000 })
        setBackendStatus('online')
      } catch {
        setBackendStatus('offline')
      }
    }
    checkBackend()
    const interval = setInterval(checkBackend, 10000)
    return () => clearInterval(interval)
  }, [])

  return (
    <div className="flex h-screen bg-[#0f1117] text-gray-100 overflow-hidden">
      {/* Sidebar */}
      <aside
        className={`flex flex-col flex-shrink-0 bg-[#161b22] border-r border-[#30363d] transition-all duration-200 ${
          collapsed ? 'w-16' : 'w-56'
        }`}
      >
        {/* Logo */}
        <div className="flex items-center gap-3 px-4 py-4 border-b border-[#30363d]">
          <Shield className="text-green-400 flex-shrink-0" size={22} />
          {!collapsed && (
            <div>
              <div className="text-sm font-bold text-green-400 tracking-wider">AppSleuth</div>
              <div className="text-[10px] text-gray-500 tracking-widest">SECURITY TOOLKIT</div>
            </div>
          )}
        </div>

        {/* Nav */}
        <nav className="flex-1 py-3 overflow-y-auto">
          {navItems.map((item) => (
            <NavLink
              key={item.path}
              to={item.path}
              end={item.exact}
              className={({ isActive }) =>
                `flex items-center gap-3 px-4 py-2.5 mx-2 rounded-md text-sm transition-all ${
                  isActive
                    ? 'bg-green-500/10 text-green-400 border border-green-500/20'
                    : 'text-gray-400 hover:text-gray-100 hover:bg-[#21262d]'
                }`
              }
            >
              <item.icon size={16} className="flex-shrink-0" />
              {!collapsed && <span className="truncate">{item.label}</span>}
            </NavLink>
          ))}
        </nav>

        {/* Settings + Status */}
        <div className="border-t border-[#30363d] py-3">
          <NavLink
            to="/settings"
            className={({ isActive }) =>
              `flex items-center gap-3 px-4 py-2.5 mx-2 rounded-md text-sm transition-all ${
                isActive
                  ? 'bg-green-500/10 text-green-400 border border-green-500/20'
                  : 'text-gray-400 hover:text-gray-100 hover:bg-[#21262d]'
              }`
            }
          >
            <Settings size={16} className="flex-shrink-0" />
            {!collapsed && <span>設定</span>}
          </NavLink>

          {/* Backend status */}
          <div className="flex items-center gap-2 px-4 py-2 mx-2 mt-1">
            {backendStatus === 'online' ? (
              <>
                <Circle size={8} className="text-green-400 fill-green-400 pulse-dot" />
                {!collapsed && <span className="text-xs text-gray-500">バックエンド接続中</span>}
              </>
            ) : backendStatus === 'connecting' ? (
              <>
                <Circle size={8} className="text-yellow-400 fill-yellow-400 pulse-dot" />
                {!collapsed && <span className="text-xs text-gray-500">接続中...</span>}
              </>
            ) : (
              <>
                <Circle size={8} className="text-red-400 fill-red-400" />
                {!collapsed && <span className="text-xs text-red-400">バックエンドオフライン</span>}
              </>
            )}
          </div>
        </div>

        {/* Collapse toggle */}
        <button
          onClick={() => setCollapsed(!collapsed)}
          className="flex items-center justify-center py-2 border-t border-[#30363d] text-gray-600 hover:text-gray-300 transition-colors"
        >
          <ChevronRight
            size={14}
            className={`transition-transform duration-200 ${collapsed ? '' : 'rotate-180'}`}
          />
        </button>
      </aside>

      {/* Main content */}
      <main className="flex-1 overflow-hidden flex flex-col">
        <Routes>
          <Route path="/" element={<Dashboard backendStatus={backendStatus} />} />
          <Route path="/static" element={<StaticAnalysis />} />
          <Route path="/ghidra" element={<GhidraAnalysis />} />
          <Route path="/network" element={<NetworkAnalysis />} />
          <Route path="/memory" element={<MemoryAnalysis />} />
          <Route path="/ai" element={<AIAnalysis />} />
          <Route path="/reports" element={<ReportView />} />
          <Route path="/settings" element={<SettingsPage />} />
        </Routes>
      </main>
    </div>
  )
}

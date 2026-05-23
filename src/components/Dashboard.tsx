import React, { useState, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import {
  FileSearch, Globe, Cpu, Brain, TrendingUp, AlertTriangle,
  CheckCircle, Clock, Shield, Zap, Package, Activity
} from 'lucide-react'
import axios from 'axios'

const API_BASE = 'http://localhost:8765'

interface DashboardProps {
  backendStatus: 'connecting' | 'online' | 'offline'
}

const quickActions = [
  {
    icon: FileSearch,
    label: 'APK / EXE 静的解析',
    desc: 'バイナリファイルを解析して脆弱性を検出',
    path: '/static',
    color: 'text-blue-400',
    bg: 'bg-blue-500/10 border-blue-500/20',
  },
  {
    icon: Globe,
    label: 'ネットワーク傍受',
    desc: 'HTTP/S トラフィックをリアルタイム解析',
    path: '/network',
    color: 'text-green-400',
    bg: 'bg-green-500/10 border-green-500/20',
  },
  {
    icon: Cpu,
    label: 'メモリ / Frida',
    desc: 'プロセスにアタッチして動的解析',
    path: '/memory',
    color: 'text-orange-400',
    bg: 'bg-orange-500/10 border-orange-500/20',
  },
  {
    icon: Brain,
    label: 'AI 解析 (Claude)',
    desc: 'AI でコードや脆弱性を自動解析・改善提案',
    path: '/ai',
    color: 'text-purple-400',
    bg: 'bg-purple-500/10 border-purple-500/20',
  },
]

export default function Dashboard({ backendStatus }: DashboardProps) {
  const navigate = useNavigate()
  const [stats, setStats] = useState({ analyses: 0, vulns: 0, traffic: 0 })
  const [recentItems, setRecentItems] = useState<any[]>([])

  useEffect(() => {
    const stored = localStorage.getItem('appsleuth_history')
    if (stored) {
      try {
        const history = JSON.parse(stored)
        setRecentItems(history.slice(0, 5))
        const vulnCount = history.reduce((a: number, h: any) => a + (h.vulnCount || 0), 0)
        setStats({ analyses: history.length, vulns: vulnCount, traffic: 0 })
      } catch {}
    }
  }, [])

  return (
    <div className="h-full overflow-y-auto p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold text-gray-100">セキュリティ解析ダッシュボード</h1>
          <p className="text-sm text-gray-500 mt-0.5">AppSleuth v1.0.0 — Powered by Claude AI</p>
        </div>
        <div className={`flex items-center gap-2 px-3 py-1.5 rounded-full text-xs font-medium border ${
          backendStatus === 'online'
            ? 'bg-green-500/10 text-green-400 border-green-500/20'
            : backendStatus === 'connecting'
            ? 'bg-yellow-500/10 text-yellow-400 border-yellow-500/20'
            : 'bg-red-500/10 text-red-400 border-red-500/20'
        }`}>
          <Activity size={12} />
          {backendStatus === 'online' ? 'バックエンド稼働中' : backendStatus === 'connecting' ? '接続中...' : 'オフライン'}
        </div>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-3 gap-4">
        {[
          { label: '解析済みファイル', value: stats.analyses, icon: Package, color: 'text-blue-400' },
          { label: '検出された脆弱性', value: stats.vulns, icon: AlertTriangle, color: 'text-red-400' },
          { label: 'キャプチャトラフィック', value: `${stats.traffic}`, icon: TrendingUp, color: 'text-green-400' },
        ].map((stat) => (
          <div key={stat.label} className="bg-[#161b22] border border-[#30363d] rounded-lg p-4">
            <div className="flex items-center justify-between">
              <div>
                <div className="text-2xl font-bold text-gray-100">{stat.value}</div>
                <div className="text-xs text-gray-500 mt-1">{stat.label}</div>
              </div>
              <stat.icon size={24} className={stat.color} />
            </div>
          </div>
        ))}
      </div>

      {/* Quick Actions */}
      <div>
        <h2 className="text-sm font-semibold text-gray-400 uppercase tracking-wider mb-3">クイックスタート</h2>
        <div className="grid grid-cols-2 gap-3">
          {quickActions.map((action) => (
            <button
              key={action.path}
              onClick={() => navigate(action.path)}
              className={`flex items-start gap-4 p-4 rounded-lg border cursor-pointer text-left transition-all hover:scale-[1.01] active:scale-[0.99] ${action.bg}`}
            >
              <action.icon size={22} className={`${action.color} flex-shrink-0 mt-0.5`} />
              <div>
                <div className={`text-sm font-semibold ${action.color}`}>{action.label}</div>
                <div className="text-xs text-gray-500 mt-1">{action.desc}</div>
              </div>
            </button>
          ))}
        </div>
      </div>

      {/* Recent analyses */}
      {recentItems.length > 0 && (
        <div>
          <h2 className="text-sm font-semibold text-gray-400 uppercase tracking-wider mb-3">最近の解析</h2>
          <div className="bg-[#161b22] border border-[#30363d] rounded-lg overflow-hidden">
            {recentItems.map((item, i) => (
              <div
                key={i}
                className="flex items-center justify-between px-4 py-3 border-b border-[#30363d] last:border-0 hover:bg-[#1c2230] transition-colors"
              >
                <div className="flex items-center gap-3">
                  <FileSearch size={14} className="text-gray-500" />
                  <div>
                    <div className="text-sm text-gray-200">{item.name}</div>
                    <div className="text-xs text-gray-500">{item.type} · {item.date}</div>
                  </div>
                </div>
                {item.vulnCount > 0 ? (
                  <span className="text-xs px-2 py-0.5 rounded-full bg-red-900/30 text-red-400 border border-red-700/50">
                    {item.vulnCount} 件の脆弱性
                  </span>
                ) : (
                  <span className="text-xs px-2 py-0.5 rounded-full bg-green-900/30 text-green-400 border border-green-700/50">
                    クリーン
                  </span>
                )}
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Feature highlights */}
      <div>
        <h2 className="text-sm font-semibold text-gray-400 uppercase tracking-wider mb-3">機能一覧</h2>
        <div className="grid grid-cols-2 gap-2">
          {[
            'APK 逆コンパイル & 権限解析',
            'Windows PE / EXE 解析',
            'macOS Mach-O バイナリ解析',
            'HTTP/HTTPS プロキシ傍受',
            'Frida 動的インストゥルメンテーション',
            'Claude AI による自動脆弱性解析',
            '証明書・署名検証',
            'HTML/JSON レポート生成',
          ].map((f) => (
            <div key={f} className="flex items-center gap-2 text-xs text-gray-400 py-1">
              <CheckCircle size={12} className="text-green-400 flex-shrink-0" />
              {f}
            </div>
          ))}
        </div>
      </div>

      {/* Backend offline warning */}
      {backendStatus === 'offline' && (
        <div className="bg-red-900/20 border border-red-700/50 rounded-lg p-4">
          <div className="flex items-center gap-2 text-red-400 font-semibold text-sm mb-1">
            <AlertTriangle size={16} />
            バックエンドに接続できません
          </div>
          <div className="text-xs text-gray-400">
            Python バックエンドが起動していません。<br />
            <code className="bg-gray-800 px-1 rounded">cd backend && pip install -r requirements.txt && python main.py</code> を実行してください。
          </div>
        </div>
      )}
    </div>
  )
}

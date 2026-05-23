import React, { useState, useEffect, useRef } from 'react'
import axios from 'axios'
import {
  Play, Square, Globe, Filter, Download, RefreshCw,
  ChevronRight, Lock, Unlock, Clock, ArrowUpDown, Search
} from 'lucide-react'

const API_BASE = 'http://localhost:8765'

interface TrafficEntry {
  id: string
  method: string
  host: string
  path: string
  status: number
  size: number
  duration: number
  timestamp: string
  request_headers: Record<string, string>
  response_headers: Record<string, string>
  request_body: string
  response_body: string
  is_https: boolean
}

const methodColors: Record<string, string> = {
  GET: 'text-green-400',
  POST: 'text-blue-400',
  PUT: 'text-yellow-400',
  DELETE: 'text-red-400',
  PATCH: 'text-purple-400',
  OPTIONS: 'text-gray-400',
  HEAD: 'text-gray-400',
}

function statusColor(status: number) {
  if (status >= 500) return 'text-red-400'
  if (status >= 400) return 'text-orange-400'
  if (status >= 300) return 'text-yellow-400'
  if (status >= 200) return 'text-green-400'
  return 'text-gray-400'
}

export default function NetworkAnalysis() {
  const [running, setRunning] = useState(false)
  const [proxyHost, setProxyHost] = useState('127.0.0.1')
  const [proxyPort, setProxyPort] = useState('8080')
  const [sslIntercept, setSslIntercept] = useState(true)
  const [traffic, setTraffic] = useState<TrafficEntry[]>([])
  const [selected, setSelected] = useState<TrafficEntry | null>(null)
  const [filter, setFilter] = useState('')
  const [methodFilter, setMethodFilter] = useState('ALL')
  const [detailTab, setDetailTab] = useState<'request' | 'response'>('request')
  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null)

  const startProxy = async () => {
    try {
      await axios.post(`${API_BASE}/proxy/start`, {
        host: proxyHost,
        port: parseInt(proxyPort),
        ssl_intercept: sslIntercept,
      })
      setRunning(true)
      setTraffic([])
      pollRef.current = setInterval(fetchTraffic, 1500)
    } catch (err: any) {
      alert(`プロキシ起動エラー: ${err.response?.data?.detail || err.message}`)
    }
  }

  const stopProxy = async () => {
    try {
      await axios.post(`${API_BASE}/proxy/stop`)
      setRunning(false)
      if (pollRef.current) clearInterval(pollRef.current)
    } catch {}
  }

  const fetchTraffic = async () => {
    try {
      const res = await axios.get(`${API_BASE}/proxy/traffic`)
      setTraffic(res.data)
    } catch {}
  }

  useEffect(() => {
    return () => {
      if (pollRef.current) clearInterval(pollRef.current)
    }
  }, [])

  const filtered = traffic.filter((t) => {
    const matchText =
      filter === '' ||
      t.host.toLowerCase().includes(filter.toLowerCase()) ||
      t.path.toLowerCase().includes(filter.toLowerCase())
    const matchMethod = methodFilter === 'ALL' || t.method === methodFilter
    return matchText && matchMethod
  })

  const exportHAR = () => {
    const har = {
      log: {
        version: '1.2',
        creator: { name: 'AppSleuth', version: '1.0.0' },
        entries: traffic.map((t) => ({
          startedDateTime: t.timestamp,
          time: t.duration,
          request: {
            method: t.method,
            url: `${t.is_https ? 'https' : 'http'}://${t.host}${t.path}`,
            headers: Object.entries(t.request_headers).map(([n, v]) => ({ name: n, value: v })),
            postData: t.request_body ? { mimeType: 'text/plain', text: t.request_body } : undefined,
          },
          response: {
            status: t.status,
            headers: Object.entries(t.response_headers).map(([n, v]) => ({ name: n, value: v })),
            content: { size: t.size, text: t.response_body },
          },
        })),
      },
    }
    const blob = new Blob([JSON.stringify(har, null, 2)], { type: 'application/json' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = 'traffic.har'
    a.click()
    URL.revokeObjectURL(url)
  }

  return (
    <div className="h-full flex flex-col overflow-hidden">
      {/* Header */}
      <div className="flex items-center justify-between px-6 py-4 border-b border-[#30363d] flex-shrink-0">
        <div className="flex items-center gap-3">
          <Globe size={18} className="text-green-400" />
          <h2 className="text-base font-semibold text-gray-100">ネットワーク解析</h2>
          {running && (
            <span className="flex items-center gap-1.5 text-xs px-2 py-0.5 rounded-full bg-green-900/30 text-green-400 border border-green-700/50">
              <span className="w-1.5 h-1.5 rounded-full bg-green-400 pulse-dot inline-block" />
              プロキシ稼働中
            </span>
          )}
        </div>
        <div className="flex items-center gap-2">
          {traffic.length > 0 && (
            <button
              onClick={exportHAR}
              className="flex items-center gap-2 px-3 py-1.5 text-sm bg-[#21262d] hover:bg-[#30363d] text-gray-300 rounded-md border border-[#30363d] transition-colors"
            >
              <Download size={14} />
              HAR エクスポート
            </button>
          )}
          {!running ? (
            <button
              onClick={startProxy}
              className="flex items-center gap-2 px-4 py-1.5 text-sm bg-green-600 hover:bg-green-500 text-white rounded-md font-medium transition-colors"
            >
              <Play size={14} />
              プロキシ開始
            </button>
          ) : (
            <button
              onClick={stopProxy}
              className="flex items-center gap-2 px-4 py-1.5 text-sm bg-red-700 hover:bg-red-600 text-white rounded-md font-medium transition-colors"
            >
              <Square size={14} />
              停止
            </button>
          )}
        </div>
      </div>

      {/* Proxy config */}
      <div className="flex items-center gap-4 px-6 py-3 bg-[#161b22] border-b border-[#30363d] flex-shrink-0">
        <div className="flex items-center gap-2">
          <label className="text-xs text-gray-500">ホスト</label>
          <input
            type="text"
            value={proxyHost}
            onChange={(e) => setProxyHost(e.target.value)}
            disabled={running}
            className="px-2 py-1 bg-[#21262d] border border-[#30363d] rounded text-xs text-gray-200 w-28 disabled:opacity-50"
          />
        </div>
        <div className="flex items-center gap-2">
          <label className="text-xs text-gray-500">ポート</label>
          <input
            type="text"
            value={proxyPort}
            onChange={(e) => setProxyPort(e.target.value)}
            disabled={running}
            className="px-2 py-1 bg-[#21262d] border border-[#30363d] rounded text-xs text-gray-200 w-16 disabled:opacity-50"
          />
        </div>
        <label className="flex items-center gap-2 cursor-pointer">
          <input
            type="checkbox"
            checked={sslIntercept}
            onChange={(e) => setSslIntercept(e.target.checked)}
            disabled={running}
            className="accent-green-400"
          />
          <span className="text-xs text-gray-400">SSL インターセプト</span>
          {sslIntercept ? <Lock size={12} className="text-green-400" /> : <Unlock size={12} className="text-gray-500" />}
        </label>
        <div className="ml-auto text-xs text-gray-600">
          デバイスのプロキシを <code className="bg-[#21262d] px-1 rounded">{proxyHost}:{proxyPort}</code> に設定してください
        </div>
      </div>

      {/* Traffic area */}
      <div className="flex-1 flex overflow-hidden">
        {/* Traffic list */}
        <div className="flex flex-col flex-1 overflow-hidden border-r border-[#30363d]">
          {/* Filter bar */}
          <div className="flex items-center gap-2 px-3 py-2 border-b border-[#30363d] bg-[#161b22]">
            <Search size={13} className="text-gray-500" />
            <input
              type="text"
              placeholder="ホスト / パスで絞り込み..."
              value={filter}
              onChange={(e) => setFilter(e.target.value)}
              className="flex-1 bg-transparent text-xs text-gray-200 placeholder-gray-600 outline-none"
            />
            <select
              value={methodFilter}
              onChange={(e) => setMethodFilter(e.target.value)}
              className="text-xs bg-[#21262d] border border-[#30363d] rounded px-2 py-1 text-gray-300"
            >
              {['ALL', 'GET', 'POST', 'PUT', 'DELETE', 'PATCH'].map((m) => (
                <option key={m}>{m}</option>
              ))}
            </select>
            <span className="text-xs text-gray-600">{filtered.length} 件</span>
          </div>

          {/* Table header */}
          <div className="grid grid-cols-[60px_1fr_2fr_60px_70px_70px] gap-2 px-3 py-2 text-xs text-gray-600 border-b border-[#30363d] bg-[#161b22]">
            <span>メソッド</span>
            <span>ホスト</span>
            <span>パス</span>
            <span className="text-right">ステータス</span>
            <span className="text-right">サイズ</span>
            <span className="text-right">時間</span>
          </div>

          {/* Traffic rows */}
          <div className="flex-1 overflow-y-auto">
            {filtered.length === 0 && (
              <div className="flex items-center justify-center h-full text-sm text-gray-600">
                {running ? 'トラフィックを待機中...' : 'プロキシを開始してください'}
              </div>
            )}
            {filtered.map((t) => (
              <button
                key={t.id}
                onClick={() => setSelected(t)}
                className={`w-full grid grid-cols-[60px_1fr_2fr_60px_70px_70px] gap-2 px-3 py-1.5 text-xs border-b border-[#30363d]/50 text-left transition-colors ${
                  selected?.id === t.id ? 'bg-blue-900/20' : 'hover:bg-[#21262d]'
                }`}
              >
                <span className={`font-mono font-semibold ${methodColors[t.method] || 'text-gray-400'}`}>
                  {t.method}
                </span>
                <span className="text-gray-300 truncate">{t.host}</span>
                <span className="text-gray-500 truncate">{t.path}</span>
                <span className={`text-right font-mono ${statusColor(t.status)}`}>{t.status}</span>
                <span className="text-right text-gray-500">{t.size > 1024 ? `${(t.size / 1024).toFixed(1)}K` : `${t.size}B`}</span>
                <span className="text-right text-gray-500">{t.duration}ms</span>
              </button>
            ))}
          </div>
        </div>

        {/* Detail panel */}
        {selected && (
          <div className="w-96 flex flex-col overflow-hidden bg-[#161b22]">
            <div className="flex items-center justify-between px-3 py-2 border-b border-[#30363d]">
              <div className="flex">
                {(['request', 'response'] as const).map((t) => (
                  <button
                    key={t}
                    onClick={() => setDetailTab(t)}
                    className={`px-3 py-1 text-xs rounded-sm transition-colors ${
                      detailTab === t ? 'bg-[#21262d] text-gray-100' : 'text-gray-500 hover:text-gray-300'
                    }`}
                  >
                    {t === 'request' ? 'リクエスト' : 'レスポンス'}
                  </button>
                ))}
              </div>
              <button onClick={() => setSelected(null)} className="text-gray-600 hover:text-gray-300 text-xs">✕</button>
            </div>
            <div className="flex-1 overflow-y-auto p-3 space-y-3">
              <div className="text-xs font-semibold text-gray-500 uppercase">ヘッダー</div>
              <div className="bg-[#21262d] rounded p-2 font-mono text-xs space-y-0.5">
                {Object.entries(
                  detailTab === 'request' ? selected.request_headers : selected.response_headers
                ).map(([k, v]) => (
                  <div key={k}>
                    <span className="text-blue-400">{k}</span>
                    <span className="text-gray-500">: </span>
                    <span className="text-gray-300">{v}</span>
                  </div>
                ))}
              </div>
              {(detailTab === 'request' ? selected.request_body : selected.response_body) && (
                <>
                  <div className="text-xs font-semibold text-gray-500 uppercase">ボディ</div>
                  <div className="bg-[#0a0d14] rounded p-2 font-mono text-xs text-gray-300 whitespace-pre-wrap break-all max-h-48 overflow-y-auto">
                    {detailTab === 'request' ? selected.request_body : selected.response_body}
                  </div>
                </>
              )}
            </div>
          </div>
        )}
      </div>
    </div>
  )
}

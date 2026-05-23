import React, { useState, useEffect, useRef, useCallback } from 'react'
import axios from 'axios'
import {
  Globe, Play, Square, Download, Search, Lock, Unlock,
  Send, Plus, Trash2, ToggleLeft, ToggleRight, Edit3,
  ChevronRight, ChevronDown, Copy, AlertTriangle, CheckCircle,
  Pause, SkipForward, X, RefreshCw, Filter, Shield
} from 'lucide-react'

const API_BASE = 'http://localhost:8765'
const WS_URL = 'ws://localhost:8765/ws/proxy'

type Tab = 'traffic' | 'intercept' | 'repeater' | 'rules'

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

interface InterceptedFlow {
  id: string
  method: string
  host: string
  path: string
  is_https: boolean
  request_headers: Record<string, string>
  request_body: string
  timestamp: string
}

interface Rule {
  id: string
  name: string
  phase: string
  target: string
  header_name: string
  match: string
  replace: string
  enabled: boolean
}

const methodColors: Record<string, string> = {
  GET: 'text-green-400', POST: 'text-blue-400', PUT: 'text-yellow-400',
  DELETE: 'text-red-400', PATCH: 'text-purple-400', OPTIONS: 'text-gray-500',
  HEAD: 'text-gray-500',
}
const statusColor = (s: number) =>
  s >= 500 ? 'text-red-400' : s >= 400 ? 'text-orange-400' : s >= 300 ? 'text-yellow-400' : s >= 200 ? 'text-green-400' : 'text-gray-400'

function TabBtn({ active, onClick, children }: { active: boolean; onClick: () => void; children: React.ReactNode }) {
  return (
    <button onClick={onClick} className={`px-4 py-2 text-sm border-b-2 transition-colors whitespace-nowrap ${
      active ? 'border-green-400 text-green-400' : 'border-transparent text-gray-500 hover:text-gray-300'}`}>
      {children}
    </button>
  )
}

export default function NetworkAnalysis() {
  const [tab, setTab] = useState<Tab>('traffic')
  const [running, setRunning] = useState(false)
  const [proxyHost, setProxyHost] = useState('127.0.0.1')
  const [proxyPort, setProxyPort] = useState('8080')
  const [sslIntercept, setSslIntercept] = useState(true)

  // Traffic
  const [traffic, setTraffic] = useState<TrafficEntry[]>([])
  const [selectedFlow, setSelectedFlow] = useState<TrafficEntry | null>(null)
  const [trafficFilter, setTrafficFilter] = useState('')
  const [methodFilter, setMethodFilter] = useState('ALL')
  const [detailTab, setDetailTab] = useState<'req' | 'resp'>('req')
  const wsRef = useRef<WebSocket | null>(null)

  // Intercept
  const [interceptEnabled, setInterceptEnabled] = useState(false)
  const [interceptFilter, setInterceptFilter] = useState('')
  const [interceptQueue, setInterceptQueue] = useState<InterceptedFlow[]>([])
  const [selectedIntercept, setSelectedIntercept] = useState<InterceptedFlow | null>(null)
  const [editedHeaders, setEditedHeaders] = useState('')
  const [editedBody, setEditedBody] = useState('')
  const interceptPollRef = useRef<ReturnType<typeof setInterval> | null>(null)

  // Repeater
  const [repeaterMethod, setRepeaterMethod] = useState('GET')
  const [repeaterHost, setRepeaterHost] = useState('')
  const [repeaterPath, setRepeaterPath] = useState('/')
  const [repeaterHttps, setRepeaterHttps] = useState(false)
  const [repeaterHeaders, setRepeaterHeaders] = useState('User-Agent: AppSleuth/1.0\nAccept: */*')
  const [repeaterBody, setRepeaterBody] = useState('')
  const [repeaterResponse, setRepeaterResponse] = useState<any>(null)
  const [repeaterLoading, setRepeaterLoading] = useState(false)

  // Rules
  const [rules, setRules] = useState<Rule[]>([])
  const [showRuleForm, setShowRuleForm] = useState(false)
  const [newRule, setNewRule] = useState<Partial<Rule>>({ phase: 'both', target: 'body', enabled: true })

  // ── Proxy control ────────────────────────────────────────────────────────────

  const startProxy = async () => {
    try {
      await axios.post(`${API_BASE}/proxy/start`, { host: proxyHost, port: parseInt(proxyPort), ssl_intercept: sslIntercept })
      setRunning(true)
      setTraffic([])
      connectWS()
    } catch (e: any) {
      alert(`起動エラー: ${e.response?.data?.detail || e.message}`)
    }
  }

  const stopProxy = async () => {
    try {
      await axios.post(`${API_BASE}/proxy/stop`)
    } catch {}
    setRunning(false)
    setInterceptEnabled(false)
    if (wsRef.current) { wsRef.current.close(); wsRef.current = null }
    if (interceptPollRef.current) clearInterval(interceptPollRef.current)
  }

  const connectWS = useCallback(() => {
    if (wsRef.current) wsRef.current.close()
    const ws = new WebSocket(WS_URL)
    ws.onmessage = (e) => {
      try {
        const msg = JSON.parse(e.data)
        if (msg.type === 'traffic') {
          setTraffic(prev => {
            const updated = [msg, ...prev]
            return updated.slice(0, 2000)
          })
        }
      } catch {}
    }
    ws.onclose = () => {
      if (running) setTimeout(connectWS, 3000)
    }
    wsRef.current = ws
  }, [running])

  useEffect(() => () => {
    wsRef.current?.close()
    if (interceptPollRef.current) clearInterval(interceptPollRef.current)
  }, [])

  // ── Intercept ────────────────────────────────────────────────────────────────

  const toggleIntercept = async () => {
    const newState = !interceptEnabled
    setInterceptEnabled(newState)
    await axios.post(`${API_BASE}/proxy/intercept/mode`, { enabled: newState, filter: interceptFilter })
    if (newState) {
      interceptPollRef.current = setInterval(pollInterceptQueue, 500)
    } else {
      if (interceptPollRef.current) clearInterval(interceptPollRef.current)
      setInterceptQueue([])
      setSelectedIntercept(null)
    }
  }

  const pollInterceptQueue = async () => {
    try {
      const res = await axios.get(`${API_BASE}/proxy/intercept/queue`)
      setInterceptQueue(res.data)
      if (res.data.length > 0 && !selectedIntercept) {
        const flow = res.data[0]
        setSelectedIntercept(flow)
        setEditedHeaders(headersToText(flow.request_headers))
        setEditedBody(flow.request_body || '')
      }
    } catch {}
  }

  const selectIntercept = (flow: InterceptedFlow) => {
    setSelectedIntercept(flow)
    setEditedHeaders(headersToText(flow.request_headers))
    setEditedBody(flow.request_body || '')
  }

  const resolveIntercept = async (action: 'forward' | 'drop', withMods = false) => {
    if (!selectedIntercept) return
    const modified = withMods ? {
      request_headers: textToHeaders(editedHeaders),
      request_body: editedBody,
    } : undefined
    await axios.post(`${API_BASE}/proxy/intercept/${selectedIntercept.id}`, { action, modified })
    setInterceptQueue(prev => prev.filter(f => f.id !== selectedIntercept.id))
    const remaining = interceptQueue.filter(f => f.id !== selectedIntercept.id)
    if (remaining.length > 0) {
      selectIntercept(remaining[0])
    } else {
      setSelectedIntercept(null)
    }
  }

  const loadInRepeater = () => {
    if (!selectedIntercept) return
    setRepeaterMethod(selectedIntercept.method)
    setRepeaterHost(selectedIntercept.host)
    setRepeaterPath(selectedIntercept.path)
    setRepeaterHttps(selectedIntercept.is_https)
    setRepeaterHeaders(headersToText(selectedIntercept.request_headers))
    setRepeaterBody(selectedIntercept.request_body || '')
    setTab('repeater')
  }

  // ── Repeater ─────────────────────────────────────────────────────────────────

  const sendRepeaterRequest = async () => {
    setRepeaterLoading(true)
    setRepeaterResponse(null)
    try {
      const res = await axios.post(`${API_BASE}/proxy/repeat`, {
        method: repeaterMethod,
        host: repeaterHost,
        path: repeaterPath,
        is_https: repeaterHttps,
        request_headers: textToHeaders(repeaterHeaders),
        request_body: repeaterBody,
      })
      setRepeaterResponse(res.data)
    } catch (e: any) {
      setRepeaterResponse({ error: e.response?.data?.detail || e.message })
    } finally {
      setRepeaterLoading(false)
    }
  }

  const loadFlowInRepeater = (flow: TrafficEntry) => {
    setRepeaterMethod(flow.method)
    setRepeaterHost(flow.host)
    setRepeaterPath(flow.path)
    setRepeaterHttps(flow.is_https)
    setRepeaterHeaders(headersToText(flow.request_headers))
    setRepeaterBody(flow.request_body || '')
    setTab('repeater')
  }

  // ── Rules ────────────────────────────────────────────────────────────────────

  const loadRules = async () => {
    const res = await axios.get(`${API_BASE}/proxy/rules`)
    setRules(res.data)
  }

  useEffect(() => { loadRules() }, [])

  const addRule = async () => {
    if (!newRule.match) return
    await axios.post(`${API_BASE}/proxy/rules`, newRule)
    await loadRules()
    setNewRule({ phase: 'both', target: 'body', enabled: true })
    setShowRuleForm(false)
  }

  const deleteRule = async (id: string) => {
    await axios.delete(`${API_BASE}/proxy/rules/${id}`)
    await loadRules()
  }

  const toggleRule = async (id: string) => {
    await axios.post(`${API_BASE}/proxy/rules/${id}/toggle`)
    await loadRules()
  }

  // ── Traffic filtering ─────────────────────────────────────────────────────────

  const filteredTraffic = traffic.filter(t => {
    const matchText = !trafficFilter || t.host?.toLowerCase().includes(trafficFilter.toLowerCase()) || t.path?.toLowerCase().includes(trafficFilter.toLowerCase())
    const matchMethod = methodFilter === 'ALL' || t.method === methodFilter
    return matchText && matchMethod
  })

  const exportHAR = () => {
    const har = { log: { version: '1.2', creator: { name: 'AppSleuth', version: '1.0.0' }, entries: traffic.map(t => ({
      startedDateTime: t.timestamp, time: t.duration,
      request: { method: t.method, url: `${t.is_https ? 'https' : 'http'}://${t.host}${t.path}`,
        headers: Object.entries(t.request_headers || {}).map(([n, v]) => ({ name: n, value: v })),
        postData: t.request_body ? { mimeType: 'text/plain', text: t.request_body } : undefined },
      response: { status: t.status,
        headers: Object.entries(t.response_headers || {}).map(([n, v]) => ({ name: n, value: v })),
        content: { size: t.size, text: t.response_body } },
    })) } }
    const blob = new Blob([JSON.stringify(har, null, 2)], { type: 'application/json' })
    const a = document.createElement('a'); a.href = URL.createObjectURL(blob); a.download = 'traffic.har'; a.click()
  }

  const downloadCA = async () => {
    try {
      const res = await axios.get(`${API_BASE}/proxy/ca-cert`, { responseType: 'blob' })
      const a = document.createElement('a'); a.href = URL.createObjectURL(res.data)
      a.download = 'appsleuth-ca.pem'; a.click()
    } catch { alert('CA 証明書を取得できません') }
  }

  return (
    <div className="h-full flex flex-col overflow-hidden">
      {/* Header */}
      <div className="flex items-center justify-between px-6 py-3 border-b border-[#30363d] flex-shrink-0">
        <div className="flex items-center gap-3">
          <Globe size={18} className="text-green-400" />
          <h2 className="text-base font-semibold text-gray-100">ネットワーク解析</h2>
          {running && <span className="flex items-center gap-1.5 text-xs px-2 py-0.5 rounded-full bg-green-900/30 text-green-400 border border-green-700/50">
            <span className="w-1.5 h-1.5 rounded-full bg-green-400 pulse-dot inline-block" />稼働中
          </span>}
          {interceptEnabled && <span className="text-xs px-2 py-0.5 rounded-full bg-orange-900/30 text-orange-400 border border-orange-700/50">
            傍受モード ON {interceptQueue.length > 0 && `(${interceptQueue.length}件待機)`}
          </span>}
        </div>
        <div className="flex items-center gap-2">
          {running && <button onClick={downloadCA} className="flex items-center gap-1.5 text-xs px-2 py-1.5 bg-[#21262d] hover:bg-[#30363d] text-gray-400 rounded border border-[#30363d] transition-colors">
            <Shield size={12} />CA証明書
          </button>}
          {traffic.length > 0 && <button onClick={exportHAR} className="flex items-center gap-1.5 text-xs px-2 py-1.5 bg-[#21262d] hover:bg-[#30363d] text-gray-400 rounded border border-[#30363d] transition-colors">
            <Download size={12} />HAR
          </button>}
          {!running
            ? <button onClick={startProxy} className="flex items-center gap-2 px-4 py-1.5 text-sm bg-green-600 hover:bg-green-500 text-white rounded font-medium transition-colors"><Play size={14} />プロキシ開始</button>
            : <button onClick={stopProxy} className="flex items-center gap-2 px-4 py-1.5 text-sm bg-red-700 hover:bg-red-600 text-white rounded font-medium transition-colors"><Square size={14} />停止</button>}
        </div>
      </div>

      {/* Proxy config + intercept toggle */}
      <div className="flex items-center gap-4 px-6 py-2 bg-[#161b22] border-b border-[#30363d] flex-shrink-0 text-xs">
        <div className="flex items-center gap-1.5">
          <span className="text-gray-500">ホスト</span>
          <input type="text" value={proxyHost} onChange={e => setProxyHost(e.target.value)} disabled={running}
            className="px-2 py-1 bg-[#21262d] border border-[#30363d] rounded text-gray-200 w-24 disabled:opacity-50" />
        </div>
        <div className="flex items-center gap-1.5">
          <span className="text-gray-500">ポート</span>
          <input type="text" value={proxyPort} onChange={e => setProxyPort(e.target.value)} disabled={running}
            className="px-2 py-1 bg-[#21262d] border border-[#30363d] rounded text-gray-200 w-14 disabled:opacity-50" />
        </div>
        <label className="flex items-center gap-1.5 cursor-pointer">
          <input type="checkbox" checked={sslIntercept} onChange={e => setSslIntercept(e.target.checked)} disabled={running} className="accent-green-400" />
          <span className="text-gray-400">SSL MitM</span>
          {sslIntercept ? <Lock size={11} className="text-green-400" /> : <Unlock size={11} className="text-gray-500" />}
        </label>

        {running && (
          <>
            <div className="h-4 w-px bg-[#30363d]" />
            <button
              onClick={toggleIntercept}
              className={`flex items-center gap-1.5 px-3 py-1 rounded border text-xs font-medium transition-all ${
                interceptEnabled
                  ? 'bg-orange-900/30 text-orange-400 border-orange-700/50 hover:bg-orange-900/50'
                  : 'bg-[#21262d] text-gray-400 border-[#30363d] hover:text-gray-200'
              }`}
            >
              <Pause size={11} />
              傍受モード {interceptEnabled ? 'ON' : 'OFF'}
            </button>
            {interceptEnabled && (
              <input
                type="text"
                value={interceptFilter}
                onChange={e => setInterceptFilter(e.target.value)}
                onBlur={() => axios.post(`${API_BASE}/proxy/intercept/mode`, { enabled: true, filter: interceptFilter }).catch(() => {})}
                placeholder="フィルター (例: api.example.com)"
                className="px-2 py-1 bg-[#21262d] border border-[#30363d] rounded text-gray-200 w-44"
              />
            )}
          </>
        )}

        <span className="ml-auto text-gray-600">
          プロキシ設定: <code className="bg-[#21262d] px-1 rounded">{proxyHost}:{proxyPort}</code>
        </span>
      </div>

      {/* Tab bar */}
      <div className="flex border-b border-[#30363d] flex-shrink-0 px-4">
        <TabBtn active={tab === 'traffic'} onClick={() => setTab('traffic')}>
          トラフィック ({filteredTraffic.length})
        </TabBtn>
        <TabBtn active={tab === 'intercept'} onClick={() => setTab('intercept')}>
          傍受 {interceptQueue.length > 0 && <span className="ml-1 text-xs bg-orange-600 text-white px-1 rounded-full">{interceptQueue.length}</span>}
        </TabBtn>
        <TabBtn active={tab === 'repeater'} onClick={() => setTab('repeater')}>リピーター</TabBtn>
        <TabBtn active={tab === 'rules'} onClick={() => setTab('rules')}>
          自動改ざんルール ({rules.length})
        </TabBtn>
      </div>

      {/* ── Traffic tab ─────────────────────────────────────────────────────────── */}
      {tab === 'traffic' && (
        <div className="flex-1 flex overflow-hidden">
          <div className="flex flex-col flex-1 overflow-hidden">
            <div className="flex items-center gap-2 px-3 py-1.5 border-b border-[#30363d] bg-[#161b22]">
              <Search size={12} className="text-gray-500" />
              <input type="text" placeholder="ホスト/パスで絞り込み..." value={trafficFilter} onChange={e => setTrafficFilter(e.target.value)}
                className="flex-1 bg-transparent text-xs text-gray-200 placeholder-gray-600 outline-none" />
              <select value={methodFilter} onChange={e => setMethodFilter(e.target.value)}
                className="text-xs bg-[#21262d] border border-[#30363d] rounded px-2 py-1 text-gray-300">
                {['ALL','GET','POST','PUT','DELETE','PATCH'].map(m => <option key={m}>{m}</option>)}
              </select>
              <button onClick={() => setTraffic([])} className="text-xs text-gray-600 hover:text-gray-400">クリア</button>
            </div>
            <div className="grid grid-cols-[56px_1fr_2fr_52px_60px_60px] gap-2 px-3 py-1.5 text-[10px] text-gray-600 border-b border-[#30363d] bg-[#161b22]">
              <span>メソッド</span><span>ホスト</span><span>パス</span>
              <span className="text-right">Status</span><span className="text-right">Size</span><span className="text-right">ms</span>
            </div>
            <div className="flex-1 overflow-y-auto">
              {filteredTraffic.length === 0 && (
                <div className="flex items-center justify-center h-full text-sm text-gray-600">
                  {running ? 'トラフィックを待機中...' : 'プロキシを開始してください'}
                </div>
              )}
              {filteredTraffic.map(t => (
                <button key={t.id} onClick={() => setSelectedFlow(t)}
                  className={`w-full grid grid-cols-[56px_1fr_2fr_52px_60px_60px] gap-2 px-3 py-1.5 text-xs border-b border-[#30363d]/40 text-left transition-colors ${
                    selectedFlow?.id === t.id ? 'bg-blue-900/20' : 'hover:bg-[#21262d]'}`}>
                  <span className={`font-mono font-semibold text-[11px] ${methodColors[t.method] || 'text-gray-400'}`}>{t.method}</span>
                  <span className="text-gray-300 truncate">{t.host}</span>
                  <span className="text-gray-500 truncate">{t.path}</span>
                  <span className={`text-right font-mono text-[11px] ${statusColor(t.status)}`}>{t.status || '—'}</span>
                  <span className="text-right text-gray-500 text-[11px]">{t.size > 1024 ? `${(t.size/1024).toFixed(1)}K` : `${t.size}B`}</span>
                  <span className="text-right text-gray-500 text-[11px]">{t.duration}</span>
                </button>
              ))}
            </div>
          </div>

          {selectedFlow && (
            <div className="w-96 flex flex-col border-l border-[#30363d] bg-[#161b22] overflow-hidden">
              <div className="flex items-center justify-between px-3 py-2 border-b border-[#30363d]">
                <div className="flex gap-1">
                  {(['req','resp'] as const).map(t => (
                    <button key={t} onClick={() => setDetailTab(t)}
                      className={`px-2 py-1 text-xs rounded transition-colors ${detailTab === t ? 'bg-[#21262d] text-gray-100' : 'text-gray-500 hover:text-gray-300'}`}>
                      {t === 'req' ? 'リクエスト' : 'レスポンス'}
                    </button>
                  ))}
                </div>
                <div className="flex items-center gap-1">
                  <button onClick={() => loadFlowInRepeater(selectedFlow)} className="text-xs text-blue-400 hover:text-blue-300 px-2 py-1 bg-blue-900/20 rounded">リピーターへ</button>
                  <button onClick={() => setSelectedFlow(null)} className="text-gray-600 hover:text-gray-300 text-xs px-1">✕</button>
                </div>
              </div>
              <div className="flex-1 overflow-y-auto p-3 space-y-3 text-xs font-mono">
                <div className="text-gray-600 uppercase text-[10px]">ヘッダー</div>
                <div className="bg-[#21262d] rounded p-2 space-y-0.5">
                  {Object.entries(detailTab === 'req' ? (selectedFlow.request_headers || {}) : (selectedFlow.response_headers || {})).map(([k, v]) => (
                    <div key={k}><span className="text-blue-400">{k}</span><span className="text-gray-500">: </span><span className="text-gray-300">{v}</span></div>
                  ))}
                </div>
                {(detailTab === 'req' ? selectedFlow.request_body : selectedFlow.response_body) && (
                  <>
                    <div className="text-gray-600 uppercase text-[10px]">ボディ</div>
                    <div className="bg-[#0a0d14] rounded p-2 text-gray-300 whitespace-pre-wrap break-all max-h-56 overflow-y-auto">
                      {detailTab === 'req' ? selectedFlow.request_body : selectedFlow.response_body}
                    </div>
                  </>
                )}
              </div>
            </div>
          )}
        </div>
      )}

      {/* ── Intercept tab ────────────────────────────────────────────────────────── */}
      {tab === 'intercept' && (
        <div className="flex-1 flex overflow-hidden">
          {/* Queue list */}
          <div className="w-56 border-r border-[#30363d] flex flex-col overflow-hidden">
            <div className="px-3 py-2 text-xs text-gray-500 border-b border-[#30363d] bg-[#161b22]">
              待機中のリクエスト
            </div>
            <div className="flex-1 overflow-y-auto">
              {interceptQueue.length === 0 ? (
                <div className="flex items-center justify-center h-full text-xs text-gray-600 text-center px-3">
                  {interceptEnabled ? '傍受待機中...\nリクエストが来ると表示されます' : '傍受モードをオンにしてください'}
                </div>
              ) : interceptQueue.map(flow => (
                <button key={flow.id} onClick={() => selectIntercept(flow)}
                  className={`w-full text-left px-3 py-2 border-b border-[#30363d]/50 text-xs transition-colors ${
                    selectedIntercept?.id === flow.id ? 'bg-orange-900/20 border-l-2 border-l-orange-400' : 'hover:bg-[#21262d]'}`}>
                  <div className={`font-mono font-semibold ${methodColors[flow.method] || 'text-gray-400'}`}>{flow.method}</div>
                  <div className="text-gray-400 truncate">{flow.host}</div>
                  <div className="text-gray-600 truncate">{flow.path}</div>
                </button>
              ))}
            </div>
          </div>

          {/* Editor */}
          <div className="flex-1 flex flex-col overflow-hidden">
            {!selectedIntercept ? (
              <div className="flex-1 flex items-center justify-center text-sm text-gray-600">待機中のリクエストがありません</div>
            ) : (
              <>
                <div className="flex items-center gap-2 px-4 py-2 border-b border-[#30363d] bg-[#161b22] flex-shrink-0">
                  <span className={`text-sm font-mono font-semibold ${methodColors[selectedIntercept.method] || 'text-gray-400'}`}>{selectedIntercept.method}</span>
                  <span className="text-gray-300 text-sm">{selectedIntercept.is_https ? 'https' : 'http'}://{selectedIntercept.host}{selectedIntercept.path}</span>
                </div>
                <div className="flex-1 flex overflow-hidden">
                  <div className="flex-1 flex flex-col overflow-hidden p-3 gap-3">
                    <div>
                      <div className="text-xs text-gray-500 mb-1">リクエストヘッダー (編集可)</div>
                      <textarea
                        value={editedHeaders}
                        onChange={e => setEditedHeaders(e.target.value)}
                        className="w-full h-32 bg-[#0a0d14] border border-[#30363d] rounded p-2 text-xs font-mono text-gray-200 resize-none outline-none focus:border-orange-500/50"
                      />
                    </div>
                    <div className="flex-1 min-h-0">
                      <div className="text-xs text-gray-500 mb-1">リクエストボディ (編集可)</div>
                      <textarea
                        value={editedBody}
                        onChange={e => setEditedBody(e.target.value)}
                        className="w-full h-full min-h-[80px] bg-[#0a0d14] border border-[#30363d] rounded p-2 text-xs font-mono text-gray-200 resize-none outline-none focus:border-orange-500/50"
                      />
                    </div>
                  </div>
                </div>
                {/* Action buttons */}
                <div className="flex items-center gap-2 px-4 py-3 border-t border-[#30363d] bg-[#161b22] flex-shrink-0">
                  <button onClick={() => resolveIntercept('forward', true)}
                    className="flex items-center gap-1.5 px-4 py-2 bg-green-700 hover:bg-green-600 text-white text-sm rounded font-medium transition-colors">
                    <SkipForward size={14} />改ざんして転送
                  </button>
                  <button onClick={() => resolveIntercept('forward', false)}
                    className="flex items-center gap-1.5 px-4 py-2 bg-blue-700 hover:bg-blue-600 text-white text-sm rounded font-medium transition-colors">
                    <SkipForward size={14} />そのまま転送
                  </button>
                  <button onClick={() => resolveIntercept('drop')}
                    className="flex items-center gap-1.5 px-4 py-2 bg-red-800 hover:bg-red-700 text-white text-sm rounded font-medium transition-colors">
                    <X size={14} />ドロップ
                  </button>
                  <button onClick={loadInRepeater}
                    className="flex items-center gap-1.5 px-3 py-2 bg-[#21262d] hover:bg-[#30363d] text-gray-300 text-sm rounded border border-[#30363d] transition-colors ml-auto">
                    リピーターへ送る
                  </button>
                </div>
              </>
            )}
          </div>
        </div>
      )}

      {/* ── Repeater tab ─────────────────────────────────────────────────────────── */}
      {tab === 'repeater' && (
        <div className="flex-1 flex overflow-hidden">
          {/* Request editor */}
          <div className="flex-1 flex flex-col overflow-hidden border-r border-[#30363d]">
            <div className="flex items-center gap-2 px-3 py-2 border-b border-[#30363d] bg-[#161b22]">
              <select value={repeaterMethod} onChange={e => setRepeaterMethod(e.target.value)}
                className="text-xs bg-[#21262d] border border-[#30363d] rounded px-2 py-1.5 text-gray-200 font-mono font-semibold">
                {['GET','POST','PUT','DELETE','PATCH','OPTIONS','HEAD'].map(m => <option key={m}>{m}</option>)}
              </select>
              <label className="flex items-center gap-1 text-xs">
                <input type="checkbox" checked={repeaterHttps} onChange={e => setRepeaterHttps(e.target.checked)} className="accent-green-400" />
                <span className="text-gray-400">HTTPS</span>
              </label>
              <input type="text" value={repeaterHost} onChange={e => setRepeaterHost(e.target.value)}
                placeholder="example.com" className="flex-1 px-2 py-1.5 bg-[#21262d] border border-[#30363d] rounded text-xs text-gray-200 outline-none" />
              <input type="text" value={repeaterPath} onChange={e => setRepeaterPath(e.target.value)}
                placeholder="/api/path" className="flex-1 px-2 py-1.5 bg-[#21262d] border border-[#30363d] rounded text-xs text-gray-200 outline-none font-mono" />
              <button onClick={sendRepeaterRequest} disabled={!repeaterHost || repeaterLoading}
                className="flex items-center gap-1.5 px-4 py-1.5 bg-blue-600 hover:bg-blue-500 disabled:opacity-40 text-white text-sm rounded font-medium transition-colors">
                <Send size={13} />{repeaterLoading ? '送信中...' : '送信'}
              </button>
            </div>
            <div className="flex-1 flex flex-col overflow-hidden p-3 gap-3">
              <div>
                <div className="text-xs text-gray-500 mb-1">ヘッダー</div>
                <textarea value={repeaterHeaders} onChange={e => setRepeaterHeaders(e.target.value)}
                  className="w-full h-28 bg-[#0a0d14] border border-[#30363d] rounded p-2 text-xs font-mono text-gray-200 resize-none outline-none" />
              </div>
              <div className="flex-1 min-h-0">
                <div className="text-xs text-gray-500 mb-1">ボディ</div>
                <textarea value={repeaterBody} onChange={e => setRepeaterBody(e.target.value)}
                  placeholder="リクエストボディ (POST/PUT 等)"
                  className="w-full h-full min-h-[60px] bg-[#0a0d14] border border-[#30363d] rounded p-2 text-xs font-mono text-gray-200 resize-none outline-none" />
              </div>
            </div>
          </div>

          {/* Response */}
          <div className="flex-1 flex flex-col overflow-hidden">
            <div className="px-3 py-2 border-b border-[#30363d] bg-[#161b22] text-xs text-gray-500">レスポンス</div>
            {repeaterLoading && (
              <div className="flex-1 flex items-center justify-center text-sm text-gray-500">送信中...</div>
            )}
            {!repeaterLoading && !repeaterResponse && (
              <div className="flex-1 flex items-center justify-center text-sm text-gray-600">リクエストを送信してください</div>
            )}
            {repeaterResponse && !repeaterLoading && (
              <div className="flex-1 overflow-y-auto p-3 space-y-3 text-xs font-mono">
                {repeaterResponse.error ? (
                  <div className="text-red-400">{repeaterResponse.error}</div>
                ) : (
                  <>
                    <div className="flex items-center gap-3">
                      <span className={`font-bold text-sm ${statusColor(repeaterResponse.status)}`}>{repeaterResponse.status}</span>
                      <span className="text-gray-500">{repeaterResponse.duration}ms</span>
                      <span className="text-gray-500">{repeaterResponse.size > 1024 ? `${(repeaterResponse.size/1024).toFixed(1)}KB` : `${repeaterResponse.size}B`}</span>
                    </div>
                    <div className="text-gray-600 uppercase text-[10px]">レスポンスヘッダー</div>
                    <div className="bg-[#21262d] rounded p-2 space-y-0.5">
                      {Object.entries(repeaterResponse.response_headers || {}).map(([k, v]: [string, any]) => (
                        <div key={k}><span className="text-blue-400">{k}</span><span className="text-gray-500">: </span><span className="text-gray-300">{v}</span></div>
                      ))}
                    </div>
                    {repeaterResponse.response_body && (
                      <>
                        <div className="text-gray-600 uppercase text-[10px]">ボディ</div>
                        <div className="bg-[#0a0d14] rounded p-2 text-gray-300 whitespace-pre-wrap break-all max-h-96 overflow-y-auto">
                          {repeaterResponse.response_body}
                        </div>
                      </>
                    )}
                  </>
                )}
              </div>
            )}
          </div>
        </div>
      )}

      {/* ── Rules tab ────────────────────────────────────────────────────────────── */}
      {tab === 'rules' && (
        <div className="flex-1 overflow-y-auto p-4 space-y-3">
          <div className="flex items-center justify-between">
            <div className="text-sm text-gray-400">自動改ざんルール — マッチしたリクエスト/レスポンスを自動書き換え</div>
            <button onClick={() => setShowRuleForm(!showRuleForm)}
              className="flex items-center gap-1.5 text-sm px-3 py-1.5 bg-green-700 hover:bg-green-600 text-white rounded transition-colors">
              <Plus size={14} />ルール追加
            </button>
          </div>

          {showRuleForm && (
            <div className="bg-[#161b22] border border-[#30363d] rounded-lg p-4 space-y-3">
              <div className="text-sm font-semibold text-gray-200">新規ルール</div>
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="text-xs text-gray-500 block mb-1">ルール名</label>
                  <input type="text" value={newRule.name || ''} onChange={e => setNewRule({...newRule, name: e.target.value})}
                    className="w-full px-2 py-1.5 bg-[#21262d] border border-[#30363d] rounded text-sm text-gray-200 outline-none" />
                </div>
                <div>
                  <label className="text-xs text-gray-500 block mb-1">フェーズ</label>
                  <select value={newRule.phase} onChange={e => setNewRule({...newRule, phase: e.target.value})}
                    className="w-full px-2 py-1.5 bg-[#21262d] border border-[#30363d] rounded text-sm text-gray-200 outline-none">
                    <option value="request">リクエスト</option><option value="response">レスポンス</option><option value="both">両方</option>
                  </select>
                </div>
                <div>
                  <label className="text-xs text-gray-500 block mb-1">対象</label>
                  <select value={newRule.target} onChange={e => setNewRule({...newRule, target: e.target.value})}
                    className="w-full px-2 py-1.5 bg-[#21262d] border border-[#30363d] rounded text-sm text-gray-200 outline-none">
                    <option value="body">ボディ</option><option value="header">ヘッダー</option><option value="url">URL</option>
                  </select>
                </div>
                {newRule.target === 'header' && (
                  <div>
                    <label className="text-xs text-gray-500 block mb-1">ヘッダー名</label>
                    <input type="text" value={newRule.header_name || ''} onChange={e => setNewRule({...newRule, header_name: e.target.value})}
                      placeholder="Authorization"
                      className="w-full px-2 py-1.5 bg-[#21262d] border border-[#30363d] rounded text-sm text-gray-200 outline-none" />
                  </div>
                )}
                <div>
                  <label className="text-xs text-gray-500 block mb-1">マッチ文字列</label>
                  <input type="text" value={newRule.match || ''} onChange={e => setNewRule({...newRule, match: e.target.value})}
                    placeholder='例: "isAdmin":false'
                    className="w-full px-2 py-1.5 bg-[#21262d] border border-[#30363d] rounded text-sm text-gray-200 font-mono outline-none" />
                </div>
                <div>
                  <label className="text-xs text-gray-500 block mb-1">置換文字列</label>
                  <input type="text" value={newRule.replace || ''} onChange={e => setNewRule({...newRule, replace: e.target.value})}
                    placeholder='例: "isAdmin":true'
                    className="w-full px-2 py-1.5 bg-[#21262d] border border-[#30363d] rounded text-sm text-gray-200 font-mono outline-none" />
                </div>
              </div>
              <div className="flex gap-2">
                <button onClick={addRule} className="px-4 py-2 bg-green-700 hover:bg-green-600 text-white text-sm rounded transition-colors">追加</button>
                <button onClick={() => setShowRuleForm(false)} className="px-4 py-2 bg-[#21262d] hover:bg-[#30363d] text-gray-400 text-sm rounded transition-colors">キャンセル</button>
              </div>
            </div>
          )}

          {rules.length === 0 ? (
            <div className="text-center py-12 text-gray-600 text-sm">ルールがありません</div>
          ) : rules.map(rule => (
            <div key={rule.id} className={`bg-[#161b22] border rounded-lg px-4 py-3 flex items-center gap-3 ${rule.enabled ? 'border-[#30363d]' : 'border-[#21262d] opacity-60'}`}>
              <button onClick={() => toggleRule(rule.id)} className="flex-shrink-0">
                {rule.enabled ? <ToggleRight size={20} className="text-green-400" /> : <ToggleLeft size={20} className="text-gray-600" />}
              </button>
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2">
                  <span className="text-sm text-gray-200">{rule.name || '無名ルール'}</span>
                  <span className="text-xs px-1.5 py-0.5 bg-[#21262d] rounded text-gray-400">{rule.phase}</span>
                  <span className="text-xs px-1.5 py-0.5 bg-[#21262d] rounded text-gray-400">{rule.target}</span>
                </div>
                <div className="text-xs font-mono text-gray-500 mt-0.5">
                  <span className="text-red-300">{rule.match}</span>
                  <span className="text-gray-600 mx-1.5">→</span>
                  <span className="text-green-300">{rule.replace}</span>
                </div>
              </div>
              <button onClick={() => deleteRule(rule.id)} className="text-gray-600 hover:text-red-400 transition-colors flex-shrink-0">
                <Trash2 size={14} />
              </button>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}

function headersToText(headers: Record<string, string> = {}): string {
  return Object.entries(headers).map(([k, v]) => `${k}: ${v}`).join('\n')
}

function textToHeaders(text: string): Record<string, string> {
  const result: Record<string, string> = {}
  for (const line of text.split('\n')) {
    const idx = line.indexOf(': ')
    if (idx > 0) result[line.slice(0, idx)] = line.slice(idx + 2)
  }
  return result
}

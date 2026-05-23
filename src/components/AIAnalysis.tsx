import React, { useState, useRef, useEffect } from 'react'
import axios from 'axios'
import { Brain, Send, Key, ChevronDown, Copy, Loader, Trash2, AlertTriangle, Code2 } from 'lucide-react'

const API_BASE = 'http://localhost:8765'

type AnalysisType = 'vulnerability' | 'code_review' | 'reverse_engineering' | 'privacy' | 'improvement'

interface Message {
  role: 'user' | 'assistant'
  content: string
  timestamp: string
}

const ANALYSIS_TYPES: { id: AnalysisType; label: string; desc: string; icon: string }[] = [
  { id: 'vulnerability', label: '脆弱性スキャン', desc: 'セキュリティ脆弱性を検出', icon: '🛡️' },
  { id: 'code_review', label: 'コードレビュー', desc: 'コード品質・セキュリティレビュー', icon: '🔍' },
  { id: 'reverse_engineering', label: 'リバースエンジニアリング', desc: '難読化コードの解析・説明', icon: '⚙️' },
  { id: 'privacy', label: 'プライバシー解析', desc: '個人情報収集・トラッキング検査', icon: '🔐' },
  { id: 'improvement', label: '改善提案', desc: 'セキュリティ改善のアドバイス', icon: '✨' },
]

function MarkdownContent({ content }: { content: string }) {
  const lines = content.split('\n')
  const elements: React.ReactNode[] = []
  let i = 0

  while (i < lines.length) {
    const line = lines[i]

    if (line.startsWith('```')) {
      const lang = line.slice(3).trim()
      const codeLines: string[] = []
      i++
      while (i < lines.length && !lines[i].startsWith('```')) {
        codeLines.push(lines[i])
        i++
      }
      elements.push(
        <div key={i} className="my-3 rounded-md overflow-hidden border border-[#30363d]">
          {lang && <div className="px-3 py-1 bg-[#30363d] text-xs text-gray-400">{lang}</div>}
          <pre className="bg-[#0a0d14] px-4 py-3 text-xs font-mono text-green-300 overflow-x-auto whitespace-pre">
            {codeLines.join('\n')}
          </pre>
        </div>
      )
    } else if (line.startsWith('### ')) {
      elements.push(<h3 key={i} className="text-sm font-bold text-yellow-400 mt-4 mb-1">{line.slice(4)}</h3>)
    } else if (line.startsWith('## ')) {
      elements.push(<h2 key={i} className="text-base font-bold text-blue-400 mt-4 mb-2">{line.slice(3)}</h2>)
    } else if (line.startsWith('# ')) {
      elements.push(<h1 key={i} className="text-lg font-bold text-green-400 mt-4 mb-2">{line.slice(2)}</h1>)
    } else if (line.startsWith('- ') || line.startsWith('* ')) {
      elements.push(
        <div key={i} className="flex items-start gap-2 my-0.5">
          <span className="text-green-400 mt-0.5">•</span>
          <span className="text-gray-300 text-sm">{formatInline(line.slice(2))}</span>
        </div>
      )
    } else if (/^\d+\. /.test(line)) {
      const num = line.match(/^(\d+)\. /)?.[1]
      elements.push(
        <div key={i} className="flex items-start gap-2 my-0.5">
          <span className="text-blue-400 text-xs mt-0.5 w-4 flex-shrink-0">{num}.</span>
          <span className="text-gray-300 text-sm">{formatInline(line.replace(/^\d+\. /, ''))}</span>
        </div>
      )
    } else if (line.startsWith('**') && line.endsWith('**') && line.length > 4) {
      elements.push(<div key={i} className="font-bold text-gray-100 text-sm my-1">{line.slice(2, -2)}</div>)
    } else if (line === '') {
      elements.push(<div key={i} className="my-1" />)
    } else {
      elements.push(<p key={i} className="text-gray-300 text-sm leading-relaxed">{formatInline(line)}</p>)
    }
    i++
  }

  return <div className="space-y-0.5">{elements}</div>
}

function formatInline(text: string): React.ReactNode {
  const parts = text.split(/(`[^`]+`|\*\*[^*]+\*\*)/g)
  return parts.map((part, i) => {
    if (part.startsWith('`') && part.endsWith('`')) {
      return <code key={i} className="bg-[#21262d] text-green-300 px-1 rounded text-xs font-mono">{part.slice(1, -1)}</code>
    }
    if (part.startsWith('**') && part.endsWith('**')) {
      return <strong key={i} className="text-gray-100 font-semibold">{part.slice(2, -2)}</strong>
    }
    return part
  })
}

export default function AIAnalysis() {
  const [apiKey, setApiKey] = useState(() => localStorage.getItem('claude_api_key') || '')
  const [showKey, setShowKey] = useState(false)
  const [analysisType, setAnalysisType] = useState<AnalysisType>('vulnerability')
  const [input, setInput] = useState('')
  const [messages, setMessages] = useState<Message[]>([])
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [ghidraSource, setGhidraSource] = useState(false)
  const messagesEndRef = useRef<HTMLDivElement>(null)
  const textareaRef = useRef<HTMLTextAreaElement>(null)

  // Pick up prefill from Ghidra Analysis page
  useEffect(() => {
    const prefill = sessionStorage.getItem('ai_prefill')
    const type = sessionStorage.getItem('ai_type') as AnalysisType | null
    if (prefill) {
      setInput(prefill)
      setGhidraSource(true)
      if (type) setAnalysisType(type)
      sessionStorage.removeItem('ai_prefill')
      sessionStorage.removeItem('ai_type')
    }
  }, [])

  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' })
  }, [messages])

  const saveApiKey = () => {
    localStorage.setItem('claude_api_key', apiKey)
  }

  const sendMessage = async () => {
    if (!input.trim() || loading) return
    if (!apiKey.trim()) {
      setError('Claude API キーを設定してください')
      return
    }

    const userMsg: Message = {
      role: 'user',
      content: input.trim(),
      timestamp: new Date().toLocaleTimeString('ja-JP'),
    }

    setMessages((prev) => [...prev, userMsg])
    setInput('')
    setLoading(true)
    setError(null)

    try {
      const res = await axios.post(`${API_BASE}/ai/analyze`, {
        api_key: apiKey,
        analysis_type: analysisType,
        content: input.trim(),
        history: messages.map((m) => ({ role: m.role, content: m.content })),
      })

      const assistantMsg: Message = {
        role: 'assistant',
        content: res.data.result,
        timestamp: new Date().toLocaleTimeString('ja-JP'),
      }
      setMessages((prev) => [...prev, assistantMsg])
    } catch (err: any) {
      setError(err.response?.data?.detail || err.message || 'AI解析に失敗しました')
    } finally {
      setLoading(false)
    }
  }

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter' && (e.metaKey || e.ctrlKey)) {
      sendMessage()
    }
  }

  const copyMessage = (content: string) => {
    navigator.clipboard.writeText(content)
  }

  return (
    <div className="h-full flex flex-col overflow-hidden">
      {/* Header */}
      <div className="flex items-center justify-between px-6 py-4 border-b border-[#30363d] flex-shrink-0">
        <div className="flex items-center gap-3">
          <Brain size={18} className="text-purple-400" />
          <h2 className="text-base font-semibold text-gray-100">AI 解析 (Claude)</h2>
        </div>
        <button
          onClick={() => setMessages([])}
          className="flex items-center gap-1.5 text-xs text-gray-600 hover:text-gray-400 transition-colors"
        >
          <Trash2 size={12} />
          会話をクリア
        </button>
      </div>

      {/* Ghidra source banner */}
      {ghidraSource && (
        <div className="flex items-center gap-2 px-6 py-2 bg-cyan-900/20 border-b border-cyan-700/30 flex-shrink-0 text-xs text-cyan-400">
          <Code2 size={12} />
          Ghidra 逆コンパイル結果が読み込まれました。送信して解析を開始してください。
          <button onClick={() => setGhidraSource(false)} className="ml-auto text-cyan-600 hover:text-cyan-400">✕</button>
        </div>
      )}

      {/* API Key + Type selector */}
      <div className="flex items-center gap-3 px-6 py-3 bg-[#161b22] border-b border-[#30363d] flex-shrink-0">
        <Key size={14} className="text-gray-500 flex-shrink-0" />
        <div className="flex items-center gap-2 flex-1">
          <input
            type={showKey ? 'text' : 'password'}
            placeholder="Claude API キーを入力 (sk-ant-...)"
            value={apiKey}
            onChange={(e) => setApiKey(e.target.value)}
            onBlur={saveApiKey}
            className="flex-1 px-3 py-1.5 bg-[#21262d] border border-[#30363d] rounded text-sm text-gray-200 placeholder-gray-600 outline-none focus:border-purple-500/50 font-mono"
          />
          <button
            onClick={() => setShowKey(!showKey)}
            className="text-xs text-gray-600 hover:text-gray-400 px-2 py-1.5 bg-[#21262d] border border-[#30363d] rounded transition-colors"
          >
            {showKey ? '隠す' : '表示'}
          </button>
        </div>
        <div className="h-4 w-px bg-[#30363d]" />
        <select
          value={analysisType}
          onChange={(e) => setAnalysisType(e.target.value as AnalysisType)}
          className="px-2 py-1.5 bg-[#21262d] border border-[#30363d] rounded text-sm text-gray-300 outline-none"
        >
          {ANALYSIS_TYPES.map((t) => (
            <option key={t.id} value={t.id}>{t.icon} {t.label}</option>
          ))}
        </select>
      </div>

      {/* Messages */}
      <div className="flex-1 overflow-y-auto px-6 py-4 space-y-4">
        {messages.length === 0 && (
          <div className="text-center py-12">
            <Brain size={40} className="text-purple-400/30 mx-auto mb-4" />
            <div className="text-sm text-gray-500 mb-2">Claude AI でアプリを解析します</div>
            <div className="text-xs text-gray-600 max-w-md mx-auto">
              コード、設定ファイル、マニフェスト、逆コンパイルされたコードなどを貼り付けてください。<br />
              AI が脆弱性・問題点・改善案を分析します。
            </div>
            <div className="grid grid-cols-2 gap-2 mt-6 max-w-sm mx-auto">
              {ANALYSIS_TYPES.map((t) => (
                <button
                  key={t.id}
                  onClick={() => setAnalysisType(t.id)}
                  className={`text-left p-3 rounded-lg border text-xs transition-all ${
                    analysisType === t.id
                      ? 'bg-purple-900/30 border-purple-700/50 text-purple-300'
                      : 'bg-[#161b22] border-[#30363d] text-gray-400 hover:border-gray-500'
                  }`}
                >
                  <div className="text-base mb-1">{t.icon}</div>
                  <div className="font-semibold">{t.label}</div>
                  <div className="text-gray-600">{t.desc}</div>
                </button>
              ))}
            </div>
          </div>
        )}

        {messages.map((msg, i) => (
          <div key={i} className={`flex gap-3 ${msg.role === 'user' ? 'justify-end' : 'justify-start'}`}>
            {msg.role === 'assistant' && (
              <div className="w-7 h-7 rounded-full bg-purple-900/50 border border-purple-700/50 flex items-center justify-center flex-shrink-0 mt-1">
                <Brain size={14} className="text-purple-400" />
              </div>
            )}
            <div className={`max-w-[80%] ${msg.role === 'user' ? 'order-1' : ''}`}>
              <div className={`rounded-lg p-4 ${
                msg.role === 'user'
                  ? 'bg-blue-900/30 border border-blue-700/30 text-gray-200'
                  : 'bg-[#161b22] border border-[#30363d]'
              }`}>
                {msg.role === 'assistant' ? (
                  <MarkdownContent content={msg.content} />
                ) : (
                  <pre className="text-sm text-gray-200 whitespace-pre-wrap font-sans">{msg.content}</pre>
                )}
              </div>
              <div className="flex items-center gap-2 mt-1 px-1">
                <span className="text-xs text-gray-600">{msg.timestamp}</span>
                {msg.role === 'assistant' && (
                  <button
                    onClick={() => copyMessage(msg.content)}
                    className="text-xs text-gray-600 hover:text-gray-400 flex items-center gap-1 transition-colors"
                  >
                    <Copy size={10} />
                    コピー
                  </button>
                )}
              </div>
            </div>
            {msg.role === 'user' && (
              <div className="w-7 h-7 rounded-full bg-blue-900/50 border border-blue-700/50 flex items-center justify-center flex-shrink-0 mt-1 order-2">
                <span className="text-xs text-blue-400">U</span>
              </div>
            )}
          </div>
        ))}

        {loading && (
          <div className="flex gap-3">
            <div className="w-7 h-7 rounded-full bg-purple-900/50 border border-purple-700/50 flex items-center justify-center flex-shrink-0">
              <Brain size={14} className="text-purple-400" />
            </div>
            <div className="bg-[#161b22] border border-[#30363d] rounded-lg px-4 py-3">
              <div className="flex items-center gap-2 text-sm text-gray-400">
                <Loader size={14} className="animate-spin text-purple-400" />
                Claude が解析中...
              </div>
            </div>
          </div>
        )}

        {error && (
          <div className="flex items-center gap-2 text-sm text-red-400 bg-red-900/20 border border-red-700/50 rounded-lg px-4 py-3">
            <AlertTriangle size={14} />
            {error}
          </div>
        )}

        <div ref={messagesEndRef} />
      </div>

      {/* Input area */}
      <div className="flex-shrink-0 p-4 border-t border-[#30363d] bg-[#161b22]">
        <div className="flex gap-3">
          <textarea
            ref={textareaRef}
            value={input}
            onChange={(e) => setInput(e.target.value)}
            onKeyDown={handleKeyDown}
            placeholder={`コード、マニフェスト、設定ファイルなどを貼り付けて解析 (Ctrl+Enter で送信)\n\n解析タイプ: ${ANALYSIS_TYPES.find(t => t.id === analysisType)?.label}`}
            rows={4}
            className="flex-1 bg-[#21262d] border border-[#30363d] rounded-lg px-4 py-3 text-sm text-gray-200 placeholder-gray-600 resize-none outline-none focus:border-purple-500/50 font-mono"
            disabled={loading}
          />
          <button
            onClick={sendMessage}
            disabled={loading || !input.trim()}
            className="flex-shrink-0 px-4 py-3 bg-purple-700 hover:bg-purple-600 disabled:opacity-40 text-white rounded-lg transition-colors flex items-center gap-2 self-end"
          >
            <Send size={16} />
          </button>
        </div>
        <div className="text-xs text-gray-600 mt-1.5 px-1">
          Ctrl+Enter で送信 · API キーはローカルに保存されます
        </div>
      </div>
    </div>
  )
}

import React, { useState, useRef, useEffect } from 'react'
import { Send, TrendingUp, Bot, User, Loader2, AlertTriangle } from 'lucide-react'
import axios from 'axios'
import ReactMarkdown from 'react-markdown'

const API_BASE = 'http://localhost:8765'

interface Message {
  role: 'user' | 'assistant'
  content: string
}

const SUGGESTIONS = [
  '今日のおすすめ銘柄は？',
  'スクリーニング結果を教えて',
  '割安な銘柄を探して',
  '最近の分析レポートは？',
]

export default function StockChat() {
  const [messages, setMessages] = useState<Message[]>([])
  const [input, setInput] = useState('')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const bottomRef = useRef<HTMLDivElement>(null)

  const claudeKey = localStorage.getItem('claude_api_key') || ''
  const awsAccessKey = localStorage.getItem('aws_access_key') || ''
  const awsSecretKey = localStorage.getItem('aws_secret_key') || ''
  const awsRegion = localStorage.getItem('aws_region') || 'ap-northeast-1'

  const missingKeys = !claudeKey || !awsAccessKey || !awsSecretKey

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: 'smooth' })
  }, [messages, loading])

  const send = async (question: string) => {
    if (!question.trim() || loading) return
    setError('')
    const userMsg: Message = { role: 'user', content: question }
    setMessages((prev) => [...prev, userMsg])
    setInput('')
    setLoading(true)

    try {
      const res = await axios.post(`${API_BASE}/stock/chat`, {
        question,
        claude_api_key: claudeKey,
        aws_access_key: awsAccessKey,
        aws_secret_key: awsSecretKey,
        aws_region: awsRegion,
        history: messages,
      })
      setMessages((prev) => [...prev, { role: 'assistant', content: res.data.result }])
    } catch (e: any) {
      setError(e?.response?.data?.detail || 'エラーが発生しました')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="bg-[#161b22] border border-[#30363d] rounded-lg overflow-hidden flex flex-col" style={{ height: '480px' }}>
      {/* Header */}
      <div className="flex items-center gap-2 px-4 py-3 border-b border-[#30363d] flex-shrink-0">
        <TrendingUp size={16} className="text-green-400" />
        <span className="text-sm font-semibold text-gray-200">株チャット</span>
        <span className="ml-auto text-xs text-gray-500">S3データ × Claude AI</span>
      </div>

      {/* Missing keys warning */}
      {missingKeys && (
        <div className="mx-4 mt-3 flex items-start gap-2 bg-yellow-900/20 border border-yellow-700/40 rounded-lg p-3 text-xs text-yellow-400 flex-shrink-0">
          <AlertTriangle size={14} className="flex-shrink-0 mt-0.5" />
          <span>
            設定画面でClaude APIキーとAWS認証情報を入力してください。
            <br />（AWS Access Key ID / Secret Access Key）
          </span>
        </div>
      )}

      {/* Messages */}
      <div className="flex-1 overflow-y-auto px-4 py-3 space-y-4">
        {messages.length === 0 && (
          <div className="space-y-3">
            <p className="text-xs text-gray-500 text-center pt-2">S3に保存された株データをもとに質問に答えます</p>
            <div className="grid grid-cols-2 gap-2">
              {SUGGESTIONS.map((s) => (
                <button
                  key={s}
                  onClick={() => send(s)}
                  disabled={missingKeys}
                  className="text-left text-xs px-3 py-2 rounded-lg bg-[#21262d] border border-[#30363d] text-gray-400 hover:text-gray-200 hover:border-green-500/30 transition-all disabled:opacity-40 disabled:cursor-not-allowed"
                >
                  {s}
                </button>
              ))}
            </div>
          </div>
        )}

        {messages.map((msg, i) => (
          <div key={i} className={`flex gap-2 ${msg.role === 'user' ? 'justify-end' : 'justify-start'}`}>
            {msg.role === 'assistant' && (
              <div className="w-6 h-6 rounded-full bg-green-500/20 border border-green-500/30 flex items-center justify-center flex-shrink-0 mt-0.5">
                <Bot size={12} className="text-green-400" />
              </div>
            )}
            <div
              className={`max-w-[85%] rounded-lg px-3 py-2 text-sm ${
                msg.role === 'user'
                  ? 'bg-green-700/30 border border-green-600/30 text-gray-200'
                  : 'bg-[#21262d] border border-[#30363d] text-gray-300'
              }`}
            >
              {msg.role === 'assistant' ? (
                <div className="prose prose-invert prose-sm max-w-none prose-p:my-1 prose-headings:my-2 prose-li:my-0.5">
                  <ReactMarkdown>{msg.content}</ReactMarkdown>
                </div>
              ) : (
                msg.content
              )}
            </div>
            {msg.role === 'user' && (
              <div className="w-6 h-6 rounded-full bg-blue-500/20 border border-blue-500/30 flex items-center justify-center flex-shrink-0 mt-0.5">
                <User size={12} className="text-blue-400" />
              </div>
            )}
          </div>
        ))}

        {loading && (
          <div className="flex gap-2 justify-start">
            <div className="w-6 h-6 rounded-full bg-green-500/20 border border-green-500/30 flex items-center justify-center flex-shrink-0">
              <Bot size={12} className="text-green-400" />
            </div>
            <div className="bg-[#21262d] border border-[#30363d] rounded-lg px-3 py-2 flex items-center gap-2">
              <Loader2 size={14} className="text-green-400 animate-spin" />
              <span className="text-xs text-gray-500">S3データを取得中...</span>
            </div>
          </div>
        )}

        {error && (
          <div className="flex items-center gap-2 text-xs text-red-400 bg-red-900/20 border border-red-700/40 rounded-lg px-3 py-2">
            <AlertTriangle size={12} />
            {error}
          </div>
        )}

        <div ref={bottomRef} />
      </div>

      {/* Input */}
      <div className="border-t border-[#30363d] px-3 py-3 flex-shrink-0">
        <form
          onSubmit={(e) => { e.preventDefault(); send(input) }}
          className="flex gap-2"
        >
          <input
            value={input}
            onChange={(e) => setInput(e.target.value)}
            disabled={missingKeys || loading}
            placeholder={missingKeys ? '設定が必要です' : '株について質問してください...'}
            className="flex-1 px-3 py-2 bg-[#21262d] border border-[#30363d] rounded-lg text-sm text-gray-200 placeholder-gray-600 outline-none focus:border-green-500/50 disabled:opacity-40"
          />
          <button
            type="submit"
            disabled={!input.trim() || loading || missingKeys}
            className="px-3 py-2 bg-green-700 hover:bg-green-600 disabled:opacity-40 disabled:cursor-not-allowed rounded-lg transition-colors"
          >
            <Send size={14} className="text-white" />
          </button>
        </form>
      </div>
    </div>
  )
}

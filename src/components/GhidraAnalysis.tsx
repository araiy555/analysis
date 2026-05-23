import React, { useState, useCallback, useEffect } from 'react'
import { useDropzone } from 'react-dropzone'
import { useNavigate } from 'react-router-dom'
import axios from 'axios'
import {
  Code2, Upload, Search, Brain, AlertTriangle, CheckCircle,
  Loader, Copy, ChevronRight, ChevronDown, Terminal, Info,
  Download, Play, ExternalLink, Cpu
} from 'lucide-react'

const API_BASE = 'http://localhost:8765'

interface GhidraFunction {
  name: string
  address: string
  signature: string
  decompiled: string
  size: number
}

interface GhidraResult {
  status: 'ok' | 'error'
  message?: string
  program?: string
  language?: string
  compiler?: string
  image_base?: string
  function_count?: number
  decompiled_count?: number
  functions?: GhidraFunction[]
  errors?: { function: string; error: string }[]
  ghidra_path?: string
  raw_log?: string
  file_name?: string
  file_size?: number
}

interface GhidraStatus {
  installed: boolean
  path: string | null
  env_var: string | null
}

export default function GhidraAnalysis() {
  const navigate = useNavigate()
  const [file, setFile] = useState<File | null>(null)
  const [loading, setLoading] = useState(false)
  const [progress, setProgress] = useState(0)
  const [progressMsg, setProgressMsg] = useState('')
  const [result, setResult] = useState<GhidraResult | null>(null)
  const [ghidraStatus, setGhidraStatus] = useState<GhidraStatus | null>(null)
  const [selectedFunc, setSelectedFunc] = useState<GhidraFunction | null>(null)
  const [searchQuery, setSearchQuery] = useState('')
  const [sendingToAI, setSendingToAI] = useState(false)
  const [showLog, setShowLog] = useState(false)

  useEffect(() => {
    axios.get<GhidraStatus>(`${API_BASE}/ghidra/status`)
      .then(r => setGhidraStatus(r.data))
      .catch(() => {})
  }, [])

  const onDrop = useCallback((files: File[]) => {
    if (files.length > 0) {
      setFile(files[0])
      setResult(null)
      setSelectedFunc(null)
    }
  }, [])

  const { getRootProps, getInputProps, isDragActive } = useDropzone({
    onDrop,
    accept: {
      'application/octet-stream': ['.exe', '.dll', '.so', '.dylib', '.apk', '.elf'],
      'application/vnd.android.package-archive': ['.apk'],
      'application/x-msdownload': ['.exe', '.dll'],
    },
    maxFiles: 1,
  })

  const runAnalysis = async () => {
    if (!file) return
    setLoading(true)
    setProgress(0)
    setProgressMsg('ファイルをアップロード中...')

    const formData = new FormData()
    formData.append('file', file)

    const messages = [
      'Ghidra プロジェクト作成中...',
      'バイナリをインポート中...',
      '自動解析実行中 (関数・型・シンボル解析)...',
      'デコンパイラ実行中...',
      '関数を逆コンパイル中...',
      '結果を収集中...',
    ]
    let msgIdx = 0
    const interval = setInterval(() => {
      setProgress(p => Math.min(p + 3, 92))
      msgIdx = Math.min(msgIdx + 1, messages.length - 1)
      setProgressMsg(messages[msgIdx])
    }, 4000)

    try {
      const res = await axios.post<GhidraResult>(
        `${API_BASE}/ghidra/analyze-upload`,
        formData,
        { headers: { 'Content-Type': 'multipart/form-data' }, timeout: 360000 }
      )
      clearInterval(interval)
      setProgress(100)
      setProgressMsg('完了')
      setResult(res.data)
      if (res.data.functions && res.data.functions.length > 0) {
        setSelectedFunc(res.data.functions[0])
      }
    } catch (err: any) {
      clearInterval(interval)
      setResult({
        status: 'error',
        message: err.response?.data?.detail || err.message || '解析に失敗しました',
      })
    } finally {
      setLoading(false)
    }
  }

  const sendToAI = async (func: GhidraFunction) => {
    setSendingToAI(true)
    // Store the decompiled code in sessionStorage so AIAnalysis can pick it up
    const content = `# Ghidra 逆コンパイル: ${func.name}\n\n` +
      `アドレス: ${func.address}\n` +
      `シグネチャ: ${func.signature}\n` +
      `ファイル: ${result?.program || ''} (${result?.language || ''})\n\n` +
      `\`\`\`c\n${func.decompiled}\n\`\`\``
    sessionStorage.setItem('ai_prefill', content)
    sessionStorage.setItem('ai_type', 'reverse_engineering')
    setSendingToAI(false)
    navigate('/ai')
  }

  const sendAllToAI = () => {
    if (!result?.functions) return
    const top = result.functions.slice(0, 20)
    const content = `# Ghidra 逆コンパイル結果: ${result.program}\n\n` +
      `言語: ${result.language} | コンパイラ: ${result.compiler}\n` +
      `関数数: ${result.function_count} | デコンパイル済み: ${result.decompiled_count}\n\n` +
      top.map(f =>
        `## ${f.name} @ ${f.address}\n\`\`\`c\n${f.decompiled}\n\`\`\``
      ).join('\n\n')
    sessionStorage.setItem('ai_prefill', content)
    sessionStorage.setItem('ai_type', 'reverse_engineering')
    navigate('/ai')
  }

  const exportJSON = () => {
    if (!result) return
    const blob = new Blob([JSON.stringify(result, null, 2)], { type: 'application/json' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `${result.program || 'ghidra'}_decompiled.json`
    a.click()
    URL.revokeObjectURL(url)
  }

  const filteredFunctions = (result?.functions || []).filter(f =>
    f.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
    f.signature.toLowerCase().includes(searchQuery.toLowerCase())
  )

  return (
    <div className="h-full flex flex-col overflow-hidden">
      {/* Header */}
      <div className="flex items-center justify-between px-6 py-4 border-b border-[#30363d] flex-shrink-0">
        <div className="flex items-center gap-3">
          <Code2 size={18} className="text-cyan-400" />
          <h2 className="text-base font-semibold text-gray-100">Ghidra 逆コンパイル + AI 解析</h2>
          {ghidraStatus && (
            <span className={`text-xs px-2 py-0.5 rounded-full border ${
              ghidraStatus.installed
                ? 'bg-green-900/30 text-green-400 border-green-700/50'
                : 'bg-red-900/30 text-red-400 border-red-700/50'
            }`}>
              {ghidraStatus.installed ? `Ghidra: ${ghidraStatus.path?.split(/[\\/]/).slice(-3, -1).join('/')}` : 'Ghidra 未検出'}
            </span>
          )}
        </div>
        {result?.status === 'ok' && (
          <div className="flex items-center gap-2">
            <button
              onClick={exportJSON}
              className="flex items-center gap-1.5 text-xs px-3 py-1.5 bg-[#21262d] hover:bg-[#30363d] text-gray-300 rounded border border-[#30363d] transition-colors"
            >
              <Download size={12} />
              JSON
            </button>
            <button
              onClick={sendAllToAI}
              className="flex items-center gap-1.5 text-sm px-3 py-1.5 bg-purple-700 hover:bg-purple-600 text-white rounded transition-colors"
            >
              <Brain size={14} />
              全関数を Claude で解析
            </button>
          </div>
        )}
      </div>

      {/* Ghidra not installed warning */}
      {ghidraStatus && !ghidraStatus.installed && (
        <div className="mx-6 mt-4 bg-yellow-900/20 border border-yellow-700/50 rounded-lg p-4 flex-shrink-0">
          <div className="flex items-center gap-2 text-yellow-400 font-semibold text-sm mb-2">
            <AlertTriangle size={14} />
            Ghidra が見つかりません
          </div>
          <div className="text-xs text-gray-400 space-y-1">
            <div>1. <a href="https://ghidra-sre.org/" className="text-blue-400 underline">ghidra-sre.org</a> から Ghidra をダウンロード</div>
            <div>2. 解凍して環境変数を設定:</div>
            <div className="font-mono bg-black/30 px-2 py-1 rounded mt-1">
              # macOS/Linux<br />
              export GHIDRA_HOME=/opt/ghidra_11.0_PUBLIC<br /><br />
              # Windows (PowerShell)<br />
              $env:GHIDRA_HOME = "C:\ghidra_11.0_PUBLIC"
            </div>
            <div className="mt-1">3. バックエンドを再起動してください</div>
          </div>
        </div>
      )}

      <div className="flex-1 flex overflow-hidden">
        {/* Left panel: upload + function list */}
        <div className="flex flex-col w-72 border-r border-[#30363d] overflow-hidden flex-shrink-0">
          {/* Drop zone */}
          <div className="p-3 border-b border-[#30363d]">
            <div
              {...getRootProps()}
              className={`border-2 border-dashed rounded-lg p-4 text-center cursor-pointer transition-all text-xs ${
                isDragActive
                  ? 'border-cyan-400 bg-cyan-900/20'
                  : file
                  ? 'border-green-500/50 bg-green-900/10'
                  : 'border-[#30363d] hover:border-gray-500 bg-[#161b22]'
              }`}
            >
              <input {...getInputProps()} />
              <Code2 size={20} className={`mx-auto mb-2 ${file ? 'text-green-400' : 'text-gray-600'}`} />
              {file ? (
                <div>
                  <div className="text-green-400 font-medium truncate">{file.name}</div>
                  <div className="text-gray-600 mt-0.5">{(file.size / 1024 / 1024).toFixed(2)} MB</div>
                </div>
              ) : (
                <div className="text-gray-500">
                  EXE / DLL / APK / SO をドロップ
                </div>
              )}
            </div>
            {file && !loading && (
              <button
                onClick={runAnalysis}
                disabled={ghidraStatus !== null && !ghidraStatus.installed}
                className="mt-2 w-full py-2 flex items-center justify-center gap-2 bg-cyan-700 hover:bg-cyan-600 disabled:opacity-40 text-white text-sm rounded transition-colors"
              >
                <Play size={14} />
                Ghidra 解析開始
              </button>
            )}
          </div>

          {/* Progress */}
          {loading && (
            <div className="p-3 border-b border-[#30363d]">
              <div className="flex items-center gap-2 mb-2">
                <Loader size={13} className="text-cyan-400 animate-spin flex-shrink-0" />
                <span className="text-xs text-gray-400 truncate">{progressMsg}</span>
              </div>
              <div className="h-1 bg-[#21262d] rounded-full overflow-hidden">
                <div
                  className="h-full bg-cyan-500 rounded-full transition-all duration-500"
                  style={{ width: `${progress}%` }}
                />
              </div>
              <div className="text-xs text-gray-600 mt-1">大きなバイナリは数分かかります</div>
            </div>
          )}

          {/* Binary info */}
          {result?.status === 'ok' && (
            <div className="p-3 border-b border-[#30363d] space-y-1">
              <div className="text-xs text-gray-500">{result.program}</div>
              <div className="text-xs text-gray-600">{result.language} · {result.compiler}</div>
              <div className="flex items-center gap-2">
                <span className="text-xs text-gray-500">関数: {result.function_count}</span>
                <span className="text-xs text-cyan-400">逆コンパイル: {result.decompiled_count}</span>
              </div>
            </div>
          )}

          {/* Function list */}
          {result?.status === 'ok' && (result.functions || []).length > 0 && (
            <>
              <div className="p-2 border-b border-[#30363d]">
                <div className="relative">
                  <Search size={12} className="absolute left-2 top-1/2 -translate-y-1/2 text-gray-600" />
                  <input
                    type="text"
                    placeholder="関数名で検索..."
                    value={searchQuery}
                    onChange={e => setSearchQuery(e.target.value)}
                    className="w-full pl-7 pr-2 py-1.5 bg-[#21262d] border border-[#30363d] rounded text-xs text-gray-200 placeholder-gray-600 outline-none"
                  />
                </div>
              </div>
              <div className="flex-1 overflow-y-auto">
                {filteredFunctions.map((f, i) => (
                  <button
                    key={i}
                    onClick={() => setSelectedFunc(f)}
                    className={`w-full text-left px-3 py-2 border-b border-[#30363d]/50 transition-colors ${
                      selectedFunc?.address === f.address
                        ? 'bg-cyan-900/20 border-l-2 border-l-cyan-400'
                        : 'hover:bg-[#21262d]'
                    }`}
                  >
                    <div className={`text-xs font-mono truncate ${
                      f.name.startsWith('FUN_') || f.name.startsWith('sub_')
                        ? 'text-gray-500'
                        : 'text-cyan-300'
                    }`}>
                      {f.name}
                    </div>
                    <div className="text-xs text-gray-600 font-mono">{f.address} · {f.size}B</div>
                  </button>
                ))}
              </div>
            </>
          )}
        </div>

        {/* Right panel: decompiled code viewer */}
        <div className="flex-1 flex flex-col overflow-hidden">
          {/* Error state */}
          {result?.status === 'error' && (
            <div className="flex-1 flex items-center justify-center p-8">
              <div className="bg-red-900/20 border border-red-700/50 rounded-lg p-6 max-w-lg w-full">
                <div className="flex items-center gap-2 text-red-400 font-semibold mb-3">
                  <AlertTriangle size={16} />
                  解析エラー
                </div>
                <pre className="text-xs text-gray-300 whitespace-pre-wrap font-mono">{result.message}</pre>
              </div>
            </div>
          )}

          {/* Empty state */}
          {!result && !loading && (
            <div className="flex-1 flex items-center justify-center">
              <div className="text-center">
                <Code2 size={48} className="text-gray-700 mx-auto mb-4" />
                <div className="text-sm text-gray-500">バイナリをドロップして Ghidra 解析を開始</div>
                <div className="text-xs text-gray-600 mt-2 max-w-sm">
                  Ghidra が自動的にバイナリを解析・逆コンパイルします。<br />
                  その後 Claude AI で内容を解説します。
                </div>
                <div className="mt-6 grid grid-cols-3 gap-3 text-xs text-gray-600">
                  {['EXE / DLL', 'APK / DEX', 'ELF / SO'].map(f => (
                    <div key={f} className="bg-[#161b22] border border-[#30363d] rounded px-3 py-2">{f}</div>
                  ))}
                </div>
              </div>
            </div>
          )}

          {/* Loading state */}
          {loading && (
            <div className="flex-1 flex items-center justify-center">
              <div className="text-center">
                <Loader size={40} className="text-cyan-400 animate-spin mx-auto mb-4" />
                <div className="text-sm text-gray-400">{progressMsg}</div>
                <div className="text-xs text-gray-600 mt-2">
                  Ghidra のフル解析には数分かかる場合があります
                </div>
                <div className="mt-4 bg-[#161b22] border border-[#30363d] rounded px-4 py-2 text-xs text-gray-600 font-mono">
                  {progress}% 完了
                </div>
              </div>
            </div>
          )}

          {/* Decompiled code view */}
          {selectedFunc && result?.status === 'ok' && (
            <div className="flex flex-col h-full overflow-hidden">
              {/* Function header */}
              <div className="flex items-center justify-between px-4 py-3 border-b border-[#30363d] bg-[#161b22] flex-shrink-0">
                <div>
                  <div className="flex items-center gap-2">
                    <span className="text-sm font-mono font-semibold text-cyan-300">{selectedFunc.name}</span>
                    <span className="text-xs text-gray-600 font-mono">{selectedFunc.address}</span>
                    <span className="text-xs px-1.5 py-0.5 bg-[#21262d] rounded text-gray-500">{selectedFunc.size} bytes</span>
                  </div>
                  <div className="text-xs text-gray-500 font-mono mt-0.5 truncate max-w-md">
                    {selectedFunc.signature}
                  </div>
                </div>
                <div className="flex items-center gap-2">
                  <button
                    onClick={() => navigator.clipboard.writeText(selectedFunc.decompiled)}
                    className="flex items-center gap-1.5 text-xs px-2 py-1.5 bg-[#21262d] hover:bg-[#30363d] text-gray-400 rounded transition-colors"
                  >
                    <Copy size={11} />
                    コピー
                  </button>
                  <button
                    onClick={() => sendToAI(selectedFunc)}
                    disabled={sendingToAI}
                    className="flex items-center gap-1.5 text-xs px-3 py-1.5 bg-purple-700 hover:bg-purple-600 text-white rounded transition-colors"
                  >
                    <Brain size={12} />
                    Claude で解析
                  </button>
                </div>
              </div>

              {/* Code area */}
              <div className="flex-1 overflow-auto bg-[#0a0d14]">
                <pre className="p-5 font-mono text-sm leading-relaxed">
                  {syntaxHighlight(selectedFunc.decompiled)}
                </pre>
              </div>

              {/* Raw log toggle */}
              {result.raw_log && (
                <div className="border-t border-[#30363d] flex-shrink-0">
                  <button
                    onClick={() => setShowLog(!showLog)}
                    className="flex items-center gap-2 px-4 py-2 text-xs text-gray-600 hover:text-gray-400 transition-colors w-full"
                  >
                    <Terminal size={12} />
                    Ghidra ログ
                    {showLog ? <ChevronDown size={12} /> : <ChevronRight size={12} />}
                  </button>
                  {showLog && (
                    <div className="bg-[#0a0d14] px-4 py-3 font-mono text-xs text-gray-500 max-h-32 overflow-y-auto">
                      {result.raw_log}
                    </div>
                  )}
                </div>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  )
}

// Simple C syntax highlighter for Ghidra decompiled output
function syntaxHighlight(code: string): React.ReactNode {
  const C_KEYWORDS = new Set([
    'if', 'else', 'while', 'for', 'do', 'switch', 'case', 'break', 'return',
    'continue', 'default', 'goto', 'typedef', 'struct', 'union', 'enum',
    'void', 'int', 'char', 'long', 'short', 'unsigned', 'signed', 'float',
    'double', 'const', 'static', 'extern', 'register', 'volatile', 'inline',
    'NULL', 'true', 'false', 'undefined', 'undefined1', 'undefined2', 'undefined4',
    'undefined8', 'uint', 'ulong', 'ushort', 'bool', 'byte',
  ])

  const lines = code.split('\n')
  return (
    <>
      {lines.map((line, lineIdx) => {
        const tokens = tokenizeLine(line)
        return (
          <div key={lineIdx} className="table-row group hover:bg-white/5">
            <span className="table-cell select-none text-gray-700 pr-4 text-right w-10 sticky left-0 bg-[#0a0d14] group-hover:bg-white/5">
              {lineIdx + 1}
            </span>
            <span className="table-cell">
              {tokens.map((tok, i) => {
                if (tok.type === 'keyword' || C_KEYWORDS.has(tok.text)) {
                  return <span key={i} className="text-purple-400">{tok.text}</span>
                }
                if (tok.type === 'string') {
                  return <span key={i} className="text-green-400">{tok.text}</span>
                }
                if (tok.type === 'comment') {
                  return <span key={i} className="text-gray-600 italic">{tok.text}</span>
                }
                if (tok.type === 'number') {
                  return <span key={i} className="text-yellow-300">{tok.text}</span>
                }
                if (tok.type === 'function') {
                  return <span key={i} className="text-cyan-300">{tok.text}</span>
                }
                if (tok.type === 'type') {
                  return <span key={i} className="text-blue-300">{tok.text}</span>
                }
                return <span key={i} className="text-gray-200">{tok.text}</span>
              })}
            </span>
          </div>
        )
      })}
    </>
  )
}

interface Token { type: string; text: string }

function tokenizeLine(line: string): Token[] {
  const tokens: Token[] = []
  let i = 0
  const n = line.length

  while (i < n) {
    // Comment
    if (line[i] === '/' && line[i + 1] === '/') {
      tokens.push({ type: 'comment', text: line.slice(i) })
      break
    }
    // String
    if (line[i] === '"') {
      let j = i + 1
      while (j < n && !(line[j] === '"' && line[j - 1] !== '\\')) j++
      tokens.push({ type: 'string', text: line.slice(i, j + 1) })
      i = j + 1
      continue
    }
    // Hex number
    if (line[i] === '0' && line[i + 1] === 'x') {
      let j = i + 2
      while (j < n && /[0-9a-fA-F]/.test(line[j])) j++
      tokens.push({ type: 'number', text: line.slice(i, j) })
      i = j
      continue
    }
    // Number
    if (/[0-9]/.test(line[i])) {
      let j = i
      while (j < n && /[0-9.]/.test(line[j])) j++
      tokens.push({ type: 'number', text: line.slice(i, j) })
      i = j
      continue
    }
    // Identifier
    if (/[a-zA-Z_]/.test(line[i])) {
      let j = i
      while (j < n && /[a-zA-Z0-9_]/.test(line[j])) j++
      const word = line.slice(i, j)
      // Function call: word followed by (
      const next = line[j]
      let type = 'ident'
      if (next === '(') type = 'function'
      tokens.push({ type, text: word })
      i = j
      continue
    }
    tokens.push({ type: 'punct', text: line[i] })
    i++
  }
  return tokens
}

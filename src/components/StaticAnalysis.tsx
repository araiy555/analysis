import React, { useState, useCallback } from 'react'
import { useDropzone } from 'react-dropzone'
import axios from 'axios'
import {
  Upload, FileSearch, AlertTriangle, Shield, Key, Globe,
  Code, List, CheckCircle, XCircle, Info, Loader, Download,
  ChevronDown, ChevronRight, Copy, Search
} from 'lucide-react'

const API_BASE = 'http://localhost:8765'

type Severity = 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO'

interface Vulnerability {
  id: string
  title: string
  description: string
  severity: Severity
  location?: string
  recommendation?: string
}

interface AnalysisResult {
  file_name: string
  file_type: string
  file_size: number
  app_name?: string
  package_name?: string
  version?: string
  min_sdk?: number
  target_sdk?: number
  permissions?: { name: string; description: string; risk: 'HIGH' | 'MEDIUM' | 'LOW' }[]
  activities?: string[]
  services?: string[]
  certificates?: { issuer: string; subject: string; valid_from: string; valid_to: string; fingerprint: string }[]
  strings_found?: string[]
  urls_found?: string[]
  secrets_found?: { type: string; value: string; location: string }[]
  vulnerabilities?: Vulnerability[]
  imports?: { dll: string; functions: string[] }[]
  exports?: string[]
  sections?: { name: string; size: number; entropy: number }[]
  entitlements?: Record<string, any>
  arch?: string
  raw_manifest?: string
  decompiled_code?: string
}

const severityConfig: Record<Severity, { color: string; bg: string; label: string }> = {
  HIGH: { color: 'text-red-400', bg: 'bg-red-900/30 border-red-700/50', label: '高' },
  MEDIUM: { color: 'text-yellow-400', bg: 'bg-yellow-900/30 border-yellow-700/50', label: '中' },
  LOW: { color: 'text-blue-400', bg: 'bg-blue-900/30 border-blue-700/50', label: '低' },
  INFO: { color: 'text-gray-400', bg: 'bg-gray-800 border-gray-700', label: '情報' },
}

function SeverityBadge({ severity }: { severity: Severity }) {
  const cfg = severityConfig[severity]
  return (
    <span className={`text-xs px-2 py-0.5 rounded-full border ${cfg.bg} ${cfg.color} font-medium`}>
      {cfg.label}
    </span>
  )
}

function Tab({
  active, onClick, children
}: { active: boolean; onClick: () => void; children: React.ReactNode }) {
  return (
    <button
      onClick={onClick}
      className={`px-4 py-2 text-sm border-b-2 transition-colors whitespace-nowrap ${
        active
          ? 'border-green-400 text-green-400'
          : 'border-transparent text-gray-500 hover:text-gray-300'
      }`}
    >
      {children}
    </button>
  )
}

export default function StaticAnalysis() {
  const [file, setFile] = useState<File | null>(null)
  const [loading, setLoading] = useState(false)
  const [progress, setProgress] = useState(0)
  const [result, setResult] = useState<AnalysisResult | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [activeTab, setActiveTab] = useState('overview')
  const [searchStr, setSearchStr] = useState('')
  const [expandedVuln, setExpandedVuln] = useState<string | null>(null)

  const onDrop = useCallback((acceptedFiles: File[]) => {
    if (acceptedFiles.length > 0) {
      setFile(acceptedFiles[0])
      setResult(null)
      setError(null)
    }
  }, [])

  const { getRootProps, getInputProps, isDragActive } = useDropzone({
    onDrop,
    accept: {
      'application/vnd.android.package-archive': ['.apk'],
      'application/x-msdownload': ['.exe', '.dll'],
      'application/octet-stream': ['.dylib', '.so', '.macho'],
    },
    maxFiles: 1,
  })

  const analyze = async () => {
    if (!file) return
    setLoading(true)
    setProgress(0)
    setError(null)

    const formData = new FormData()
    formData.append('file', file)

    try {
      const progressInterval = setInterval(() => {
        setProgress((p) => Math.min(p + Math.random() * 15, 90))
      }, 400)

      const res = await axios.post(`${API_BASE}/analyze/static`, formData, {
        headers: { 'Content-Type': 'multipart/form-data' },
        timeout: 120000,
      })

      clearInterval(progressInterval)
      setProgress(100)
      setResult(res.data)
      setActiveTab('overview')

      // Save to history
      const history = JSON.parse(localStorage.getItem('appsleuth_history') || '[]')
      history.unshift({
        name: file.name,
        type: res.data.file_type,
        date: new Date().toLocaleString('ja-JP'),
        vulnCount: (res.data.vulnerabilities || []).length,
      })
      localStorage.setItem('appsleuth_history', JSON.stringify(history.slice(0, 20)))
    } catch (err: any) {
      setError(err.response?.data?.detail || err.message || '解析に失敗しました')
    } finally {
      setLoading(false)
    }
  }

  const exportResult = () => {
    if (!result) return
    const json = JSON.stringify(result, null, 2)
    const blob = new Blob([json], { type: 'application/json' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `${result.file_name}_analysis.json`
    a.click()
    URL.revokeObjectURL(url)
  }

  const highCount = result?.vulnerabilities?.filter((v) => v.severity === 'HIGH').length || 0
  const medCount = result?.vulnerabilities?.filter((v) => v.severity === 'MEDIUM').length || 0

  return (
    <div className="h-full flex flex-col overflow-hidden">
      {/* Header */}
      <div className="flex items-center justify-between px-6 py-4 border-b border-[#30363d] flex-shrink-0">
        <div className="flex items-center gap-3">
          <FileSearch size={18} className="text-blue-400" />
          <h2 className="text-base font-semibold text-gray-100">静的解析</h2>
          {result && (
            <span className="text-xs px-2 py-0.5 rounded-full bg-blue-900/30 text-blue-400 border border-blue-700/50">
              {result.file_type}
            </span>
          )}
        </div>
        {result && (
          <button
            onClick={exportResult}
            className="flex items-center gap-2 px-3 py-1.5 rounded-md text-sm bg-[#21262d] hover:bg-[#30363d] text-gray-300 border border-[#30363d] transition-colors"
          >
            <Download size={14} />
            JSONエクスポート
          </button>
        )}
      </div>

      <div className="flex-1 overflow-y-auto p-6 space-y-4">
        {/* Drop zone */}
        <div
          {...getRootProps()}
          className={`border-2 border-dashed rounded-lg p-8 text-center cursor-pointer transition-all ${
            isDragActive
              ? 'border-blue-400 bg-blue-900/20'
              : file
              ? 'border-green-500/50 bg-green-900/10'
              : 'border-[#30363d] hover:border-gray-500 bg-[#161b22]'
          }`}
        >
          <input {...getInputProps()} />
          <Upload size={32} className={`mx-auto mb-3 ${file ? 'text-green-400' : 'text-gray-600'}`} />
          {file ? (
            <div>
              <div className="text-sm font-medium text-green-400">{file.name}</div>
              <div className="text-xs text-gray-500 mt-1">
                {(file.size / 1024 / 1024).toFixed(2)} MB
              </div>
            </div>
          ) : (
            <div>
              <div className="text-sm text-gray-400">
                APK / EXE / DLL / DYLIB をドロップまたはクリック
              </div>
              <div className="text-xs text-gray-600 mt-1">
                Android・Windows・macOS バイナリに対応
              </div>
            </div>
          )}
        </div>

        {/* Analyze button */}
        {file && !loading && (
          <button
            onClick={analyze}
            className="w-full py-2.5 bg-blue-600 hover:bg-blue-500 text-white font-medium rounded-lg transition-colors"
          >
            解析開始
          </button>
        )}

        {/* Progress */}
        {loading && (
          <div className="bg-[#161b22] border border-[#30363d] rounded-lg p-4">
            <div className="flex items-center gap-3 mb-3">
              <Loader size={16} className="text-blue-400 animate-spin" />
              <span className="text-sm text-gray-300">解析中...</span>
              <span className="text-sm text-blue-400 ml-auto">{Math.round(progress)}%</span>
            </div>
            <div className="h-1.5 bg-[#21262d] rounded-full overflow-hidden">
              <div
                className="h-full bg-blue-500 rounded-full transition-all duration-300"
                style={{ width: `${progress}%` }}
              />
            </div>
          </div>
        )}

        {/* Error */}
        {error && (
          <div className="bg-red-900/20 border border-red-700/50 rounded-lg p-4 text-sm text-red-400">
            <div className="flex items-center gap-2 mb-1 font-semibold">
              <XCircle size={14} />
              解析エラー
            </div>
            {error}
          </div>
        )}

        {/* Results */}
        {result && (
          <div className="bg-[#161b22] border border-[#30363d] rounded-lg overflow-hidden">
            {/* Summary bar */}
            <div className="flex items-center gap-6 px-4 py-3 bg-[#1c2230] border-b border-[#30363d]">
              <div>
                <div className="text-xs text-gray-500">ファイル名</div>
                <div className="text-sm font-medium text-gray-100">{result.file_name}</div>
              </div>
              {result.app_name && (
                <div>
                  <div className="text-xs text-gray-500">アプリ名</div>
                  <div className="text-sm text-gray-100">{result.app_name}</div>
                </div>
              )}
              {result.version && (
                <div>
                  <div className="text-xs text-gray-500">バージョン</div>
                  <div className="text-sm text-gray-100">{result.version}</div>
                </div>
              )}
              <div className="ml-auto flex items-center gap-3">
                {highCount > 0 && (
                  <span className="text-xs px-2 py-1 rounded-full bg-red-900/30 text-red-400 border border-red-700/50">
                    High: {highCount}
                  </span>
                )}
                {medCount > 0 && (
                  <span className="text-xs px-2 py-1 rounded-full bg-yellow-900/30 text-yellow-400 border border-yellow-700/50">
                    Medium: {medCount}
                  </span>
                )}
              </div>
            </div>

            {/* Tabs */}
            <div className="flex border-b border-[#30363d] overflow-x-auto">
              {[
                ['overview', '概要'],
                ['vulns', `脆弱性 (${result.vulnerabilities?.length || 0})`],
                ['permissions', `権限 (${result.permissions?.length || 0})`],
                ['strings', '文字列'],
                ['network', `ネットワーク (${result.urls_found?.length || 0})`],
                ['certificates', '証明書'],
                result.imports ? ['imports', 'インポート'] : null,
                result.sections ? ['sections', 'セクション'] : null,
              ]
                .filter(Boolean)
                .map(([id, label]) => (
                  <Tab key={id} active={activeTab === id} onClick={() => setActiveTab(id!)}>
                    {label}
                  </Tab>
                ))}
            </div>

            <div className="p-4">
              {/* Overview tab */}
              {activeTab === 'overview' && (
                <div className="grid grid-cols-2 gap-4">
                  {[
                    ['ファイルタイプ', result.file_type],
                    ['サイズ', `${(result.file_size / 1024 / 1024).toFixed(2)} MB`],
                    result.package_name ? ['パッケージ名', result.package_name] : null,
                    result.version ? ['バージョン', result.version] : null,
                    result.min_sdk ? ['最小 SDK', String(result.min_sdk)] : null,
                    result.target_sdk ? ['対象 SDK', String(result.target_sdk)] : null,
                    result.arch ? ['アーキテクチャ', result.arch] : null,
                  ]
                    .filter(Boolean)
                    .map(([k, v]) => (
                      <div key={k} className="bg-[#21262d] rounded-md p-3">
                        <div className="text-xs text-gray-500 mb-1">{k}</div>
                        <div className="text-sm text-gray-100 font-mono break-all">{v}</div>
                      </div>
                    ))}
                </div>
              )}

              {/* Vulnerabilities tab */}
              {activeTab === 'vulns' && (
                <div className="space-y-2">
                  {(result.vulnerabilities || []).length === 0 ? (
                    <div className="text-center py-8 text-gray-500 text-sm">
                      <CheckCircle size={24} className="text-green-400 mx-auto mb-2" />
                      脆弱性は検出されませんでした
                    </div>
                  ) : (
                    (result.vulnerabilities || []).map((v) => (
                      <div
                        key={v.id}
                        className={`rounded-md border overflow-hidden ${severityConfig[v.severity].bg}`}
                      >
                        <button
                          className="w-full flex items-center gap-3 px-4 py-3 text-left"
                          onClick={() => setExpandedVuln(expandedVuln === v.id ? null : v.id)}
                        >
                          <SeverityBadge severity={v.severity} />
                          <span className="text-sm text-gray-200 flex-1">{v.title}</span>
                          {expandedVuln === v.id ? (
                            <ChevronDown size={14} className="text-gray-500" />
                          ) : (
                            <ChevronRight size={14} className="text-gray-500" />
                          )}
                        </button>
                        {expandedVuln === v.id && (
                          <div className="px-4 pb-4 border-t border-gray-700/50 mt-1 pt-3 space-y-2">
                            <p className="text-sm text-gray-300">{v.description}</p>
                            {v.location && (
                              <div className="text-xs font-mono bg-black/30 px-2 py-1 rounded text-gray-400">
                                場所: {v.location}
                              </div>
                            )}
                            {v.recommendation && (
                              <div className="text-sm text-green-300">
                                <span className="font-semibold text-green-400">推奨対策: </span>
                                {v.recommendation}
                              </div>
                            )}
                          </div>
                        )}
                      </div>
                    ))
                  )}
                </div>
              )}

              {/* Permissions tab */}
              {activeTab === 'permissions' && (
                <div className="space-y-1">
                  {(result.permissions || []).map((p, i) => (
                    <div key={i} className="flex items-start gap-3 py-2 border-b border-[#30363d] last:border-0">
                      <span className={`text-xs px-1.5 py-0.5 rounded border flex-shrink-0 mt-0.5 ${
                        p.risk === 'HIGH'
                          ? 'bg-red-900/30 text-red-400 border-red-700/50'
                          : p.risk === 'MEDIUM'
                          ? 'bg-yellow-900/30 text-yellow-400 border-yellow-700/50'
                          : 'bg-gray-800 text-gray-400 border-gray-700'
                      }`}>
                        {p.risk}
                      </span>
                      <div className="min-w-0">
                        <div className="text-xs font-mono text-gray-300 truncate">{p.name}</div>
                        <div className="text-xs text-gray-500 mt-0.5">{p.description}</div>
                      </div>
                    </div>
                  ))}
                  {(result.permissions || []).length === 0 && (
                    <div className="text-sm text-gray-500 text-center py-4">権限情報なし</div>
                  )}
                </div>
              )}

              {/* Strings tab */}
              {activeTab === 'strings' && (
                <div>
                  <div className="relative mb-3">
                    <Search size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-gray-500" />
                    <input
                      type="text"
                      placeholder="文字列を検索..."
                      value={searchStr}
                      onChange={(e) => setSearchStr(e.target.value)}
                      className="w-full pl-8 pr-3 py-2 bg-[#21262d] border border-[#30363d] rounded-md text-sm text-gray-100 placeholder-gray-600 outline-none focus:border-blue-500"
                    />
                  </div>
                  <div className="max-h-64 overflow-y-auto space-y-0.5">
                    {(result.strings_found || [])
                      .filter((s) => s.toLowerCase().includes(searchStr.toLowerCase()))
                      .slice(0, 200)
                      .map((s, i) => (
                        <div key={i} className="font-mono text-xs text-gray-300 py-0.5 px-2 hover:bg-[#21262d] rounded">
                          {s}
                        </div>
                      ))}
                  </div>
                  <div className="text-xs text-gray-600 mt-2">
                    {result.strings_found?.length || 0} 件の文字列
                  </div>
                </div>
              )}

              {/* Network/URLs tab */}
              {activeTab === 'network' && (
                <div className="space-y-2">
                  {result.secrets_found && result.secrets_found.length > 0 && (
                    <div className="bg-red-900/20 border border-red-700/50 rounded-lg p-3 mb-4">
                      <div className="text-sm font-semibold text-red-400 mb-2 flex items-center gap-2">
                        <Key size={14} />
                        ハードコードされたシークレット ({result.secrets_found.length} 件)
                      </div>
                      {result.secrets_found.map((s, i) => (
                        <div key={i} className="text-xs font-mono bg-black/30 p-2 rounded mb-1">
                          <span className="text-red-300">[{s.type}]</span>{' '}
                          <span className="text-gray-300">{s.value}</span>
                          <span className="text-gray-600 ml-2">@ {s.location}</span>
                        </div>
                      ))}
                    </div>
                  )}
                  <div className="font-semibold text-xs text-gray-500 uppercase mb-2">エンドポイント</div>
                  {(result.urls_found || []).map((url, i) => (
                    <div key={i} className="flex items-center gap-2 text-xs font-mono py-1.5 px-2 bg-[#21262d] rounded hover:bg-[#30363d]">
                      <Globe size={12} className="text-blue-400 flex-shrink-0" />
                      <span className="text-gray-300 truncate">{url}</span>
                    </div>
                  ))}
                  {(result.urls_found || []).length === 0 && (
                    <div className="text-sm text-gray-500 text-center py-4">URLは検出されませんでした</div>
                  )}
                </div>
              )}

              {/* Certificates tab */}
              {activeTab === 'certificates' && (
                <div className="space-y-3">
                  {(result.certificates || []).map((cert, i) => (
                    <div key={i} className="bg-[#21262d] rounded-lg p-4 space-y-2">
                      <div className="text-xs text-gray-500">証明書 {i + 1}</div>
                      {[
                        ['発行者 (Issuer)', cert.issuer],
                        ['サブジェクト', cert.subject],
                        ['有効期間 (開始)', cert.valid_from],
                        ['有効期間 (終了)', cert.valid_to],
                        ['フィンガープリント', cert.fingerprint],
                      ].map(([k, v]) => (
                        <div key={k} className="grid grid-cols-3 gap-2">
                          <div className="text-xs text-gray-500 col-span-1">{k}</div>
                          <div className="text-xs font-mono text-gray-300 col-span-2 break-all">{v}</div>
                        </div>
                      ))}
                    </div>
                  ))}
                  {(result.certificates || []).length === 0 && (
                    <div className="text-sm text-gray-500 text-center py-4">証明書情報なし</div>
                  )}
                </div>
              )}

              {/* Imports tab */}
              {activeTab === 'imports' && result.imports && (
                <div className="space-y-2 max-h-96 overflow-y-auto">
                  {result.imports.map((imp, i) => (
                    <div key={i} className="bg-[#21262d] rounded-md overflow-hidden">
                      <div className="px-3 py-2 bg-[#30363d] text-xs font-semibold text-gray-300">{imp.dll}</div>
                      <div className="px-3 py-2 space-y-0.5">
                        {imp.functions.slice(0, 20).map((fn, j) => (
                          <div key={j} className="text-xs font-mono text-gray-400">{fn}</div>
                        ))}
                        {imp.functions.length > 20 && (
                          <div className="text-xs text-gray-600">...他 {imp.functions.length - 20} 件</div>
                        )}
                      </div>
                    </div>
                  ))}
                </div>
              )}

              {/* Sections tab */}
              {activeTab === 'sections' && result.sections && (
                <table className="w-full text-sm">
                  <thead>
                    <tr className="text-xs text-gray-500 border-b border-[#30363d]">
                      <th className="text-left py-2 pr-4">セクション</th>
                      <th className="text-right py-2 pr-4">サイズ</th>
                      <th className="text-right py-2">エントロピー</th>
                    </tr>
                  </thead>
                  <tbody>
                    {result.sections.map((sec, i) => (
                      <tr key={i} className="border-b border-[#30363d] last:border-0">
                        <td className="py-2 pr-4 font-mono text-gray-300">{sec.name}</td>
                        <td className="py-2 pr-4 text-right text-gray-400">{(sec.size / 1024).toFixed(1)} KB</td>
                        <td className={`py-2 text-right font-mono ${
                          sec.entropy > 7.5 ? 'text-red-400' : sec.entropy > 6.5 ? 'text-yellow-400' : 'text-gray-400'
                        }`}>
                          {sec.entropy.toFixed(3)}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            </div>
          </div>
        )}
      </div>
    </div>
  )
}

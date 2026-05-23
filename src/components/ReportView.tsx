import React, { useState } from 'react'
import axios from 'axios'
import { FileText, Download, Trash2, Clock, AlertTriangle, CheckCircle } from 'lucide-react'

const API_BASE = 'http://localhost:8765'

interface HistoryItem {
  name: string
  type: string
  date: string
  vulnCount: number
}

export default function ReportView() {
  const [history, setHistory] = useState<HistoryItem[]>(() => {
    try {
      return JSON.parse(localStorage.getItem('appsleuth_history') || '[]')
    } catch {
      return []
    }
  })
  const [generating, setGenerating] = useState(false)

  const generateReport = async () => {
    if (history.length === 0) return
    setGenerating(true)
    try {
      const res = await axios.post(`${API_BASE}/report/generate`, { history })
      const blob = new Blob([res.data.html], { type: 'text/html' })
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = `appsleuth-report-${new Date().toISOString().slice(0, 10)}.html`
      a.click()
      URL.revokeObjectURL(url)
    } catch {
      // Fallback: generate client-side
      const html = generateClientReport(history)
      const blob = new Blob([html], { type: 'text/html' })
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = `appsleuth-report-${new Date().toISOString().slice(0, 10)}.html`
      a.click()
      URL.revokeObjectURL(url)
    } finally {
      setGenerating(false)
    }
  }

  const clearHistory = () => {
    if (confirm('解析履歴をすべて削除しますか？')) {
      localStorage.removeItem('appsleuth_history')
      setHistory([])
    }
  }

  const totalVulns = history.reduce((a, h) => a + (h.vulnCount || 0), 0)

  return (
    <div className="h-full overflow-y-auto p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <FileText size={18} className="text-gray-400" />
          <h2 className="text-base font-semibold text-gray-100">レポート</h2>
        </div>
        <div className="flex items-center gap-2">
          {history.length > 0 && (
            <>
              <button
                onClick={clearHistory}
                className="flex items-center gap-1.5 text-xs px-3 py-1.5 bg-[#21262d] hover:bg-[#30363d] text-gray-400 rounded border border-[#30363d] transition-colors"
              >
                <Trash2 size={12} />
                履歴削除
              </button>
              <button
                onClick={generateReport}
                disabled={generating}
                className="flex items-center gap-1.5 text-sm px-4 py-1.5 bg-gray-700 hover:bg-gray-600 text-white rounded border border-gray-600 transition-colors disabled:opacity-50"
              >
                <Download size={14} />
                {generating ? '生成中...' : 'HTML レポート出力'}
              </button>
            </>
          )}
        </div>
      </div>

      {/* Stats */}
      {history.length > 0 && (
        <div className="grid grid-cols-3 gap-4">
          <div className="bg-[#161b22] border border-[#30363d] rounded-lg p-4">
            <div className="text-2xl font-bold text-gray-100">{history.length}</div>
            <div className="text-xs text-gray-500 mt-1">解析済みファイル</div>
          </div>
          <div className="bg-[#161b22] border border-[#30363d] rounded-lg p-4">
            <div className={`text-2xl font-bold ${totalVulns > 0 ? 'text-red-400' : 'text-green-400'}`}>{totalVulns}</div>
            <div className="text-xs text-gray-500 mt-1">検出された脆弱性</div>
          </div>
          <div className="bg-[#161b22] border border-[#30363d] rounded-lg p-4">
            <div className="text-2xl font-bold text-gray-100">
              {history.filter((h) => h.vulnCount === 0).length}
            </div>
            <div className="text-xs text-gray-500 mt-1">クリーンなファイル</div>
          </div>
        </div>
      )}

      {/* History table */}
      {history.length === 0 ? (
        <div className="flex flex-col items-center justify-center py-24 text-center">
          <FileText size={48} className="text-gray-700 mb-4" />
          <div className="text-gray-500 text-sm">まだ解析が行われていません</div>
          <div className="text-gray-600 text-xs mt-1">静的解析を実行すると、ここに履歴が表示されます</div>
        </div>
      ) : (
        <div className="bg-[#161b22] border border-[#30363d] rounded-lg overflow-hidden">
          <div className="grid grid-cols-[2fr_1fr_1fr_1fr] gap-4 px-4 py-2 border-b border-[#30363d] text-xs text-gray-600 uppercase">
            <span>ファイル名</span>
            <span>種別</span>
            <span>解析日時</span>
            <span className="text-right">脆弱性</span>
          </div>
          {history.map((item, i) => (
            <div
              key={i}
              className="grid grid-cols-[2fr_1fr_1fr_1fr] gap-4 px-4 py-3 border-b border-[#30363d] last:border-0 hover:bg-[#1c2230] transition-colors items-center"
            >
              <div className="flex items-center gap-2">
                <FileText size={14} className="text-gray-500 flex-shrink-0" />
                <span className="text-sm text-gray-200 truncate">{item.name}</span>
              </div>
              <span className="text-xs text-gray-500">{item.type}</span>
              <div className="flex items-center gap-1.5 text-xs text-gray-500">
                <Clock size={11} />
                {item.date}
              </div>
              <div className="text-right">
                {item.vulnCount > 0 ? (
                  <span className="flex items-center justify-end gap-1 text-xs text-red-400">
                    <AlertTriangle size={11} />
                    {item.vulnCount} 件
                  </span>
                ) : (
                  <span className="flex items-center justify-end gap-1 text-xs text-green-400">
                    <CheckCircle size={11} />
                    クリーン
                  </span>
                )}
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}

function generateClientReport(history: HistoryItem[]): string {
  const totalVulns = history.reduce((a, h) => a + h.vulnCount, 0)
  const now = new Date().toLocaleString('ja-JP')

  return `<!DOCTYPE html>
<html lang="ja">
<head>
<meta charset="UTF-8">
<title>AppSleuth セキュリティレポート</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: 'Segoe UI', sans-serif; background: #0f1117; color: #e6edf3; padding: 40px; line-height: 1.6; }
  h1 { color: #39d353; font-size: 28px; margin-bottom: 8px; }
  h2 { color: #58a6ff; font-size: 18px; margin: 32px 0 16px; border-bottom: 1px solid #30363d; padding-bottom: 8px; }
  .meta { color: #8b949e; font-size: 14px; margin-bottom: 32px; }
  .stats { display: grid; grid-template-columns: repeat(3, 1fr); gap: 16px; margin-bottom: 32px; }
  .stat { background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 20px; }
  .stat-value { font-size: 32px; font-weight: bold; }
  .stat-label { color: #8b949e; font-size: 13px; margin-top: 4px; }
  table { width: 100%; border-collapse: collapse; background: #161b22; border-radius: 8px; overflow: hidden; }
  th { background: #1c2230; padding: 10px 16px; text-align: left; font-size: 12px; color: #8b949e; text-transform: uppercase; }
  td { padding: 12px 16px; border-top: 1px solid #30363d; font-size: 14px; }
  .vuln-badge { color: #f85149; font-weight: 600; }
  .clean-badge { color: #39d353; }
  .footer { margin-top: 40px; color: #484f58; font-size: 12px; text-align: center; }
</style>
</head>
<body>
  <h1>🛡️ AppSleuth セキュリティレポート</h1>
  <div class="meta">生成日時: ${now} · AppSleuth v1.0.0</div>

  <div class="stats">
    <div class="stat"><div class="stat-value">${history.length}</div><div class="stat-label">解析済みファイル</div></div>
    <div class="stat"><div class="stat-value" style="color:${totalVulns > 0 ? '#f85149' : '#39d353'}">${totalVulns}</div><div class="stat-label">検出された脆弱性</div></div>
    <div class="stat"><div class="stat-value">${history.filter(h => h.vulnCount === 0).length}</div><div class="stat-label">クリーンなファイル</div></div>
  </div>

  <h2>解析履歴</h2>
  <table>
    <thead><tr><th>ファイル名</th><th>種別</th><th>解析日時</th><th>脆弱性</th></tr></thead>
    <tbody>
      ${history.map(h => `
        <tr>
          <td>${h.name}</td>
          <td style="color:#8b949e">${h.type}</td>
          <td style="color:#8b949e">${h.date}</td>
          <td class="${h.vulnCount > 0 ? 'vuln-badge' : 'clean-badge'}">${h.vulnCount > 0 ? `⚠ ${h.vulnCount} 件` : '✓ クリーン'}</td>
        </tr>`).join('')}
    </tbody>
  </table>

  <div class="footer">AppSleuth Security Analysis Tool · Powered by Claude AI</div>
</body>
</html>`
}

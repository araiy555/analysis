import React, { useState } from 'react'
import { Settings, Key, Globe, Cpu, Save, CheckCircle } from 'lucide-react'

export default function SettingsPage() {
  const [claudeKey, setClaudeKey] = useState(() => localStorage.getItem('claude_api_key') || '')
  const [proxyHost, setProxyHost] = useState(() => localStorage.getItem('proxy_host') || '127.0.0.1')
  const [proxyPort, setProxyPort] = useState(() => localStorage.getItem('proxy_port') || '8080')
  const [fridaHost, setFridaHost] = useState(() => localStorage.getItem('frida_host') || 'localhost')
  const [fridaPort, setFridaPort] = useState(() => localStorage.getItem('frida_port') || '27042')
  const [apktoolPath, setApktoolPath] = useState(() => localStorage.getItem('apktool_path') || 'apktool')
  const [jadxPath, setJadxPath] = useState(() => localStorage.getItem('jadx_path') || 'jadx')
  const [saved, setSaved] = useState(false)

  const saveSettings = () => {
    localStorage.setItem('claude_api_key', claudeKey)
    localStorage.setItem('proxy_host', proxyHost)
    localStorage.setItem('proxy_port', proxyPort)
    localStorage.setItem('frida_host', fridaHost)
    localStorage.setItem('frida_port', fridaPort)
    localStorage.setItem('apktool_path', apktoolPath)
    localStorage.setItem('jadx_path', jadxPath)
    setSaved(true)
    setTimeout(() => setSaved(false), 2000)
  }

  return (
    <div className="h-full overflow-y-auto p-6 space-y-6 max-w-2xl">
      <div className="flex items-center gap-3">
        <Settings size={18} className="text-gray-400" />
        <h2 className="text-base font-semibold text-gray-100">設定</h2>
      </div>

      {/* Claude API */}
      <div className="bg-[#161b22] border border-[#30363d] rounded-lg overflow-hidden">
        <div className="px-4 py-3 border-b border-[#30363d] flex items-center gap-2">
          <Key size={14} className="text-purple-400" />
          <span className="text-sm font-semibold text-gray-200">Claude AI 設定</span>
        </div>
        <div className="p-4 space-y-3">
          <div>
            <label className="text-xs text-gray-500 block mb-1.5">Claude API キー</label>
            <input
              type="password"
              value={claudeKey}
              onChange={(e) => setClaudeKey(e.target.value)}
              placeholder="sk-ant-api03-..."
              className="w-full px-3 py-2 bg-[#21262d] border border-[#30363d] rounded text-sm text-gray-200 placeholder-gray-600 outline-none focus:border-purple-500/50 font-mono"
            />
            <div className="text-xs text-gray-600 mt-1">
              Anthropic Console (<a href="#" className="text-blue-400 hover:underline">console.anthropic.com</a>) から取得
            </div>
          </div>
        </div>
      </div>

      {/* Proxy */}
      <div className="bg-[#161b22] border border-[#30363d] rounded-lg overflow-hidden">
        <div className="px-4 py-3 border-b border-[#30363d] flex items-center gap-2">
          <Globe size={14} className="text-green-400" />
          <span className="text-sm font-semibold text-gray-200">ネットワークプロキシ設定</span>
        </div>
        <div className="p-4 grid grid-cols-2 gap-3">
          <div>
            <label className="text-xs text-gray-500 block mb-1.5">プロキシホスト</label>
            <input
              type="text"
              value={proxyHost}
              onChange={(e) => setProxyHost(e.target.value)}
              className="w-full px-3 py-2 bg-[#21262d] border border-[#30363d] rounded text-sm text-gray-200 outline-none focus:border-green-500/50"
            />
          </div>
          <div>
            <label className="text-xs text-gray-500 block mb-1.5">ポート</label>
            <input
              type="text"
              value={proxyPort}
              onChange={(e) => setProxyPort(e.target.value)}
              className="w-full px-3 py-2 bg-[#21262d] border border-[#30363d] rounded text-sm text-gray-200 outline-none focus:border-green-500/50"
            />
          </div>
        </div>
      </div>

      {/* Frida */}
      <div className="bg-[#161b22] border border-[#30363d] rounded-lg overflow-hidden">
        <div className="px-4 py-3 border-b border-[#30363d] flex items-center gap-2">
          <Cpu size={14} className="text-orange-400" />
          <span className="text-sm font-semibold text-gray-200">Frida 設定</span>
        </div>
        <div className="p-4 grid grid-cols-2 gap-3">
          <div>
            <label className="text-xs text-gray-500 block mb-1.5">Frida サーバーホスト</label>
            <input
              type="text"
              value={fridaHost}
              onChange={(e) => setFridaHost(e.target.value)}
              className="w-full px-3 py-2 bg-[#21262d] border border-[#30363d] rounded text-sm text-gray-200 outline-none focus:border-orange-500/50"
            />
          </div>
          <div>
            <label className="text-xs text-gray-500 block mb-1.5">ポート</label>
            <input
              type="text"
              value={fridaPort}
              onChange={(e) => setFridaPort(e.target.value)}
              className="w-full px-3 py-2 bg-[#21262d] border border-[#30363d] rounded text-sm text-gray-200 outline-none focus:border-orange-500/50"
            />
          </div>
        </div>
        <div className="px-4 pb-4 text-xs text-gray-600">
          Android デバイスで <code className="bg-[#21262d] px-1 rounded">frida-server</code> を起動し、ADB でポートフォワード:<br />
          <code className="bg-[#21262d] px-1 rounded mt-1 inline-block">adb forward tcp:27042 tcp:27042</code>
        </div>
      </div>

      {/* Tool paths */}
      <div className="bg-[#161b22] border border-[#30363d] rounded-lg overflow-hidden">
        <div className="px-4 py-3 border-b border-[#30363d]">
          <span className="text-sm font-semibold text-gray-200">外部ツールパス</span>
        </div>
        <div className="p-4 space-y-3">
          <div>
            <label className="text-xs text-gray-500 block mb-1.5">apktool パス</label>
            <input
              type="text"
              value={apktoolPath}
              onChange={(e) => setApktoolPath(e.target.value)}
              className="w-full px-3 py-2 bg-[#21262d] border border-[#30363d] rounded text-sm text-gray-200 font-mono outline-none focus:border-blue-500/50"
            />
          </div>
          <div>
            <label className="text-xs text-gray-500 block mb-1.5">jadx パス</label>
            <input
              type="text"
              value={jadxPath}
              onChange={(e) => setJadxPath(e.target.value)}
              className="w-full px-3 py-2 bg-[#21262d] border border-[#30363d] rounded text-sm text-gray-200 font-mono outline-none focus:border-blue-500/50"
            />
          </div>
          <div className="text-xs text-gray-600">
            apktool と jadx は PATH が通っているか絶対パスを指定してください
          </div>
        </div>
      </div>

      {/* Save button */}
      <div className="flex justify-end">
        <button
          onClick={saveSettings}
          className="flex items-center gap-2 px-6 py-2.5 bg-green-700 hover:bg-green-600 text-white rounded-lg font-medium transition-all"
        >
          {saved ? <CheckCircle size={16} /> : <Save size={16} />}
          {saved ? '保存しました' : '設定を保存'}
        </button>
      </div>
    </div>
  )
}

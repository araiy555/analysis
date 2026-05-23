import React, { useState, useRef, useEffect, useCallback } from 'react'
import axios from 'axios'
import { Cpu, Play, RefreshCw, Terminal, Code, Square } from 'lucide-react'

const API_BASE = 'http://localhost:8765'
const WS_BASE = 'ws://localhost:8765'

interface Process { pid: number; name: string; path?: string }

const SCRIPT_TEMPLATES: Record<string, string> = {
  'SSL ピン固定バイパス': `Java.perform(function() {
  var TrustManagerImpl = Java.registerClass({
    name: 'com.appsleuth.TrustManager',
    implements: [Java.use('javax.net.ssl.X509TrustManager')],
    methods: {
      checkClientTrusted: function(chain, authType) {},
      checkServerTrusted: function(chain, authType) {},
      getAcceptedIssuers: function() { return []; }
    }
  });
  var sslContext = Java.use('javax.net.ssl.SSLContext').getInstance('TLS');
  sslContext.init(null, [TrustManagerImpl.$new()], null);
  Java.use('javax.net.ssl.SSLContext').getDefault.overload().implementation = function() {
    return sslContext;
  };
  console.log('[+] SSL Pinning bypassed');
});`,

  'HTTP 通信フック': `Java.perform(function() {
  Java.use('okhttp3.OkHttpClient').newCall.overload('okhttp3.Request').implementation = function(req) {
    console.log('[HTTP] ' + req.method() + ' ' + req.url().toString());
    console.log('[Headers] ' + req.headers().toString());
    return this.newCall(req);
  };
});`,

  '暗号化キー抽出': `Java.perform(function() {
  Java.use('javax.crypto.spec.SecretKeySpec').$init.overload('[B', 'java.lang.String').implementation = function(key, alg) {
    var hex = Array.from(key, b => ('0' + (b & 0xff).toString(16)).slice(-2)).join('');
    console.log('[CRYPTO] Alg=' + alg + ' Key=' + hex);
    return this.$init(key, alg);
  };
  Java.use('javax.crypto.Cipher').doFinal.overload('[B').implementation = function(data) {
    console.log('[CIPHER] Input len=' + data.length);
    var r = this.doFinal(data);
    console.log('[CIPHER] Output len=' + r.length);
    return r;
  };
});`,

  'ルート検出バイパス': `Java.perform(function() {
  try {
    var RootBeer = Java.use('com.scottyab.rootbeer.RootBeer');
    RootBeer.isRooted.implementation = function() { return false; };
    console.log('[+] RootBeer bypassed');
  } catch(e) { console.log('[!] RootBeer not found'); }

  Java.use('java.lang.Runtime').exec.overload('java.lang.String').implementation = function(cmd) {
    if (cmd.includes('su') || cmd.includes('busybox')) {
      console.log('[ROOT] Blocked: ' + cmd);
      throw Java.use('java.io.IOException').$new('Permission denied');
    }
    return this.exec(cmd);
  };
});`,

  'メモリダンプ (シークレット検索)': `Process.enumerateRangesSync({protection: 'r--', coalesce: true}).forEach(function(range) {
  try {
    var size = Math.min(range.size, 8192);
    var bytes = Memory.readByteArray(range.base, size);
    var str = '';
    new Uint8Array(bytes).forEach(function(b) {
      if (b >= 0x20 && b <= 0x7e) str += String.fromCharCode(b);
      else {
        if (str.length >= 8) {
          if (/token|key|secret|password|auth|bearer/i.test(str)) {
            console.log('[MEM] ' + str);
          }
        }
        str = '';
      }
    });
  } catch(e) {}
});`,

  'API コールトレース': `Java.perform(function() {
  var targetPkg = 'com.target.app'; // ← パッケージ名を変更
  Java.enumerateLoadedClassesSync().forEach(function(cls) {
    if (cls.startsWith(targetPkg)) {
      try {
        Java.use(cls).class.getDeclaredMethods().forEach(function(m) {
          try {
            Java.use(cls)[m.getName()].overloads.forEach(function(ov) {
              ov.implementation = function() {
                console.log('[TRACE] ' + cls + '.' + m.getName());
                return ov.apply(this, arguments);
              };
            });
          } catch(e) {}
        });
      } catch(e) {}
    }
  });
});`,

  '権限チェックバイパス': `Java.perform(function() {
  var PM = Java.use('android.app.ApplicationPackageManager');
  PM.checkPermission.overload('java.lang.String', 'java.lang.String').implementation = function(perm, pkg) {
    console.log('[PERM] Granting: ' + perm);
    return 0; // PERMISSION_GRANTED
  };
  Java.use('android.content.Context').checkSelfPermission.overload('java.lang.String').implementation = function(p) {
    return 0;
  };
  console.log('[+] Permission bypass active');
});`,
}

interface OutputLine {
  text: string
  color: string
  key: number
}

export default function MemoryAnalysis() {
  const [processes, setProcesses] = useState<Process[]>([])
  const [selectedPid, setSelectedPid] = useState<number | null>(null)
  const [attached, setAttached] = useState(false)
  const [script, setScript] = useState(SCRIPT_TEMPLATES['SSL ピン固定バイパス'])
  const [output, setOutput] = useState<OutputLine[]>([])
  const [running, setRunning] = useState(false)
  const [loadingProcs, setLoadingProcs] = useState(false)
  const [selectedTemplate, setSelectedTemplate] = useState('SSL ピン固定バイパス')
  const [timeout, setTimeout_] = useState(30)
  const outputRef = useRef<HTMLDivElement>(null)
  const wsRef = useRef<WebSocket | null>(null)
  const lineKeyRef = useRef(0)

  useEffect(() => {
    if (outputRef.current) {
      outputRef.current.scrollTop = outputRef.current.scrollHeight
    }
  }, [output])

  useEffect(() => () => { wsRef.current?.close() }, [])

  const addLine = useCallback((text: string) => {
    const ts = new Date().toTimeString().slice(0, 8)
    const line = `${ts} ${text}`
    const color =
      text.includes('[ERROR]') ? 'text-red-400' :
      text.includes('[+]') ? 'text-green-400' :
      text.includes('[CRYPTO]') || text.includes('[CIPHER]') ? 'text-yellow-400' :
      text.includes('[HTTP]') ? 'text-blue-400' :
      text.includes('[MEM]') ? 'text-purple-400' :
      text.includes('[ROOT]') || text.includes('[PERM]') ? 'text-orange-400' :
      text.includes('[TRACE]') ? 'text-cyan-400' :
      text.includes('[*]') || text.includes('[!]') ? 'text-gray-400' :
      'text-green-300'
    setOutput(prev => [...prev.slice(-500), { text: line, color, key: lineKeyRef.current++ }])
  }, [])

  const loadProcesses = async () => {
    setLoadingProcs(true)
    try {
      const res = await axios.get(`${API_BASE}/memory/processes`)
      setProcesses(res.data)
    } catch (err: any) {
      addLine(`[ERROR] プロセス取得失敗: ${err.message}`)
    } finally {
      setLoadingProcs(false)
    }
  }

  const attachProcess = async () => {
    if (!selectedPid) return
    try {
      await axios.post(`${API_BASE}/memory/attach`, { pid: selectedPid })
      setAttached(true)
      addLine(`[+] PID ${selectedPid} にアタッチしました`)
    } catch (err: any) {
      addLine(`[ERROR] アタッチ失敗: ${err.response?.data?.detail || err.message}`)
    }
  }

  const runScript = () => {
    if (!selectedPid) { addLine('[ERROR] プロセスを選択してください'); return }

    // Close existing WebSocket
    if (wsRef.current) { wsRef.current.close(); wsRef.current = null }
    setRunning(true)
    addLine(`[*] WebSocket 経由でスクリプトを実行中 (PID ${selectedPid})...`)

    const ws = new WebSocket(`${WS_BASE}/ws/frida/${selectedPid}`)
    wsRef.current = ws

    ws.onopen = () => {
      ws.send(JSON.stringify({ script, timeout }))
    }

    ws.onmessage = (e) => {
      try {
        const msg = JSON.parse(e.data)
        if (msg.type === 'output') {
          addLine(msg.line)
        } else if (msg.type === 'done') {
          setRunning(false)
        } else if (msg.type === 'error') {
          addLine(msg.line)
          setRunning(false)
        }
      } catch {
        addLine(e.data)
      }
    }

    ws.onerror = () => {
      addLine('[ERROR] WebSocket 接続エラー。バックエンドが起動しているか確認してください。')
      setRunning(false)
    }

    ws.onclose = () => {
      setRunning(false)
    }
  }

  const stopScript = () => {
    if (wsRef.current) { wsRef.current.close(); wsRef.current = null }
    setRunning(false)
    addLine('[*] スクリプトを停止しました')
  }

  return (
    <div className="h-full flex flex-col overflow-hidden">
      <div className="flex items-center gap-3 px-6 py-4 border-b border-[#30363d] flex-shrink-0">
        <Cpu size={18} className="text-orange-400" />
        <h2 className="text-base font-semibold text-gray-100">メモリ解析 (Frida)</h2>
        {running && <span className="flex items-center gap-1.5 text-xs px-2 py-0.5 rounded-full bg-orange-900/30 text-orange-400 border border-orange-700/50">
          <span className="w-1.5 h-1.5 rounded-full bg-orange-400 pulse-dot inline-block" />リアルタイム実行中
        </span>}
        {attached && !running && <span className="text-xs px-2 py-0.5 rounded-full bg-orange-900/30 text-orange-400 border border-orange-700/50">
          PID {selectedPid} アタッチ中
        </span>}
      </div>

      <div className="flex-1 flex overflow-hidden">
        {/* Left: Process + script */}
        <div className="flex flex-col w-96 border-r border-[#30363d] overflow-hidden">
          {/* Process selector */}
          <div className="p-4 border-b border-[#30363d]">
            <div className="flex items-center justify-between mb-2">
              <div className="text-xs font-semibold text-gray-500 uppercase">プロセス</div>
              <button onClick={loadProcesses} disabled={loadingProcs}
                className="flex items-center gap-1 text-xs text-gray-500 hover:text-gray-300 transition-colors">
                <RefreshCw size={12} className={loadingProcs ? 'animate-spin' : ''} />更新
              </button>
            </div>
            {processes.length === 0 ? (
              <button onClick={loadProcesses} disabled={loadingProcs}
                className="w-full py-2 text-sm bg-[#21262d] hover:bg-[#30363d] text-gray-400 rounded border border-[#30363d] transition-colors">
                {loadingProcs ? '取得中...' : 'プロセス一覧を取得'}
              </button>
            ) : (
              <div className="max-h-40 overflow-y-auto space-y-0.5">
                {processes.map(p => (
                  <button key={p.pid} onClick={() => { setSelectedPid(p.pid); setAttached(false) }}
                    className={`w-full flex items-center gap-3 px-2 py-1.5 rounded text-xs text-left transition-colors ${
                      selectedPid === p.pid ? 'bg-orange-900/20 text-orange-400 border border-orange-700/50' : 'hover:bg-[#21262d] text-gray-400'}`}>
                    <span className="text-gray-600 font-mono w-10 text-right flex-shrink-0">{p.pid}</span>
                    <span className="truncate">{p.name}</span>
                  </button>
                ))}
              </div>
            )}
            {selectedPid && !attached && (
              <button onClick={attachProcess}
                className="mt-2 w-full py-2 text-sm bg-orange-700 hover:bg-orange-600 text-white rounded transition-colors">
                PID {selectedPid} にアタッチ
              </button>
            )}
          </div>

          {/* Script editor */}
          <div className="flex-1 flex flex-col overflow-hidden p-4">
            <div className="flex items-center justify-between mb-2">
              <div className="text-xs font-semibold text-gray-500 uppercase flex items-center gap-1.5">
                <Code size={12} />スクリプト
              </div>
              <select value={selectedTemplate} onChange={e => { setSelectedTemplate(e.target.value); setScript(SCRIPT_TEMPLATES[e.target.value]) }}
                className="text-xs bg-[#21262d] border border-[#30363d] rounded px-2 py-1 text-gray-300 max-w-[160px]">
                {Object.keys(SCRIPT_TEMPLATES).map(t => <option key={t}>{t}</option>)}
              </select>
            </div>
            <textarea value={script} onChange={e => setScript(e.target.value)}
              className="flex-1 bg-[#0a0d14] border border-[#30363d] rounded p-3 text-xs font-mono text-green-300 resize-none outline-none focus:border-orange-500/50 min-h-0"
              spellCheck={false} />
            <div className="flex items-center gap-2 mt-3">
              <div className="flex items-center gap-1.5 text-xs text-gray-500">
                <span>タイムアウト</span>
                <input type="number" value={timeout} onChange={e => setTimeout_(Number(e.target.value))} min={5} max={300}
                  className="w-14 px-2 py-1 bg-[#21262d] border border-[#30363d] rounded text-gray-200 text-xs text-center outline-none" />
                <span>秒</span>
              </div>
              {!running ? (
                <button onClick={runScript} disabled={!selectedPid}
                  className="flex-1 flex items-center justify-center gap-2 py-2 bg-orange-700 hover:bg-orange-600 disabled:opacity-40 text-white text-sm rounded transition-colors">
                  <Play size={14} />リアルタイム実行
                </button>
              ) : (
                <button onClick={stopScript}
                  className="flex-1 flex items-center justify-center gap-2 py-2 bg-red-800 hover:bg-red-700 text-white text-sm rounded transition-colors">
                  <Square size={14} />停止
                </button>
              )}
            </div>
          </div>
        </div>

        {/* Right: Console output */}
        <div className="flex-1 flex flex-col overflow-hidden">
          <div className="flex items-center justify-between px-4 py-2 border-b border-[#30363d] bg-[#161b22]">
            <div className="flex items-center gap-2 text-xs text-gray-500">
              <Terminal size={13} />
              リアルタイム出力コンソール
              {running && <span className="text-orange-400 pulse-dot">●</span>}
            </div>
            <button onClick={() => setOutput([])} className="text-xs text-gray-600 hover:text-gray-400 transition-colors">クリア</button>
          </div>
          <div ref={outputRef} className="flex-1 overflow-y-auto p-4 terminal-output font-mono text-xs space-y-0.5">
            {output.length === 0 ? (
              <div className="text-gray-700">
                {'// プロセスにアタッチしてスクリプトを実行すると'}<br />
                {'// リアルタイムで出力がストリーミングされます'}<br />
                {'// WebSocket 経由で逐次更新'}
              </div>
            ) : output.map(line => (
              <div key={line.key} className={line.color}>{line.text}</div>
            ))}
          </div>
        </div>
      </div>
    </div>
  )
}

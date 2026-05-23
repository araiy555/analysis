import React, { useState, useRef, useEffect } from 'react'
import axios from 'axios'
import { Cpu, Play, RefreshCw, Terminal, Code, ChevronDown } from 'lucide-react'

const API_BASE = 'http://localhost:8765'

interface Process {
  pid: number
  name: string
  path?: string
}

const SCRIPT_TEMPLATES: Record<string, string> = {
  'SSL ピン固定バイパス': `// SSL Certificate Pinning bypass
Java.perform(function() {
  var TrustManager = Java.use('javax.net.ssl.X509TrustManager');
  var SSLContext = Java.use('javax.net.ssl.SSLContext');

  var TrustManagerImpl = Java.registerClass({
    name: 'com.appsleuth.TrustManager',
    implements: [TrustManager],
    methods: {
      checkClientTrusted: function(chain, authType) {},
      checkServerTrusted: function(chain, authType) {},
      getAcceptedIssuers: function() { return []; }
    }
  });

  var trustManagers = [TrustManagerImpl.$new()];
  var sslContext = SSLContext.getInstance('TLS');
  sslContext.init(null, trustManagers, null);
  SSLContext.getDefault.overload().implementation = function() {
    return sslContext;
  };
  console.log('[+] SSL Pinning bypassed');
});`,

  'HTTP 通信フック': `// Hook HTTP/HTTPS calls and log them
Java.perform(function() {
  var OkHttpClient = Java.use('okhttp3.OkHttpClient');
  var Request = Java.use('okhttp3.Request');
  var Response = Java.use('okhttp3.Response');

  OkHttpClient.newCall.overload('okhttp3.Request').implementation = function(req) {
    console.log('[HTTP] ' + req.method() + ' ' + req.url().toString());
    console.log('[Headers] ' + req.headers().toString());
    return this.newCall(req);
  };
});`,

  '暗号化キー抽出': `// Hook crypto operations to extract keys
Java.perform(function() {
  var SecretKeySpec = Java.use('javax.crypto.spec.SecretKeySpec');
  SecretKeySpec.$init.overload('[B', 'java.lang.String').implementation = function(key, alg) {
    var keyHex = Array.from(key, b => ('0' + (b & 0xff).toString(16)).slice(-2)).join('');
    console.log('[CRYPTO] Algorithm: ' + alg + ', Key: ' + keyHex);
    return this.$init(key, alg);
  };

  var Cipher = Java.use('javax.crypto.Cipher');
  Cipher.doFinal.overload('[B').implementation = function(data) {
    console.log('[CIPHER] Input data length: ' + data.length);
    var result = this.doFinal(data);
    console.log('[CIPHER] Output data length: ' + result.length);
    return result;
  };
});`,

  'ルート検出バイパス': `// Root detection bypass
Java.perform(function() {
  var RootBeer = null;
  try {
    RootBeer = Java.use('com.scottyab.rootbeer.RootBeer');
    RootBeer.isRooted.implementation = function() { return false; };
    console.log('[+] RootBeer bypass applied');
  } catch(e) {}

  // Generic root checks
  var Runtime = Java.use('java.lang.Runtime');
  Runtime.exec.overload('java.lang.String').implementation = function(cmd) {
    if (cmd.includes('su') || cmd.includes('which su')) {
      console.log('[ROOT] Blocked su check: ' + cmd);
      throw Java.use('java.io.IOException').$new('Permission denied');
    }
    return this.exec(cmd);
  };
});`,

  'メモリダンプ (文字列検索)': `// Dump strings from memory
Process.enumerateRangesSync({protection: 'r--', coalesce: true}).forEach(function(range) {
  try {
    var mem = Memory.readByteArray(range.base, Math.min(range.size, 4096));
    var str = '';
    new Uint8Array(mem).forEach(function(b) {
      if (b >= 0x20 && b <= 0x7e) str += String.fromCharCode(b);
      else if (str.length >= 8) {
        if (str.includes('token') || str.includes('key') || str.includes('secret') || str.includes('password')) {
          console.log('[MEM] Found: ' + str);
        }
        str = '';
      } else str = '';
    });
  } catch(e) {}
});`,

  'API コールトレース': `// Trace all Java method calls (use carefully - very verbose)
Java.perform(function() {
  Java.enumerateLoadedClassesSync().forEach(function(className) {
    if (className.startsWith('com.target.app')) { // Modify package name
      try {
        var clazz = Java.use(className);
        clazz.class.getDeclaredMethods().forEach(function(method) {
          var methodName = method.getName();
          try {
            clazz[methodName].overloads.forEach(function(overload) {
              overload.implementation = function() {
                console.log('[TRACE] ' + className + '.' + methodName);
                return overload.apply(this, arguments);
              };
            });
          } catch(e) {}
        });
      } catch(e) {}
    }
  });
});`,
}

export default function MemoryAnalysis() {
  const [processes, setProcesses] = useState<Process[]>([])
  const [selectedPid, setSelectedPid] = useState<number | null>(null)
  const [attached, setAttached] = useState(false)
  const [script, setScript] = useState(SCRIPT_TEMPLATES['SSL ピン固定バイパス'])
  const [output, setOutput] = useState<string[]>([])
  const [loading, setLoading] = useState(false)
  const [loadingProcs, setLoadingProcs] = useState(false)
  const [selectedTemplate, setSelectedTemplate] = useState('SSL ピン固定バイパス')
  const outputRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    if (outputRef.current) {
      outputRef.current.scrollTop = outputRef.current.scrollHeight
    }
  }, [output])

  const loadProcesses = async () => {
    setLoadingProcs(true)
    try {
      const res = await axios.get(`${API_BASE}/memory/processes`)
      setProcesses(res.data)
    } catch (err: any) {
      addOutput(`[ERROR] プロセス一覧の取得に失敗: ${err.message}`)
    } finally {
      setLoadingProcs(false)
    }
  }

  const attachProcess = async () => {
    if (!selectedPid) return
    setLoading(true)
    try {
      await axios.post(`${API_BASE}/memory/attach`, { pid: selectedPid })
      setAttached(true)
      addOutput(`[+] PID ${selectedPid} にアタッチしました`)
    } catch (err: any) {
      addOutput(`[ERROR] アタッチ失敗: ${err.response?.data?.detail || err.message}`)
    } finally {
      setLoading(false)
    }
  }

  const runScript = async () => {
    if (!selectedPid) {
      addOutput('[ERROR] プロセスを選択してください')
      return
    }
    setLoading(true)
    addOutput('[*] スクリプトを実行中...')
    try {
      const res = await axios.post(`${API_BASE}/memory/run-script`, {
        pid: selectedPid,
        script: script,
      })
      const lines: string[] = res.data.output || []
      lines.forEach((l) => addOutput(l))
      if (lines.length === 0) addOutput('[+] スクリプト実行完了 (出力なし)')
    } catch (err: any) {
      addOutput(`[ERROR] ${err.response?.data?.detail || err.message}`)
    } finally {
      setLoading(false)
    }
  }

  const addOutput = (line: string) => {
    const timestamp = new Date().toTimeString().slice(0, 8)
    setOutput((prev) => [...prev, `${timestamp} ${line}`])
  }

  return (
    <div className="h-full flex flex-col overflow-hidden">
      {/* Header */}
      <div className="flex items-center gap-3 px-6 py-4 border-b border-[#30363d] flex-shrink-0">
        <Cpu size={18} className="text-orange-400" />
        <h2 className="text-base font-semibold text-gray-100">メモリ解析 (Frida)</h2>
        {attached && (
          <span className="text-xs px-2 py-0.5 rounded-full bg-orange-900/30 text-orange-400 border border-orange-700/50">
            PID {selectedPid} にアタッチ中
          </span>
        )}
      </div>

      <div className="flex-1 flex overflow-hidden">
        {/* Left: Process selector + script */}
        <div className="flex flex-col w-96 border-r border-[#30363d] overflow-hidden">
          {/* Process list */}
          <div className="p-4 border-b border-[#30363d]">
            <div className="flex items-center justify-between mb-2">
              <div className="text-xs font-semibold text-gray-500 uppercase">プロセス</div>
              <button
                onClick={loadProcesses}
                disabled={loadingProcs}
                className="flex items-center gap-1 text-xs text-gray-500 hover:text-gray-300 transition-colors"
              >
                <RefreshCw size={12} className={loadingProcs ? 'animate-spin' : ''} />
                更新
              </button>
            </div>

            {processes.length === 0 ? (
              <button
                onClick={loadProcesses}
                disabled={loadingProcs}
                className="w-full py-2 text-sm bg-[#21262d] hover:bg-[#30363d] text-gray-400 rounded border border-[#30363d] transition-colors"
              >
                {loadingProcs ? '取得中...' : 'プロセス一覧を取得'}
              </button>
            ) : (
              <div className="max-h-40 overflow-y-auto space-y-0.5">
                {processes.map((p) => (
                  <button
                    key={p.pid}
                    onClick={() => { setSelectedPid(p.pid); setAttached(false) }}
                    className={`w-full flex items-center gap-3 px-2 py-1.5 rounded text-xs text-left transition-colors ${
                      selectedPid === p.pid
                        ? 'bg-orange-900/20 text-orange-400 border border-orange-700/50'
                        : 'hover:bg-[#21262d] text-gray-400'
                    }`}
                  >
                    <span className="text-gray-600 font-mono w-12 text-right flex-shrink-0">{p.pid}</span>
                    <span className="truncate">{p.name}</span>
                  </button>
                ))}
              </div>
            )}

            {selectedPid && !attached && (
              <button
                onClick={attachProcess}
                disabled={loading}
                className="mt-2 w-full py-2 text-sm bg-orange-700 hover:bg-orange-600 text-white rounded transition-colors disabled:opacity-50"
              >
                {loading ? 'アタッチ中...' : `PID ${selectedPid} にアタッチ`}
              </button>
            )}
          </div>

          {/* Script editor */}
          <div className="flex-1 flex flex-col overflow-hidden p-4">
            <div className="flex items-center justify-between mb-2">
              <div className="text-xs font-semibold text-gray-500 uppercase flex items-center gap-2">
                <Code size={12} />
                Frida スクリプト
              </div>
              <select
                value={selectedTemplate}
                onChange={(e) => {
                  setSelectedTemplate(e.target.value)
                  setScript(SCRIPT_TEMPLATES[e.target.value])
                }}
                className="text-xs bg-[#21262d] border border-[#30363d] rounded px-2 py-1 text-gray-300 max-w-[160px]"
              >
                {Object.keys(SCRIPT_TEMPLATES).map((t) => (
                  <option key={t}>{t}</option>
                ))}
              </select>
            </div>
            <textarea
              value={script}
              onChange={(e) => setScript(e.target.value)}
              className="flex-1 bg-[#0a0d14] border border-[#30363d] rounded p-3 text-xs font-mono text-green-300 resize-none outline-none focus:border-orange-500/50 min-h-0"
              spellCheck={false}
            />
            <button
              onClick={runScript}
              disabled={loading || !selectedPid}
              className="mt-3 flex items-center justify-center gap-2 py-2 bg-orange-700 hover:bg-orange-600 disabled:opacity-40 text-white text-sm rounded transition-colors"
            >
              <Play size={14} />
              {loading ? '実行中...' : 'スクリプト実行'}
            </button>
          </div>
        </div>

        {/* Right: Output console */}
        <div className="flex-1 flex flex-col overflow-hidden">
          <div className="flex items-center justify-between px-4 py-2 border-b border-[#30363d] bg-[#161b22]">
            <div className="flex items-center gap-2 text-xs text-gray-500">
              <Terminal size={13} />
              出力コンソール
            </div>
            <button
              onClick={() => setOutput([])}
              className="text-xs text-gray-600 hover:text-gray-400 transition-colors"
            >
              クリア
            </button>
          </div>
          <div
            ref={outputRef}
            className="flex-1 overflow-y-auto p-4 terminal-output font-mono text-xs space-y-0.5"
          >
            {output.length === 0 ? (
              <div className="text-gray-700">
                {'// プロセスを選択してアタッチし、Frida スクリプトを実行してください'}<br />
                {'// 組み込みテンプレートから選択することもできます'}
              </div>
            ) : (
              output.map((line, i) => (
                <div key={i} className={`${
                  line.includes('[ERROR]') ? 'text-red-400' :
                  line.includes('[+]') ? 'text-green-400' :
                  line.includes('[CRYPTO]') || line.includes('[CIPHER]') ? 'text-yellow-400' :
                  line.includes('[HTTP]') ? 'text-blue-400' :
                  line.includes('[MEM]') ? 'text-purple-400' :
                  line.includes('[ROOT]') ? 'text-orange-400' :
                  'text-green-300'
                }`}>
                  {line}
                </div>
              ))
            )}
          </div>
        </div>
      </div>
    </div>
  )
}

const { app, BrowserWindow, ipcMain, dialog, shell } = require('electron')
const path = require('path')
const { spawn, execFile } = require('child_process')
const fs = require('fs')
const http = require('http')

const isDev = process.env.NODE_ENV === 'development' || !app.isPackaged
const BACKEND_PORT = 8765

let mainWindow = null
let backendProcess = null
let backendReady = false

// ── バックエンドの実行ファイルを探す ──────────────────────────────

function getBackendExecutable() {
  const platform = process.platform

  // 本番: Electron の extraResources に同梱されたバイナリ
  if (!isDev) {
    const binName = platform === 'win32' ? 'appsleuth-backend.exe' : 'appsleuth-backend'
    const bundled = path.join(process.resourcesPath, 'bin', binName)
    if (fs.existsSync(bundled)) return { type: 'binary', path: bundled }
  }

  // 開発: Python スクリプトを直接実行
  const scriptPath = path.join(__dirname, '..', 'backend', 'main.py')
  if (fs.existsSync(scriptPath)) {
    const python = platform === 'win32' ? 'python' : 'python3'
    return { type: 'script', python, path: scriptPath }
  }

  return null
}

// ── バックエンド起動 ──────────────────────────────────────────────

function startBackend() {
  const backend = getBackendExecutable()
  if (!backend) {
    console.log('Backend not found, skipping')
    return
  }

  const env = { ...process.env, BACKEND_PORT: String(BACKEND_PORT) }

  if (backend.type === 'binary') {
    backendProcess = spawn(backend.path, [], {
      stdio: ['ignore', 'pipe', 'pipe'],
      env,
      detached: false,
    })
  } else {
    backendProcess = spawn(backend.python, [backend.path], {
      stdio: ['ignore', 'pipe', 'pipe'],
      env,
      detached: false,
    })
  }

  backendProcess.stdout?.on('data', (data) => {
    const msg = data.toString()
    console.log(`[Backend] ${msg.trim()}`)
    if (msg.includes('Application startup complete') || msg.includes('Uvicorn running')) {
      onBackendReady()
    }
  })

  backendProcess.stderr?.on('data', (data) => {
    const msg = data.toString()
    console.log(`[Backend stderr] ${msg.trim()}`)
    if (msg.includes('Application startup complete') || msg.includes('Uvicorn running')) {
      onBackendReady()
    }
  })

  backendProcess.on('close', (code) => {
    console.log(`Backend exited: ${code}`)
    backendProcess = null
  })

  // ポーリングでバックエンドの起動を確認 (最大30秒)
  let attempts = 0
  const poll = setInterval(() => {
    attempts++
    checkBackendHealth().then((ok) => {
      if (ok) {
        clearInterval(poll)
        onBackendReady()
      } else if (attempts > 60) {
        clearInterval(poll)
        console.log('Backend health check timeout')
        // タイムアウトしても画面は表示する
        onBackendReady()
      }
    })
  }, 500)
}

function checkBackendHealth() {
  return new Promise((resolve) => {
    const req = http.get(`http://127.0.0.1:${BACKEND_PORT}/health`, (res) => {
      resolve(res.statusCode === 200)
    })
    req.on('error', () => resolve(false))
    req.setTimeout(400, () => { req.destroy(); resolve(false) })
  })
}

function onBackendReady() {
  if (backendReady) return
  backendReady = true
  mainWindow?.webContents.send('backend-ready')
}

// ── ウィンドウ作成 ────────────────────────────────────────────────

function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1400,
    height: 900,
    minWidth: 1100,
    minHeight: 700,
    backgroundColor: '#0f1117',
    titleBarStyle: process.platform === 'darwin' ? 'hiddenInset' : 'default',
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false,
      webSecurity: false,
    },
    show: false, // ロード完了後に表示
  })

  // ローディング画面を最初に表示
  mainWindow.loadURL(`data:text/html,${encodeURIComponent(LOADING_HTML)}`)
  mainWindow.once('ready-to-show', () => mainWindow.show())

  // バックエンド準備完了後にメインアプリを読み込む
  const loadMainApp = () => {
    if (isDev) {
      mainWindow?.loadURL('http://localhost:5173')
    } else {
      mainWindow?.loadFile(path.join(__dirname, '..', 'dist', 'renderer', 'index.html'))
    }
  }

  if (backendReady) {
    loadMainApp()
  } else {
    // backend-ready イベントを待つ
    const { ipcMain } = require('electron')
    mainWindow.webContents.ipc?.on('check-backend', () => {
      if (backendReady) loadMainApp()
    })

    // タイマーでポーリング
    const timer = setInterval(() => {
      if (backendReady) {
        clearInterval(timer)
        loadMainApp()
      }
    }, 300)

    // 最大10秒待ってから強制ロード
    setTimeout(() => {
      clearInterval(timer)
      loadMainApp()
    }, 10000)
  }

  mainWindow.on('closed', () => { mainWindow = null })

  if (isDev) {
    mainWindow.webContents.openDevTools({ mode: 'detach' })
  }
}

// ── IPC ハンドラ ──────────────────────────────────────────────────

ipcMain.handle('open-file-dialog', async (_, options) => {
  return dialog.showOpenDialog(mainWindow, {
    properties: ['openFile'],
    filters: options?.filters || [
      { name: 'All Supported', extensions: ['apk', 'exe', 'dll', 'dylib', 'so'] },
      { name: 'Android APK', extensions: ['apk'] },
      { name: 'Windows PE', extensions: ['exe', 'dll'] },
      { name: 'macOS Binary', extensions: ['dylib', 'so'] },
      { name: 'All Files', extensions: ['*'] },
    ],
  })
})

ipcMain.handle('save-report', async (_, { content, filename }) => {
  const result = await dialog.showSaveDialog(mainWindow, {
    defaultPath: filename || 'appsleuth-report.html',
    filters: [{ name: 'HTML', extensions: ['html'] }, { name: 'JSON', extensions: ['json'] }],
  })
  if (!result.canceled && result.filePath) {
    fs.writeFileSync(result.filePath, content, 'utf-8')
    shell.openPath(result.filePath)
    return { success: true, path: result.filePath }
  }
  return { success: false }
})

ipcMain.handle('get-system-info', () => ({
  platform: process.platform,
  arch: process.arch,
  version: app.getVersion(),
}))

ipcMain.handle('open-external', async (_, url) => shell.openExternal(url))

// ── アプリライフサイクル ──────────────────────────────────────────

app.whenReady().then(() => {
  startBackend()
  createWindow()
  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow()
  })
})

app.on('window-all-closed', () => {
  if (backendProcess) backendProcess.kill()
  if (process.platform !== 'darwin') app.quit()
})

app.on('before-quit', () => {
  if (backendProcess) backendProcess.kill()
})

// ── ローディング画面 HTML ─────────────────────────────────────────

const LOADING_HTML = `<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<style>
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body {
    background: #0f1117;
    color: #e6edf3;
    font-family: 'Segoe UI', system-ui, sans-serif;
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    height: 100vh;
    gap: 24px;
    -webkit-app-region: drag;
  }
  .logo { font-size: 28px; font-weight: 700; color: #39d353; letter-spacing: 2px; }
  .sub { font-size: 12px; color: #484f58; letter-spacing: 4px; text-transform: uppercase; }
  .spinner {
    width: 36px; height: 36px;
    border: 3px solid #21262d;
    border-top-color: #39d353;
    border-radius: 50%;
    animation: spin 0.8s linear infinite;
  }
  .msg { font-size: 13px; color: #8b949e; }
  @keyframes spin { to { transform: rotate(360deg); } }
</style>
</head>
<body>
  <div class="logo">AppSleuth</div>
  <div class="sub">Security Analysis Toolkit</div>
  <div class="spinner"></div>
  <div class="msg">バックエンドを起動中...</div>
</body>
</html>`

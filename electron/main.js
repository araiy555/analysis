const { app, BrowserWindow, ipcMain, dialog, shell } = require('electron')
const path = require('path')
const { spawn } = require('child_process')
const fs = require('fs')

const isDev = process.env.NODE_ENV === 'development' || !app.isPackaged

let mainWindow = null
let backendProcess = null

function getBackendPath() {
  if (isDev) {
    return path.join(__dirname, '..', 'backend', 'main.py')
  }
  return path.join(process.resourcesPath, 'backend', 'main.py')
}

function startBackend() {
  const backendScript = getBackendPath()
  if (!fs.existsSync(backendScript)) {
    console.log('Backend script not found, skipping:', backendScript)
    return
  }

  const python = process.platform === 'win32' ? 'python' : 'python3'
  backendProcess = spawn(python, [backendScript], {
    stdio: ['ignore', 'pipe', 'pipe'],
    env: { ...process.env },
  })

  backendProcess.stdout.on('data', (data) => {
    console.log(`Backend: ${data}`)
    if (data.toString().includes('Application startup complete')) {
      mainWindow?.webContents.send('backend-ready')
    }
  })

  backendProcess.stderr.on('data', (data) => {
    const msg = data.toString()
    console.error(`Backend stderr: ${msg}`)
    if (msg.includes('Application startup complete') || msg.includes('Uvicorn running')) {
      mainWindow?.webContents.send('backend-ready')
    }
  })

  backendProcess.on('close', (code) => {
    console.log(`Backend exited with code ${code}`)
    backendProcess = null
  })
}

function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1400,
    height: 900,
    minWidth: 1100,
    minHeight: 700,
    backgroundColor: '#0f1117',
    titleBarStyle: process.platform === 'darwin' ? 'hiddenInset' : 'default',
    frame: process.platform !== 'darwin',
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false,
      webSecurity: false,
    },
    icon: path.join(__dirname, '..', 'assets', 'icon.png'),
    show: false,
  })

  mainWindow.once('ready-to-show', () => {
    mainWindow.show()
  })

  if (isDev) {
    mainWindow.loadURL('http://localhost:5173')
    mainWindow.webContents.openDevTools({ mode: 'detach' })
  } else {
    mainWindow.loadFile(path.join(__dirname, '..', 'dist', 'renderer', 'index.html'))
  }

  mainWindow.on('closed', () => {
    mainWindow = null
  })
}

ipcMain.handle('open-file-dialog', async (_, options) => {
  const result = await dialog.showOpenDialog(mainWindow, {
    properties: ['openFile'],
    filters: options?.filters || [
      { name: 'All Supported', extensions: ['apk', 'exe', 'dll', 'dylib', 'so', 'app'] },
      { name: 'Android APK', extensions: ['apk'] },
      { name: 'Windows PE', extensions: ['exe', 'dll'] },
      { name: 'macOS Binary', extensions: ['dylib', 'so'] },
      { name: 'All Files', extensions: ['*'] },
    ],
  })
  return result
})

ipcMain.handle('save-report', async (_, { content, filename }) => {
  const result = await dialog.showSaveDialog(mainWindow, {
    defaultPath: filename || 'appsleuth-report.html',
    filters: [
      { name: 'HTML Report', extensions: ['html'] },
      { name: 'JSON', extensions: ['json'] },
    ],
  })
  if (!result.canceled && result.filePath) {
    fs.writeFileSync(result.filePath, content, 'utf-8')
    shell.openPath(result.filePath)
    return { success: true, path: result.filePath }
  }
  return { success: false }
})

ipcMain.handle('get-system-info', () => {
  return {
    platform: process.platform,
    arch: process.arch,
    version: app.getVersion(),
  }
})

ipcMain.handle('open-external', async (_, url) => {
  await shell.openExternal(url)
})

app.whenReady().then(() => {
  startBackend()
  createWindow()

  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow()
  })
})

app.on('window-all-closed', () => {
  if (backendProcess) {
    backendProcess.kill()
  }
  if (process.platform !== 'darwin') app.quit()
})

app.on('before-quit', () => {
  if (backendProcess) {
    backendProcess.kill()
  }
})

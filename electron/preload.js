const { contextBridge, ipcRenderer } = require('electron')

contextBridge.exposeInMainWorld('electronAPI', {
  openFileDialog: (options) => ipcRenderer.invoke('open-file-dialog', options),
  saveReport: (data) => ipcRenderer.invoke('save-report', data),
  getSystemInfo: () => ipcRenderer.invoke('get-system-info'),
  openExternal: (url) => ipcRenderer.invoke('open-external', url),
  onBackendReady: (callback) => {
    ipcRenderer.on('backend-ready', () => callback())
  },
  isElectron: true,
})

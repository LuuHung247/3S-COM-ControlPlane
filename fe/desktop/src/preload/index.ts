import { contextBridge, ipcRenderer } from 'electron'
import { electronAPI } from '@electron-toolkit/preload'

const api = {
  getVersion: (): string => '0.1.3',
  connectDaemon: (_host: string, _port: number): Promise<boolean> => {
    return Promise.resolve(false) // placeholder
  },
  onEvent: (callback: (event: unknown) => void): (() => void) => {
    const handler = (_: unknown, data: unknown): void => callback(data)
    ipcRenderer.on('threat-event', handler)
    return () => ipcRenderer.removeListener('threat-event', handler)
  }
}

if (process.contextIsolated) {
  try {
    contextBridge.exposeInMainWorld('electron', electronAPI)
    contextBridge.exposeInMainWorld('api', api)
  } catch (error) {
    console.error(error)
  }
} else {
  // @ts-ignore
  window.electron = electronAPI
  // @ts-ignore
  window.api = api
}

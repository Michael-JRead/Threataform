/**
 * Threataform — Electron Preload Script
 *
 * Runs in an isolated context between the main process and the renderer.
 * Exposes a safe, narrow API via contextBridge — the renderer accesses
 * window.electronAPI without ever having direct Node.js access.
 */

const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('electronAPI', {
  /** True only when running inside Electron */
  isElectron: true,

  /**
   * Returns { port: number, models: string[] }
   * port   — the localhost port of the model HTTP server
   * models — list of .gguf filenames found in /models
   */
  getModelInfo: () => ipcRenderer.invoke('get-model-info'),
});

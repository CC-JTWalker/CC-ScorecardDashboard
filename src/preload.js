'use strict';

const { contextBridge, ipcRenderer, webUtils } = require('electron');

contextBridge.exposeInMainWorld('scorecardRadar', {
  chooseDirectory: () => ipcRenderer.invoke('directory:choose'),
  scanDirectory: (request) => ipcRenderer.invoke('directory:scan', request),
  enrichVulnerabilities: (identifiers) => ipcRenderer.invoke('intel:enrich', identifiers),
  clearIntelCache: () => ipcRenderer.invoke('intel:clear-cache'),
  getSettings: () => ipcRenderer.invoke('settings:get'),
  setGitHubToken: (token) => ipcRenderer.invoke('settings:set-github-token', token),
  showInFolder: (filePath) => ipcRenderer.invoke('path:show', filePath),
  openExternal: (url) => ipcRenderer.invoke('external:open', url),
  exportCsv: (csvText) => ipcRenderer.invoke('export:csv', csvText),
  getPathForFile: (file) => webUtils.getPathForFile(file),
  onDirectoryRequested: (callback) => {
    const listener = (_event, directory) => callback(directory);
    ipcRenderer.on('directory:requested', listener);
    return () => ipcRenderer.removeListener('directory:requested', listener);
  },
  onIntelProgress: (callback) => {
    const listener = (_event, progress) => callback(progress);
    ipcRenderer.on('intel:progress', listener);
    return () => ipcRenderer.removeListener('intel:progress', listener);
  }
});

'use strict';

const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('zecocmDesktop', Object.freeze({
  platform: process.platform,
  version: () => ipcRenderer.invoke('desktop:version'),
  workspaceStatus: () => ipcRenderer.invoke('desktop:workspace-status'),
  signIn: credentials => ipcRenderer.invoke('desktop:sign-in', credentials),
  synchronize: projectId => ipcRenderer.invoke('desktop:sync', projectId),
  signOut: () => ipcRenderer.invoke('desktop:sign-out'),
  queueOperation: input => ipcRenderer.invoke('desktop:queue-operation', input),
  pendingOperations: (projectId, limit) => ipcRenderer.invoke('desktop:pending-operations', projectId, limit),
  applyReceipts: receipts => ipcRenderer.invoke('desktop:apply-receipts', receipts),
  applySnapshot: snapshot => ipcRenderer.invoke('desktop:apply-snapshot', snapshot),
  cryptographicErase: () => ipcRenderer.invoke('desktop:cryptographic-erase'),
  serverHealth: () => ipcRenderer.invoke('desktop:server-health'),
  openWorkspace: () => ipcRenderer.invoke('desktop:open-workspace'),
  openServer: () => ipcRenderer.invoke('desktop:open-server'),
  backupNow: options => ipcRenderer.invoke('desktop:backup-now', options),
  restoreBackup: passphrase => ipcRenderer.invoke('desktop:restore-backup', passphrase),
  backupInfo: () => ipcRenderer.invoke('desktop:backup-info'),
  safetyCopyInfo: () => ipcRenderer.invoke('desktop:safety-copy-info')
}));

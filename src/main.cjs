'use strict';

const { app, BrowserWindow, ipcMain, shell, session, screen, dialog } = require('electron');
const path = require('node:path');
const os = require('node:os');
const fs = require('node:fs');
const { EncryptedStore } = require('./encrypted-store.cjs');

const serverBase = process.env.TRACE_SERVER_URL || process.env.ZECOCM_SERVER_URL || 'https://app.tracems.com';
let mainWindow;
let workspaceWindow;
let store;

// Without this, launching the app a second time (e.g. double-clicking the desktop
// shortcut again right after install, when "run after finish" already opened one copy)
// starts a whole separate OS process with its own independent mainWindow. That produces
// exactly the "two windows" symptom users report -- but it has nothing to do with
// in-page navigation or window.open(), so no amount of fixing the workspace window's
// popup handling touches it. Only one instance of the app is now allowed to actually run;
// a second launch attempt hands off to 'second-instance' below and exits immediately.
const gotSingleInstanceLock = app.requestSingleInstanceLock();
if (!gotSingleInstanceLock) {
  app.quit();
  return;
}

async function serverRequest(pathname, options = {}, token = null) {
  const response = await fetch(serverBase + pathname, {...options,headers:{Accept:'application/json','Content-Type':'application/json',...(token?{Authorization:`Bearer ${token}`}:{}) ,...options.headers},signal:AbortSignal.timeout(15000)});
  let body = {};
  try { body = await response.json(); } catch (_error) { body = {}; }
  if (!response.ok) {
    const error = new Error(body.message || `TRACE server returned ${response.status}.`);
    error.status = response.status;
    throw error;
  }
  return body;
}

async function signIn(credentials) {
  // Corrected route per TRACE-DESKTOP-WEB-ALIGNMENT-20260905.md: the native client must
  // authenticate through the client-specific endpoint, not the browser session route.
  const login = await serverRequest('/api/client/login',{method:'POST',body:JSON.stringify({email:credentials.email,password:credentials.password})});
  const platform = process.platform === 'darwin' ? 'macos' : 'windows';
  // Fix (2026-09-09): live enrollment was failing with "The public key field is required."
  // identity.public_key is a fresh Ed25519 public key generated and persisted locally (see
  // ensureDeviceCredentials / generateDeviceCredentials) -- the matching private key never
  // leaves this device. Everything else about this call (login.token, /api/projects) is
  // deliberately UNCHANGED: I found a newer reference client alongside the server source that
  // also swaps in a device-scoped token and a /api/client/projects route, but the server-side
  // controller source I could actually read alongside it doesn't return that token from this
  // endpoint, so adopting that part would be guessing. Only touching the one field the live
  // server's own error message confirmed.
  const identity = store.ensureDeviceCredentials();
  const device = await serverRequest('/api/client/devices',{method:'POST',body:JSON.stringify({device_uuid:identity.device_uuid,platform,client_version:app.getVersion(),name:os.hostname() || 'TRACE Desktop',public_key:identity.public_key})},login.token);
  const projects = await serverRequest('/api/projects',{},login.token);
  return store.setSession({token:login.token,user:login.user,device:device.device,projects:Array.isArray(projects)?projects:[]});
}

async function synchronize(projectId) {
  const sessionData = store.session();
  if (!sessionData?.token || !sessionData?.device?.id) throw new Error('Enroll this desktop before synchronizing.');
  try {
    const pending = store.pendingOperations(Number(projectId), 250);
    if (pending.length) {
      const pushed = await serverRequest('/api/client/operations',{method:'POST',body:JSON.stringify({device_id:sessionData.device.id,project_id:Number(projectId),operations:pending.map(({local_state,...operation})=>operation)})},sessionData.token);
      store.applyReceipts(pushed.receipts || []);
    }
    const status = await serverRequest(`/api/client/devices/${sessionData.device.id}`,{},sessionData.token);
    if (status.device?.wipe_required) { store.cryptographicErase(); throw new Error('This device was revoked and its local key was erased.'); }
    const current = store.status();
    const snapshot = await serverRequest(`/api/client/snapshots?device_id=${sessionData.device.id}&project_id=${Number(projectId)}&cursor=${Number(current.last_cursor || 0)}`,{},sessionData.token);
    store.applySnapshot(snapshot);
    return {...store.status(),synced_at:new Date().toISOString()};
  } catch (error) {
    // Known gap (TRACE-DESKTOP-WEB-ALIGNMENT-20260905.md): the server invalidates a
    // revoked device's bearer token before this client can retrieve wipe_required, so
    // the explicit-erase path above can be unreachable for a revoked device. We cannot
    // safely auto-erase on every 401 here -- a 401 is also the normal, non-malicious
    // shape of an expired 14-day token, and silently destroying a contractor's queued
    // offline drafts on ordinary expiry would be a worse regression than the bug this
    // is meant to fix. So: force the stale session out of local memory (no further
    // requests go out with a dead token) and surface the ambiguity honestly rather than
    // guess. Deterministic protection for a genuinely lost/revoked device is the
    // explicit "Erase this device's local data" action (desktop:cryptographic-erase),
    // which does not depend on any server round-trip succeeding.
    if (error.status === 401) {
      store.clearSession();
      const wrapped = new Error('This device’s session is no longer valid (401). If it was revoked, local drafts are NOT automatically erased in this build — use "Erase this device’s local data" below, or sign in again if this was just an expired session.');
      wrapped.status = 401;
      throw wrapped;
    }
    throw error;
  }
}

// Added 2026-09-09 (offline backup): a passphrase-encrypted, portable snapshot of the local
// queue -- deliberately separate from the OS-tied encrypted store above, so it can actually
// be put on a USB drive, network share, or synced cloud folder and still mean something on
// another machine. "silent" is the automatic path: it writes to whatever folder was
// remembered from the last manual backup, with no dialog, so it can run unattended every
// time the connectivity badge goes offline (see app.js) -- but it still requires the
// passphrase to be supplied fresh from renderer memory each time; nothing here ever caches
// or persists the passphrase itself. If no folder has been chosen yet, silent backup simply
// has nowhere to write and reports that back rather than guessing a location.
async function backupNow({ passphrase, silent = false } = {}) {
  const envelope = store.exportBackup(passphrase);
  const activeWindow = (workspaceWindow && !workspaceWindow.isDestroyed()) ? workspaceWindow : mainWindow;
  let targetFile;
  if (silent) {
    const info = store.backupInfo();
    if (!info.folder) return { saved: false, reason: 'no-folder-remembered' };
    targetFile = path.join(info.folder, 'trace-desktop-auto-backup.tracebackup');
  } else {
    const { canceled, filePath } = await dialog.showSaveDialog(activeWindow, {
      title: 'Save TRACE Desktop offline backup',
      defaultPath: path.join(app.getPath('documents'), `TRACE-Desktop-Backup-${new Date().toISOString().slice(0, 10)}.tracebackup`),
      filters: [{ name: 'TRACE Desktop encrypted backup', extensions: ['tracebackup'] }]
    });
    if (canceled || !filePath) return { saved: false, reason: 'canceled' };
    targetFile = filePath;
    store.rememberBackupFolder(path.dirname(filePath));
  }
  fs.writeFileSync(targetFile, JSON.stringify(envelope), { mode: 0o600 });
  store.recordBackup();
  return { saved: true, path: targetFile };
}

// Restoring never trusts the file just because it opened -- decryptBackupEnvelope's
// authentication tag and importBackup's per-operation hash re-check (see
// encrypted-store.cjs) are what actually validate the content; this function just wires the
// file picker to that.
async function restoreBackup(passphrase) {
  const activeWindow = (workspaceWindow && !workspaceWindow.isDestroyed()) ? workspaceWindow : mainWindow;
  const { canceled, filePaths } = await dialog.showOpenDialog(activeWindow, {
    title: 'Restore TRACE Desktop offline backup',
    properties: ['openFile'],
    filters: [{ name: 'TRACE Desktop encrypted backup', extensions: ['tracebackup'] }]
  });
  if (canceled || !filePaths?.length) return { restored: false, reason: 'canceled' };
  let envelope;
  try { envelope = JSON.parse(fs.readFileSync(filePaths[0], 'utf8')); }
  catch (_error) { throw new Error('This file is not a readable TRACE Desktop backup.'); }
  const result = store.importBackup(passphrase, envelope);
  return { restored: true, path: filePaths[0], ...result };
}

function sameServerOrigin(candidate) {
  try { return new URL(candidate).origin === new URL(serverBase).origin; }
  catch (_error) { return false; }
}

// Requested 2026-09-09: the home office has a mix of screens (laptops of different
// sizes, monitors) and the old fixed pixel sizes (1440x920 / 1500x960) could be larger
// than a smaller laptop's actual screen, forcing people to manually resize/drag the
// window every time just to see the whole thing. Instead of a fixed size, compute the
// window's size as a fraction of whichever screen it's actually opening on (~75% of the
// available width, ~82% of the available height -- tall enough for real work, but never
// edge-to-edge), and center it. Still respects minWidth/minHeight so it never shrinks
// below a usable size on a very small screen, and the window stays fully user-resizable
// after opening (this only sets the initial size/position, nothing is locked down).
function fittedWindowBounds({minWidth, maxWidth, minHeight, maxHeight, widthFraction = 0.75, heightFraction = 0.82}) {
  const display = screen.getDisplayNearestPoint(screen.getCursorScreenPoint()) || screen.getPrimaryDisplay();
  const work = display.workArea; // excludes the taskbar/dock, in DIP (already DPI-correct)
  const width = Math.min(maxWidth, Math.max(minWidth, Math.round(work.width * widthFraction)));
  const height = Math.min(maxHeight, Math.max(minHeight, Math.round(work.height * heightFraction)));
  const x = Math.round(work.x + (work.width - width) / 2);
  const y = Math.round(work.y + (work.height - height) / 2);
  return {width, height, x, y};
}

// Safeguard against ANY future stuck-login/stuck-page scenario, not just the specific
// popup/opener bug fixed above. A silent, indefinitely blank or spinning window is the
// worst failure mode for a login screen -- the person has no way to tell "still loading"
// from "broken" and no recourse but force-quitting the app. This watchdog gives every
// navigation in the workspace window a hard ceiling: if it hasn't finished (or failed)
// within STUCK_LOAD_TIMEOUT_MS, we replace it with a plain, honest "this is taking too
// long" page with a Retry link and a way back to TRACE home -- instead of leaving people
// staring at a frozen screen. A real navigation failure (DNS, connection refused, TLS)
// shows the same kind of recovery page immediately, without waiting for the timeout.
const STUCK_LOAD_TIMEOUT_MS = 20000;
let stuckLoadTimer = null;

function clearStuckLoadWatchdog() {
  if (stuckLoadTimer) { clearTimeout(stuckLoadTimer); stuckLoadTimer = null; }
}

function armStuckLoadWatchdog(win, url) {
  clearStuckLoadWatchdog();
  stuckLoadTimer = setTimeout(() => {
    if (win && !win.isDestroyed()) showLoadTrouble(win, url, 'This is taking longer than expected.');
  }, STUCK_LOAD_TIMEOUT_MS);
}

function showLoadTrouble(win, url, headline) {
  clearStuckLoadWatchdog();
  const homeUrl = serverBase + '/portal/home';
  const escape = (s) => String(s).replace(/&/g, '&amp;').replace(/"/g, '&quot;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  win.loadURL('data:text/html;charset=utf-8,' + encodeURIComponent(`<!doctype html><html><head><meta charset="utf-8"><title>TRACE Desktop</title><style>
body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;background:#081a1f;color:#eef6f7;font-family:system-ui,-apple-system,sans-serif}
.box{max-width:420px;text-align:center;padding:32px}
h1{font-size:18px;margin:0 0 12px}
p{color:#b6c9cd;line-height:1.55;font-size:14px}
a.button{display:inline-block;margin:18px 6px 0;border:0;background:#57acbe;color:#07181c;border-radius:10px;padding:12px 18px;font-weight:750;font-size:13px;text-decoration:none}
a.secondary{background:transparent;border:1px solid #3a5158;color:#dff1f3}
</style></head><body><div class="box">
<h1>${escape(headline)}</h1>
<p>TRACE hasn't finished loading. This can happen if the connection is slow, was interrupted mid sign-in, or the server is briefly unavailable. Nothing on this device was changed -- it's safe to retry.</p>
<a class="button" href="${escape(url)}">Retry</a>
<a class="button secondary" href="${escape(homeUrl)}">Go to TRACE home</a>
</div></body></html>`));
}

function createWorkspaceWindow() {
  if (workspaceWindow && !workspaceWindow.isDestroyed()) { workspaceWindow.focus(); return; }
  workspaceWindow = new BrowserWindow({
    ...fittedWindowBounds({minWidth: 1024, maxWidth: 1800, minHeight: 680, maxHeight: 1100}),
    backgroundColor: '#081a1f', title: 'TRACE',
    webPreferences: {contextIsolation:true,nodeIntegration:false,sandbox:true,webSecurity:true,partition:'persist:zecocm-authoritative'}
  });
  workspaceWindow.setMenuBarVisibility(false);
  // Hide (never close) the local status/enrollment window while the live workspace is
  // open, instead of leaving two separate top-level windows visible at once -- that
  // read as a broken duplicate-page bug rather than the intended launcher+workspace
  // design. mainWindow still owns the encrypted store and the sign-in/erase UI, so it
  // is restored, not destroyed, when the workspace window closes.
  if (mainWindow && !mainWindow.isDestroyed()) mainWindow.hide();
  workspaceWindow.on('closed', () => { if (mainWindow && !mainWindow.isDestroyed()) mainWindow.show(); });
  workspaceWindow.webContents.on('will-navigate', (event, url) => {
    if (!sameServerOrigin(url)) { event.preventDefault(); return; }
    armStuckLoadWatchdog(workspaceWindow, url);
  });
  workspaceWindow.webContents.on('did-finish-load', clearStuckLoadWatchdog);
  workspaceWindow.webContents.on('did-fail-load', (_event, errorCode, errorDescription, validatedURL) => {
    if (errorCode === -3) return; // ERR_ABORTED -- a superseded/intentional navigation, not a real failure
    if (workspaceWindow && !workspaceWindow.isDestroyed()) {
      showLoadTrouble(workspaceWindow, validatedURL || serverBase + '/portal/home', `Couldn't load this page (${errorDescription || 'connection error'}).`);
    }
  });
  // Reported bug (2026-09-09): clicking sign-in inside the live web content opened a
  // SECOND top-level window that got stuck forever on "Checking session...". Root cause:
  // the web app uses window.open()/target="_blank" for what is conceptually just
  // in-app navigation (its own sign-in / session-check step), not a real popup. Electron
  // does not give a spawned BrowserWindow a working window.opener back-channel to its
  // parent the way a browser tab does -- doubly so under contextIsolation+sandbox -- so
  // any page whose flow depends on postMessage-ing the opener (a common pattern for
  // popup-based auth) hangs indefinitely in the child window with nothing to receive it.
  // Fix: same-origin "popups" are no longer opened as a second window at all -- we
  // navigate this SAME workspace window to the requested URL instead, which is both what
  // the user asked for ("not in the same page") and sidesteps the broken-opener class of
  // bug entirely, since there is no popup/opener relationship left to break.
  // NOTE: this removes the earlier same-origin-popup allowance that existed for a
  // hypothetical print/export view (see TRACE-DESKTOP-WEB-ALIGNMENT-20260905.md,
  // "child-window hardening"). If a real print/export flow turns out to need a genuine
  // second window, that should be special-cased once it's actually observed failing --
  // not guessed at now.
  workspaceWindow.webContents.setWindowOpenHandler(({url}) => {
    if (sameServerOrigin(url) && workspaceWindow && !workspaceWindow.isDestroyed()) {
      armStuckLoadWatchdog(workspaceWindow, url);
      workspaceWindow.loadURL(url);
    }
    return {action: 'deny'};
  });
  workspaceWindow.webContents.session.setPermissionRequestHandler((_contents, permission, callback) => callback(['media','geolocation'].includes(permission)));
  workspaceWindow.webContents.session.setPermissionCheckHandler((_contents, permission) => ['media','geolocation'].includes(permission));
  workspaceWindow.on('closed', () => { workspaceWindow = null; clearStuckLoadWatchdog(); });
  // Corrected destination per TRACE-DESKTOP-WEB-ALIGNMENT-20260905.md: the generic
  // /portal route is not the workspace entry point.
  armStuckLoadWatchdog(workspaceWindow, serverBase + '/portal/home');
  workspaceWindow.loadURL(serverBase + '/portal/home');
}

function createWindow() {
  mainWindow = new BrowserWindow({
    ...fittedWindowBounds({minWidth: 900, maxWidth: 1600, minHeight: 650, maxHeight: 1050}),
    backgroundColor: '#0b2026', title: 'TRACE Desktop',
    webPreferences: {preload:path.join(__dirname,'preload.cjs'),contextIsolation:true,nodeIntegration:false,sandbox:true,webSecurity:true}
  });
  mainWindow.setMenuBarVisibility(false);
  mainWindow.loadFile(path.join(__dirname, '..', 'renderer', 'index.html'));
  mainWindow.webContents.setWindowOpenHandler(({url}) => {
    if (url.startsWith('https://tracems.com/') || url.startsWith('https://www.tracems.com/') || url.startsWith(serverBase + '/')) shell.openExternal(url);
    return {action:'deny'};
  });
}

// Added 2026-09-10: runs with zero interaction, ever -- no dialog, no prompt, no passphrase.
// This is the fully autonomous part; see EncryptedStore.saveSafetyCopy for exactly what it
// does and does not protect against (this machine's file getting lost/corrupted, not the
// machine itself being lost -- that still needs the passphrase-based portable backup, on
// purpose). A failure here is always swallowed: this is a safety net running in the
// background, it must never itself become something that can interrupt or block the app.
const SAFETY_COPY_INTERVAL_MS = 10 * 60 * 1000;
let safetyCopyTimer = null;

app.whenReady().then(() => {
  session.defaultSession.setPermissionRequestHandler((_webContents, _permission, callback) => callback(false));
  session.defaultSession.setPermissionCheckHandler(() => false);
  store = new EncryptedStore();
  createWindow();
  try { store.saveSafetyCopy(); } catch (_error) { /* best-effort, never blocks startup */ }
  safetyCopyTimer = setInterval(() => {
    try { store.saveSafetyCopy(); } catch (_error) { /* best-effort */ }
  }, SAFETY_COPY_INTERVAL_MS);
});

app.on('window-all-closed', () => { if (process.platform !== 'darwin') app.quit(); });
app.on('activate', () => { if (BrowserWindow.getAllWindows().length === 0) createWindow(); });
app.on('second-instance', () => {
  // A second launch was attempted (e.g. the desktop shortcut clicked again) and lost the
  // single-instance lock above, so no second process/window was created by it. Just
  // surface whichever of our own windows is currently front-most instead of doing
  // nothing, so the click still feels like it did something.
  const target = (workspaceWindow && !workspaceWindow.isDestroyed()) ? workspaceWindow
    : (mainWindow && !mainWindow.isDestroyed()) ? mainWindow : null;
  if (target) { if (target.isMinimized()) target.restore(); target.focus(); }
});

ipcMain.handle('desktop:version', () => app.getVersion());
ipcMain.handle('desktop:workspace-status', () => store.status());
ipcMain.handle('desktop:sign-in', (_event, credentials) => signIn(credentials || {}));
ipcMain.handle('desktop:sync', (_event, projectId) => synchronize(projectId));
ipcMain.handle('desktop:sign-out', async () => {
  const sessionData=store.session();
  // Corrected route per TRACE-DESKTOP-WEB-ALIGNMENT-20260905.md.
  if(sessionData?.token){try{await serverRequest('/api/client/logout',{method:'POST'},sessionData.token);}catch(_error){/* local removal still fails closed */}}
  return store.clearSession();
});
ipcMain.handle('desktop:queue-operation', (_event, input) => store.queueOperation(input || {}));
ipcMain.handle('desktop:pending-operations', (_event, projectId, limit) => store.pendingOperations(projectId ?? null, limit));
ipcMain.handle('desktop:apply-receipts', (_event, receipts) => store.applyReceipts(Array.isArray(receipts) ? receipts : []));
ipcMain.handle('desktop:apply-snapshot', (_event, snapshot) => store.applySnapshot(snapshot));
ipcMain.handle('desktop:cryptographic-erase', () => { const erased = store.cryptographicErase(); return erased; });
ipcMain.handle('desktop:server-health', async () => {
  try {
    const response = await fetch(serverBase + '/up', {headers:{Accept:'application/json'},signal:AbortSignal.timeout(7000)});
    return {reachable:response.ok,status:response.status,server:serverBase};
  } catch (_error) {
    return {reachable:false,status:0,server:serverBase};
  }
});
ipcMain.handle('desktop:open-server', async () => { await shell.openExternal(serverBase + '/portal'); return true; });
ipcMain.handle('desktop:open-workspace', () => { createWorkspaceWindow(); return true; });
ipcMain.handle('desktop:backup-now', (_event, options) => backupNow(options || {}));
ipcMain.handle('desktop:restore-backup', (_event, passphrase) => restoreBackup(passphrase));
ipcMain.handle('desktop:backup-info', () => store.backupInfo());
ipcMain.handle('desktop:safety-copy-info', () => store.safetyCopyInfo());

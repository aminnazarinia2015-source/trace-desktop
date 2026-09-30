'use strict';

const TRACE_QUOTES = [
  'Every plan. Every detail. Connected.',
  'TRACE technology is built around your project.',
  'Bring cited AI, CAD and BIM, field records and project controls into one TRACE workspace — from the first drawing to final handover.',
  'Work in the real platform.'
];

function rotateQuotes() {
  const el = document.getElementById('rotating-quote');
  if (!el) return;
  let i = 0;
  setInterval(() => {
    i = (i + 1) % TRACE_QUOTES.length;
    el.style.opacity = '0';
    setTimeout(() => { el.textContent = '“' + TRACE_QUOTES[i] + '”'; el.style.opacity = '1'; }, 220);
  }, 6000);
}

// Persistent online/offline badge plus automatic sync the moment connectivity
// returns. The offline path was never blocking -- queueOperation/pendingOperations
// already write to the local encrypted store with no network involved -- what was
// missing was (a) a status indicator that keeps checking instead of checking once at
// boot, and (b) actually flushing the queue automatically on reconnect instead of
// requiring a manual "Sync now" click every time.
const CONNECTIVITY_POLL_MS = 15000;
let wasReachable = null; // null = not yet known, so first check never counts as a "reconnect"

function setConnectivityBadge(state, text) {
  const badge = document.getElementById('connectivity-badge');
  const label = document.getElementById('connectivity-text');
  if (!badge || !label) return;
  badge.classList.remove('online', 'offline', 'syncing');
  badge.classList.add(state);
  label.textContent = text;
}

async function autoSyncAllProjects(api) {
  const workspace = await api.workspaceStatus();
  const projects = workspace.projects || [];
  let totalPending = 0, totalConflicts = 0, synced = 0;
  for (const project of projects) {
    const pending = await api.pendingOperations(project.id, 1);
    if (!pending.length) continue;
    try {
      const result = await api.synchronize(project.id);
      totalPending += result.operations;
      totalConflicts += result.conflicts;
      synced += 1;
    } catch (_error) {
      // One project failing to sync (e.g. it was revoked, or has its own conflict)
      // must not block the others -- keep going.
    }
  }
  return { synced, totalPending, totalConflicts };
}

function startConnectivityWatch(api) {
  const check = async () => {
    let server;
    try { server = await api.serverHealth(); } catch (_error) { server = { reachable: false }; }
    document.getElementById('server').textContent = server.reachable ? 'Server reachable' : 'Server unavailable';
    document.getElementById('server-detail').textContent = server.reachable ? 'Secure portal is available at ' + server.server : 'Working offline -- governed drafts are queued and encrypted on this device.';

    if (server.reachable && wasReachable === false) {
      // Just reconnected: flush whatever queued while offline, automatically.
      setConnectivityBadge('syncing', 'Reconnected — syncing queued drafts…');
      const result = await autoSyncAllProjects(api);
      const workspace = await api.workspaceStatus();
      document.getElementById('sync').textContent = workspace.operations ? workspace.operations + ' operation(s) pending' : 'Queue clear';
      document.getElementById('sync-detail').textContent = workspace.conflicts ? workspace.conflicts + ' conflict(s) require review.' : (result.synced ? `Auto-synced ${result.synced} project(s) on reconnect.` : 'No unresolved local conflicts.');
      setConnectivityBadge('online', 'Online — synced');
    } else if (server.reachable) {
      setConnectivityBadge('online', 'Online');
    } else {
      setConnectivityBadge('offline', 'Offline — working locally, will sync on reconnect');
      // No manual backup step while offline: the encrypted local store is already
      // written with every queued operation (EncryptedStore, OS-protected key), and the
      // fully automatic safety copy (main.cjs, no passphrase, no prompt) keeps running on
      // its own timer regardless of connectivity state. Nothing here requires a human.
    }
    wasReachable = server.reachable;
  };
  check();
  setInterval(check, CONNECTIVITY_POLL_MS);
}

// No manual "Back up" / "Restore" controls on the dashboard: the encrypted local store
// (OS-protected device key, AES-256-GCM) is written automatically as work queues, and the
// safety copy in main.cjs runs on its own timer with no passphrase and no prompt. This is
// just the plain-status readout of that automatic process -- nothing here is a button.
async function updateSafetyHint(api) {
  const hint = document.getElementById('safety-hint');
  if (!hint) return;
  const safety = await api.safetyCopyInfo();
  hint.textContent = safety.last_saved_at
    ? 'Local safety copy saved automatically — last saved ' + new Date(safety.last_saved_at).toLocaleTimeString() + '.'
    : 'Local safety copy starting automatically…';
}

// Shared by boot() and by a successful restore-from-backup, so restoring can refresh the
// on-screen counts in place instead of needing a full page reload (which would lose the
// "N recovered, M refused" message the person just needs to see).
async function refreshWorkspaceDisplay(api) {
  const workspace = await api.workspaceStatus();
  document.getElementById('workspace').textContent = workspace.encrypted ? 'OS-protected encryption ready' : 'Workspace locked';
  document.getElementById('workspace-detail').textContent = workspace.encrypted ? (workspace.enrolled ? `Enrolled to ${workspace.user}; ` : 'Not enrolled; ') + workspace.operations + ' queued operation(s); ' + workspace.conflicts + ' conflict(s).' : workspace.message;
  const projectSelect = document.getElementById('project-id');
  projectSelect.length = 1; // keep the "Select project" placeholder, drop the rest before repopulating
  for (const project of workspace.projects || []) { const option = document.createElement('option'); option.value = project.id; option.textContent = `${project.number} · ${project.name}`; projectSelect.appendChild(option); }
  document.getElementById('sync').textContent = workspace.operations ? workspace.operations + ' operation(s) pending' : 'Queue clear';
  document.getElementById('sync-detail').textContent = workspace.conflicts ? workspace.conflicts + ' conflict(s) require review.' : 'No unresolved local conflicts.';
  return workspace;
}

async function boot() {
  rotateQuotes();
  const api = window.zecocmDesktop;
  startConnectivityWatch(api);
  document.getElementById('version').textContent = 'TRACE Desktop v' + await api.version();
  await refreshWorkspaceDisplay(api);
  document.getElementById('open-workspace').addEventListener('click', () => api.openWorkspace());
  document.getElementById('enroll').addEventListener('click', () => document.getElementById('signin').showModal());
  document.getElementById('signin-submit').addEventListener('click', async event => {
    event.preventDefault(); const button=event.currentTarget; button.disabled=true;
    try {await api.signIn({email:document.getElementById('email').value,password:document.getElementById('password').value});document.getElementById('password').value='';document.getElementById('signin').close();window.location.reload();}
    catch(error){document.getElementById('signin-error').textContent=error.message;}
    finally{button.disabled=false;}
  });
  document.getElementById('sync-now').addEventListener('click', async () => {
    const projectId=document.getElementById('project-id').value;
    if(!/^\d+$/.test(projectId)){document.getElementById('sync-detail').textContent='Select an authorized project.';return;}
    document.getElementById('sync').textContent='Synchronizing…';
    try{const result=await api.synchronize(Number(projectId));document.getElementById('sync').textContent='Synchronized';document.getElementById('sync-detail').textContent=`${result.operations} pending; ${result.conflicts} conflict(s).`;}
    catch(error){document.getElementById('sync').textContent='Sync stopped safely';document.getElementById('sync-detail').textContent=error.message;}
  });
  document.getElementById('open-server').addEventListener('click', () => api.openServer());
  await updateSafetyHint(api);
  document.getElementById('erase-local-data').addEventListener('click', () => document.getElementById('erase-confirm').showModal());
  document.getElementById('erase-confirm-submit').addEventListener('click', async event => {
    event.preventDefault(); const button = event.currentTarget; button.disabled = true;
    try {
      await api.cryptographicErase();
      document.getElementById('erase-confirm').close();
      window.location.reload();
    } catch (error) {
      document.getElementById('erase-error').textContent = error.message;
    } finally {
      button.disabled = false;
    }
  });
}

boot().catch(() => { document.getElementById('workspace').textContent = 'Desktop initialization failed safely'; });

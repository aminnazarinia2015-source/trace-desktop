'use strict';

const { app, safeStorage } = require('electron');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const { createOperation, generateDeviceCredentials, sha256, encryptBackupEnvelope, decryptBackupEnvelope } = require('./client-core.cjs');

const FORMAT = 'zecocm-encrypted-store-v1';

class EncryptedStore {
  constructor() {
    this.root = path.join(app.getPath('userData'), 'secure-workspace');
    this.keyPath = path.join(this.root, 'device-key.bin');
    this.storePath = path.join(this.root, 'workspace.enc.json');
  }

  initialize() {
    fs.mkdirSync(this.root, { recursive: true, mode: 0o700 });
    if (!safeStorage.isEncryptionAvailable()) {
      throw new Error('Operating-system protected storage is unavailable. Offline project storage remains locked.');
    }
    if (!fs.existsSync(this.keyPath)) {
      const protectedKey = safeStorage.encryptString(crypto.randomBytes(32).toString('base64'));
      fs.writeFileSync(this.keyPath, protectedKey, { mode: 0o600, flag: 'wx' });
    }
  }

  deviceKey() {
    this.initialize();
    const encoded = safeStorage.decryptString(fs.readFileSync(this.keyPath));
    return Buffer.from(encoded, 'base64');
  }

  read() {
    if (!fs.existsSync(this.storePath)) return this.empty();
    const envelope = JSON.parse(fs.readFileSync(this.storePath, 'utf8'));
    if (envelope.format !== FORMAT) throw new Error('Unsupported encrypted workspace format.');
    const iv = Buffer.from(envelope.iv, 'base64');
    const tag = Buffer.from(envelope.tag, 'base64');
    const ciphertext = Buffer.from(envelope.ciphertext, 'base64');
    const decipher = crypto.createDecipheriv('aes-256-gcm', this.deviceKey(), iv);
    decipher.setAAD(Buffer.from(FORMAT));
    decipher.setAuthTag(tag);
    return JSON.parse(Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString('utf8'));
  }

  write(value) {
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', this.deviceKey(), iv);
    cipher.setAAD(Buffer.from(FORMAT));
    const plaintext = Buffer.from(JSON.stringify(value));
    const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
    const envelope = {format:FORMAT,iv:iv.toString('base64'),tag:cipher.getAuthTag().toString('base64'),ciphertext:ciphertext.toString('base64')};
    const temporary = this.storePath + '.tmp';
    fs.writeFileSync(temporary, JSON.stringify(envelope), { mode: 0o600 });
    fs.renameSync(temporary, this.storePath);
  }

  mutate(callback) {
    const data = this.read();
    const result = callback(data);
    this.write(data);
    return result;
  }

  queueOperation(input) {
    // Monotonic counter persists across app restarts and only ever increments, per
    // device -- required for the server's replay-protection contract (each device's
    // operations must carry a strictly increasing counter, not one that resets to 0
    // every launch).
    return this.mutate(data => {
      data.monotonic_counter = Number(data.monotonic_counter || 0) + 1;
      const operation = {...createOperation({...input, record_client_id: input.record_client_id || crypto.randomUUID(), monotonic_counter: data.monotonic_counter}), local_state:'queued'};
      data.operations.push(operation);
      return operation;
    });
  }

  // Filtering to one authorized project at sync time (rather than sending every queued
  // operation regardless of which project it belongs to) matches
  // TRACE-DESKTOP-WEB-ALIGNMENT-20260905.md's project-isolation correction.
  pendingOperations(projectId = null, limit = 250) {
    const queued = this.read().operations.filter(item => item.local_state === 'queued');
    const scoped = projectId == null ? queued : queued.filter(item => item.project_id === Number(projectId));
    return scoped.slice(0, Math.min(Number(limit) || 250, 250));
  }

  // Replaces the old ensureDeviceIdentity() (device_uuid only) now that the live server
  // requires a public_key on enrollment -- see client-core.cjs's generateDeviceCredentials
  // for why this is evidence-based, not guessed. The keypair is generated once and reused
  // (not regenerated per sign-in), so re-enrolling this device after a sign-out still
  // presents the same public key the server saw the first time.
  ensureDeviceCredentials() {
    return this.mutate(data => {
      data.device_uuid ||= crypto.randomUUID();
      data.device_credentials ||= generateDeviceCredentials();
      return { device_uuid: data.device_uuid, public_key: data.device_credentials.public_key };
    });
  }

  setSession(session) {
    return this.mutate(data => {
      data.session = session;
      data.device = session.device;
      return {user:session.user,device:session.device};
    });
  }

  session() { return this.read().session || null; }

  clearSession() {
    return this.mutate(data => { data.session = null; data.device = null; return true; });
  }

  applyReceipts(receipts) {
    return this.mutate(data => {
      const byId = new Map(receipts.map(receipt => [receipt.operation_uuid, receipt]));
      for (const operation of data.operations) {
        const receipt = byId.get(operation.operation_uuid);
        if (!receipt) continue;
        operation.local_state = receipt.status === 'accepted' ? 'synced' : 'refused';
        // Preserve the server's conflict status instead of only recording local
        // refusal, per TRACE-DESKTOP-WEB-ALIGNMENT-20260905.md's conflict-visibility
        // correction -- the operator needs to see *why* a record was refused.
        if (receipt.status !== 'accepted') {
          data.conflicts.push({
            operation_uuid: operation.operation_uuid,
            record_type: operation.record_type,
            record_client_id: operation.record_client_id,
            server_status: receipt.status,
            reason: receipt.reason || receipt.message || null,
            recorded_at: new Date().toISOString()
          });
        }
      }
      data.receipts.push(...receipts);
      return {received: receipts.length};
    });
  }

  applySnapshot(snapshot) {
    if (!snapshot || snapshot.schema_version !== 1 || !Number.isInteger(snapshot.cursor)) throw new Error('Invalid server snapshot.');
    return this.mutate(data => {
      data.snapshots = [snapshot];
      data.sync_cursor = snapshot.cursor;
      return {cursor: snapshot.cursor};
    });
  }

  // Everything needed to recover queued-but-unsynced drafts on another machine, or on this
  // one after a reinstall -- but deliberately NOT the device's own Ed25519 private key
  // (device_credentials). A restored backup re-enters as new offline work under whatever
  // device it's restored onto; it does not clone this device's signed identity elsewhere.
  exportBackup(passphrase) {
    if (!passphrase || String(passphrase).length < 8) throw new Error('Choose a backup passphrase of at least 8 characters.');
    const data = this.read();
    const payload = {
      schema_version: 1,
      device_uuid: data.device_uuid,
      session: data.session,
      operations: data.operations,
      conflicts: data.conflicts,
      receipts: data.receipts,
      sync_cursor: data.sync_cursor,
      monotonic_counter: data.monotonic_counter,
      exported_at: new Date().toISOString()
    };
    return encryptBackupEnvelope(passphrase, payload);
  }

  // Never a blind overwrite. Decrypting only proves the passphrase was right and the file
  // wasn't corrupted in transit/storage (GCM's auth tag) -- it does NOT prove any individual
  // operation inside is trustworthy, so every operation is independently re-hashed here and
  // compared to its own recorded payload_sha256 (the same check the server performs on
  // push) before being accepted. Anything that fails that check is refused and counted, not
  // silently dropped or silently trusted. Only operations this store doesn't already have
  // (by operation_uuid) are added, so restoring the same backup twice is harmless.
  importBackup(passphrase, envelope) {
    const payload = decryptBackupEnvelope(passphrase, envelope);
    if (payload.schema_version !== 1) throw new Error('This backup was made by an incompatible version of TRACE Desktop.');
    return this.mutate(data => {
      const existingIds = new Set(data.operations.map(op => op.operation_uuid));
      let recovered = 0, rejected = 0;
      for (const operation of payload.operations || []) {
        if (existingIds.has(operation.operation_uuid)) continue;
        if (sha256(operation.payload) !== operation.payload_sha256) { rejected += 1; continue; }
        data.operations.push(operation);
        existingIds.add(operation.operation_uuid);
        recovered += 1;
      }
      if (!data.device_uuid && payload.device_uuid) data.device_uuid = payload.device_uuid;
      if (!data.session && payload.session) data.session = payload.session;
      return { recovered, rejected, total: (payload.operations || []).length };
    });
  }

  // The backup FOLDER path is not sensitive (it's just a location on this machine), so it's
  // fine to remember it here for convenience -- the passphrase itself is never written
  // anywhere, in this store or otherwise; it only ever lives in memory for the running
  // session, supplied fresh by the person each time they arm automatic backup.
  backupInfo() {
    const data = this.read();
    return { folder: data.backup?.folder || null, last_backup_at: data.backup?.last_backup_at || null };
  }

  rememberBackupFolder(folder) {
    return this.mutate(data => { data.backup = data.backup || {}; data.backup.folder = folder; return true; });
  }

  recordBackup() {
    return this.mutate(data => { data.backup = data.backup || {}; data.backup.last_backup_at = new Date().toISOString(); return true; });
  }

  // Added 2026-09-10: a fully automatic, zero-interaction safety copy -- no passphrase, no
  // dialog, no prompt, ever. It mirrors the SAME OS-protected encrypted files this device
  // already uses (still only decryptable on this exact Windows profile) to a second folder
  // outside this app's own data directory, so a bad uninstall, an accidental delete, or a
  // corrupted primary file doesn't lose queued drafts. This is genuinely autonomous because
  // it asks for nothing -- but that's also its honest limit: because nothing is required to
  // read it, it protects against losing the FILE, not against losing the MACHINE (a lost or
  // stolen laptop takes this safety copy's protection with it, same as the primary). Real
  // off-machine recovery is what exportBackup/importBackup above are for, and that one
  // requiring a passphrase isn't a missing feature to work around -- an automatically
  // restorable copy that needs no human secret is, by definition, exactly as exposed as
  // whatever it's copying.
  safetyCopyFolder() {
    return path.join(app.getPath('documents'), 'TRACE Desktop Safety Backups');
  }

  saveSafetyCopy() {
    if (!fs.existsSync(this.storePath)) return { saved: false, reason: 'nothing-to-back-up' };
    const folder = this.safetyCopyFolder();
    fs.mkdirSync(folder, { recursive: true, mode: 0o700 });
    fs.copyFileSync(this.storePath, path.join(folder, 'workspace.enc.json'));
    if (fs.existsSync(this.keyPath)) fs.copyFileSync(this.keyPath, path.join(folder, 'device-key.bin'));
    const savedAt = new Date().toISOString();
    fs.writeFileSync(path.join(folder, 'last-saved.json'), JSON.stringify({ saved_at: savedAt }), { mode: 0o600 });
    return { saved: true, folder, saved_at: savedAt };
  }

  safetyCopyInfo() {
    const folder = this.safetyCopyFolder();
    try {
      const stamp = JSON.parse(fs.readFileSync(path.join(folder, 'last-saved.json'), 'utf8'));
      return { folder, last_saved_at: stamp.saved_at || null };
    } catch (_error) {
      return { folder, last_saved_at: null };
    }
  }

  cryptographicErase() {
    if (fs.existsSync(this.storePath)) fs.rmSync(this.storePath);
    if (fs.existsSync(this.keyPath)) fs.rmSync(this.keyPath);
    // The automatic safety copy is a mirror of exactly these two files -- leaving it behind
    // after an intentional security wipe would defeat the point of erasing in the first
    // place, so it's removed too. The passphrase-protected portable backups made with
    // "Back up now" are NOT touched here: those are deliberate, user-directed exports the
    // person chose to keep, not an incidental copy this app made on its own.
    const safetyFolder = this.safetyCopyFolder();
    if (fs.existsSync(safetyFolder)) fs.rmSync(safetyFolder, { recursive: true, force: true });
    return true;
  }

  empty() {
    return {schema_version:1,device_uuid:null,device_credentials:null,device:null,session:null,snapshots:[],operations:[],commands:[],attachments:[],conflicts:[],receipts:[],sync_cursor:null,monotonic_counter:0,backup:{folder:null,last_backup_at:null}};
  }

  status() {
    try {
      const data = this.read();
      return {locked:false,encrypted:true,enrolled:Boolean(data.session?.device),user:data.session?.user?.name || null,projects:(data.session?.projects||[]).map(({id,number,name})=>({id,number,name})),operations:data.operations.filter(item=>item.local_state==='queued').length,conflicts:data.conflicts.length,receipts:data.receipts.length,last_cursor:data.sync_cursor};
    } catch (error) {
      return {locked:true,encrypted:false,message:error.message};
    }
  }
}

module.exports = { EncryptedStore };

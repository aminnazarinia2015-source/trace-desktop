'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const Module = require('node:module');

const temporary = fs.mkdtempSync(path.join(os.tmpdir(), 'zecocm-store-test-'));
const originalLoad = Module._load;
Module._load = function(request, parent, isMain) {
  if (request === 'electron') return {
    app:{getPath:()=>temporary},
    safeStorage:{isEncryptionAvailable:()=>true,encryptString:value=>Buffer.from(`protected:${value}`),decryptString:value=>value.toString().replace(/^protected:/,'')}
  };
  return originalLoad.call(this, request, parent, isMain);
};
const { EncryptedStore } = require('../src/encrypted-store.cjs');
const { encryptBackupEnvelope } = require('../src/client-core.cjs');
Module._load = originalLoad;

test.after(() => fs.rmSync(temporary,{recursive:true,force:true}));

test('workspace ciphertext does not contain project plaintext', () => {
  const store=new EncryptedStore();
  store.write({...store.empty(),snapshots:[{project_name:'Confidential Pump Station'}]});
  const raw=fs.readFileSync(path.join(temporary,'secure-workspace','workspace.enc.json'),'utf8');
  assert.doesNotMatch(raw,/Confidential Pump Station/);
  assert.equal(store.read().snapshots[0].project_name,'Confidential Pump Station');
});

test('offline queue is idempotently receipted and snapshots advance cursor', () => {
  const store=new EncryptedStore();
  const operation=store.queueOperation({project_id:3115,record_type:'daily_report_draft',record_client_id:'daily-1',field:'weather',operation_type:'set',payload:{value:'Clear'}});
  assert.equal(store.pendingOperations(3115).length,1);
  store.applyReceipts([{operation_uuid:operation.operation_uuid,status:'accepted'}]);
  assert.equal(store.pendingOperations(3115).length,0);
  store.applySnapshot({schema_version:1,cursor:9,operations:[]});
  assert.equal(store.status().last_cursor,9);
});

test('unknown consequential operations are refused locally', () => {
  const store=new EncryptedStore();
  assert.throws(()=>store.queueOperation({project_id:3115,record_type:'change_order_approval',record_client_id:'co-1',operation_type:'set',payload:{value:'approved'}}));
});

test('the removed "resolve" operation type is refused locally, matching the server allowlist', () => {
  const store=new EncryptedStore();
  assert.throws(()=>store.queueOperation({project_id:3115,record_type:'daily_report_draft',record_client_id:'d-2',operation_type:'resolve',payload:{}}));
});

test('an operation without a project_id is refused, so it can never bypass project-scoped sync', () => {
  const store=new EncryptedStore();
  assert.throws(()=>store.queueOperation({record_type:'daily_report_draft',record_client_id:'d-3',operation_type:'set',payload:{value:'x'}}));
});

test('pendingOperations filters to the requested project instead of leaking other projects\' drafts', () => {
  const store=new EncryptedStore();
  store.queueOperation({project_id:3115,record_type:'daily_report_draft',record_client_id:'a',operation_type:'set',payload:{value:'x'}});
  store.queueOperation({project_id:9999,record_type:'daily_report_draft',record_client_id:'b',operation_type:'set',payload:{value:'y'}});
  assert.equal(store.pendingOperations(3115).length,1);
  assert.equal(store.pendingOperations(9999).length,1);
  assert.equal(store.pendingOperations().length,2);
});

test('the monotonic counter persists across instances and only increments', () => {
  const store=new EncryptedStore();
  const baseline=store.read().monotonic_counter||0;
  const first=store.queueOperation({project_id:3115,record_type:'daily_report_draft',record_client_id:'c1',operation_type:'set',payload:{value:'x'}});
  const second=store.queueOperation({project_id:3115,record_type:'daily_report_draft',record_client_id:'c2',operation_type:'set',payload:{value:'y'}});
  assert.equal(first.monotonic_counter,baseline+1);
  assert.equal(second.monotonic_counter,baseline+2);
  // A fresh instance re-reads the same on-disk counter rather than restarting at 0 --
  // this is what makes the counter meaningful as replay protection across app restarts.
  const reopened=new EncryptedStore();
  const third=reopened.queueOperation({project_id:3115,record_type:'daily_report_draft',record_client_id:'c3',operation_type:'set',payload:{value:'z'}});
  assert.equal(third.monotonic_counter,baseline+3);
});

test('a refused receipt is recorded as a visible conflict, not just a silent local refusal', () => {
  const store=new EncryptedStore();
  const conflictsBefore=store.status().conflicts;
  const operation=store.queueOperation({project_id:3115,record_type:'daily_report_draft',record_client_id:'d-4',operation_type:'set',payload:{value:'x'}});
  store.applyReceipts([{operation_uuid:operation.operation_uuid,status:'stale_base_version',reason:'Server record has moved on.'}]);
  const status=store.status();
  assert.equal(status.conflicts,conflictsBefore+1);
  const raw=store.read();
  const conflict=raw.conflicts.find(item=>item.operation_uuid===operation.operation_uuid);
  const stored=raw.operations.find(item=>item.operation_uuid===operation.operation_uuid);
  assert.equal(conflict.reason,'Server record has moved on.');
  assert.equal(stored.local_state,'refused');
});

test('ensureDeviceCredentials issues a base64 Ed25519 public key and keeps the private key local', () => {
  const store=new EncryptedStore();
  const identity=store.ensureDeviceCredentials();
  assert.ok(identity.device_uuid);
  assert.match(identity.public_key,/^[A-Za-z0-9+/]{40,}={0,2}$/);
  assert.equal(Buffer.from(identity.public_key,'base64').length,32);
  const raw=fs.readFileSync(path.join(temporary,'secure-workspace','workspace.enc.json'),'utf8');
  assert.doesNotMatch(raw,/BEGIN PRIVATE KEY/); // private key must only ever exist inside the encrypted envelope
});

test('ensureDeviceCredentials is stable across calls -- re-enrolling reuses the same keypair', () => {
  const store=new EncryptedStore();
  const first=store.ensureDeviceCredentials();
  const second=store.ensureDeviceCredentials();
  assert.equal(first.device_uuid,second.device_uuid);
  assert.equal(first.public_key,second.public_key);
});

// A dedicated pair of directories (rather than the shared `temporary` every other test in
// this file reuses) so this genuinely simulates two separate machines instead of exporting
// whatever operations happen to already be sitting in the shared store from earlier tests.
function freshStoreAt(dir) {
  const store = new EncryptedStore();
  store.root = dir;
  store.keyPath = path.join(dir, 'device-key.bin');
  store.storePath = path.join(dir, 'workspace.enc.json');
  return store;
}

test('exportBackup/importBackup recovers queued drafts after this device\'s local data is lost', () => {
  const sourceDir = fs.mkdtempSync(path.join(os.tmpdir(), 'zecocm-backup-src-'));
  const destDir = fs.mkdtempSync(path.join(os.tmpdir(), 'zecocm-backup-dst-'));
  try {
    const source = freshStoreAt(sourceDir);
    source.queueOperation({project_id:3115,record_type:'daily_report_draft',record_client_id:'bk-1',operation_type:'set',payload:{value:'Poured footings'}});
    source.queueOperation({project_id:3115,record_type:'time_card_draft',record_client_id:'bk-2',operation_type:'set',payload:{hours:8}});
    const envelope = source.exportBackup('correct horse battery staple');
    // Simulate losing that machine entirely and recovering onto a fresh one with only the
    // backup file in hand -- destDir was never touched by `source`.
    const recovered = freshStoreAt(destDir);
    assert.equal(recovered.pendingOperations().length, 0);
    const result = recovered.importBackup('correct horse battery staple', envelope);
    assert.equal(result.recovered, 2);
    assert.equal(result.rejected, 0);
    assert.equal(recovered.pendingOperations().length, 2);
  } finally {
    fs.rmSync(sourceDir, {recursive:true, force:true});
    fs.rmSync(destDir, {recursive:true, force:true});
  }
});

test('importBackup refuses the wrong passphrase instead of returning garbage', () => {
  const store = new EncryptedStore();
  store.queueOperation({project_id:3115,record_type:'daily_report_draft',record_client_id:'bk-3',operation_type:'set',payload:{value:'x'}});
  const envelope = store.exportBackup('the-real-passphrase');
  assert.throws(() => store.importBackup('a-wrong-guess', envelope), /[Ww]rong passphrase|corrupted|tampered/);
});

test('importBackup rejects an operation whose payload does not match its own recorded hash', () => {
  const store = new EncryptedStore();
  const forged = encryptBackupEnvelope('shared-passphrase', {
    schema_version: 1,
    device_uuid: 'forged-device',
    session: null,
    operations: [{operation_uuid:'11111111-1111-4111-8111-111111111111',project_id:3115,record_type:'daily_report_draft',record_client_id:'forged-1',field:null,operation_type:'set',logical_clock:1,base_server_version:null,device_wall_clock:new Date().toISOString(),monotonic_counter:1,payload:{value:'tampered after hashing'},payload_sha256:'0000000000000000000000000000000000000000000000000000000000000000'.slice(0,64)}],
    conflicts: [], receipts: [], sync_cursor: null, monotonic_counter: 0
  });
  const result = store.importBackup('shared-passphrase', forged);
  assert.equal(result.recovered, 0);
  assert.equal(result.rejected, 1);
});

test('exportBackup refuses a weak/missing passphrase', () => {
  const store = new EncryptedStore();
  assert.throws(() => store.exportBackup('short'));
  assert.throws(() => store.exportBackup());
});

test('saveSafetyCopy mirrors the encrypted files automatically, no passphrase involved', () => {
  const store = new EncryptedStore();
  store.queueOperation({project_id:3115,record_type:'daily_report_draft',record_client_id:'sc-1',operation_type:'set',payload:{value:'x'}});
  const result = store.saveSafetyCopy();
  assert.equal(result.saved, true);
  assert.equal(fs.existsSync(path.join(result.folder, 'workspace.enc.json')), true);
  assert.equal(fs.existsSync(path.join(result.folder, 'device-key.bin')), true);
  const info = store.safetyCopyInfo();
  assert.equal(info.folder, result.folder);
  assert.ok(info.last_saved_at);
});

test('cryptographic erase also clears the automatic safety copy, but not a portable backup file made with "Back up now"', () => {
  const store=new EncryptedStore();
  store.write(store.empty());
  store.queueOperation({project_id:3115,record_type:'daily_report_draft',record_client_id:'sc-2',operation_type:'set',payload:{value:'x'}});
  store.saveSafetyCopy();
  const safetyFolder = store.safetyCopyFolder();
  assert.equal(fs.existsSync(path.join(safetyFolder,'workspace.enc.json')), true);
  store.cryptographicErase();
  assert.equal(fs.existsSync(path.join(temporary,'secure-workspace','workspace.enc.json')),false);
  assert.equal(fs.existsSync(path.join(temporary,'secure-workspace','device-key.bin')),false);
  assert.equal(fs.existsSync(safetyFolder), false);
});

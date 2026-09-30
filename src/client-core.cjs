'use strict';

const crypto = require('node:crypto');

const RECORD_CAPABILITIES = Object.freeze({
  daily_report_draft: 'daily.create',
  time_card_draft: 'timecard.create',
  quality_observation: 'quality.create',
  plan_markup_draft: 'plans.markup'
});
// Matches the server allowlist exactly (TRACE-DESKTOP-WEB-ALIGNMENT-20260905.md
// correction: 'resolve' is not a supported native operation type).
const OPERATION_TYPES = Object.freeze(['set', 'append', 'add', 'remove']);

function canonicalize(value) {
  if (Array.isArray(value)) return value.map(canonicalize);
  if (value && typeof value === 'object') {
    return Object.keys(value).sort().reduce((result, key) => {
      result[key] = canonicalize(value[key]);
      return result;
    }, {});
  }
  return value;
}

function canonicalJson(value) {
  return JSON.stringify(canonicalize(value));
}

function sha256(value) {
  return crypto.createHash('sha256').update(typeof value === 'string' ? value : canonicalJson(value)).digest('hex');
}

// Added 2026-09-09: the live TRACE server now rejects device enrollment with
// "The public key field is required." Confirmed against a matching, more-recently-dated
// reference implementation of this same client found in the team's own server source tree
// (ZecoCM-Product-Source/clients/desktop, 2026-09-05) that sends exactly this shape to
// exactly this endpoint -- not guessed. Generates a fresh Ed25519 keypair: the raw 32-byte
// public key (base64) is what the server field expects, and the private key never leaves
// this device (kept PEM-encoded in the encrypted local store, used only to prove possession
// of this device identity later if the server starts requiring signed operations too --
// nothing today submits a signature, so none is produced yet).
function generateDeviceCredentials() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  const publicDer = publicKey.export({ format: 'der', type: 'spki' });
  const rawPublicKey = publicDer.subarray(publicDer.length - 32);
  if (rawPublicKey.length !== 32) throw new Error('Could not create the required Ed25519 device identity.');
  return {
    public_key: rawPublicKey.toString('base64'),
    private_key_pem: privateKey.export({ format: 'pem', type: 'pkcs8' }).toString()
  };
}

function createOperation(input, clock = {}) {
  if (!Object.hasOwn(RECORD_CAPABILITIES, input.record_type)) throw new Error('Offline record type is not permitted.');
  if (!OPERATION_TYPES.includes(input.operation_type)) throw new Error('Offline operation is not permitted.');
  if (!input.record_client_id) throw new Error('record_client_id is required.');
  const payload = canonicalize(input.payload || {});
  if (['add', 'remove'].includes(input.operation_type) && !payload.element_id) throw new Error('Set operations require payload.element_id.');
  if (!input.project_id) throw new Error('project_id is required so this operation can be filtered to its authorized project at sync time.');
  const operation = {
    operation_uuid: input.operation_uuid || crypto.randomUUID(),
    project_id: Number(input.project_id),
    record_type: input.record_type,
    record_client_id: String(input.record_client_id),
    field: input.field ? String(input.field) : null,
    operation_type: input.operation_type,
    logical_clock: Number(clock.logical_clock ?? input.logical_clock ?? Date.now()),
    base_server_version: input.base_server_version ?? null,
    device_wall_clock: input.device_wall_clock || new Date().toISOString(),
    monotonic_counter: Number(clock.monotonic_counter ?? input.monotonic_counter ?? 0),
    payload
  };
  operation.payload_sha256 = sha256(payload);
  return operation;
}

// Added 2026-09-09 (offline backup): a portable, encrypted export of the local queue that
// does NOT depend on this machine's OS-protected key (unlike the device key in
// encrypted-store.cjs, which is tied to this Windows profile via safeStorage and cannot be
// decrypted anywhere else). This is the actual answer to "can we attach an extra backup
// somewhere" -- a passphrase-derived key means the resulting file is safe to put on a USB
// drive, a network share, or a synced cloud folder: without the passphrase it's inert
// ciphertext, and with it, it's restorable on any machine running this app.
const BACKUP_FORMAT = 'zecocm-offline-backup-v1';

// scrypt is deliberately slow and memory-hard -- appropriate here because a human-chosen
// passphrase carries far less entropy than the device's own random 256-bit key, so the KDF
// itself has to be expensive to resist offline guessing if a backup file ever leaked.
function deriveBackupKey(passphrase, salt) {
  return crypto.scryptSync(String(passphrase), salt, 32, { N: 16384, r: 8, p: 1 });
}

function encryptBackupEnvelope(passphrase, payload) {
  const salt = crypto.randomBytes(16);
  const key = deriveBackupKey(passphrase, salt);
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  cipher.setAAD(Buffer.from(BACKUP_FORMAT));
  const plaintext = Buffer.from(canonicalJson(payload));
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  return {
    format: BACKUP_FORMAT,
    created_at: new Date().toISOString(),
    salt: salt.toString('base64'),
    iv: iv.toString('base64'),
    tag: cipher.getAuthTag().toString('base64'),
    ciphertext: ciphertext.toString('base64')
  };
}

// GCM's authentication tag means a wrong passphrase or a corrupted/tampered file fails
// LOUDLY right here -- decipher.final() throws -- rather than silently handing back garbage
// that looks like real data. This is the concrete answer to "how do we validate what comes
// back in": nothing is trusted just because it decrypted; every operation inside is also
// re-checked against its own payload_sha256 by encrypted-store.cjs's importBackup before
// being accepted, the same check the server itself performs on push.
function decryptBackupEnvelope(passphrase, envelope) {
  if (!envelope || envelope.format !== BACKUP_FORMAT) throw new Error('This file is not a recognized TRACE Desktop backup.');
  const salt = Buffer.from(envelope.salt, 'base64');
  const key = deriveBackupKey(passphrase, salt);
  const iv = Buffer.from(envelope.iv, 'base64');
  const tag = Buffer.from(envelope.tag, 'base64');
  const ciphertext = Buffer.from(envelope.ciphertext, 'base64');
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAAD(Buffer.from(BACKUP_FORMAT));
  decipher.setAuthTag(tag);
  let plaintext;
  try {
    plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  } catch (_error) {
    throw new Error('Wrong passphrase, or this backup file is corrupted or has been tampered with.');
  }
  return JSON.parse(plaintext.toString('utf8'));
}

module.exports = { RECORD_CAPABILITIES, OPERATION_TYPES, canonicalize, canonicalJson, sha256, createOperation, generateDeviceCredentials, BACKUP_FORMAT, encryptBackupEnvelope, decryptBackupEnvelope };

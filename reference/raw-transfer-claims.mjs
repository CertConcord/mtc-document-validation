// CertConcord application-profile claims over a selected original-byte set.
// This does not prove physical custody, clock truth or source completeness.
import {createHash, createPublicKey, verify} from 'node:crypto';
import {TextDecoder, types} from 'node:util';

const HANDOFF_DOMAIN = Buffer.from('MTC-DV-TRANSFER-HANDOFF-v1\0', 'ascii');
const OBSERVATION_DOMAIN = Buffer.from('MTC-DV-TRANSFER-OBSERVATION-v1\0', 'ascii');
const SET_KEYS = ['version', 'selectedAt', 'items'];
const ITEM_KEYS = ['id', 'role', 'sha256', 'retainThrough'];
const HANDOFF_KEYS = ['version', 'id', 'fromId', 'toId', 'acceptedAt',
  'responsibleThrough', 'requiredSetSha256', 'previousSha256', 'itemIds'];
const OBSERVATION_KEYS = ['version', 'observerId', 'handoffId',
  'requiredSetSha256', 'observedAt', 'items'];
const OBSERVED_ITEM_KEYS = ['id', 'sha256'];
const nativeArray = Object.getPrototypeOf(Uint8Array.prototype);
const getBuffer = Object.getOwnPropertyDescriptor(nativeArray, 'buffer').get;
const getByteOffset = Object.getOwnPropertyDescriptor(nativeArray, 'byteOffset').get;
const getByteLength = Object.getOwnPropertyDescriptor(nativeArray, 'byteLength').get;
const fail = code => {const error = new Error(code); error.code = code; throw error;};
const sha = value => createHash('sha256').update(value).digest('hex');
const label = value => typeof value === 'string' && /^[\x21-\x7e]+$/.test(value);
const digest = value => typeof value === 'string' && /^[a-f0-9]{64}$/.test(value);
const time = value => Number.isSafeInteger(value) && value >= 0;
const keysEqual = (value, keys) => JSON.stringify(Object.keys(value)) ===
  JSON.stringify(keys);

function bytes(value, code) {
  if (!types.isUint8Array(value)) fail(code);
  try {
    const backing = getBuffer.call(value);
    if (types.isSharedArrayBuffer(backing)) fail(code);
    const offset = getByteOffset.call(value);
    const length = getByteLength.call(value);
    const owned = Buffer.alloc(length);
    Uint8Array.prototype.set.call(owned,
      new Uint8Array(backing, offset, length));
    return owned;
  } catch { fail(code); }
}
function publicKey(value) {
  if (typeof value !== 'string' ||
      !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value))
    fail('TRANSFER_POLICY');
  const der = Buffer.from(value, 'base64');
  let parsed;
  try { parsed = createPublicKey({key: der, format: 'der', type: 'spki'}); }
  catch { fail('TRANSFER_POLICY'); }
  if (parsed.asymmetricKeyType !== 'ed25519' ||
      !parsed.export({format: 'der', type: 'spki'}).equals(der))
    fail('TRANSFER_POLICY');
  return {parsed, der};
}
function record(raw, expectedKeys, code) {
  let parsed, text;
  try {
    text = new TextDecoder('utf-8', {fatal: true}).decode(raw);
    parsed = JSON.parse(text);
  } catch { fail(code); }
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed) ||
      !keysEqual(parsed, expectedKeys) ||
      !raw.equals(Buffer.from(JSON.stringify(parsed), 'utf8')))
    fail(code);
  return parsed;
}
function verified(raw, signature, domain, key, code) {
  if (signature.length !== 64 || !verify(null,
    Buffer.concat([domain, raw]), key, signature)) fail(code);
}
function sortedUnique(items, getId) {
  for (let i = 0; i < items.length; i++) {
    const id = getId(items[i]);
    if (!label(id) || (i && getId(items[i - 1]) >= id)) return false;
  }
  return true;
}
function copyList(value, code) {
  if (!Array.isArray(value)) fail(code);
  const count = value.length;
  const copy = [];
  for (let i = 0; i < count; i++) copy.push(value[i]);
  return copy;
}
function outcome(reasons) {
  return {decision: reasons.some(item => item.code === 'TRANSFER_BYTES_MISMATCH') ?
    'REJECTED' :
    reasons.length ? 'INDETERMINATE' : 'BOUND_CLAIMS', reasons};
}
function overall(responsibility, observationClaims) {
  return [responsibility, observationClaims].some(x => x.decision === 'REJECTED') ?
    'REJECTED' : [responsibility, observationClaims].some(x =>
      x.decision === 'INDETERMINATE') ? 'INDETERMINATE' : 'BOUND_CLAIMS';
}

// Policy must come from outside the archive and fixes the selected-set digest,
// claimed selection time, participant keys, retirement and document horizon.
export function assessRawTransferClaims({policy, requiredSetRaw, handoffs,
  observations, supplied}) {
  if (!policy) fail('TRANSFER_INPUT');
  const handoffInputs = copyList(handoffs, 'TRANSFER_INPUT');
  const observationInputs = copyList(observations, 'TRANSFER_INPUT');
  const suppliedInputs = copyList(supplied, 'TRANSFER_INPUT');
  const initialCustodianId = policy.initialCustodianId;
  const observerId = policy.observerId;
  const selectedAt = policy.selectedAt;
  const retiredAt = policy.retiredAt;
  const documentThrough = policy.documentThrough;
  const requiredSetSha256 = policy.requiredSetSha256;
  const sourceKeys = policy.custodianKeys;
  const sourceObserverKey = policy.observerPublicKeySpkiBase64;
  if (![initialCustodianId, observerId].every(label) ||
      ![selectedAt, retiredAt, documentThrough].every(time) ||
      selectedAt > retiredAt || retiredAt > documentThrough ||
      !digest(requiredSetSha256)) fail('TRANSFER_POLICY');
  const sourceKeyRows = copyList(sourceKeys, 'TRANSFER_POLICY');
  if (sourceKeyRows.length < 2) fail('TRANSFER_POLICY');
  const keys = new Map();
  const keyBytes = [];
  for (let i = 0; i < sourceKeyRows.length; i++) {
    const row = sourceKeyRows[i];
    if (!row) fail('TRANSFER_POLICY');
    const id = row.id;
    const spki = row.publicKeySpkiBase64;
    if (!label(id) || keys.has(id)) fail('TRANSFER_POLICY');
    const key = publicKey(spki);
    keys.set(id, key.parsed);
    keyBytes.push(key.der.toString('hex'));
  }
  if (!keys.has(initialCustodianId)) fail('TRANSFER_POLICY');
  const observerKey = publicKey(sourceObserverKey);
  keyBytes.push(observerKey.der.toString('hex'));
  if (new Set(keyBytes).size !== keyBytes.length) fail('TRANSFER_POLICY');
  const setBytes = bytes(requiredSetRaw, 'TRANSFER_SET');
  if (sha(setBytes) !== requiredSetSha256) fail('TRANSFER_SET_ANCHOR');
  const set = record(setBytes, SET_KEYS, 'TRANSFER_SET');
  if (set.version !== 1 || set.selectedAt !== selectedAt ||
      !Array.isArray(set.items) || !set.items.length ||
      !sortedUnique(set.items, item => item?.id)) fail('TRANSFER_SET');
  const required = [];
  const requiredById = new Map();
  for (const item of set.items) {
    if (!item || typeof item !== 'object' || Array.isArray(item) ||
        !keysEqual(item, ITEM_KEYS) || !label(item.role) ||
        !digest(item.sha256) || !time(item.retainThrough) ||
        item.retainThrough < documentThrough) fail('TRANSFER_SET');
    requiredById.set(item.id, item);
    required.push(item);
  }
  if (!required.some(item => item.role === 'original-document') ||
      !required.some(item => item.role === 'preservation-evidence'))
    fail('TRANSFER_SET');
  const handoffRows = [];
  const handoffById = new Map();
  const rawHashes = [];
  for (let index = 0; index < handoffInputs.length; index++) {
    const envelope = handoffInputs[index];
    if (!envelope || typeof envelope !== 'object') fail('TRANSFER_HANDOFF');
    const raw = bytes(envelope.raw, 'TRANSFER_HANDOFF');
    const predecessorSignature = bytes(envelope.predecessorSignature,
      'TRANSFER_HANDOFF');
    const successorSignature = bytes(envelope.successorSignature,
      'TRANSFER_HANDOFF');
    const row = record(raw, HANDOFF_KEYS, 'TRANSFER_HANDOFF');
    if (row.version !== 1 || !label(row.id) || !label(row.fromId) ||
        !label(row.toId) || row.fromId === row.toId ||
        !time(row.acceptedAt) || !time(row.responsibleThrough) ||
        row.acceptedAt <= selectedAt ||
        row.requiredSetSha256 !== requiredSetSha256 ||
        !Array.isArray(row.itemIds) ||
        !sortedUnique(row.itemIds, id => id) ||
        row.itemIds.some(id => !requiredById.has(id)) ||
        handoffById.has(row.id) ||
        (index === 0 ? row.previousSha256 !== null :
          row.previousSha256 !== rawHashes[index - 1]))
      fail('TRANSFER_HANDOFF');
    if (!keys.has(row.fromId) || !keys.has(row.toId))
      fail('TRANSFER_HANDOFF_SCOPE');
    verified(raw, predecessorSignature, HANDOFF_DOMAIN,
      keys.get(row.fromId), 'TRANSFER_HANDOFF_SIGNATURE');
    verified(raw, successorSignature, HANDOFF_DOMAIN,
      keys.get(row.toId), 'TRANSFER_HANDOFF_SIGNATURE');
    handoffById.set(row.id, row);
    handoffRows.push(row);
    rawHashes.push(sha(raw));
  }
  const observationsById = new Map();
  for (let index = 0; index < observationInputs.length; index++) {
    const envelope = observationInputs[index];
    if (!envelope || typeof envelope !== 'object') fail('TRANSFER_OBSERVATION');
    const raw = bytes(envelope.raw, 'TRANSFER_OBSERVATION');
    const signature = bytes(envelope.signature, 'TRANSFER_OBSERVATION');
    verified(raw, signature, OBSERVATION_DOMAIN, observerKey.parsed,
      'TRANSFER_OBSERVATION_SIGNATURE');
    const row = record(raw, OBSERVATION_KEYS, 'TRANSFER_OBSERVATION');
    if (row.version !== 1 || row.observerId !== observerId ||
        !label(row.handoffId) ||
        row.requiredSetSha256 !== requiredSetSha256 ||
        !time(row.observedAt) || !Array.isArray(row.items) ||
        !sortedUnique(row.items, item => item?.id) ||
        observationsById.has(row.handoffId) ||
        !handoffById.has(row.handoffId)) fail('TRANSFER_OBSERVATION');
    for (const item of row.items)
      if (!item || typeof item !== 'object' || Array.isArray(item) ||
          !keysEqual(item, OBSERVED_ITEM_KEYS) ||
          !requiredById.has(item.id) || !digest(item.sha256))
        fail('TRANSFER_OBSERVATION');
    observationsById.set(row.handoffId, row);
  }
  const suppliedById = new Map();
  for (let index = 0; index < suppliedInputs.length; index++) {
    const value = suppliedInputs[index];
    if (!value) fail('TRANSFER_INPUT');
    const handoffId = value.handoffId;
    const itemId = value.itemId;
    const original = bytes(value.bytes, 'TRANSFER_INPUT');
    if (!label(handoffId) || !label(itemId) ||
        !handoffById.has(handoffId) ||
        !requiredById.has(itemId)) fail('TRANSFER_INPUT');
    const key = `${handoffId}\0${itemId}`;
    if (suppliedById.has(key)) fail('TRANSFER_INPUT');
    suppliedById.set(key, original);
  }
  const responsibilityReasons = [];
  const byteReasons = [];
  if (!handoffRows.length) {
    responsibilityReasons.push({code: 'TRANSFER_NOT_RECORDED'});
    byteReasons.push({code: 'TRANSFER_NOT_RECORDED'});
  }
  let predecessor = initialCustodianId;
  let coveredThrough = retiredAt;
  let previousAt = -1;
  for (const row of handoffRows) {
    if (row.acceptedAt <= previousAt) fail('TRANSFER_HANDOFF');
    if (row.fromId !== predecessor)
      responsibilityReasons.push({handoffId: row.id,
        code: 'TRANSFER_PREDECESSOR_MISMATCH'});
    if (row.acceptedAt > coveredThrough)
      responsibilityReasons.push({handoffId: row.id,
        code: 'TRANSFER_RESPONSIBILITY_GAP'});
    if (row.responsibleThrough < row.acceptedAt)
      responsibilityReasons.push({handoffId: row.id, code: 'TRANSFER_TERM_SHORT'});
    for (const item of required) {
      if (!row.itemIds.includes(item.id))
        responsibilityReasons.push({handoffId: row.id, itemId: item.id,
          code: 'TRANSFER_SCOPE_MISSING'});
      const observed = observationsById.get(row.id);
      const observationItem = observed?.items.find(x => x.id === item.id);
      const original = suppliedById.get(`${row.id}\0${item.id}`);
      if (!observed || observed.observedAt !== row.acceptedAt ||
          !observationItem || !original)
        byteReasons.push({handoffId: row.id, itemId: item.id,
          code: 'TRANSFER_ITEM_MISSING'});
      else if (sha(original) !== item.sha256 ||
          sha(original) !== observationItem.sha256)
        byteReasons.push({handoffId: row.id, itemId: item.id,
          code: 'TRANSFER_BYTES_MISMATCH'});
    }
    predecessor = row.toId;
    coveredThrough = row.responsibleThrough;
    previousAt = row.acceptedAt;
  }
  if (handoffRows.length && coveredThrough < documentThrough)
    responsibilityReasons.push({handoffId: handoffRows.at(-1).id,
      code: 'TRANSFER_HORIZON_SHORT'});
  const responsibility = outcome(responsibilityReasons);
  const observationClaims = outcome(byteReasons);
  return {decision: overall(responsibility, observationClaims),
    responsibility, observationClaims, requiredSetSha256,
    handoffCount: handoffRows.length, requiredItemCount: required.length};
}

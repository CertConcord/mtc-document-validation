import {verify} from 'node:crypto';
import {types} from 'node:util';
import {DerError} from './der.mjs';
import {verifyMtcLogConsistencyProof} from './raw-mtc-log-consistency.mjs';

const label = Buffer.from('subtree/v1\n\0', 'ascii');
const fail = code => { throw new DerError(code); };
const nativeArray = Object.getPrototypeOf(Uint8Array.prototype);
const getBuffer = Object.getOwnPropertyDescriptor(nativeArray, 'buffer').get;
const getByteOffset = Object.getOwnPropertyDescriptor(nativeArray, 'byteOffset').get;
const getByteLength = Object.getOwnPropertyDescriptor(nativeArray, 'byteLength').get;

// Buffer.from(object) may call an input's valueOf. Capture the actual typed
// array extent, bypassing caller-visible length, buffer and conversion hooks.
function nativeBytes(value, code) {
  if (!Buffer.isBuffer(value) || !types.isUint8Array(value)) fail(code);
  try {
    const backing = getBuffer.call(value);
    const offset = getByteOffset.call(value);
    const length = getByteLength.call(value);
    const owned = Buffer.alloc(length);
    Uint8Array.prototype.set.call(owned,
      new Uint8Array(backing, offset, length));
    return owned;
  } catch { fail(code); }
}

function parsedCheckpoint(message, cosignerName, logOrigin) {
  if (!Buffer.isBuffer(message)) fail('MTC_CHECKPOINT_FORMAT');
  let at = 0;
  const take = length => {
    if (at + length > message.length) fail('MTC_CHECKPOINT_FORMAT');
    const bytes = message.subarray(at, at + length);
    at += length;
    return bytes;
  };
  if (!take(label.length).equals(label)) fail('MTC_CHECKPOINT_FORMAT');
  const signer = take(take(1)[0]);
  const expectedSigner = Buffer.from(`oid/1.3.6.1.4.1.${cosignerName}`,
    'ascii');
  if (!signer.equals(expectedSigner)) fail('MTC_CHECKPOINT_ORIGIN');
  const timestamp = take(8).readBigUInt64BE();
  const origin = take(take(1)[0]);
  const expectedOrigin = Buffer.from(`oid/1.3.6.1.4.1.${logOrigin}`,
    'ascii');
  if (!origin.equals(expectedOrigin)) fail('MTC_CHECKPOINT_ORIGIN');
  const start = take(8).readBigUInt64BE();
  const end = take(8).readBigUInt64BE();
  const root = take(32);
  if (at !== message.length || timestamp === 0n || start !== 0n ||
      end === 0n || end >= (1n << 48n)) fail('MTC_CHECKPOINT_FORMAT');
  return {timestamp, treeSize: Number(end), root};
}

// The caller must obtain admitted from an independent CA/cosigner policy.
// A supplied reference tuple is untrusted until every required cosigner's
// signed direct checkpoint or signed later checkpoint plus RFC 9162 edge
// binds it. When omitted, the first direct signature supplies that tuple.
// Only independently admitted IDs participate; an unadmitted extra record
// cannot add a role or veto the admitted quorum.
export function verifyMtcReferenceCheckpoint({reference, signatures, admitted,
  logOrigin, minimumTreeSize}) {
  if (!Array.isArray(signatures) || !admitted ||
      !Number.isSafeInteger(minimumTreeSize) || minimumTreeSize < 1 ||
      minimumTreeSize >= 2 ** 48 || typeof logOrigin !== 'string')
    fail('MTC_CHECKPOINT_POLICY');
  const cosigners = admitted.cosigners;
  const requiredRoles = admitted.requiredRoles;
  if (!(cosigners instanceof Map) || !Array.isArray(requiredRoles))
    fail('MTC_CHECKPOINT_POLICY');
  const required = requiredRoles.slice();
  let selected = null;
  if (reference !== undefined) {
    if (!reference) fail('MTC_CHECKPOINT_POLICY');
    const treeSize = reference.treeSize;
    const rootHash = nativeBytes(reference.rootHash,
      'MTC_CHECKPOINT_POLICY');
    if (!Number.isSafeInteger(treeSize) || treeSize < 1 ||
        treeSize >= 2 ** 48 ||
        rootHash.length !== 32) fail('MTC_CHECKPOINT_POLICY');
    selected = {treeSize, rootHash};
  }
  const seen = new Set(), roles = new Set(), parsedSignatures = [];
  for (const item of signatures) {
    if (!item) fail('MTC_CHECKPOINT_FORMAT');
    const idHex = item.idHex;
    if (typeof idHex !== 'string')
      fail('MTC_CHECKPOINT_FORMAT');
    const cosigner = cosigners.get(idHex);
    if (!cosigner) continue;
    if (seen.has(idHex)) fail('MTC_CHECKPOINT_FORMAT');
    const message = nativeBytes(item.message, 'MTC_CHECKPOINT_FORMAT');
    const signature = nativeBytes(item.signature, 'MTC_CHECKPOINT_FORMAT');
    if (signature.length !== 64)
      fail('MTC_CHECKPOINT_FORMAT');
    const rawProof = item.consistencyProof;
    const consistencyProof = rawProof === undefined ? undefined :
      nativeBytes(rawProof, 'MTC_CHECKPOINT_FORMAT');
    seen.add(idHex);
    const parsed = parsedCheckpoint(message, cosigner.name, logOrigin);
    if (!verify(null, message, cosigner.key, signature))
      fail('MTC_CHECKPOINT_SIGNATURE');
    if (!selected && consistencyProof === undefined)
      selected = {treeSize: parsed.treeSize, rootHash: Buffer.from(parsed.root)};
    roles.add(cosigner.role);
    parsedSignatures.push({idHex, ...parsed, consistencyProof});
  }
  if (!selected || !required.every(role => roles.has(role)))
    fail('MTC_CHECKPOINT_QUORUM');
  if (selected.treeSize < minimumTreeSize) fail('MTC_CHECKPOINT_SIZE');
  for (const parsed of parsedSignatures) {
    if (parsed.treeSize === selected.treeSize) {
      if (parsed.consistencyProof !== undefined)
        fail('MTC_CHECKPOINT_FORMAT');
      if (!parsed.root.equals(selected.rootHash))
        fail('MTC_CHECKPOINT_MISMATCH');
    } else if (parsed.treeSize > selected.treeSize) {
      if (!parsed.consistencyProof) fail('MTC_CHECKPOINT_CONSISTENCY');
      verifyMtcLogConsistencyProof({firstSize: selected.treeSize,
        secondSize: parsed.treeSize, firstRoot: selected.rootHash,
        secondRoot: parsed.root, proof: parsed.consistencyProof});
    } else fail('MTC_CHECKPOINT_SIZE');
  }
  return {treeSize: selected.treeSize, rootHash: Buffer.from(selected.rootHash),
    admittedRoles: [...roles].sort(),
    claimedTimestamps: parsedSignatures.map(item => ({idHex: item.idHex,
      timestamp: item.timestamp.toString()}))};
}

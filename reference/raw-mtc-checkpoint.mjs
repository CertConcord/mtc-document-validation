import {verify} from 'node:crypto';
import {DerError} from './der.mjs';
import {verifyMtcLogConsistencyProof} from './raw-mtc-log-consistency.mjs';

const label = Buffer.from('subtree/v1\n\0', 'ascii');
const fail = code => { throw new DerError(code); };

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
      !(admitted.cosigners instanceof Map) ||
      !Array.isArray(admitted.requiredRoles) ||
      !Number.isSafeInteger(minimumTreeSize) || minimumTreeSize < 1 ||
      minimumTreeSize >= 2 ** 48 || typeof logOrigin !== 'string' ||
      (reference !== undefined && (!reference ||
        !Number.isSafeInteger(reference.treeSize) ||
        reference.treeSize < 1 || reference.treeSize >= 2 ** 48 ||
        !Buffer.isBuffer(reference.rootHash) ||
        reference.rootHash.length !== 32)))
    fail('MTC_CHECKPOINT_POLICY');
  const seen = new Set(), roles = new Set(), parsedSignatures = [];
  let selected = reference ?? null;
  for (const item of signatures) {
    if (!item || typeof item.idHex !== 'string')
      fail('MTC_CHECKPOINT_FORMAT');
    const cosigner = admitted.cosigners.get(item.idHex);
    if (!cosigner) continue;
    if (seen.has(item.idHex) || !Buffer.isBuffer(item.message) ||
        !Buffer.isBuffer(item.signature) || item.signature.length !== 64 ||
        (item.consistencyProof !== undefined &&
          !Buffer.isBuffer(item.consistencyProof)))
      fail('MTC_CHECKPOINT_FORMAT');
    seen.add(item.idHex);
    const parsed = parsedCheckpoint(item.message, cosigner.name, logOrigin);
    if (!verify(null, item.message, cosigner.key, item.signature))
      fail('MTC_CHECKPOINT_SIGNATURE');
    if (!selected && item.consistencyProof === undefined)
      selected = {treeSize: parsed.treeSize, rootHash: parsed.root};
    roles.add(cosigner.role);
    parsedSignatures.push({idHex: item.idHex, ...parsed,
      consistencyProof: item.consistencyProof});
  }
  if (!selected || !admitted.requiredRoles.every(role => roles.has(role)))
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
  return {treeSize: selected.treeSize, rootHash: selected.rootHash,
    admittedRoles: [...roles].sort(),
    claimedTimestamps: parsedSignatures.map(item => ({idHex: item.idHex,
      timestamp: item.timestamp.toString()}))};
}

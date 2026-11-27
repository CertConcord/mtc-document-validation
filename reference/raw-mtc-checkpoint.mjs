import {verify} from 'node:crypto';
import {DerError} from './der.mjs';

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
// Directly cosigned reference checkpoints are this first raw profile; a
// cosigner on a later checkpoint needs a separately verified consistency edge.
export function verifyMtcReferenceCheckpoint({signatures, admitted, logOrigin,
  minimumTreeSize}) {
  if (!Array.isArray(signatures) || !admitted ||
      !(admitted.cosigners instanceof Map) ||
      !Array.isArray(admitted.requiredRoles) ||
      !Number.isSafeInteger(minimumTreeSize) || minimumTreeSize < 1 ||
      minimumTreeSize >= 2 ** 48 || typeof logOrigin !== 'string')
    fail('MTC_CHECKPOINT_POLICY');
  const seen = new Set(), roles = new Set(), parsedSignatures = [];
  let reference = null;
  for (const item of signatures) {
    if (!item || typeof item.idHex !== 'string' || seen.has(item.idHex) ||
        !Buffer.isBuffer(item.message) || !Buffer.isBuffer(item.signature) ||
        item.signature.length !== 64)
      fail('MTC_CHECKPOINT_FORMAT');
    seen.add(item.idHex);
    const cosigner = admitted.cosigners.get(item.idHex);
    if (!cosigner) fail('MTC_CHECKPOINT_POLICY');
    const parsed = parsedCheckpoint(item.message, cosigner.name, logOrigin);
    if (!verify(null, item.message, cosigner.key, item.signature))
      fail('MTC_CHECKPOINT_SIGNATURE');
    if (!reference && cosigner.role === 'ca') reference = parsed;
    roles.add(cosigner.role);
    parsedSignatures.push({idHex: item.idHex, ...parsed});
  }
  if (!reference || !admitted.requiredRoles.every(role => roles.has(role)))
    fail('MTC_CHECKPOINT_QUORUM');
  if (reference.treeSize < minimumTreeSize) fail('MTC_CHECKPOINT_SIZE');
  for (const parsed of parsedSignatures) {
    if (parsed.treeSize !== reference.treeSize ||
        !parsed.root.equals(reference.root)) fail('MTC_CHECKPOINT_MISMATCH');
  }
  return {treeSize: reference.treeSize, rootHash: reference.root,
    admittedRoles: [...roles].sort(),
    claimedTimestamps: parsedSignatures.map(item => ({idHex: item.idHex,
      timestamp: item.timestamp.toString()}))};
}

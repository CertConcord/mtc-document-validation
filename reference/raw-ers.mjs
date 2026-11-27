import {createHash} from 'node:crypto';
import {DerError, children, content, expect, oid, one, raw, smallInteger} from './der.mjs';
import {assessRawTimestampToken} from './raw-timestamp.mjs';

const SHA256 = '2.16.840.1.101.3.4.2.1';
const bad = code => { throw new DerError(code); };
const hash = bytes => createHash('sha256').update(bytes).digest();
const hex = bytes => hash(bytes).toString('hex');

function sequence(items) {
  const value = Buffer.concat(items);
  if (value.length < 128) return Buffer.concat([Buffer.from([0x30, value.length]), value]);
  let size = value.length, count = 0;
  while (size) { size = Math.floor(size / 256); count++; }
  const length = Buffer.alloc(count);
  length.writeUIntBE(value.length, 0, count);
  return Buffer.concat([Buffer.from([0x30, 0x80 | count]), length, value]);
}

function algorithm(value, tag = 0x30) {
  const fields = children(expect(value, tag));
  if (fields.length < 1 || fields.length > 2 ||
      (fields.length === 2 && !raw(fields[1]).equals(Buffer.from('0500', 'hex'))))
    bad('ERS_ALGORITHM_UNSUPPORTED');
  if (oid(fields[0]) !== SHA256) bad('ERS_ALGORITHM_UNSUPPORTED');
}

function archive(value) {
  const fields = children(expect(value, 0x30));
  let at = 0;
  if (fields[at]?.tag === 0xa0) algorithm(fields[at++], 0xa0);
  if (fields[at]?.tag === 0xa1) bad('ERS_ATTRIBUTES_UNSUPPORTED');
  let tree = null;
  if (fields[at]?.tag === 0xa2) {
    tree = children(fields[at++]).map(level => {
      const hashes = children(expect(level, 0x30)).map(item => {
        const bytes = content(expect(item, 0x04));
        if (bytes.length !== 32) bad('ERS_HASH_LENGTH');
        return bytes;
      });
      if (!hashes.length) bad('ERS_TREE_EMPTY');
      for (let i = 1; i < hashes.length; i++)
        if (Buffer.compare(hashes[i - 1], hashes[i]) > 0) bad('ERS_TREE_ORDER');
      return hashes;
    });
    if (!tree.length) bad('ERS_TREE_EMPTY');
  }
  if (at !== fields.length - 1) bad('ERS_ARCHIVE_STRUCTURE');
  const token = raw(expect(fields[at], 0x30));
  return {token, tree};
}

function record(bytes) {
  const fields = children(one(bytes, 0x30));
  if (fields.length < 3 || fields.length > 5 || smallInteger(fields[0]) !== 1)
    bad('ERS_VERSION_UNSUPPORTED');
  const algorithms = children(expect(fields[1], 0x30));
  if (algorithms.length !== 1) bad('ERS_ALGORITHM_UNSUPPORTED');
  algorithm(algorithms[0]);
  let at = 2;
  if (fields[at]?.tag === 0xa0) bad('ERS_CRYPTO_INFOS_UNSUPPORTED');
  if (fields[at]?.tag === 0xa1) bad('ERS_ENCRYPTION_UNSUPPORTED');
  if (at !== fields.length - 1) bad('ERS_RECORD_STRUCTURE');
  const chains = children(expect(fields[at], 0x30)).map(chain => {
    const stamps = children(expect(chain, 0x30));
    if (!stamps.length) bad('ERS_CHAIN_EMPTY');
    return {encoded: raw(chain), stamps: stamps.map(archive)};
  });
  if (!chains.length) bad('ERS_SEQUENCE_EMPTY');
  return chains;
}

function treePreimage(source, reduced) {
  if (!reduced) return source;
  let current = hash(source), preimage;
  for (let index = 0; index < reduced.length; index++) {
    const level = reduced[index];
    if (index === 0 && !level.some(value => value.equals(current)))
      bad('ERS_TREE_BINDING');
    const nodes = index === 0 ? level : [current, ...level].sort(Buffer.compare);
    preimage = Buffer.concat(nodes);
    current = hash(preimage);
  }
  return preimage;
}

function signedSortedVariant(objectDer, historyHash, source, stamp, supplied) {
  const sorted = Buffer.concat([hash(objectDer), historyHash].sort(Buffer.compare));
  if (sorted.equals(source)) return false;
  try {
    const alternate = treePreimage(sorted, stamp.tree);
    return assessRawTimestampToken({...supplied, tokenDer: stamp.token,
      coveredDer: alternate}).decision === 'SIGNED_CLAIM';
  } catch (error) {
    if (error instanceof DerError) return false;
    throw error;
  }
}

// timestampEvidence[chain][stamp] supplies independently admitted TSA/issuer
// certificates and policy, plus an optional original request for that token.
export function assessRawErs({evidenceDer, objectDer, timestampEvidence}) {
  if (!Buffer.isBuffer(evidenceDer) || !Buffer.isBuffer(objectDer) ||
      !Array.isArray(timestampEvidence))
    throw Object.assign(new Error('ERS_INPUT'), {code: 'ERS_INPUT'});
  const evidenceSha256 = hex(evidenceDer);
  try {
    const chains = record(evidenceDer);
    if (timestampEvidence.length !== chains.length)
      bad('ERS_TIMESTAMP_EVIDENCE_MISSING');
    const observations = [];
    const priorChains = [];
    let previousToken = null;
    let previousTime = null;
    for (let chain = 0; chain < chains.length; chain++) {
      if (!Array.isArray(timestampEvidence[chain]) ||
          timestampEvidence[chain].length !== chains[chain].stamps.length)
        bad('ERS_TIMESTAMP_EVIDENCE_MISSING');
      for (let index = 0; index < chains[chain].stamps.length; index++) {
        const stamp = chains[chain].stamps[index];
        const supplied = timestampEvidence[chain][index];
        if (!supplied || !Buffer.isBuffer(supplied.tsaDer) ||
            !Buffer.isBuffer(supplied.issuerDer) || !supplied.policy)
          bad('ERS_TIMESTAMP_EVIDENCE_MISSING');
        let source, historyHash;
        if (chain === 0 && index === 0) source = objectDer;
        else if (index > 0) source = previousToken;
        else {
          const previousSequence = sequence(priorChains);
          historyHash = hash(previousSequence);
          source = Buffer.concat([hash(objectDer), historyHash]);
        }
        let coveredDer;
        try {
          coveredDer = treePreimage(source, stamp.tree);
        } catch (error) {
          if (error instanceof DerError && error.code === 'ERS_TREE_BINDING' &&
              chain > 0 && index === 0 &&
              signedSortedVariant(objectDer, historyHash, source, stamp, supplied))
            return {decision: 'UNSUPPORTED',
              reasons: ['ERS_HASH_RENEWAL_SORTED_VARIANT_UNSUPPORTED'],
              evidenceSha256};
          throw error;
        }
        const claim = assessRawTimestampToken({...supplied,
          tokenDer: stamp.token, coveredDer});
        if (claim.decision !== 'SIGNED_CLAIM') {
          if (chain > 0 && index === 0 && !stamp.tree &&
              claim.reasons[0] === 'TIMESTAMP_IMPRINT_MISMATCH' &&
              signedSortedVariant(objectDer, historyHash, source, stamp, supplied))
            return {decision: 'UNSUPPORTED',
              reasons: ['ERS_HASH_RENEWAL_SORTED_VARIANT_UNSUPPORTED'],
              evidenceSha256};
          return {decision: claim.decision, reasons: claim.reasons, evidenceSha256};
        }
        const time = BigInt(claim.genTimeMicros);
        if (previousTime !== null && time < previousTime) bad('ERS_TIME_ORDER');
        previousTime = time;
        observations.push({chain, index, tokenSha256: hex(stamp.token),
          rootSha256: hex(coveredDer), tsaSha256: claim.tsaSha256,
          genTimeMicros: claim.genTimeMicros,
          claimedUpperBoundMicros: claim.claimedUpperBoundMicros,
          requestBinding: claim.requestBinding});
        previousToken = stamp.token;
      }
      priorChains.push(chains[chain].encoded);
    }
    return {decision: 'BOUND_CLAIMS', reasons: [], evidenceSha256, observations};
  } catch (error) {
    if (!(error instanceof DerError)) throw error;
    const unresolved = error.code === 'ERS_TIMESTAMP_EVIDENCE_MISSING';
    const unsupported = error.code.endsWith('_UNSUPPORTED') || error.code === 'DER_UNSUPPORTED';
    return {decision: unresolved ? 'INDETERMINATE' : unsupported ? 'UNSUPPORTED' : 'REJECTED',
      reasons: [error.code], evidenceSha256};
  }
}

import {createHash} from 'node:crypto';
import {DerError} from './der.mjs';
import {admittedPolicy, deriveMtcLogId} from './raw-mtc-issuance.mjs';
import {parseMtcLandmarkPublication} from './raw-mtc-landmark.mjs';
import {selectMtcCoveringSubtrees,
  verifyMtcSubtreeConsistencyProof} from './raw-mtc-consistency.mjs';
import {verifyMtcReferenceCheckpoint} from './raw-mtc-checkpoint.mjs';
import {snapshotMtcBuffer} from './raw-mtc-native-bytes.mjs';

const fail = code => { throw new DerError(code); };
const decimal = value => typeof value === 'string' &&
  /^(?:0|[1-9][0-9]*)$/.test(value);
const digest = bytes => createHash('sha256').update(bytes).digest('hex');

function sourceFacts(source, caId) {
  if (!source) fail('MTC_ACTIVE_POLICY');
  const facts = {sourceId: source.sourceId, caIdHex: source.caIdHex,
    logNumber: source.logNumber, logOrigin: source.logOrigin,
    publicationSha256: source.publicationSha256,
    admittedAt: source.admittedAt, evaluatedAt: source.evaluatedAt,
    freshThrough: source.freshThrough,
    minimumTrustedTreeSize: source.minimumTrustedTreeSize,
    maxActiveLandmarksForLog: source.maxActiveLandmarksForLog,
    previousLatest: source.previousLatest,
    previousPublicationSha256: source.previousPublicationSha256};
  if (typeof facts.sourceId !== 'string' ||
      !/^[A-Za-z0-9._:/-]{1,128}$/.test(facts.sourceId) ||
      facts.caIdHex !== caId.toString('hex') ||
      !Number.isInteger(facts.logNumber) || facts.logNumber < 1 ||
      facts.logNumber > 65535 ||
      typeof facts.publicationSha256 !== 'string' ||
      !/^[a-f0-9]{64}$/.test(facts.publicationSha256) ||
      !decimal(facts.admittedAt) || !decimal(facts.evaluatedAt) ||
      !decimal(facts.freshThrough) ||
      !decimal(facts.minimumTrustedTreeSize) ||
      !Number.isInteger(facts.maxActiveLandmarksForLog) ||
      facts.maxActiveLandmarksForLog < 0 ||
      facts.maxActiveLandmarksForLog > 4096)
    fail('MTC_ACTIVE_POLICY');
  const logId = deriveMtcLogId(caId, facts.logNumber);
  if (facts.logOrigin !== logId.origin) fail('MTC_ACTIVE_SCOPE');
  const admittedAt = BigInt(facts.admittedAt);
  const evaluatedAt = BigInt(facts.evaluatedAt);
  const freshThrough = BigInt(facts.freshThrough);
  const minimumTrustedTreeSize = BigInt(facts.minimumTrustedTreeSize);
  if (admittedAt === 0n || evaluatedAt < admittedAt ||
      freshThrough < evaluatedAt || freshThrough >= (1n << 64n) ||
      minimumTrustedTreeSize < 1n ||
      minimumTrustedTreeSize >= (1n << 48n)) fail('MTC_ACTIVE_POLICY');
  const previousLatest = facts.previousLatest;
  const previousPublicationSha256 = facts.previousPublicationSha256;
  if (previousLatest === null) {
    if (previousPublicationSha256 !== null) fail('MTC_ACTIVE_POLICY');
  } else if (!Number.isSafeInteger(previousLatest) || previousLatest < 0 ||
      previousLatest >= 2 ** 48 ||
      typeof previousPublicationSha256 !== 'string' ||
      !/^[a-f0-9]{64}$/.test(previousPublicationSha256))
    fail('MTC_ACTIVE_POLICY');
  return {sourceId: facts.sourceId, caIdHex: facts.caIdHex,
    logNumber: facts.logNumber, logOrigin: logId.origin,
    publicationSha256: facts.publicationSha256,
    admittedAt: facts.admittedAt, evaluatedAt: facts.evaluatedAt,
    freshThrough: facts.freshThrough,
    minimumTrustedTreeSize: Number(minimumTrustedTreeSize),
    maxActiveLandmarksForLog: facts.maxActiveLandmarksForLog,
    previousLatest, previousPublicationSha256};
}

// Read-only §7.4 admission relative to one independently admitted publication.
// The caller chooses an explicit older suffix; this function never upgrades a
// failed subtree into a trusted one or advances persistent source/watermark state.
export function assessRawMtcActiveSubtreeSet({policy, sourceAdmission,
  landmarkPublication, acceptedHeadNumber, referenceCheckpoint,
  checkpointSignatures, subtreeProofs}) {
  try {
    const admitted = admittedPolicy(policy, 'relative');
    admitted.requiredRoles = admitted.requiredRoles.slice();
    const source = sourceFacts(sourceAdmission, admitted.caId);
    const publicationBytes = snapshotMtcBuffer(landmarkPublication,
      'MTC_ACTIVE_SOURCE');
    const publication = parseMtcLandmarkPublication(publicationBytes,
      source.evaluatedAt);
    if (publication.publicationSha256 !== source.publicationSha256)
      fail('MTC_ACTIVE_SOURCE');
    if (source.previousLatest !== null &&
        (publication.latest < source.previousLatest ||
         (publication.latest === source.previousLatest &&
          publication.publicationSha256 !==
            source.previousPublicationSha256))) fail('MTC_ACTIVE_REPLAY');
    const active = publication.rows.slice(0, -1);
    if (!Array.isArray(subtreeProofs)) fail('MTC_ACTIVE_SUBTREES');
    if (acceptedHeadNumber === null) {
      if (subtreeProofs.length !== 0) fail('MTC_ACTIVE_SUBTREES');
      return {decision: 'NO_ADMITTED_SUBTREES', reason: null,
        source, publishedLatest: publication.latest,
        activeLandmarks: active.map(row => row.number),
        acceptedLandmarks: [], droppedLatestLandmarks:
          active.map(row => row.number), subtrees: []};
    }
    if (!Number.isSafeInteger(acceptedHeadNumber))
      fail('MTC_ACTIVE_POLICY');
    const first = active.findIndex(row => row.number === acceptedHeadNumber);
    if (first < 0) fail('MTC_ACTIVE_POLICY');
    const accepted = active.slice(first);
    if (accepted.length > source.maxActiveLandmarksForLog ||
        subtreeProofs.length !== accepted.length * 2)
      fail('MTC_ACTIVE_SUBTREES');
    const checkpoint = verifyMtcReferenceCheckpoint({
      reference: referenceCheckpoint, signatures: checkpointSignatures,
      admitted, logOrigin: source.logOrigin,
      minimumTreeSize: Math.max(accepted[0].treeSize,
        source.minimumTrustedTreeSize)});
    const subtrees = [];
    for (let i = 0; i < accepted.length; i++) {
      const row = accepted[i], predecessor = publication.rows[first + i + 1];
      const cover = selectMtcCoveringSubtrees(predecessor.treeSize,
        row.treeSize);
      for (let position = 0; position < 2; position++) {
        const supplied = subtreeProofs[i * 2 + position];
        const range = cover[position];
        if (!supplied || supplied.landmarkNumber !== row.number ||
            supplied.position !== position ||
            supplied.start !== range.start || supplied.end !== range.end)
          fail('MTC_ACTIVE_SUBTREES');
        const subtreeHash = snapshotMtcBuffer(supplied.subtreeHash,
          'MTC_ACTIVE_SUBTREES');
        const proof = snapshotMtcBuffer(supplied.proof,
          'MTC_ACTIVE_SUBTREES');
        verifyMtcSubtreeConsistencyProof({start: range.start,
          end: range.end, treeSize: checkpoint.treeSize, subtreeHash,
          rootHash: checkpoint.rootHash, proof});
        subtrees.push({logNumber: source.logNumber,
          landmarkNumber: row.number, previousTreeSize: predecessor.treeSize,
          landmarkTreeSize: row.treeSize,
          landmarkExpiration: row.expiration.toString(),
          position, start: range.start, end: range.end,
          subtreeSha256: subtreeHash.toString('hex'),
          proofSha256: digest(proof),
          certificateEligible: range.start < range.end});
      }
    }
    return {decision: first === 0 ? 'ACTIVE_SUBTREE_SET_BOUND' :
        'ACTIVE_SUBTREE_SUFFIX_BOUND', reason: null, source,
      publishedLatest: publication.latest,
      activeLandmarks: active.map(row => row.number),
      acceptedLandmarks: accepted.map(row => row.number),
      droppedLatestLandmarks: active.slice(0, first).map(row => row.number),
      referenceTreeSize: checkpoint.treeSize,
      referenceRootSha256: checkpoint.rootHash.toString('hex'),
      admittedRoles: checkpoint.admittedRoles,
      claimedTimestamps: checkpoint.claimedTimestamps,
      subtrees};
  } catch (error) {
    if (!(error instanceof DerError)) throw error;
    return {decision: error.code.endsWith('_UNSUPPORTED') ? 'UNSUPPORTED' :
      'REJECTED', reason: error.code};
  }
}

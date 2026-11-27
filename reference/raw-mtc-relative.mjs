import {createHash} from 'node:crypto';
import {DerError} from './der.mjs';
import {parseRawMtcCertificateCandidate} from './raw-mtc-issuance.mjs';
import {parseMtcLandmarkPublication,
  selectMtcLandmarkSubtree} from './raw-mtc-landmark.mjs';
import {verifyMtcReferenceCheckpoint} from './raw-mtc-checkpoint.mjs';
import {verifyMtcSubtreeConsistencyProof} from './raw-mtc-consistency.mjs';

const fail = code => { throw new DerError(code); };
const decimal = value => typeof value === 'string' && /^(?:0|[1-9][0-9]*)$/.test(value);

// This bounded path authenticates one relative certificate's selected
// landmark subtree against a directly cosigned reference checkpoint.
// The publication digest, admission time, and minimum tree-size watermark
// must come from independently admitted policy, never the archive package.
export function assessRawMtcRelativeIssuance({certificateDer, policy,
  landmarkPublication, checkpointSignatures, subtreeConsistencyProof}) {
  if (!Buffer.isBuffer(certificateDer)) fail('MTC_INPUT');
  const certificateSha256 = createHash('sha256').update(certificateDer)
    .digest('hex');
  try {
    if (!policy || !/^[a-f0-9]{64}$/.test(policy.landmarkPublicationSha256) ||
        !decimal(policy.landmarkAdmittedAt) ||
        !decimal(policy.minimumTrustedTreeSize) ||
        BigInt(policy.minimumTrustedTreeSize) >= (1n << 48n) ||
        typeof policy.landmarkLogOrigin !== 'string' ||
        !Buffer.isBuffer(landmarkPublication) ||
        !Buffer.isBuffer(subtreeConsistencyProof)) fail('MTC_RELATIVE_POLICY');
    const candidate = parseRawMtcCertificateCandidate({certificateDer, policy});
    if (candidate.logId.origin !== policy.landmarkLogOrigin)
      fail('MTC_LANDMARK_SCOPE');
    const publication = parseMtcLandmarkPublication(landmarkPublication,
      policy.landmarkAdmittedAt);
    if (publication.publicationSha256 !== policy.landmarkPublicationSha256)
      fail('MTC_LANDMARK_SOURCE');
    const selection = selectMtcLandmarkSubtree(publication,
      candidate.index);
    if (BigInt(selection.landmarkExpiration) <
        BigInt(candidate.certificateNotAfter)) fail('MTC_LANDMARK_EXPIRY');
    if (candidate.parsed.start !== selection.subtree.start ||
        candidate.parsed.end !== selection.subtree.end)
      fail('MTC_RELATIVE_SUBTREE');
    const checkpoint = verifyMtcReferenceCheckpoint({
      signatures: checkpointSignatures,
      admitted: candidate.admitted,
      logOrigin: candidate.logId.origin,
      minimumTreeSize: Math.max(publication.rows[0].treeSize,
        Number(policy.minimumTrustedTreeSize))
    });
    verifyMtcSubtreeConsistencyProof({
      start: candidate.parsed.start, end: candidate.parsed.end,
      treeSize: checkpoint.treeSize, subtreeHash: candidate.root,
      rootHash: checkpoint.rootHash, proof: subtreeConsistencyProof
    });
    return {decision: 'RELATIVE_ISSUANCE_BOUND', reason: null,
      certificateSha256, logNumber: candidate.logNumber,
      index: candidate.index, landmarkNumber: selection.landmarkNumber,
      landmarkPublicationSha256: publication.publicationSha256,
      subtreeSha256: candidate.root.toString('hex'),
      referenceTreeSize: checkpoint.treeSize,
      referenceRootSha256: checkpoint.rootHash.toString('hex'),
      admittedRoles: checkpoint.admittedRoles,
      claimedTimestamps: checkpoint.claimedTimestamps};
  } catch (error) {
    if (!(error instanceof DerError)) throw error;
    return {decision: error.code.endsWith('_UNSUPPORTED') ? 'UNSUPPORTED' : 'REJECTED',
      reason: error.code, certificateSha256};
  }
}

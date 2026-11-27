import {certificate, admittedIssuer, admittedMtcIssuer, digest} from './cert-der.mjs';
import {DerError} from './der.mjs';
import {parseOcsp} from './ocsp-der.mjs';
import {parseCrl} from './crl-der.mjs';
import {admittedPolicy, assessRawMtcIssuance, mtcCaName} from './raw-mtc-issuance.mjs';
import {snapshotMtcBuffer} from './raw-mtc-native-bytes.mjs';

const time = value => Number.isSafeInteger(value) && value >= 0;
const hash = value => typeof value === 'string' && /^[a-f0-9]{64}$/.test(value);
const name = value => typeof value === 'string' && value.length > 0;
const fail = code => { const error = new Error(code); error.code = code; throw error; };
const decision = (status, reason, observation = {}) => ({decision: status,
  reasons: reason ? [reason] : [], ...observation});

// Admitted policy, issuer and receipt are caller-supplied trust inputs. This
// function verifies their binding to original DER, never their provenance or
// the completeness of all status changes through knownAt.
function assessStatus({kind, recordDer, targetDer, issuerDer, responderDer,
  requestDer, stateAt, knownAt, policy, admittedReceipt}, admitTarget, directMtcCa) {
  if (!['OCSP', 'CRL'].includes(kind) || ![recordDer, targetDer, issuerDer].every(Buffer.isBuffer) ||
      (responderDer !== undefined && !Buffer.isBuffer(responderDer)) ||
      (requestDer !== undefined && !Buffer.isBuffer(requestDer)) ||
      !time(stateAt) || !time(knownAt) || knownAt < stateAt ||
      !policy || !hash(policy.issuerSha256) || !name(policy.sourceId) ||
      (kind === 'CRL' && !name(policy.crlDistributionPoint)) ||
      !['use-invalidity-date', 'revocation-time-only'].includes(policy.compromiseMode))
    fail('RAW_STATUS_INPUT');

  const recordSha256 = digest(recordDer);
  let observation;
  try {
    const target = certificate(targetDer);
    const issuer = certificate(issuerDer);
    admitTarget(target, issuer, policy, stateAt, kind);
    observation = kind === 'OCSP'
      ? parseOcsp({recordDer, target, issuer, responderDer, requestDer, directMtcCa})
      : parseCrl({recordDer, target, issuer, directMtcCa});
    if (kind === 'CRL' && observation.distributionPoint !== policy.crlDistributionPoint)
      throw new DerError('CRL_DISTRIBUTION_NOT_ADMITTED');
  } catch (error) {
    if (!(error instanceof DerError)) throw error;
    const unresolved = ['OCSP_TARGET_NOT_FOUND', 'OCSP_NONCE_REQUEST_MISSING',
      'OCSP_RESPONSE_UNAVAILABLE',
      'RESPONDER_REVOCATION_UNRESOLVED', 'CRL_TARGET_SCOPE_UNPROVEN',
      'CRL_DISTRIBUTION_NOT_ADMITTED'].includes(error.code);
    const unsupported = error.code.endsWith('_UNSUPPORTED') || error.code === 'DER_UNSUPPORTED';
    return {kind, recordSha256, stateAt, knownAt,
      ...decision(unresolved ? 'INDETERMINATE' : unsupported ? 'UNSUPPORTED' : 'REJECTED', error.code)};
  }
  const observed = {kind, stateAt, knownAt, ...observation};
  if (admittedReceipt === undefined || admittedReceipt === null)
    return decision('INDETERMINATE', 'RECEIPT_MISSING', observed);
  if (!hash(admittedReceipt.recordSha256) || !time(admittedReceipt.observedAt) ||
      !name(admittedReceipt.sourceId)) fail('RAW_STATUS_RECEIPT');
  if (admittedReceipt.recordSha256 !== recordSha256)
    return decision('REJECTED', 'RECEIPT_RECORD_MISMATCH', observed);
  if (admittedReceipt.sourceId !== policy.sourceId)
    return decision('INDETERMINATE', 'SOURCE_NOT_ADMITTED', observed);
  const recordIssuedAt = kind === 'OCSP' ? observation.producedAt : observation.thisUpdate;
  if (admittedReceipt.observedAt < recordIssuedAt)
    return decision('REJECTED', 'RECEIPT_BEFORE_RECORD', observed);
  if (admittedReceipt.observedAt > knownAt)
    return decision('INDETERMINATE', 'RECORD_NOT_YET_KNOWN', observed);
  if (kind === 'OCSP' && observation.producedAt > knownAt)
    return decision('INDETERMINATE', 'RESPONSE_AFTER_KNOWLEDGE_CUTOFF', observed);

  if (observation.status === 'REVOKED') {
    const effective = policy.compromiseMode === 'use-invalidity-date' &&
      observation.invalidityDate !== null
      ? Math.min(observation.revocationTime, observation.invalidityDate)
      : observation.revocationTime;
    return stateAt >= effective
      ? decision('REVOKED', null, {...observed, effectiveRevocationAt: effective})
      : decision('INDETERMINATE', 'REVOCATION_AFTER_STATE_TIME', observed);
  }
  if (observation.nextUpdate === null || stateAt < observation.thisUpdate ||
      stateAt > observation.nextUpdate)
    return decision('INDETERMINATE', 'STATUS_INTERVAL_NOT_COVERED', observed);
  if (observation.status === 'UNKNOWN') return decision('UNKNOWN', null, observed);
  return decision('GOOD', null, observed);
}

export function assessRawStatus(input) {
  return assessStatus(input, (target, issuer, policy, stateAt) =>
    admittedIssuer(target, issuer, policy.issuerSha256, stateAt), false);
}

function captureMtcPolicy(value) {
  if (!value || !Array.isArray(value.cosigners) ||
      !Array.isArray(value.requiredRoles) || !Array.isArray(value.revokedRanges))
    fail('MTC_POLICY');
  const cosigners = [];
  for (let i = 0, n = value.cosigners.length; i < n; i++) {
    const x = value.cosigners[i];
    cosigners.push(x && {idHex: x.idHex, role: x.role,
      publicKeySpkiBase64: x.publicKeySpkiBase64});
  }
  const requiredRoles = [];
  for (let i = 0, n = value.requiredRoles.length; i < n; i++)
    requiredRoles.push(value.requiredRoles[i]);
  const revokedRanges = [];
  for (let i = 0, n = value.revokedRanges.length; i < n; i++) {
    const x = value.revokedRanges[i];
    revokedRanges.push(x && {start: x.start, end: x.end});
  }
  return {mtcRevision: value.mtcRevision, logHash: value.logHash,
    representation: value.representation, minSerial: value.minSerial,
    maxSerial: value.maxSerial, caIdHex: value.caIdHex,
    cosigners, requiredRoles, revokedRanges};
}

// The direct MTC status path checks the original certificate's MTCProof before
// consulting OCSP/CRL. Trust in the CA representation and receipt is supplied
// independently; no certificate path or complete history is inferred here.
export function assessRawMtcStatus(input) {
  if (!input || typeof input !== 'object') fail('RAW_STATUS_INPUT');
  const mtcPolicy = captureMtcPolicy(input.mtcPolicy);
  const copy = (value, code = 'RAW_STATUS_INPUT') =>
    value === undefined ? undefined : snapshotMtcBuffer(value, code);
  const statusPolicy = input.policy;
  const receipt = input.admittedReceipt;
  const captured = {
    kind: input.kind,
    recordDer: copy(input.recordDer), targetDer: copy(input.targetDer),
    issuerDer: copy(input.issuerDer), responderDer: copy(input.responderDer),
    requestDer: copy(input.requestDer), stateAt: input.stateAt,
    knownAt: input.knownAt,
    policy: statusPolicy && {issuerSha256: statusPolicy.issuerSha256,
      sourceId: statusPolicy.sourceId,
      crlDistributionPoint: statusPolicy.crlDistributionPoint,
      compromiseMode: statusPolicy.compromiseMode},
    admittedReceipt: receipt && {recordSha256: receipt.recordSha256,
      observedAt: receipt.observedAt, sourceId: receipt.sourceId}
  };
  return assessStatus(captured, (target, issuer, policy, stateAt, kind) => {
    const issuance = assessRawMtcIssuance({certificateDer: target.encoded,
      policy: mtcPolicy});
    if (issuance.decision !== 'ISSUANCE_PROVEN')
      throw new DerError(issuance.reason);
    const admitted = admittedPolicy(mtcPolicy);
    const caKey = admitted.cosigners.get(mtcPolicy.caIdHex).key;
    const usage = admittedMtcIssuer(target, issuer, policy.issuerSha256,
      stateAt, {caName: mtcCaName(admitted.caId),
        caSpki: caKey.export({format: 'der', type: 'spki'}),
        minSerial: admitted.minSerial, maxSerial: admitted.maxSerial});
    // Explicit application restriction for direct OCSP ResponseData signing.
    if (kind === 'OCSP' && !(usage & 0x80)) throw new DerError('OCSP_SIGNING_KEY_USAGE');
  }, true);
}

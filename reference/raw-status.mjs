import {certificate, admittedIssuer, digest} from './cert-der.mjs';
import {DerError} from './der.mjs';
import {parseOcsp} from './ocsp-der.mjs';
import {parseCrl} from './crl-der.mjs';

const time = value => Number.isSafeInteger(value) && value >= 0;
const hash = value => typeof value === 'string' && /^[a-f0-9]{64}$/.test(value);
const name = value => typeof value === 'string' && value.length > 0;
const fail = code => { const error = new Error(code); error.code = code; throw error; };
const decision = (status, reason, observation = {}) => ({decision: status,
  reasons: reason ? [reason] : [], ...observation});

// Admitted policy, issuer and receipt are caller-supplied trust inputs. This
// function verifies their binding to original DER, never their provenance or
// the completeness of all status changes through knownAt.
export function assessRawStatus({kind, recordDer, targetDer, issuerDer, responderDer,
  requestDer, stateAt, knownAt, policy, admittedReceipt}) {
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
    admittedIssuer(target, issuer, policy.issuerSha256, stateAt);
    observation = kind === 'OCSP'
      ? parseOcsp({recordDer, target, issuer, responderDer, requestDer})
      : parseCrl({recordDer, target, issuer});
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

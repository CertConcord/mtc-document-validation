import {certificate, digest, OID} from './cert-der.mjs';
import {parseCrl} from './crl-der.mjs';
import {DerError} from './der.mjs';
import {assessRawTimestamp} from './raw-timestamp.mjs';
import {snapshotMtcBuffer} from './raw-mtc-native-bytes.mjs';

const hash = value => typeof value === 'string' && /^[a-f0-9]{64}$/.test(value);
const time = value => Number.isSafeInteger(value) && value >= 0;
const fail = code => { const error = new Error(code); error.code = code; throw error; };
const result = (decision, reason, details = {}) => ({decision,
  reasons: reason ? [reason] : [], ...details});

// This is one source-signed revocation observation about a verified token.
// Source admission, trusted receipt time, status-stream completeness and
// clock reliability remain external to this bounded application profile.
export function assessRawTsaRetirement(input) {
  if (!input || typeof input !== 'object') fail('TSA_RETIREMENT_INPUT');
  const responseDer = snapshotMtcBuffer(input.responseDer, 'TSA_RETIREMENT_INPUT');
  const coveredDer = snapshotMtcBuffer(input.coveredDer, 'TSA_RETIREMENT_INPUT');
  const tsaDer = snapshotMtcBuffer(input.tsaDer, 'TSA_RETIREMENT_INPUT');
  const issuerDer = snapshotMtcBuffer(input.issuerDer, 'TSA_RETIREMENT_INPUT');
  const crlDer = snapshotMtcBuffer(input.crlDer, 'TSA_RETIREMENT_INPUT');
  const requestDer = input.requestDer === undefined ? undefined
    : snapshotMtcBuffer(input.requestDer, 'TSA_RETIREMENT_INPUT');
  const tp = input.timestampPolicy;
  const sp = input.sourcePolicy;
  const receipt = input.admittedReceipt;
  const timestampPolicy = tp && {tsaSha256: tp.tsaSha256,
    issuerSha256: tp.issuerSha256, policyOid: tp.policyOid,
    maxAccuracyMicros: tp.maxAccuracyMicros};
  const sourcePolicy = sp && {issuerSha256: sp.issuerSha256,
    sourceId: sp.sourceId, scope: sp.scope};
  const admittedReceipt = receipt == null ? null : {
    recordSha256: receipt.recordSha256, sourceId: receipt.sourceId,
    observedAt: receipt.observedAt};
  const knownAt = input.knownAt;
  if (!timestampPolicy || !hash(timestampPolicy.tsaSha256) ||
      !hash(timestampPolicy.issuerSha256) ||
      typeof timestampPolicy.policyOid !== 'string' ||
      !Number.isSafeInteger(timestampPolicy.maxAccuracyMicros) ||
      timestampPolicy.maxAccuracyMicros < 0 ||
      !sourcePolicy || !hash(sourcePolicy.issuerSha256) ||
      typeof sourcePolicy.sourceId !== 'string' || !sourcePolicy.sourceId ||
      sourcePolicy.scope !== 'DIRECT_ISSUER_COMPLETE_NO_CDP' ||
      !time(knownAt) ||
      (admittedReceipt && (!hash(admittedReceipt.recordSha256) ||
        typeof admittedReceipt.sourceId !== 'string' ||
        !admittedReceipt.sourceId || !time(admittedReceipt.observedAt))))
    fail('TSA_RETIREMENT_INPUT');
  const crlSha256 = digest(crlDer);
  const timestamp = assessRawTimestamp({responseDer, requestDer, coveredDer,
    tsaDer, issuerDer, policy: timestampPolicy});
  const base = {timestampSha256: timestamp.recordSha256, crlSha256, knownAt};
  if (timestamp.decision !== 'SIGNED_CLAIM')
    return result(timestamp.decision, timestamp.reasons[0], base);
  const token = {tsaSha256: timestamp.tsaSha256,
    genTimeMicros: timestamp.genTimeMicros,
    claimedUpperBoundMicros: timestamp.claimedUpperBoundMicros};
  if (sourcePolicy.issuerSha256 !== timestamp.issuerSha256)
    return result('INDETERMINATE', 'TSA_CRL_ISSUER_NOT_ADMITTED', {...base, ...token});
  let crl;
  try {
    const target = certificate(tsaDer);
    const issuer = certificate(issuerDer);
    if (target.extensions.has(OID.crlDistributionPoints))
      throw new DerError('TSA_CRL_SCOPE_UNSUPPORTED');
    if (!target.issuer.equals(issuer.subject) ||
        !target.x509.verify(issuer.x509.publicKey))
      throw new DerError('TSA_CRL_ISSUER_MISMATCH');
    crl = parseCrl({recordDer: crlDer, target, issuer,
      allowNoDistributionPoint: true});
  } catch (error) {
    if (!(error instanceof DerError)) throw error;
    const decision = error.code.endsWith('_UNSUPPORTED') ? 'UNSUPPORTED' :
      error.code === 'CRL_TARGET_SCOPE_UNPROVEN' ? 'INDETERMINATE' : 'REJECTED';
    return result(decision, error.code, {...base, ...token});
  }
  const observed = {...base, ...token, sourceId: sourcePolicy.sourceId,
    crlThisUpdate: crl.thisUpdate, crlNextUpdate: crl.nextUpdate,
    revocationTime: crl.revocationTime, reasonCode: crl.reason,
    targetSerial: crl.targetSerial};
  if (!admittedReceipt)
    return result('INDETERMINATE', 'TSA_CRL_RECEIPT_MISSING', observed);
  if (admittedReceipt.recordSha256 !== crlSha256)
    return result('REJECTED', 'TSA_CRL_RECEIPT_RECORD_MISMATCH', observed);
  if (admittedReceipt.sourceId !== sourcePolicy.sourceId)
    return result('INDETERMINATE', 'TSA_CRL_SOURCE_NOT_ADMITTED', observed);
  if (admittedReceipt.observedAt < crl.thisUpdate)
    return result('REJECTED', 'TSA_CRL_RECEIPT_BEFORE_RECORD', observed);
  if (admittedReceipt.observedAt > knownAt || crl.thisUpdate > knownAt)
    return result('INDETERMINATE', 'TSA_CRL_NOT_YET_KNOWN', observed);
  if (crl.status !== 'REVOKED')
    return result('INDETERMINATE', 'TSA_CRL_NO_TARGET_REVOCATION', observed);
  if (crl.reason === null)
    return result('REJECTED', 'TSA_CRL_REASON_MISSING', observed);
  if (crl.reason === 1)
    return result('REJECTED', 'TSA_KEY_COMPROMISE', observed);
  if (![0, 3, 4, 5].includes(crl.reason))
    return result('UNSUPPORTED', 'TSA_CRL_REASON_UNSUPPORTED', observed);
  const revocationMicros = BigInt(crl.revocationTime) * 1_000_000n;
  if (BigInt(timestamp.genTimeMicros) >= revocationMicros)
    return result('REJECTED', 'TSA_TOKEN_NOT_BEFORE_REVOCATION', observed);
  if (BigInt(timestamp.claimedUpperBoundMicros) >= revocationMicros)
    return result('INDETERMINATE', 'TSA_TOKEN_INTERVAL_OVERLAPS_REVOCATION', observed);
  return result('BOUNDED_PRE_REVOCATION_CLAIM', null, observed);
}

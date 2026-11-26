import {createHash, verify} from 'node:crypto';
import {certificate, admittedIssuer, digest, OID as certOID} from './cert-der.mjs';
import {DerError, bitString, children, content, expect, one, oid,
  positiveInteger, raw, smallInteger} from './der.mjs';

const OID = {
  signedData: '1.2.840.113549.1.7.2',
  tstInfo: '1.2.840.113549.1.9.16.1.4',
  sha256: '2.16.840.1.101.3.4.2.1',
  rsa: '1.2.840.113549.1.1.1',
  rsaSha256: '1.2.840.113549.1.1.11',
  contentType: '1.2.840.113549.1.9.3',
  messageDigest: '1.2.840.113549.1.9.4',
  signingCertificate: '1.2.840.113549.1.9.16.2.12',
  signingCertificateV2: '1.2.840.113549.1.9.16.2.47',
  timeStamping: '1.3.6.1.5.5.7.3.8'
};
const bad = code => { throw new DerError(code); };
const sha256 = bytes => createHash('sha256').update(bytes).digest();

function explicit(value, tag, inside) {
  expect(value, tag);
  const values = children(value);
  if (values.length !== 1) bad('DER_MALFORMED');
  return expect(values[0], inside);
}

function algorithm(value) {
  const fields = children(expect(value, 0x30));
  if (fields.length < 1 || fields.length > 2) bad('DER_MALFORMED');
  if (fields.length === 2 && !raw(fields[1]).equals(Buffer.from('0500', 'hex')))
    bad('DER_UNSUPPORTED');
  return oid(fields[0]);
}

function imprint(value) {
  const fields = children(expect(value, 0x30));
  if (fields.length !== 2) bad('DER_MALFORMED');
  const hashOid = algorithm(fields[0]);
  if (hashOid !== OID.sha256) bad('TIMESTAMP_IMPRINT_ALGORITHM_UNSUPPORTED');
  const hash = content(expect(fields[1], 0x04));
  if (hash.length !== 32) bad('TIMESTAMP_IMPRINT_LENGTH');
  return hash;
}

function integer(value, tag, min, max) {
  expect(value, tag);
  const bytes = content(value);
  if (!bytes.length || bytes[0] & 0x80 ||
      (bytes.length > 1 && bytes[0] === 0 && !(bytes[1] & 0x80)) ||
      bytes.length > 5) bad('DER_MALFORMED');
  let number = 0;
  for (const byte of bytes) number = number * 256 + byte;
  if (number < min || number > max) bad('TIMESTAMP_ACCURACY_UNSUPPORTED');
  return number;
}

function generalizedTime(value) {
  expect(value, 0x18);
  const time = content(value).toString('ascii');
  const match = /^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(?:\.(\d{1,6}))?Z$/.exec(time);
  if (!match || match[7]?.endsWith('0')) bad('TIMESTAMP_TIME_UNSUPPORTED');
  const [year, month, day, hour, minute, second] = match.slice(1, 7).map(Number);
  if (year < 100 || second === 60) bad('TIMESTAMP_TIME_UNSUPPORTED');
  const millis = Date.UTC(year, month - 1, day, hour, minute, second);
  const date = new Date(millis);
  if (date.getUTCFullYear() !== year || date.getUTCMonth() + 1 !== month ||
      date.getUTCDate() !== day || date.getUTCHours() !== hour ||
      date.getUTCMinutes() !== minute || date.getUTCSeconds() !== second)
    bad('DER_MALFORMED');
  const fractionalMicros = Number((match[7] ?? '').padEnd(6, '0'));
  return {seconds: millis / 1000 + fractionalMicros / 1e6,
    micros: (BigInt(millis / 1000) * 1_000_000n + BigInt(fractionalMicros)).toString()};
}

function accuracy(value) {
  const fields = children(expect(value, 0x30));
  let at = 0, micros = 0;
  if (fields[at]?.tag === 0x02) micros += integer(fields[at++], 0x02, 0, 86400) * 1e6;
  if (fields[at]?.tag === 0x80) micros += integer(fields[at++], 0x80, 1, 999) * 1000;
  if (fields[at]?.tag === 0x81) micros += integer(fields[at++], 0x81, 1, 999);
  if (at !== fields.length) bad('DER_MALFORMED');
  return micros;
}

function request(bytes) {
  const fields = children(one(Buffer.from(bytes), 0x30));
  let at = 0;
  if (smallInteger(fields[at++]) !== 1) bad('TIMESTAMP_VERSION_UNSUPPORTED');
  const requestImprint = imprint(fields[at++]);
  const policyOid = fields[at]?.tag === 0x06 ? oid(fields[at++]) : null;
  const nonce = fields[at]?.tag === 0x02 ? positiveInteger(fields[at++]) : null;
  let certReq = false;
  if (fields[at]?.tag === 0x01) {
    const flag = content(fields[at++]);
    if (flag.length !== 1 || flag[0] !== 0xff) bad('DER_MALFORMED');
    certReq = true;
  }
  if (at < fields.length) bad('TIMESTAMP_REQUEST_EXTENSION_UNSUPPORTED');
  return {imprint: requestImprint, policyOid, nonce, certReq};
}

function tstInfo(bytes) {
  const fields = children(one(bytes, 0x30));
  let at = 0;
  if (smallInteger(fields[at++]) !== 1) bad('TIMESTAMP_VERSION_UNSUPPORTED');
  const policyOid = oid(fields[at++]);
  const messageImprint = imprint(fields[at++]);
  const serial = positiveInteger(fields[at++]);
  const genTime = generalizedTime(fields[at++]);
  const accuracyMicros = fields[at]?.tag === 0x30 ? accuracy(fields[at++]) : null;
  let ordering = false;
  if (fields[at]?.tag === 0x01) {
    const flag = content(fields[at++]);
    if (flag.length !== 1 || flag[0] !== 0xff) bad('DER_MALFORMED');
    ordering = true;
  }
  const nonce = fields[at]?.tag === 0x02 ? positiveInteger(fields[at++]) : null;
  let tsaName = null;
  if (fields[at]?.tag === 0xa0) {
    const generalName = explicit(fields[at++], 0xa0, 0xa4);
    tsaName = raw(explicit(generalName, 0xa4, 0x30));
  }
  if (at < fields.length) bad('TIMESTAMP_TST_EXTENSION_UNSUPPORTED');
  return {policyOid, messageImprint, serial, genTime: genTime.seconds,
    genTimeMicros: genTime.micros, accuracyMicros,
    ordering, nonce, tsaName};
}

function attributes(value) {
  expect(value, 0xa0); // SignerInfo.signedAttrs is IMPLICIT SET OF.
  const entries = children(value);
  const attrs = new Map();
  let previous = null;
  for (const entry of entries) {
    if (previous && Buffer.compare(previous, raw(entry)) > 0) bad('DER_MALFORMED');
    previous = raw(entry);
    const fields = children(expect(entry, 0x30));
    if (fields.length !== 2) bad('DER_MALFORMED');
    const id = oid(fields[0]);
    if (attrs.has(id)) bad('DER_MALFORMED');
    const values = children(expect(fields[1], 0x31));
    if (values.length !== 1) bad('TIMESTAMP_ATTRIBUTE_UNSUPPORTED');
    attrs.set(id, values[0]);
  }
  return attrs;
}

function signerInfo(value, tsa, signedContent) {
  const fields = children(expect(value, 0x30));
  if (fields.length !== 6 || smallInteger(fields[0]) !== 1)
    bad('TIMESTAMP_SIGNER_UNSUPPORTED');
  const sid = children(expect(fields[1], 0x30));
  if (sid.length !== 2 || !raw(expect(sid[0], 0x30)).equals(tsa.issuer) ||
      positiveInteger(sid[1]) !== tsa.serial) bad('TIMESTAMP_SIGNER_MISMATCH');
  if (algorithm(fields[2]) !== OID.sha256 ||
      ![OID.rsa, OID.rsaSha256].includes(algorithm(fields[4])) ||
      tsa.x509.publicKey.asymmetricKeyType !== 'rsa')
    bad('TIMESTAMP_SIGNATURE_ALGORITHM_UNSUPPORTED');
  const attrs = attributes(fields[3]);
  const signature = content(expect(fields[5], 0x04));
  const signedAttrs = Buffer.from(raw(fields[3]));
  signedAttrs[0] = 0x31; // CMS signs the DER SET OF tag, not the IMPLICIT [0].
  try {
    if (!verify('RSA-SHA256', signedAttrs, tsa.x509.publicKey, signature))
      bad('TIMESTAMP_SIGNATURE_INVALID');
  } catch (error) {
    if (error instanceof DerError) throw error;
    bad('TIMESTAMP_SIGNATURE_ALGORITHM_UNSUPPORTED');
  }
  if (oid(attrs.get(OID.contentType)) !== OID.tstInfo)
    bad('TIMESTAMP_CONTENT_TYPE_MISMATCH');
  if (!content(expect(attrs.get(OID.messageDigest), 0x04)).equals(sha256(signedContent)))
    bad('TIMESTAMP_CONTENT_DIGEST_MISMATCH');
  const signingCert = attrs.get(OID.signingCertificateV2);
  if (attrs.has(OID.signingCertificate) && signingCert)
    bad('TIMESTAMP_ESS_DUAL_UNSUPPORTED');
  if (attrs.has(OID.signingCertificate)) bad('TIMESTAMP_ESS_LEGACY_UNSUPPORTED');
  if (!signingCert) bad('TIMESTAMP_ESS_MISSING');
  const signingFields = children(expect(signingCert, 0x30));
  if (signingFields.length !== 1) bad('TIMESTAMP_ESS_UNSUPPORTED');
  const certs = children(expect(signingFields[0], 0x30));
  if (certs.length !== 1) bad('TIMESTAMP_ESS_UNSUPPORTED');
  const identifier = children(expect(certs[0], 0x30));
  let index = 0;
  if (identifier[index]?.tag === 0x30 && algorithm(identifier[index++]) !== OID.sha256)
    bad('TIMESTAMP_ESS_ALGORITHM_UNSUPPORTED');
  if (identifier.length !== index + 1) bad('TIMESTAMP_ESS_UNSUPPORTED');
  const certHash = content(expect(identifier[index], 0x04));
  if (certHash.length !== 32 || !certHash.equals(sha256(tsa.encoded)))
    bad('TIMESTAMP_ESS_CERT_MISMATCH');
}

function tsaAuthority(tsa, issuer, policy, genTime) {
  if (tsa.sha256 !== policy.tsaSha256) bad('TIMESTAMP_TSA_NOT_ADMITTED');
  admittedIssuer(tsa, issuer, policy.issuerSha256, genTime);
  const eku = tsa.extensions.get(certOID.extendedKeyUsage);
  if (!eku || !eku.critical) bad('TIMESTAMP_TSA_EKU');
  const usages = children(one(eku.value, 0x30));
  if (usages.length !== 1 || oid(usages[0]) !== OID.timeStamping)
    bad('TIMESTAMP_TSA_EKU');
  const usage = tsa.extensions.get(certOID.keyUsage);
  if (!usage || !(bitString(one(usage.value, 0x03)).bytes[0] & 0x80))
    bad('TIMESTAMP_TSA_KEY_USAGE');
  const basic = tsa.extensions.get(certOID.basicConstraints);
  if (!basic || children(one(basic.value, 0x30)).some(x => x.tag === 0x01 &&
      content(x).length === 1 && content(x)[0] === 0xff))
    bad('TIMESTAMP_TSA_CA_CONSTRAINT');
}

function signedData(value, tsa, issuer, policy, covered, requestBytes) {
  const contentInfo = children(expect(value, 0x30));
  if (contentInfo.length !== 2 || oid(contentInfo[0]) !== OID.signedData)
    bad('TIMESTAMP_CONTENT_TYPE_UNSUPPORTED');
  const fields = children(explicit(contentInfo[1], 0xa0, 0x30));
  if (fields.length < 4 || fields.length > 6 || smallInteger(fields[0]) !== 3)
    bad('TIMESTAMP_CMS_UNSUPPORTED');
  const algorithms = children(expect(fields[1], 0x31));
  if (algorithms.length !== 1 || algorithm(algorithms[0]) !== OID.sha256)
    bad('TIMESTAMP_CMS_DIGEST_UNSUPPORTED');
  const encapsulated = children(expect(fields[2], 0x30));
  if (encapsulated.length !== 2 || oid(encapsulated[0]) !== OID.tstInfo)
    bad('TIMESTAMP_CONTENT_TYPE_UNSUPPORTED');
  const signedContent = content(explicit(encapsulated[1], 0xa0, 0x04));
  const info = tstInfo(signedContent);
  let at = 3, embedded = [];
  if (fields[at]?.tag === 0xa0) embedded = children(fields[at++]).map(raw);
  if (fields[at]?.tag === 0xa1) bad('TIMESTAMP_CMS_CRL_UNSUPPORTED');
  if (at !== fields.length - 1) bad('TIMESTAMP_CMS_UNSUPPORTED');
  const signerInfos = children(expect(fields[at], 0x31));
  if (signerInfos.length !== 1) bad('TIMESTAMP_SIGNER_UNSUPPORTED');
  tsaAuthority(tsa, issuer, policy, info.genTime);
  if (info.tsaName && !info.tsaName.equals(tsa.subject))
    bad('TIMESTAMP_TSA_NAME_MISMATCH');
  signerInfo(signerInfos[0], tsa, signedContent);
  if (info.policyOid !== policy.policyOid) bad('TIMESTAMP_POLICY_MISMATCH');
  if (!info.messageImprint.equals(sha256(covered))) bad('TIMESTAMP_IMPRINT_MISMATCH');
  if (requestBytes) {
    const asked = request(requestBytes);
    if (!asked.imprint.equals(info.messageImprint)) bad('TIMESTAMP_REQUEST_IMPRINT_MISMATCH');
    if (asked.policyOid && asked.policyOid !== info.policyOid)
      bad('TIMESTAMP_REQUEST_POLICY_MISMATCH');
    if (asked.nonce !== info.nonce) bad('TIMESTAMP_NONCE_MISMATCH');
    if (asked.certReq && !embedded.some(bytes => bytes.equals(tsa.encoded)))
      bad('TIMESTAMP_REQUEST_CERT_MISSING');
  } else if (info.nonce) bad('TIMESTAMP_REQUEST_MISSING');
  if (info.accuracyMicros === null) bad('TIMESTAMP_ACCURACY_MISSING');
  if (info.accuracyMicros > policy.maxAccuracyMicros)
    bad('TIMESTAMP_ACCURACY_EXCEEDS_POLICY');
  return {tsaSha256: tsa.sha256, issuerSha256: issuer.sha256,
    policyOid: info.policyOid, serial: info.serial, genTime: info.genTime,
    genTimeMicros: info.genTimeMicros,
    accuracyMicros: info.accuracyMicros,
    claimedUpperBoundMicros:
      (BigInt(info.genTimeMicros) + BigInt(info.accuracyMicros)).toString(),
    ordering: info.ordering, nonce: info.nonce,
    coveredSha256: sha256(covered).toString('hex')};
}

export function assessRawTimestamp({responseDer, requestDer, coveredDer,
  tsaDer, issuerDer, policy}) {
  if (![responseDer, coveredDer, tsaDer, issuerDer].every(Buffer.isBuffer) ||
      (requestDer !== undefined && !Buffer.isBuffer(requestDer)) ||
      !policy || !/^[a-f0-9]{64}$/.test(policy.issuerSha256 ?? '') ||
      !/^[a-f0-9]{64}$/.test(policy.tsaSha256 ?? '') ||
      typeof policy.policyOid !== 'string' || !/^\d+(?:\.\d+)+$/.test(policy.policyOid) ||
      !Number.isSafeInteger(policy.maxAccuracyMicros) || policy.maxAccuracyMicros < 0)
    throw Object.assign(new Error('TIMESTAMP_INPUT'), {code: 'TIMESTAMP_INPUT'});
  const recordSha256 = digest(responseDer);
  try {
    const fields = children(one(Buffer.from(responseDer), 0x30));
    if (fields.length < 1 || fields.length > 2) bad('DER_MALFORMED');
    const status = children(expect(fields[0], 0x30));
    if (!status.length || status.length > 3) bad('DER_MALFORMED');
    const code = smallInteger(status[0]);
    if (![0, 1, 2, 3, 4, 5].includes(code)) bad('TIMESTAMP_RESPONSE_STATUS_UNSUPPORTED');
    if (code > 1) {
      if (fields.length !== 1) bad('TIMESTAMP_UNEXPECTED_TOKEN');
      return {decision: 'NO_TOKEN', reasons: ['TIMESTAMP_RESPONSE_NOT_GRANTED'], recordSha256};
    }
    if (fields.length !== 2) bad('TIMESTAMP_GRANTED_WITHOUT_TOKEN');
    if (code === 1) bad('TIMESTAMP_GRANTED_WITH_MODS_UNSUPPORTED');
    const tsa = certificate(tsaDer);
    const issuer = certificate(issuerDer);
    return {decision: 'SIGNED_CLAIM', reasons: [], recordSha256,
      ...signedData(fields[1], tsa, issuer, policy, coveredDer, requestDer)};
  } catch (error) {
    if (!(error instanceof DerError)) throw error;
    const unresolved = ['TIMESTAMP_REQUEST_MISSING', 'TIMESTAMP_ACCURACY_MISSING']
      .includes(error.code);
    const unsupported = error.code.endsWith('_UNSUPPORTED') || error.code === 'DER_UNSUPPORTED';
    return {decision: unresolved ? 'INDETERMINATE' : unsupported ? 'UNSUPPORTED' : 'REJECTED',
      reasons: [error.code], recordSha256};
  }
}

import {X509Certificate, createHash} from 'node:crypto';
import {DerError, bitString, children, content, encodedTime, expect, extensions,
  one, positiveInteger, raw} from './der.mjs';

const bad = code => { throw new DerError(code); };
const OID = {
  basicConstraints: '2.5.29.19',
  keyUsage: '2.5.29.15',
  extendedKeyUsage: '2.5.29.37',
  ocspSigning: '1.3.6.1.5.5.7.3.9',
  ocspNoCheck: '1.3.6.1.5.5.7.48.1.5',
  crlDistributionPoints: '2.5.29.31',
  mtcCaSha256: '1.3.6.1.5.5.7.1.38'
};

export const digest = bytes => createHash('sha256').update(bytes).digest('hex');

export function certificate(bytes) {
  const encoded = Buffer.from(bytes);
  const parts = children(one(encoded, 0x30));
  if (parts.length !== 3) bad('DER_MALFORMED');
  const tbs = children(expect(parts[0], 0x30));
  let at = 0;
  if (tbs[at]?.tag === 0xa0) {
    const version = children(tbs[at++]);
    if (version.length !== 1 || content(expect(version[0], 0x02)).length !== 1 ||
        content(version[0])[0] !== 2)
      bad('DER_UNSUPPORTED');
  }
  if (tbs.length < at + 6) bad('DER_MALFORMED');
  const serial = positiveInteger(tbs[at++]);
  expect(tbs[at++], 0x30); // TBSCertificate signature algorithm
  const issuer = raw(expect(tbs[at++], 0x30));
  const validity = children(expect(tbs[at++], 0x30));
  if (validity.length !== 2) bad('DER_MALFORMED');
  const validFrom = encodedTime(validity[0]);
  const validUntil = encodedTime(validity[1]);
  if (validUntil <= validFrom) bad('DER_MALFORMED');
  const subject = raw(expect(tbs[at++], 0x30));
  const spkiValue = expect(tbs[at++], 0x30);
  const spki = children(spkiValue);
  if (spki.length !== 2) bad('DER_MALFORMED');
  const publicKeyBits = bitString(spki[1]);
  if (publicKeyBits.unused !== 0) bad('DER_UNSUPPORTED');
  let ext = new Map();
  let sawExtensions = false;
  for (; at < tbs.length; at++) {
    if (tbs[at].tag !== 0xa3 || sawExtensions) bad('DER_UNSUPPORTED');
    sawExtensions = true;
    const wrapper = children(tbs[at]);
    if (wrapper.length !== 1) bad('DER_MALFORMED');
    ext = extensions(wrapper[0]);
  }
  let x509;
  try { x509 = new X509Certificate(encoded); }
  catch { bad('CERT_MALFORMED'); }
  return {encoded, sha256: digest(encoded), serial, issuer, subject,
    publicKeyBits: publicKeyBits.bytes, spkiDer: raw(spkiValue),
    validFrom, validUntil,
    extensions: ext, x509};
}

function issuerConstraints(target, issuer, stateAt) {
  if (stateAt < issuer.validFrom || stateAt > issuer.validUntil)
    bad('ISSUER_CERT_TIME');
  if (stateAt < target.validFrom || stateAt > target.validUntil)
    bad('TARGET_TIME_OUTSIDE_CERTIFICATE');
  const basic = issuer.extensions.get(OID.basicConstraints);
  if (!basic) bad('ISSUER_CA_UNPROVEN');
  const values = children(one(basic.value, 0x30));
  if (!values.some(x => x.tag === 0x01 && content(x).length === 1 && content(x)[0] === 0xff))
    bad('ISSUER_CA_UNPROVEN');
  const usage = issuer.extensions.get(OID.keyUsage);
  if (!usage) bad('ISSUER_USAGE_UNPROVEN');
  const bits = bitString(one(usage.value, 0x03)).bytes;
  if (!bits.length || !(bits[0] & 0x04))
    bad('ISSUER_USAGE_UNPROVEN');
  return bits[0];
}

export function admittedIssuer(target, issuer, expectedSha256, stateAt) {
  if (issuer.sha256 !== expectedSha256) bad('ISSUER_NOT_ADMITTED');
  if (!target.issuer.equals(issuer.subject)) bad('TARGET_ISSUER_MISMATCH');
  try { if (!target.x509.verify(issuer.x509.publicKey)) bad('TARGET_ISSUER_MISMATCH'); }
  catch (error) {
    if (error instanceof DerError) throw error;
    bad('TARGET_SIGNATURE_UNSUPPORTED');
  }
  issuerConstraints(target, issuer, stateAt);
}

// The caller has already verified the exact target's MTCProof. This checks the
// separately admitted CA representation; its superior certificate path remains
// an external trust input.
export function admittedMtcIssuer(target, issuer, expectedSha256, stateAt,
  {caName, caSpki, minSerial, maxSerial}) {
  if (issuer.sha256 !== expectedSha256) bad('ISSUER_NOT_ADMITTED');
  if (!target.issuer.equals(issuer.subject) || !issuer.subject.equals(caName))
    bad('MTC_CA_NAME');
  const usage = issuerConstraints(target, issuer, stateAt);
  if (!issuer.spkiDer.equals(caSpki))
    bad('MTC_CA_KEY');
  const extension = issuer.extensions.get(OID.mtcCaSha256);
  if (!extension || !extension.critical) bad('MTC_CA_EXTENSION');
  const fields = children(one(extension.value, 0x30));
  const ed25519 = Buffer.from('300506032b6570', 'hex');
  if (fields.length !== 3 || !raw(fields[0]).equals(ed25519))
    bad('MTC_CA_EXTENSION');
  const lower = BigInt(`0x${positiveInteger(fields[1])}`);
  const upper = BigInt(`0x${positiveInteger(fields[2])}`);
  if (lower < (1n << 48n) || upper > (1n << 64n) - 1n || lower > upper ||
      lower !== minSerial || upper !== maxSerial)
    bad('MTC_CA_RANGE');
  return usage;
}

export function admittedResponder(responder, issuer, producedAt) {
  if (!responder.issuer.equals(issuer.subject)) bad('RESPONDER_NOT_DELEGATED');
  try { if (!responder.x509.verify(issuer.x509.publicKey)) bad('RESPONDER_NOT_DELEGATED'); }
  catch (error) {
    if (error instanceof DerError) throw error;
    bad('RESPONDER_CERT_SIGNATURE_UNSUPPORTED');
  }
  if (producedAt < responder.validFrom || producedAt > responder.validUntil)
    bad('RESPONDER_CERT_TIME');
  const basic = responder.extensions.get(OID.basicConstraints);
  if (!basic || children(one(basic.value, 0x30)).some(x => x.tag === 0x01 &&
      content(x).length === 1 && content(x)[0] === 0xff)) bad('RESPONDER_CA_CONSTRAINT');
  const usage = responder.extensions.get(OID.keyUsage);
  if (!usage || !(bitString(one(usage.value, 0x03)).bytes[0] & 0x80))
    bad('RESPONDER_USAGE');
  const eku = responder.extensions.get(OID.extendedKeyUsage);
  if (!eku) bad('RESPONDER_EKU');
  const identifiers = children(one(eku.value, 0x30));
  // A small local OID decoder avoids accepting an extension only by its text.
  const ocspSigningDer = Buffer.from('06082b06010505070309', 'hex');
  if (!identifiers.some(id => raw(id).equals(ocspSigningDer))) bad('RESPONDER_EKU');
  const noCheck = responder.extensions.get(OID.ocspNoCheck);
  if (!noCheck || !noCheck.value.equals(Buffer.from('0500', 'hex')))
    bad('RESPONDER_REVOCATION_UNRESOLVED');
}

export {OID};

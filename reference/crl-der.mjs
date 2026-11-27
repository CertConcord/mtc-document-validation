import {verify} from 'node:crypto';
import {digest, OID as certificateOid} from './cert-der.mjs';
import {DerError, bitString, children, content, encodedTime, expect, extensions,
  one, oid, positiveInteger, raw, smallInteger} from './der.mjs';

const bad = code => { throw new DerError(code); };
const OID = {
  rsaSha256: '1.2.840.113549.1.1.11',
  ed25519: '1.3.101.112',
  authorityKeyIdentifier: '2.5.29.35',
  crlNumber: '2.5.29.20',
  issuingDistributionPoint: '2.5.29.28',
  deltaCrlIndicator: '2.5.29.27',
  certificateIssuer: '2.5.29.29',
  reason: '2.5.29.21',
  invalidityDate: '2.5.29.24'
};

function algorithm(value) {
  const fields = children(expect(value, 0x30));
  if (fields.length < 1 || fields.length > 2) bad('DER_MALFORMED');
  if (fields.length === 2 && !raw(fields[1]).equals(Buffer.from('0500', 'hex')))
    bad('DER_UNSUPPORTED');
  return oid(fields[0]);
}

function distributionUri(target) {
  const extension = target.extensions.get(certificateOid.crlDistributionPoints);
  if (!extension) bad('CRL_TARGET_SCOPE_UNPROVEN');
  const points = children(one(extension.value, 0x30));
  if (points.length !== 1) bad('CRL_DISTRIBUTION_SCOPE_UNSUPPORTED');
  const fields = children(expect(points[0], 0x30));
  if (fields.length !== 1 || fields[0].tag !== 0xa0)
    bad('CRL_DISTRIBUTION_SCOPE_UNSUPPORTED');
  const names = children(fields[0]);
  if (names.length !== 1 || names[0].tag !== 0xa0)
    bad('CRL_DISTRIBUTION_SCOPE_UNSUPPORTED');
  const generalNames = children(names[0]);
  if (generalNames.length !== 1 || generalNames[0].tag !== 0x86)
    bad('CRL_DISTRIBUTION_SCOPE_UNSUPPORTED');
  const uri = content(generalNames[0]).toString('ascii');
  if (!/^https?:\/\/[^\s]+$/.test(uri)) bad('CRL_DISTRIBUTION_SCOPE_UNSUPPORTED');
  return uri;
}

function revokedEntry(value) {
  const fields = children(expect(value, 0x30));
  if (fields.length < 2 || fields.length > 3) bad('DER_MALFORMED');
  const serial = positiveInteger(fields[0]);
  const revocationTime = encodedTime(fields[1]);
  let reason = null, invalidityDate = null;
  if (fields.length === 3) {
    const ext = extensions(expect(fields[2], 0x30));
    if (ext.has(OID.certificateIssuer)) bad('CRL_INDIRECT_UNSUPPORTED');
    for (const [id, item] of ext) if (item.critical && ![OID.reason, OID.invalidityDate].includes(id))
      bad('CRL_CRITICAL_ENTRY_EXTENSION_UNSUPPORTED');
    if (ext.has(OID.reason)) reason = smallInteger(one(ext.get(OID.reason).value, 0x0a), 0x0a);
    if (ext.has(OID.invalidityDate))
      invalidityDate = encodedTime(one(ext.get(OID.invalidityDate).value, 0x18));
  }
  if (reason === 8) bad('CRL_REMOVE_FROM_COMPLETE_UNSUPPORTED');
  return {serial, revocationTime, reason, invalidityDate,
    hasExtensions: fields.length === 3};
}

export function parseCrl({recordDer, target, issuer, directMtcCa = false,
  allowNoDistributionPoint = false}) {
  const record = Buffer.from(recordDer);
  const outer = children(one(record, 0x30));
  if (outer.length !== 3) bad('DER_MALFORMED');
  const signedAlgorithm = algorithm(outer[1]);
  if (signedAlgorithm !== (directMtcCa ? OID.ed25519 : OID.rsaSha256) ||
      (directMtcCa && children(outer[1]).length !== 1))
    bad('CRL_SIGNATURE_ALGORITHM_UNSUPPORTED');
  const signature = bitString(outer[2]);
  if (signature.unused !== 0) bad('DER_MALFORMED');
  const fields = children(expect(outer[0], 0x30));
  let at = 0;
  const hasVersion = fields[at]?.tag === 0x02;
  if (hasVersion && smallInteger(fields[at++]) !== 1) bad('CRL_VERSION_UNSUPPORTED');
  const inner = fields[at++];
  if (algorithm(inner) !== signedAlgorithm ||
      (directMtcCa && children(inner).length !== 1))
    bad('CRL_SIGNATURE_ALGORITHM_UNSUPPORTED');
  if (!raw(expect(fields[at++], 0x30)).equals(issuer.subject))
    bad('CRL_ISSUER_MISMATCH');
  const usage = issuer.extensions.get(certificateOid.keyUsage);
  if (!usage || !(bitString(one(usage.value, 0x03)).bytes[0] & 0x02))
    bad('CRL_SIGNING_KEY_USAGE');
  if (issuer.x509.publicKey.asymmetricKeyType !== (directMtcCa ? 'ed25519' : 'rsa'))
    bad('CRL_SIGNATURE_ALGORITHM_UNSUPPORTED');
  try {
    if (directMtcCa && signature.bytes.length !== 64)
      bad('CRL_SIGNATURE_INVALID');
    if (!verify(directMtcCa ? null : 'RSA-SHA256', raw(outer[0]),
      issuer.x509.publicKey, signature.bytes))
      bad('CRL_SIGNATURE_INVALID');
  } catch (error) {
    if (error instanceof DerError) throw error;
    bad('CRL_SIGNATURE_ALGORITHM_UNSUPPORTED');
  }
  const thisUpdate = encodedTime(fields[at++]);
  if (thisUpdate < issuer.validFrom || thisUpdate > issuer.validUntil)
    bad('CRL_SIGNER_CERT_TIME');
  let nextUpdate = null;
  if ([0x17, 0x18].includes(fields[at]?.tag)) nextUpdate = encodedTime(fields[at++]);
  if (nextUpdate === null || nextUpdate <= thisUpdate) bad('CRL_TIME_UNSUPPORTED');
  let entries = [];
  if (fields[at]?.tag === 0x30) entries = children(fields[at++]).map(revokedEntry);
  if (!hasVersion && entries.some(entry => entry.hasExtensions))
    bad('CRL_VERSION_REQUIRED');
  if (fields[at]?.tag === 0xa0) {
    if (!hasVersion) bad('CRL_VERSION_REQUIRED');
    const wrapper = children(fields[at++]);
    if (wrapper.length !== 1) bad('DER_MALFORMED');
    const ext = extensions(wrapper[0]);
    if (ext.has(OID.issuingDistributionPoint)) bad('CRL_PARTITION_UNSUPPORTED');
    if (ext.has(OID.deltaCrlIndicator)) bad('CRL_DELTA_UNSUPPORTED');
    for (const [, item] of ext) if (item.critical)
      bad('CRL_CRITICAL_EXTENSION_UNSUPPORTED');
  }
  if (at !== fields.length) bad('DER_MALFORMED');
  // The issuer-wide, no-CDP path is used only by a caller that explicitly
  // admits this direct complete CRL source. IDP and delta CRLs were rejected
  // above, and the caller must bind the target to this issuer independently.
  const distributionPoint = allowNoDistributionPoint &&
    !target.extensions.has(certificateOid.crlDistributionPoints)
    ? null : distributionUri(target);
  const matches = entries.filter(entry => entry.serial === target.serial);
  if (matches.length > 1) bad('CRL_DUPLICATE_TARGET');
  return {recordSha256: digest(record), signerSha256: issuer.sha256,
    targetSerial: target.serial, distributionPoint, thisUpdate, nextUpdate,
    status: matches.length ? 'REVOKED' : 'GOOD',
    revocationTime: matches[0]?.revocationTime ?? null,
    reason: matches[0]?.reason ?? null,
    invalidityDate: matches[0]?.invalidityDate ?? null};
}

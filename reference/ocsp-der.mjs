import {createHash, verify} from 'node:crypto';
import {certificate, admittedResponder, digest} from './cert-der.mjs';
import {DerError, bitString, children, content, encodedTime, expect, extensions,
  one, oid, positiveInteger, raw, smallInteger} from './der.mjs';

const bad = code => { throw new DerError(code); };
const OID = {
  basic: '1.3.6.1.5.5.7.48.1.1',
  sha1: '1.3.14.3.2.26',
  sha256: '2.16.840.1.101.3.4.2.1',
  rsaSha256: '1.2.840.113549.1.1.11',
  ed25519: '1.3.101.112',
  nonce: '1.3.6.1.5.5.7.48.1.2',
  reason: '2.5.29.21',
  invalidityDate: '2.5.29.24'
};

function explicit(value, tag, inside = 0x30) {
  expect(value, tag);
  const items = children(value);
  if (items.length !== 1) bad('DER_MALFORMED');
  return expect(items[0], inside);
}

function algorithm(value) {
  const fields = children(expect(value, 0x30));
  if (fields.length < 1 || fields.length > 2) bad('DER_MALFORMED');
  if (fields.length === 2 && !raw(fields[1]).equals(Buffer.from('0500', 'hex')))
    bad('DER_UNSUPPORTED');
  return oid(fields[0]);
}

function certId(value) {
  const fields = children(expect(value, 0x30));
  if (fields.length !== 4) bad('DER_MALFORMED');
  return {raw: raw(value), hashOid: algorithm(fields[0]),
    nameHash: content(expect(fields[1], 0x04)),
    keyHash: content(expect(fields[2], 0x04)),
    serial: positiveInteger(fields[3])};
}

function targetIdMatches(id, target, issuer) {
  const hash = id.hashOid === OID.sha256 ? 'sha256' : id.hashOid === OID.sha1 ? 'sha1' : null;
  if (!hash) bad('OCSP_CERTID_HASH_UNSUPPORTED');
  const nameHash = createHash(hash).update(issuer.subject).digest();
  const keyHash = createHash(hash).update(issuer.publicKeyBits).digest();
  return id.nameHash.equals(nameHash) && id.keyHash.equals(keyHash) && id.serial === target.serial;
}

function knownExtensions(ext, known) {
  for (const [id, item] of ext) if (item.critical && !known.includes(id))
    bad('OCSP_CRITICAL_EXTENSION_UNSUPPORTED');
}

function nonce(ext) {
  const item = ext.get(OID.nonce);
  return item ? content(one(item.value, 0x04)) : null;
}

function requestCertIdAndNonce(bytes) {
  const fields = children(one(Buffer.from(bytes), 0x30));
  if (fields.length < 1 || fields.length > 2) bad('DER_MALFORMED');
  if (fields.length === 2) bad('OCSP_SIGNED_REQUEST_UNSUPPORTED');
  const tbs = children(expect(fields[0], 0x30));
  let at = 0;
  if (tbs[at]?.tag === 0xa0) {
    const v = explicit(tbs[at++], 0xa0, 0x02);
    if (smallInteger(v) !== 0) bad('OCSP_VERSION_UNSUPPORTED');
  }
  if (tbs[at]?.tag === 0xa1) bad('OCSP_REQUESTOR_UNSUPPORTED');
  const list = children(expect(tbs[at++], 0x30));
  if (list.length !== 1) bad('OCSP_MULTITARGET_REQUEST_UNSUPPORTED');
  const request = children(expect(list[0], 0x30));
  if (request.length !== 1) bad('OCSP_REQUEST_EXTENSION_UNSUPPORTED');
  const id = certId(request[0]);
  let requestNonce = null;
  if (at < tbs.length) {
    const ext = extensions(explicit(tbs[at++], 0xa2));
    knownExtensions(ext, [OID.nonce]);
    requestNonce = nonce(ext);
  }
  if (at !== tbs.length) bad('DER_MALFORMED');
  return {id, nonce: requestNonce};
}

function singleResponse(value) {
  const fields = children(expect(value, 0x30));
  if (fields.length < 3 || fields.length > 5) bad('DER_MALFORMED');
  const id = certId(fields[0]);
  const statusField = fields[1];
  let status, revocationTime = null, reason = null;
  if (statusField.tag === 0x80 && !content(statusField).length) status = 'GOOD';
  else if (statusField.tag === 0x82 && !content(statusField).length) status = 'UNKNOWN';
  else if (statusField.tag === 0xa1) {
    status = 'REVOKED';
    const details = children(statusField); // IMPLICIT RevokedInfo
    if (details.length < 1 || details.length > 2) bad('DER_MALFORMED');
    revocationTime = encodedTime(expect(details[0], 0x18));
    if (details.length === 2) reason = smallInteger(explicit(details[1], 0xa0, 0x0a), 0x0a);
  } else bad('OCSP_STATUS_UNSUPPORTED');
  const thisUpdate = encodedTime(expect(fields[2], 0x18));
  let at = 3, nextUpdate = null, invalidityDate = null;
  if (fields[at]?.tag === 0xa0) nextUpdate = encodedTime(explicit(fields[at++], 0xa0, 0x18));
  if (fields[at]?.tag === 0xa1) {
    const ext = extensions(explicit(fields[at++], 0xa1));
    knownExtensions(ext, [OID.reason, OID.invalidityDate]);
    if (ext.has(OID.reason)) reason = smallInteger(one(ext.get(OID.reason).value, 0x0a), 0x0a);
    if (ext.has(OID.invalidityDate)) invalidityDate = encodedTime(one(ext.get(OID.invalidityDate).value, 0x18));
  }
  if (at !== fields.length || (nextUpdate !== null && nextUpdate <= thisUpdate)) bad('DER_MALFORMED');
  return {id, status, thisUpdate, nextUpdate, revocationTime, reason, invalidityDate};
}

function responderMatches(value, signer) {
  if (value.tag === 0xa1) return raw(explicit(value, 0xa1)).equals(signer.subject);
  if (value.tag === 0xa2) {
    const keyHash = content(explicit(value, 0xa2, 0x04));
    return keyHash.equals(createHash('sha1').update(signer.publicKeyBits).digest());
  }
  bad('OCSP_RESPONDER_ID_UNSUPPORTED');
}

export function parseOcsp({recordDer, target, issuer, responderDer, requestDer,
  directMtcCa = false}) {
  if (directMtcCa && responderDer) bad('OCSP_RESPONDER_CERT_UNSUPPORTED');
  const record = Buffer.from(recordDer);
  const outer = children(one(record, 0x30));
  if (outer.length < 1 || outer.length > 2) bad('DER_MALFORMED');
  const responseStatus = smallInteger(outer[0], 0x0a);
  if (responseStatus !== 0) {
    if (outer.length !== 1) bad('DER_MALFORMED');
    if ([2, 3, 5].includes(responseStatus)) bad('OCSP_RESPONSE_UNAVAILABLE');
    bad('OCSP_RESPONSE_NOT_SUCCESSFUL');
  }
  if (outer.length !== 2) bad('DER_MALFORMED');
  const responseBytes = children(explicit(outer[1], 0xa0));
  if (responseBytes.length !== 2 || oid(responseBytes[0]) !== OID.basic)
    bad('OCSP_RESPONSE_TYPE_UNSUPPORTED');
  const basic = children(one(content(expect(responseBytes[1], 0x04)), 0x30));
  if (basic.length < 3 || basic.length > 4) bad('DER_MALFORMED');
  const signedAlgorithm = algorithm(basic[1]);
  const expectedAlgorithm = directMtcCa ? OID.ed25519 : OID.rsaSha256;
  if (signedAlgorithm !== expectedAlgorithm ||
      (directMtcCa && children(basic[1]).length !== 1))
    bad('OCSP_SIGNATURE_ALGORITHM_UNSUPPORTED');
  const signed = raw(basic[0]);
  const signature = bitString(basic[2]);
  if (signature.unused !== 0) bad('DER_MALFORMED');
  if (basic.length === 4) {
    const candidates = children(explicit(basic[3], 0xa0));
    for (const candidate of candidates) expect(candidate, 0x30);
  }
  const data = children(expect(basic[0], 0x30));
  let at = 0;
  if (data[at]?.tag === 0xa0) {
    if (smallInteger(explicit(data[at++], 0xa0, 0x02)) !== 0)
      bad('OCSP_VERSION_UNSUPPORTED');
  }
  const responderId = data[at++];
  const producedAt = encodedTime(expect(data[at++], 0x18));
  const responseList = expect(data[at++], 0x30);
  const responseExtensions = data[at]?.tag === 0xa1 ? data[at++] : null;
  if (at !== data.length) bad('DER_MALFORMED');
  const signer = responderDer ? certificate(responderDer) : issuer;
  if (!responderMatches(responderId, signer)) bad('OCSP_RESPONDER_ID_MISMATCH');
  if (producedAt < signer.validFrom || producedAt > signer.validUntil)
    bad('OCSP_SIGNER_CERT_TIME');
  if (responderDer) admittedResponder(signer, issuer, producedAt);
  if (signer.x509.publicKey.asymmetricKeyType !== (directMtcCa ? 'ed25519' : 'rsa'))
    bad('OCSP_SIGNATURE_ALGORITHM_UNSUPPORTED');
  try {
    if (directMtcCa && signature.bytes.length !== 64)
      bad('OCSP_SIGNATURE_INVALID');
    if (!verify(directMtcCa ? null : 'RSA-SHA256', signed,
      signer.x509.publicKey, signature.bytes))
      bad('OCSP_SIGNATURE_INVALID');
  } catch (error) {
    if (error instanceof DerError) throw error;
    bad('OCSP_SIGNATURE_ALGORITHM_UNSUPPORTED');
  }
  const responses = children(responseList).map(singleResponse);
  if (!responses.length) bad('OCSP_EMPTY_RESPONSE');
  let responseNonce = null;
  if (responseExtensions) {
    const ext = extensions(explicit(responseExtensions, 0xa1));
    knownExtensions(ext, [OID.nonce]);
    responseNonce = nonce(ext);
  }
  const matches = responses.filter(x => targetIdMatches(x.id, target, issuer));
  if (matches.length !== 1) bad(matches.length ? 'OCSP_DUPLICATE_TARGET' : 'OCSP_TARGET_NOT_FOUND');
  let requestNonce = null;
  if (requestDer) {
    const request = requestCertIdAndNonce(requestDer);
    if (!request.id.raw.equals(matches[0].id.raw)) bad('OCSP_REQUEST_TARGET_MISMATCH');
    requestNonce = request.nonce;
    if (requestNonce && (!responseNonce || !requestNonce.equals(responseNonce)))
      bad('OCSP_NONCE_MISMATCH');
    if (!requestNonce && responseNonce) bad('OCSP_UNSOLICITED_NONCE_UNSUPPORTED');
  } else if (responseNonce) bad('OCSP_NONCE_REQUEST_MISSING');
  return {recordSha256: digest(record), signerSha256: signer.sha256,
    targetSerial: target.serial, producedAt, responseNonce: responseNonce?.toString('hex') ?? null,
    requestNonce: requestNonce?.toString('hex') ?? null,
    ...Object.fromEntries(Object.entries(matches[0]).filter(([key]) => key !== 'id'))};
}

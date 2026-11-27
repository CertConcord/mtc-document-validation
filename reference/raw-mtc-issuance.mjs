import {createHash, createPublicKey, verify} from 'node:crypto';
import {DerError, bitString, children, expect, one, positiveInteger, raw} from './der.mjs';
import {certificate} from './cert-der.mjs';

// A bounded revision-07 certificate-signature check. It does not perform PKIX
// path, status, document-signature, time, or archive validation.
const MTC_ALGORITHM = Buffer.from('300a06082b06010505070643', 'hex');
const CA_NAME_OID = Buffer.from('06082b06010505071903', 'hex');
const LABEL = Buffer.from('subtree/v1\n\0', 'ascii');
const fail = code => { throw new DerError(code); };
const hash = (...parts) => createHash('sha256').update(Buffer.concat(parts)).digest();
const hex = value => typeof value === 'string' && /^(?:[a-f0-9]{2})+$/.test(value);
const decimal = value => typeof value === 'string' && /^(?:0|[1-9][0-9]*)$/.test(value);

function relativeOid(bytes, errorCode = 'MTC_POLICY') {
  if (!bytes.length || bytes.length > 32) fail(errorCode);
  const arcs = [];
  let value = 0n;
  let first = true;
  for (const byte of bytes) {
    if (first && byte === 0x80) fail(errorCode);
    value = (value << 7n) | BigInt(byte & 0x7f);
    first = false;
    if (!(byte & 0x80)) {
      arcs.push(value.toString());
      value = 0n;
      first = true;
    }
  }
  if (!first) fail(errorCode);
  return arcs.join('.');
}

export function deriveMtcLogId(caId, logNumber) {
  if (!Buffer.isBuffer(caId) ||
      !Number.isInteger(logNumber) || logNumber < 1 || logNumber > 65535)
    fail('MTC_POLICY');
  const arcs = relativeOid(caId);
  let number = BigInt(logNumber);
  const encodedNumber = [Number(number & 127n)];
  while (number > 127n) {
    number >>= 7n;
    encodedNumber.unshift(0x80 | Number(number & 127n));
  }
  const binary = Buffer.concat([caId, Buffer.from([0, ...encodedNumber])]);
  if (binary.length > 32) fail('MTC_POLICY');
  return {binary, origin: `${arcs}.0.${logNumber}`};
}

function caName(caId) {
  const value = Buffer.concat([Buffer.from([0x0d, caId.length]), caId]);
  const attribute = Buffer.concat([CA_NAME_OID, value]);
  const sequence = Buffer.concat([Buffer.from([0x30, attribute.length]), attribute]);
  const set = Buffer.concat([Buffer.from([0x31, sequence.length]), sequence]);
  return Buffer.concat([Buffer.from([0x30, set.length]), set]);
}

export function admittedPolicy(policy, representation = 'standalone') {
  if (!policy || typeof policy.mtcRevision !== 'string' ||
      typeof policy.logHash !== 'string' ||
      policy.representation !== representation ||
      !hex(policy.caIdHex) || !Array.isArray(policy.cosigners) ||
      !Array.isArray(policy.requiredRoles) || !Array.isArray(policy.revokedRanges) ||
      !decimal(policy.minSerial) || !decimal(policy.maxSerial))
    fail('MTC_POLICY');
  if (policy.mtcRevision !== '07' || policy.logHash !== 'sha256')
    fail('MTC_UNSUPPORTED');
  const minSerial = BigInt(policy.minSerial);
  const maxSerial = BigInt(policy.maxSerial);
  if (minSerial < (1n << 48n) || maxSerial > (1n << 64n) - 1n ||
      minSerial > maxSerial) fail('MTC_POLICY');
  const caId = Buffer.from(policy.caIdHex, 'hex');
  relativeOid(caId);
  const cosigners = new Map();
  for (const entry of policy.cosigners) {
    if (!entry || !hex(entry.idHex) || typeof entry.role !== 'string' ||
        !/^[a-z][a-z0-9-]*$/.test(entry.role) ||
        typeof entry.publicKeySpkiBase64 !== 'string' ||
        !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(entry.publicKeySpkiBase64) ||
        cosigners.has(entry.idHex)) fail('MTC_POLICY');
    const id = Buffer.from(entry.idHex, 'hex');
    const name = relativeOid(id);
    if ((entry.role === 'ca') !== (entry.idHex === policy.caIdHex)) fail('MTC_POLICY');
    const spki = Buffer.from(entry.publicKeySpkiBase64, 'base64');
    let key;
    try { key = createPublicKey({key: spki, format: 'der', type: 'spki'}); }
    catch { fail('MTC_POLICY'); }
    if (key.asymmetricKeyType !== 'ed25519' ||
        !key.export({format: 'der', type: 'spki'}).equals(spki)) fail('MTC_POLICY');
    cosigners.set(entry.idHex, {role: entry.role, key, name});
  }
  if (!cosigners.has(policy.caIdHex) ||
      !policy.requiredRoles.includes('ca') ||
      new Set(policy.requiredRoles).size !== policy.requiredRoles.length ||
      !policy.requiredRoles.every(role =>
        typeof role === 'string' && [...cosigners.values()].some(x => x.role === role)))
    fail('MTC_POLICY');
  const revokedRanges = policy.revokedRanges.map(range => {
    if (!range || !decimal(range.start) || !decimal(range.end))
      fail('MTC_POLICY');
    const start = BigInt(range.start), end = BigInt(range.end);
    if (start < 0n || end > (1n << 64n) || start >= end) fail('MTC_POLICY');
    return {start, end};
  });
  return {caId, cosigners, requiredRoles: policy.requiredRoles,
    minSerial, maxSerial, revokedRanges};
}

function certificateParts(der, caId) {
  const certificate = children(one(der, 0x30));
  if (certificate.length !== 3 ||
      !raw(expect(certificate[1], 0x30)).equals(MTC_ALGORITHM))
    fail('MTC_CERTIFICATE');
  const signature = bitString(certificate[2]);
  if (signature.unused !== 0) fail('MTC_PROOF_ENCODING');
  const fields = children(expect(certificate[0], 0x30));
  let at = 0;
  const copied = [];
  if (fields[at]?.tag === 0xa0) {
    if (!raw(fields[at]).equals(Buffer.from('a003020102', 'hex')))
      fail('MTC_CERTIFICATE');
    copied.push(raw(fields[at++]));
  }
  if (fields.length < at + 6) fail('MTC_CERTIFICATE');
  const serial = BigInt(`0x${positiveInteger(fields[at++])}`);
  if (!raw(expect(fields[at++], 0x30)).equals(MTC_ALGORITHM))
    fail('MTC_CERTIFICATE');
  const issuer = raw(expect(fields[at++], 0x30));
  if (!issuer.equals(caName(caId))) fail('MTC_ISSUER');
  const validity = raw(expect(fields[at++], 0x30));
  const subject = raw(expect(fields[at++], 0x30));
  const spki = fields[at++];
  const spkiFields = children(expect(spki, 0x30));
  if (spkiFields.length !== 2 ||
      bitString(spkiFields[1]).unused !== 0) fail('MTC_CERTIFICATE');
  const algorithm = raw(expect(spkiFields[0], 0x30));
  copied.push(issuer, validity, subject, algorithm,
    Buffer.from([0x04, 0x20]), hash(raw(spki)));
  for (const tag of [0x81, 0x82, 0xa3]) {
    if (fields[at]?.tag === tag) {
      if (tag === 0xa3) {
        const wrapper = children(fields[at]);
        if (wrapper.length !== 1 || wrapper[0].tag !== 0x30)
          fail('MTC_CERTIFICATE');
      }
      copied.push(raw(fields[at++]));
    }
  }
  if (at !== fields.length) fail('MTC_CERTIFICATE');
  return {serial, signature: signature.bytes, logEntryContents: Buffer.concat(copied)};
}

function proof(bytes) {
  let at = 0;
  const take = length => {
    if (length < 0 || at + length > bytes.length) fail('MTC_PROOF_ENCODING');
    const result = bytes.subarray(at, at + length);
    at += length;
    return result;
  };
  const u16 = () => take(2).readUInt16BE();
  const u24 = () => { const data = take(3); return data.readUIntBE(0, 3); };
  const u48 = () => take(6).readUIntBE(0, 6);
  const extensions = take(u16());
  for (let e = 0, last = -1; e < extensions.length;) {
    if (e + 4 > extensions.length) fail('MTC_PROOF_ENCODING');
    const type = extensions.readUInt16BE(e);
    const length = extensions.readUInt16BE(e + 2);
    if (type <= last || e + 4 + length > extensions.length)
      fail('MTC_PROOF_ENCODING');
    e += 4 + length;
    last = type;
  }
  const start = u48(), end = u48();
  const path = take(u16());
  if (path.length % 32) fail('MTC_PROOF_ENCODING');
  const signaturesLength = u24();
  const signaturesEnd = at + signaturesLength;
  if (signaturesEnd !== bytes.length) fail('MTC_PROOF_ENCODING');
  const signatures = [];
  let previous = null;
  while (at < signaturesEnd) {
    const id = take(take(1)[0]);
    if (!id.length || id.length > 32 ||
        (previous && (id.length < previous.length ||
          (id.length === previous.length && Buffer.compare(id, previous) <= 0))))
      fail('MTC_PROOF_ENCODING');
    relativeOid(id, 'MTC_PROOF_ENCODING');
    signatures.push({id, value: take(u16())});
    previous = id;
  }
  return {extensions: Buffer.concat([Buffer.from([extensions.length >> 8,
    extensions.length & 255]), extensions]), start, end, path, signatures};
}

export function evaluateMtcSubtreeProof(leaf, index, start, end, path) {
  if (!Buffer.isBuffer(leaf) || leaf.length !== 32 ||
      !Buffer.isBuffer(path) || path.length % 32 !== 0 ||
      ![index, start, end].every(x => Number.isSafeInteger(x) &&
        x >= 0 && x < 2 ** 48)) fail('MTC_PATH');
  const size = end - start;
  let alignment = 1;
  while (alignment < size) alignment *= 2;
  if (size < 1 || index < start || index >= end ||
      start % alignment !== 0)
    fail('MTC_SUBTREE');
  let fn = index - start, sn = size - 1, root = leaf;
  for (let at = 0; at < path.length; at += 32) {
    if (sn === 0) fail('MTC_PATH');
    const peer = path.subarray(at, at + 32);
    if (fn % 2 === 1 || fn === sn) {
      root = hash(Buffer.from([1]), peer, root);
      while (fn % 2 === 0) {
        fn = Math.floor(fn / 2);
        sn = Math.floor(sn / 2);
      }
    } else root = hash(Buffer.from([1]), root, peer);
    fn = Math.floor(fn / 2);
    sn = Math.floor(sn / 2);
  }
  if (sn !== 0) fail('MTC_PATH');
  return root;
}

function cosignedSubtree(name, origin, start, end, root) {
  const signer = Buffer.from(`oid/1.3.6.1.4.1.${name}`, 'ascii');
  const log = Buffer.from(`oid/1.3.6.1.4.1.${origin}`, 'ascii');
  if (!signer.length || signer.length > 255 || !log.length || log.length > 255)
    fail('MTC_POLICY');
  const bounds = Buffer.alloc(24);
  bounds.writeBigUInt64BE(BigInt(start), 8);
  bounds.writeBigUInt64BE(BigInt(end), 16);
  return Buffer.concat([LABEL, Buffer.from([signer.length]), signer,
    bounds.subarray(0, 8), Buffer.from([log.length]), log,
    bounds.subarray(8), root]);
}

function rawMtcCertificateCandidate(certificateDer, admitted) {
  const x509 = certificate(certificateDer);
  const cert = certificateParts(certificateDer, admitted.caId);
  if (cert.serial < admitted.minSerial || cert.serial > admitted.maxSerial ||
      admitted.revokedRanges.some(({start, end}) => start <= cert.serial && cert.serial < end))
    fail('MTC_SERIAL');
  const logNumber = cert.serial >> 48n;
  if (logNumber === 0n) fail('MTC_SERIAL');
  const logId = deriveMtcLogId(admitted.caId, Number(logNumber));
  const index = Number(cert.serial & ((1n << 48n) - 1n));
  const parsed = proof(cert.signature);
  const entry = Buffer.concat([parsed.extensions, Buffer.from([0, 1]),
    cert.logEntryContents]);
  if (entry.length > 65535) fail('MTC_LOG_ENTRY');
  const leaf = hash(Buffer.from([0]), entry);
  const root = evaluateMtcSubtreeProof(leaf, index, parsed.start,
    parsed.end, parsed.path);
  return {logNumber: Number(logNumber), logId, index, parsed, root,
    certificateNotAfter: x509.validUntil};
}

// This helper returns untrusted inputs to the relative-provenance verifier.
// A candidate root never establishes CA certification by itself.
export function parseRawMtcCertificateCandidate({certificateDer, policy}) {
  if (!Buffer.isBuffer(certificateDer)) fail('MTC_INPUT');
  const admitted = admittedPolicy(policy, 'relative');
  const certificateSha256 = hash(certificateDer).toString('hex');
  return {admitted, certificateSha256,
    ...rawMtcCertificateCandidate(certificateDer, admitted)};
}

export function assessRawMtcIssuance({certificateDer, policy}) {
  if (!Buffer.isBuffer(certificateDer)) fail('MTC_INPUT');
  const admitted = admittedPolicy(policy);
  const certificateSha256 = hash(certificateDer).toString('hex');
  try {
    const {logNumber, logId, index, parsed, root} =
      rawMtcCertificateCandidate(certificateDer, admitted);
    const roles = new Set();
    for (const signature of parsed.signatures) {
      const cosigner = admitted.cosigners.get(signature.id.toString('hex'));
      if (!cosigner) continue;
      const message = cosignedSubtree(cosigner.name,
        logId.origin, parsed.start, parsed.end, root);
      if (verify(null, message, cosigner.key, signature.value))
        roles.add(cosigner.role);
    }
    if (!admitted.requiredRoles.every(role => roles.has(role)))
      fail('MTC_COSIGNER_QUORUM');
    return {decision: 'ISSUANCE_PROVEN', reason: null, certificateSha256,
      logNumber, index, start: parsed.start, end: parsed.end,
      subtreeSha256: root.toString('hex'), admittedRoles: [...roles].sort()};
  } catch (error) {
    if (!(error instanceof DerError)) throw error;
    return {decision: error.code.endsWith('_UNSUPPORTED') ? 'UNSUPPORTED' : 'REJECTED',
      reason: error.code, certificateSha256};
  }
}

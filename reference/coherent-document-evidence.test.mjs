import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash, verify, X509Certificate} from 'node:crypto';
import {readFileSync} from 'node:fs';
import {assessRawMtcIssuance} from './raw-mtc-issuance.mjs';
import {assessRawMtcStatus} from './raw-status.mjs';
import {assessRawAuthorityHistory} from './raw-authority-history.mjs';
import {assessRawTimestamp} from './raw-timestamp.mjs';
import {assessRawErs} from './raw-ers.mjs';
import {assessRawPublicationWitness} from './raw-publication-witness.mjs';
import {assessRawRetirementClosure} from './raw-retirement-closure.mjs';
import {children, one, raw} from './der.mjs';

const corpus = JSON.parse(readFileSync(new URL(
  '../vectors/coherent-document-evidence.json', import.meta.url)));
const {original_core: core, authority, timestamp, ers,
  retirement} = corpus;
const sha = bytes => createHash('sha256').update(bytes).digest('hex');
const frozen = (item, encoded = 'base64') => {
  const bytes = Buffer.from(item[encoded], 'base64');
  if (item.bytes !== undefined) assert.equal(bytes.length, item.bytes);
  assert.equal(sha(bytes), item.sha256);
  return bytes;
};
const coreBytes = id => frozen(core.objects[id],
  core.objects[id].derBase64 === undefined ? 'base64' : 'derBase64');
const stampBytes = id => frozen(timestamp.objects[id], 'derBase64');
const signed = item => ({raw: Buffer.from(item.rawBase64, 'base64'),
  signature: Buffer.from(item.signatureBase64, 'base64')});
const authorityBytes = id => {
  const item = authority.objects[id];
  const raw = Buffer.from(item.rawBase64, 'base64');
  const signature = Buffer.from(item.signatureBase64, 'base64');
  assert.equal(sha(raw), item.rawSha256);
  assert.equal(sha(signature), item.signatureSha256);
  return Buffer.concat([raw, signature]);
};
const document = coreBytes('document');
const signature = coreBytes('signature');
const target = coreBytes('target');
const ca = coreBytes('ca');
const signerKey = new X509Certificate(target).publicKey;

test('frozen original identities connect every source without a retained signing key', () => {
  assert.equal(corpus.format, 'original-coherent-document-evidence-v1');
  assert.equal(corpus.cases.length, 26);
  assert.equal(sha(document), authority.documentSha256);
  assert.equal(sha(document), retirement.originals.document.sha256);
  assert.equal(sha(signature), timestamp.coveredSignatureSha256);
  assert.equal(sha(signature), retirement.originals['document-signature'].sha256);
  assert.equal(sha(target), retirement.originals['mtc-certificate'].sha256);
  assert.equal(sha(ca), retirement.originals['mtc-ca-representation'].sha256);
  assert.equal(sha(coreBytes('superior')),
    retirement.originals['mtc-superior'].sha256);
  assert.equal(sha(coreBytes('ocsp')), retirement.originals['historical-status'].sha256);
  assert.equal(sha(coreBytes('crl')), retirement.originals['historical-crl'].sha256);
  assert.equal(sha(frozen(ers.objects.document.evidence)),
    retirement.originals['preservation-document'].sha256);
  assert.equal(sha(frozen(ers.objects.signature.evidence)),
    retirement.originals['preservation-signature'].sha256);
  assert.equal(sha(stampBytes('response')),
    retirement.originals['signature-timestamp-response'].sha256);
  assert.equal(sha(stampBytes('request')),
    retirement.originals['signature-timestamp-request'].sha256);
  assert.equal(sha(stampBytes('tsa')),
    retirement.originals['timestamp-tsa'].sha256);
  assert.equal(sha(stampBytes('issuer')),
    retirement.originals['timestamp-issuer'].sha256);
  assert(Buffer.concat(['issuer-allow', 'issuer-seal', 'action-allow',
    'action-seal'].map(authorityBytes)).equals(
    frozen(retirement.originals['authority-history'])));
  assert.equal(ers.objects.document.request.sha256,
    retirement.originals['document-timestamp-request'].sha256);
  assert.equal(ers.objects.document.response.sha256,
    retirement.originals['document-timestamp-response'].sha256);
  assert.equal(sha(signerKey.export({format: 'der', type: 'spki'})),
    authority.signerSpkiSha256);
  const issuance = assessRawMtcIssuance({certificateDer: target,
    policy: core.mtcPolicy});
  assert.equal(issuance.decision, 'ISSUANCE_PROVEN');
  const issuerRequirement = authority.policy.requirements.find(item =>
    item.role === 'issuer-authorization');
  const actionRequirement = authority.policy.requirements.find(item =>
    item.role === 'document-action');
  assert.equal(issuerRequirement.subjectId,
    `mtc-ca:${core.mtcPolicy.caIdHex}`);
  assert.equal(issuerRequirement.scope,
    `ca:${core.mtcPolicy.caIdHex}/log:${issuance.logNumber}`);
  assert.equal(retirement.policy.issuerId, issuerRequirement.subjectId);
  assert.equal(actionRequirement.subjectId,
    `signer-spki:${sha(signerKey.export({format: 'der', type: 'spki'}))}`);
  assert.equal(actionRequirement.scope, `sha256:${sha(document)}`);
  assert.equal(new X509Certificate(ca).publicKey.export({
    format: 'der', type: 'spki'}).toString('base64'),
  core.mtcPolicy.cosigners.find(item => item.role === 'ca').publicKeySpkiBase64);
  assert(new X509Certificate(ca).verify(
    new X509Certificate(coreBytes('superior')).publicKey));
  assert.equal(authority.stateAt, core.status.stateAt);
  assert.equal(authority.knownAt, core.status.knownAt);
  assert.equal(retirement.publication.entryIds.length, 4);
  assert(!retirement.publication.entryIds.includes('action-deny'));
  assert.equal(retirement.unsubmittedSameSecondDeny.sha256,
    sha(authorityBytes('action-deny')));
});

function directStatus(kind) {
  const record = kind.toLowerCase();
  const result = assessRawMtcStatus({kind,
    recordDer: coreBytes(record), targetDer: target, issuerDer: ca,
    stateAt: core.status.stateAt, knownAt: core.status.knownAt,
    mtcPolicy: core.mtcPolicy,
    policy: {issuerSha256: core.status.issuerSha256,
      sourceId: core.status.sourceId,
      crlDistributionPoint: core.status.crlDistributionPoint,
      compromiseMode: 'use-invalidity-date'},
    admittedReceipt: {recordSha256: core.status[`${record}Sha256`],
      observedAt: core.status.receiptAt,
      sourceId: core.status.sourceId}});
  assert.equal(result.targetSerial, '01000000000000');
  assert(!Object.hasOwn(result, 'documentValidity'));
  return result.decision;
}
function authorityResult(id) {
  const vector = authority.cases.find(item => item.id === id);
  assert(vector, id);
  const result = assessRawAuthorityHistory({stateAt: authority.stateAt,
    knownAt: authority.knownAt, policy: authority.policy, document,
    records: vector.records.map(record => authority.objects[record])});
  assert.equal(result.reasons[0]?.code ?? null, vector.reason ?? null);
  return result.decision;
}
function timestampResult(coveredDer) {
  const result = assessRawTimestamp({responseDer: stampBytes('response'),
    requestDer: stampBytes('request'), tsaDer: stampBytes('tsa'),
    issuerDer: stampBytes('issuer'), policy: timestamp.policy,
    coveredDer});
  if (result.decision === 'SIGNED_CLAIM') {
    assert.equal(result.coveredSha256, sha(signature));
    assert(BigInt(result.claimedUpperBoundMicros) <
      BigInt(core.status.stateAt) * 1000000n);
  } else assert.deepEqual(result.reasons, ['TIMESTAMP_IMPRINT_MISMATCH']);
  return result.decision;
}
function ersAssessment(id, source) {
  const item = ers.objects[id];
  const result = assessRawErs({evidenceDer: frozen(item.evidence),
    objectDer: source,
    timestampEvidence: [[{requestDer: frozen(item.request),
      tsaDer: stampBytes('tsa'), issuerDer: stampBytes('issuer'),
      policy: ers.policy}]]});
  if (result.decision === 'BOUND_CLAIMS') {
    assert.equal(result.observations.length, 1);
    assert.equal(result.observations[0].tokenSha256, item.token.sha256);
    assert(BigInt(result.observations[0].claimedUpperBoundMicros) <
      BigInt(core.status.stateAt) * 1000000n);
  } else assert.deepEqual(result.reasons, ['TIMESTAMP_IMPRINT_MISMATCH']);
  return result;
}
const ersResult = (id, source) => ersAssessment(id, source).decision;
function documentTimestampResult(request, response, expectedReason = null) {
  const responseDer = frozen(response);
  const result = assessRawTimestamp({responseDer,
    requestDer: frozen(request), coveredDer: document,
    tsaDer: stampBytes('tsa'), issuerDer: stampBytes('issuer'),
    policy: ers.policy});
  if (expectedReason !== null) {
    assert.deepEqual(result.reasons, [expectedReason]);
  } else {
    assert.equal(result.decision, 'SIGNED_CLAIM');
    assert.equal(result.recordSha256, sha(responseDer));
    assert.equal(result.coveredSha256, sha(document));
    const observation = ersAssessment('document', document);
    assert.equal(observation.decision, 'BOUND_CLAIMS');
    const token = raw(children(one(responseDer, 0x30))[1]);
    assert.equal(sha(token), observation.observations[0].tokenSha256);
  }
  return result.decision;
}
const publication = {entries: retirement.publication.entryIds.map(authorityBytes),
  head: signed(retirement.publication.head),
  monitor: signed(retirement.publication.monitor),
  proof: frozen(retirement.publication.proof)};
function witnessResult() {
  for (let i = 0; i < publication.entries.length; i++)
    assert(publication.entries[i].equals(frozen(retirement.publication.entries[i])));
  const result = assessRawPublicationWitness({
    policy: retirement.policy.publicationPolicy, ...publication,
    anchor: retirement.policy.publicationAnchor,
    knownAt: retirement.checkAt});
  assert.equal(result.treeSize, 4);
  assert.equal(result.headSha256, retirement.publication.head.rawSha256);
  return result.decision;
}
const manifest = signed(retirement.manifest);
const manifestItems = JSON.parse(manifest.raw.toString('utf8')).items;
const originals = {...Object.fromEntries(Object.entries(retirement.originals)
  .map(([id, item]) => [id, frozen(item)])),
  'publication-head': Buffer.concat([publication.head.raw,
    publication.head.signature]),
  'monitor-observation': Buffer.concat([publication.monitor.raw,
    publication.monitor.signature]),
  'consistency-proof': publication.proof,
  ...Object.fromEntries(publication.entries.map((value, index) =>
    [`log-entry:${index}`, value]))};
function retirementResult(id, changes = {}) {
  const retrieved = manifestItems.map(item => ({id: item.id,
    bytes: originals[item.id],
    receipt: signed(retirement.receipts[item.id])}));
  assert.equal(retrieved.length, 23);
  if (id) Object.assign(retrieved.find(item => item.id === id), changes);
  const result = assessRawRetirementClosure({policy: retirement.policy,
    publication, manifest, retrieved, checkAt: retirement.checkAt});
  assert.equal(result.publication, 'MONITORED_STREAM_THROUGH');
  assert(!Object.hasOwn(result, 'documentValid'));
  return result;
}

const cases = {
  'coherent-document-signature': () => verify(null, document, signerKey,
    signature) ? 'SIGNATURE_VERIFIED' : 'REJECTED',
  'coherent-wrong-key-signature': () => verify(null, document, signerKey,
    coreBytes('wrongKeySignature')) ? 'SIGNATURE_VERIFIED' : 'REJECTED',
  'coherent-changed-document': () => {
    const changed = Buffer.from(document); changed[0] ^= 1;
    return verify(null, changed, signerKey, signature) ?
      'SIGNATURE_VERIFIED' : 'REJECTED';
  },
  'coherent-mtc-issuance': () => assessRawMtcIssuance({certificateDer: target,
    policy: core.mtcPolicy}).decision,
  'coherent-direct-ocsp': () => directStatus('OCSP'),
  'coherent-direct-crl': () => directStatus('CRL'),
  'coherent-authority-allow': () => authorityResult('coherent-authority-allow'),
  'coherent-authority-same-second-deny': () =>
    authorityResult('coherent-authority-deny-same-second'),
  'coherent-authority-other-document': () =>
    authorityResult('coherent-authority-other-document'),
  'coherent-authority-missing-seal': () =>
    authorityResult('coherent-authority-missing-action-seal'),
  'coherent-timestamp-signature': () => timestampResult(signature),
  'coherent-timestamp-other-signature': () =>
    timestampResult(coreBytes('wrongKeySignature')),
  'coherent-document-timestamp': () => documentTimestampResult(
    ers.objects.document.request, ers.objects.document.response),
  'coherent-document-timestamp-signature-request': () => documentTimestampResult(
    ers.objects.signature.request, ers.objects.document.response,
    'TIMESTAMP_REQUEST_IMPRINT_MISMATCH'),
  'coherent-document-timestamp-signature-response': () => documentTimestampResult(
    ers.objects.document.request, ers.objects.signature.response,
    'TIMESTAMP_IMPRINT_MISMATCH'),
  'coherent-ers-document': () => ersResult('document', document),
  'coherent-ers-signature': () => ersResult('signature', signature),
  'coherent-ers-cross-object': () => ersResult('signature', document),
  'coherent-four-entry-monitor': witnessResult,
  'coherent-retirement-all-originals': () => {
    const result = retirementResult();
    assert.equal(result.itemCount, 23);
    return result.decision;
  },
  'coherent-retirement-status-missing': () => {
    const result = retirementResult('historical-status', {bytes: null});
    assert(result.reasons.some(item => item.id === 'historical-status' &&
      item.code === 'RETIREMENT_BYTES_MISSING'));
    return result.decision;
  },
  'coherent-retirement-receipt-missing': () => {
    const result = retirementResult('preservation-document', {receipt: null});
    assert(result.reasons.some(item => item.id === 'preservation-document' &&
      item.code === 'RETIREMENT_RECEIPT_MISSING'));
    return result.decision;
  },
  'coherent-retirement-certificate-changed': () => {
    const changed = Buffer.from(originals['mtc-certificate']); changed[0] ^= 1;
    const result = retirementResult('mtc-certificate', {bytes: changed});
    assert(result.reasons.some(item => item.id === 'mtc-certificate' &&
      item.code === 'RETIREMENT_BYTES_MISMATCH'));
    return result.decision;
  },
  'coherent-retirement-authority-changed': () => {
    const changed = Buffer.from(originals['authority-history']); changed[0] ^= 1;
    const result = retirementResult('authority-history', {bytes: changed});
    assert(result.reasons.some(item => item.id === 'authority-history' &&
      item.code === 'RETIREMENT_BYTES_MISMATCH'));
    return result.decision;
  },
  'coherent-unsubmitted-deny': () => {
    assert(!retirement.publication.entryIds.includes('action-deny'));
    return authorityResult('coherent-authority-deny-same-second');
  },
  'coherent-retirement-false-receipt': () => {
    try { retirementResult('historical-status', {receipt: false}); }
    catch (error) { return error.code; }
    return 'UNEXPECTED_SUCCESS';
  }
};
assert.deepEqual(Object.keys(cases), corpus.cases.map(item => item.id));
for (const vector of corpus.cases)
  test(vector.id, () => assert.equal(cases[vector.id](), vector.expected));

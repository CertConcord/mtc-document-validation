import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash, X509Certificate} from 'node:crypto';
import {readFileSync} from 'node:fs';
import {assessRawMtcStatus, assessRawStatus} from './raw-status.mjs';
import {certificate} from './cert-der.mjs';
import {parseCrl} from './crl-der.mjs';

const corpus = JSON.parse(readFileSync(new URL('../vectors/raw-mtc-status-der.json', import.meta.url)));
const vectors = JSON.parse(readFileSync(new URL('../vectors/raw-mtc-status-cases.json', import.meta.url)));
const bytes = id => Buffer.from(corpus.objects[id].derBase64, 'base64');
const hash = value => createHash('sha256').update(value).digest('hex');

function input(item) {
  const defaults = vectors.defaults;
  const issuer = item.issuer ?? defaults.issuer;
  return {kind: item.kind, recordDer: bytes(item.record),
    targetDer: bytes(item.target ?? defaults.target), issuerDer: bytes(issuer),
    responderDer: item.responder ? bytes(item.responder) : undefined,
    stateAt: item.stateAt ?? defaults.stateAt,
    knownAt: item.knownAt ?? defaults.knownAt,
    policy: {issuerSha256: corpus.objects[issuer].sha256,
      sourceId: defaults.sourceId,
      crlDistributionPoint: item.crlDistributionPoint ?? defaults.crlDistributionPoint,
      compromiseMode: defaults.compromiseMode},
    mtcPolicy: item.fixture === 'chronological'
      ? corpus.supplementalMtcPolicy : corpus.mtcPolicy,
    admittedReceipt: item.receipt === false ? undefined :
      {recordSha256: corpus.objects[item.receiptRecord ?? item.record].sha256,
        observedAt: item.receiptAt ?? defaults.receiptAt,
        sourceId: defaults.sourceId}};
}

test('original MTC target, CA representation and status DER are pinned', () => {
  assert.equal(corpus.format, 'original-mtc07-status-der-v1');
  assert.equal(Object.keys(corpus.objects).length, 28);
  for (const [id, item] of Object.entries(corpus.objects)) {
    const original = bytes(id);
    assert.equal(original.length, item.bytes, id);
    assert.equal(hash(original), item.sha256, id);
  }
  const superior = new X509Certificate(bytes('superior'));
  const ca = new X509Certificate(bytes('mtc-ca'));
  assert.ok(ca.verify(superior.publicKey));
  assert.notDeepEqual(ca.publicKey.export({format: 'der', type: 'spki'}),
    superior.publicKey.export({format: 'der', type: 'spki'}));
  assert.equal(ca.publicKey.export({format: 'der', type: 'spki'}).toString('base64'),
    corpus.mtcPolicy.cosigners[0].publicKeySpkiBase64);
  const chronologicalSuperior = new X509Certificate(bytes('chronological-superior'));
  const chronologicalCa = new X509Certificate(bytes('chronological-ca'));
  assert.ok(chronologicalCa.verify(chronologicalSuperior.publicKey));
  assert.equal(chronologicalCa.publicKey.export({format: 'der', type: 'spki'})
    .toString('base64'), corpus.supplementalMtcPolicy.cosigners[0].publicKeySpkiBase64);
  const prior = parseCrl({recordDer: bytes('crl-revoked'),
    target: certificate(bytes('mtc-target')),
    issuer: certificate(bytes('mtc-ca')), directMtcCa: true});
  const corrected = parseCrl({recordDer: bytes('chronological-crl'),
    target: certificate(bytes('chronological-target')),
    issuer: certificate(bytes('chronological-ca')), directMtcCa: true});
  assert(prior.revocationTime > prior.thisUpdate);
  assert.equal(prior.hasFutureRevocation, true);
  assert.equal(corrected.revocationTime, corrected.thisUpdate);
  assert.equal(corrected.hasFutureRevocation, false);
});

test('MTC proof and direct CA status edges use the same original target', async t => {
  assert.equal(vectors.format, 'original-mtc07-status-cases-v1');
  for (const item of vectors.cases) await t.test(item.id, () => {
    const actual = assessRawMtcStatus(input(item));
    assert.equal(actual.decision, item.expected, item.id);
    assert.deepEqual(actual.reasons, item.reason ? [item.reason] : [], item.id);
    assert.equal(actual.recordSha256, corpus.objects[item.record].sha256, item.id);
    for (const forbidden of ['VALID', 'historyComplete', 'knowledgeThrough'])
      assert.ok(!Object.hasOwn(actual, forbidden), `${item.id}: ${forbidden}`);
  });
});

test('ordinary certificate-signature admission cannot replace an MTC proof', () => {
  const original = input(vectors.cases[0]);
  const ordinary = assessRawStatus(original);
  assert.equal(ordinary.decision, 'REJECTED');
  assert.deepEqual(ordinary.reasons, ['TARGET_ISSUER_MISMATCH']);
});

import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {readFileSync} from 'node:fs';
import {assessRawStatus} from './raw-status.mjs';
import {certificate} from './cert-der.mjs';
import {parseCrl} from './crl-der.mjs';

const corpus = JSON.parse(readFileSync(new URL('../vectors/raw-status-der.json', import.meta.url), 'utf8'));
const vectors = JSON.parse(readFileSync(new URL('../vectors/raw-status-cases.json', import.meta.url), 'utf8'));
const object = id => {
  assert.ok(Object.hasOwn(corpus.objects, id), id);
  return Buffer.from(corpus.objects[id].derBase64, 'base64');
};
const sha256 = bytes => createHash('sha256').update(bytes).digest('hex');

test('frozen original DER has the recorded byte count and SHA-256', () => {
  assert.equal(corpus.format, 'frozen-der-status-corpus-v1');
  assert.ok(Object.keys(corpus.objects).length >= 16);
  for (const [id, item] of Object.entries(corpus.objects)) {
    const bytes = object(id);
    assert.equal(bytes.length, item.bytes, id);
    assert.equal(sha256(bytes), item.sha256, id);
  }
});

test('signed CRL equality and future-date controls bind the same target', () => {
  const target = certificate(object('leaf'));
  const issuer = certificate(object('ca'));
  const equal = parseCrl({recordDer: object('crl-revoked'), target, issuer});
  const future = parseCrl({recordDer: object('crl-revocation-after-issue'),
    target, issuer});
  assert.equal(equal.targetSerial, future.targetSerial);
  assert.equal(equal.thisUpdate, future.thisUpdate);
  assert.equal(equal.revocationTime, equal.thisUpdate);
  assert(future.revocationTime > future.thisUpdate);
  assert(future.revocationTime < future.nextUpdate);
});

test('original DER status observations and adversarial pairings', async t => {
  assert.equal(vectors.format, 'original-der-status-observation-cases-v1');
  const defaults = vectors.defaults;
  for (const vector of vectors.cases) {
    await t.test(vector.id, () => {
    const record = object(vector.record);
    const recordDer = vector.truncate ? record.subarray(0, record.length - vector.truncate) : record;
    const issuer = vector.issuer ?? defaults.issuer;
    const input = {
      kind: vector.kind,
      recordDer,
      targetDer: object(vector.target ?? defaults.target),
      issuerDer: object(issuer),
      responderDer: vector.responder ? object(vector.responder) : undefined,
      requestDer: vector.request ? object(vector.request) : undefined,
      stateAt: vector.stateAt ?? defaults.stateAt,
      knownAt: vector.knownAt ?? defaults.knownAt,
      policy: {
        issuerSha256: corpus.objects[vector.policyIssuer ?? defaults.issuer].sha256,
        sourceId: defaults.sourceId,
        crlDistributionPoint: vector.crlDistributionPoint ?? defaults.crlDistributionPoint,
        compromiseMode: vector.compromiseMode ?? defaults.compromiseMode
      },
      admittedReceipt: vector.receipt === false ? undefined : {
        recordSha256: corpus.objects[vector.receiptRecord ?? vector.record].sha256,
        observedAt: vector.receiptAt ?? defaults.receiptAt,
        sourceId: vector.receiptSource ?? defaults.sourceId
      }
    };
    const actual = assessRawStatus(input);
    assert.equal(actual.decision, vector.expected, vector.id);
    assert.deepEqual(actual.reasons, vector.reason ? [vector.reason] : [], vector.id);
    assert.equal(actual.recordSha256, sha256(recordDer), vector.id);
    if (vector.effectiveRevocationAt !== undefined)
      assert.equal(actual.effectiveRevocationAt, vector.effectiveRevocationAt, vector.id);
    for (const forbidden of ['knowledgeThrough', 'ALLOW', 'documentValidity'])
      assert.ok(!Object.hasOwn(actual, forbidden), `${vector.id}: ${forbidden}`);
    });
  }
});

test('malformed caller policy and receipt are explicit input errors', () => {
  const base = {
    kind: 'OCSP', recordDer: object('good-ca'), targetDer: object('leaf'),
    issuerDer: object('ca'), requestDer: object('request-nonce'),
    stateAt: 1795815600, knownAt: 1795815600,
    policy: {issuerSha256: corpus.objects.ca.sha256, sourceId: 'admitted-archive',
      compromiseMode: 'use-invalidity-date'},
    admittedReceipt: {recordSha256: corpus.objects['good-ca'].sha256,
      observedAt: 1795729180, sourceId: 'admitted-archive'}
  };
  assert.throws(() => assessRawStatus({...base, knownAt: base.stateAt - 1}),
    {code: 'RAW_STATUS_INPUT'});
  assert.throws(() => assessRawStatus({...base, policy: {...base.policy,
    issuerSha256: 'unadmitted'}}), {code: 'RAW_STATUS_INPUT'});
  assert.throws(() => assessRawStatus({...base, admittedReceipt: {...base.admittedReceipt,
    observedAt: -1}}), {code: 'RAW_STATUS_RECEIPT'});
});

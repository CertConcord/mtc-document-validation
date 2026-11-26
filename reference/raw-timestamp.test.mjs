import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {readFileSync} from 'node:fs';
import {assessRawTimestamp} from './raw-timestamp.mjs';

const corpus = JSON.parse(readFileSync(new URL('../vectors/raw-timestamp-der.json', import.meta.url)));
const vectors = JSON.parse(readFileSync(new URL('../vectors/raw-timestamp-cases.json', import.meta.url)));
const object = id => {
  assert.ok(Object.hasOwn(corpus.objects, id), id);
  return Buffer.from(corpus.objects[id].base64, 'base64');
};
const sha256 = bytes => createHash('sha256').update(bytes).digest('hex');

test('original timestamp bytes match frozen counts and SHA-256', () => {
  assert.equal(corpus.format, 'frozen-rfc3161-der-corpus-v1');
  assert.equal(Object.keys(corpus.objects).length, 41);
  for (const [id, item] of Object.entries(corpus.objects)) {
    const bytes = object(id);
    assert.equal(bytes.length, item.bytes, id);
    assert.equal(sha256(bytes), item.sha256, id);
  }
});

test('signed RFC 3161 claims and original adversarial pairings', async t => {
  assert.equal(vectors.format, 'original-der-timestamp-observation-cases-v1');
  for (const vector of vectors.cases) {
    await t.test(vector.id, () => {
      const defaults = vectors.defaults;
      const response = object(vector.response ?? defaults.response);
      const responseDer = vector.truncate ? response.subarray(0, response.length - vector.truncate) : response;
      const tsa = vector.tsa ?? defaults.tsa;
      const issuer = vector.issuer ?? defaults.issuer;
      const actual = assessRawTimestamp({
        responseDer,
        requestDer: vector.request === null ? undefined : object(vector.request ?? defaults.request),
        coveredDer: object(vector.covered ?? defaults.covered),
        tsaDer: object(tsa), issuerDer: object(issuer),
        policy: {tsaSha256: corpus.objects[vector.policyTsa ?? tsa].sha256,
          issuerSha256: corpus.objects[vector.policyIssuer ?? issuer].sha256,
          policyOid: vector.policyOid ?? defaults.policyOid,
          maxAccuracyMicros: vector.maxAccuracyMicros ?? defaults.maxAccuracyMicros}
      });
      assert.equal(actual.decision, vector.expected, vector.id);
      assert.deepEqual(actual.reasons, vector.reason ? [vector.reason] : [], vector.id);
      assert.equal(actual.recordSha256, sha256(responseDer), vector.id);
      for (const forbidden of ['poeUpperBound', 'knowledgeThrough', 'documentValidity', 'VALID'])
        assert.ok(!Object.hasOwn(actual, forbidden), `${vector.id}: ${forbidden}`);
      if (actual.decision === 'SIGNED_CLAIM') {
        assert.equal(actual.coveredSha256, sha256(object(vector.covered ?? defaults.covered)));
        assert.equal(actual.accuracyMicros, 1_500_000, vector.id);
        assert.equal(BigInt(actual.claimedUpperBoundMicros),
          BigInt(actual.genTimeMicros) + 1_500_000n, vector.id);
        if (vector.genTimeFraction !== undefined)
          assert.equal(actual.genTime % 1, vector.genTimeFraction, vector.id);
        if (vector.genTimeFraction !== undefined)
          assert.equal(BigInt(actual.genTimeMicros) % 1_000_000n, 500_000n, vector.id);
      }
    });
  }
});

test('caller trust and accuracy inputs are explicit', () => {
  const base = {responseDer: object('response'), requestDer: object('request'),
    coveredDer: object('document'), tsaDer: object('tsa'), issuerDer: object('tsa-ca'),
    policy: {tsaSha256: corpus.objects.tsa.sha256,
      issuerSha256: corpus.objects['tsa-ca'].sha256,
      policyOid: vectors.defaults.policyOid, maxAccuracyMicros: 2_000_000}};
  assert.throws(() => assessRawTimestamp({...base, policy: {...base.policy,
    issuerSha256: 'self-appointed'}}), {code: 'TIMESTAMP_INPUT'});
  assert.throws(() => assessRawTimestamp({...base, policy: {...base.policy,
    maxAccuracyMicros: -1}}), {code: 'TIMESTAMP_INPUT'});
  assert.throws(() => assessRawTimestamp({...base, coveredDer: 'not original bytes'}),
    {code: 'TIMESTAMP_INPUT'});
});

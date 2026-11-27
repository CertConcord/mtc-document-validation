import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {readFileSync} from 'node:fs';
import {children, one, raw} from './der.mjs';
import {assessRawErs} from './raw-ers.mjs';
import {assessRawTimestampToken} from './raw-timestamp.mjs';

const corpus = JSON.parse(readFileSync(new URL('../vectors/raw-ers-der.json', import.meta.url)));
const vectors = JSON.parse(readFileSync(new URL('../vectors/raw-ers-cases.json', import.meta.url)));
const bytes = id => {
  assert.ok(Object.hasOwn(corpus.objects, id), id);
  return Buffer.from(corpus.objects[id].base64, 'base64');
};
const sha256 = value => createHash('sha256').update(value).digest('hex');
const policy = vector => ({
  tsaSha256: corpus.objects[vector.policyTsa ?? vectors.defaults.tsa].sha256,
  issuerSha256: corpus.objects[vector.policyIssuer ?? vectors.defaults.issuer].sha256,
  policyOid: vector.policyOid ?? vectors.defaults.policyOid,
  maxAccuracyMicros: vector.maxAccuracyMicros ?? vectors.defaults.maxAccuracyMicros
});
const requestSet = vector => vectors.requestSets[vector.requestSet];
const supplied = (vector, requestId) => {
  const tsaId = Object.hasOwn(vector, 'tsa') ? vector.tsa : vectors.defaults.tsa;
  const issuerId = Object.hasOwn(vector, 'issuer') ? vector.issuer : vectors.defaults.issuer;
  return {requestDer: requestId === null ? undefined : bytes(requestId),
    tsaDer: tsaId === null ? undefined : bytes(tsaId),
    issuerDer: issuerId === null ? undefined : bytes(issuerId),
    policy: policy(vector)};
};
const embeddedToken = (recordDer, chain, index) => {
  const fields = children(one(recordDer, 0x30));
  const chains = children(fields.at(-1));
  const stamps = children(chains[chain]);
  return raw(children(stamps[index]).at(-1));
};

test('original ERS bytes match frozen counts and SHA-256', () => {
  assert.equal(corpus.format, 'frozen-rfc4998-original-der-corpus-v1');
  assert.equal(Object.keys(corpus.objects).length, 58);
  for (const [id, item] of Object.entries(corpus.objects)) {
    const original = bytes(id);
    assert.equal(original.length, item.bytes, id);
    assert.equal(sha256(original), item.sha256, id);
  }
});

test('original ERS binding, renewal and signed adversarial pairings', async t => {
  assert.equal(vectors.format, 'original-rfc4998-one-object-cases-v1');
  assert.equal(vectors.cases.length, 35);
  for (const vector of vectors.cases) {
    await t.test(vector.id, () => {
      const recordDer = bytes(vector.record);
      const requests = requestSet(vector);
      assert.ok(Array.isArray(requests), vector.id);
      const timestampEvidence = requests.map(row => row.map(id => supplied(vector, id)));
      const actual = assessRawErs({evidenceDer: recordDer,
        objectDer: bytes(vector.object ?? vectors.defaults.object), timestampEvidence});
      assert.equal(actual.decision, vector.expected, vector.id);
      assert.deepEqual(actual.reasons, vector.reason ? [vector.reason] : [], vector.id);
      assert.equal(actual.evidenceSha256, sha256(recordDer), vector.id);
      for (const forbidden of ['VALID', 'poeUpperBound', 'documentValidity', 'groupExclusive'])
        assert.ok(!Object.hasOwn(actual, forbidden), `${vector.id}: ${forbidden}`);
      if (actual.decision === 'BOUND_CLAIMS') {
        assert.equal(actual.observations.length, vector.observationCount, vector.id);
        assert.ok(actual.observations.every((observation, i, all) =>
          i === 0 || BigInt(all[i - 1].genTimeMicros) <=
            BigInt(observation.genTimeMicros)), vector.id);
        assert.ok(actual.observations.every(observation =>
          observation.requestBinding === (vector.requestBinding ?? 'CHECKED')), vector.id);
      }
      if (vector.signedControl) {
        const {chain, index, preimage} = vector.signedControl;
        const tokenDer = embeddedToken(recordDer, chain, index);
        const control = assessRawTimestampToken({tokenDer,
          coveredDer: bytes(preimage),
          ...supplied(vector, requests[chain][index])});
        assert.equal(control.decision, 'SIGNED_CLAIM',
          `${vector.id}: intentionally wrong input has a valid signed token`);
        assert.equal(control.tokenSha256, sha256(tokenDer), vector.id);
      }
    });
  }
});

test('ERS caller must supply original buffers and timestamp inputs', () => {
  assert.throws(() => assessRawErs({evidenceDer: 'not DER',
    objectDer: bytes('document'), timestampEvidence: []}), {code: 'ERS_INPUT'});
  assert.throws(() => assessRawErs({evidenceDer: bytes('ers-initial'),
    objectDer: bytes('document'), timestampEvidence: 'missing'}), {code: 'ERS_INPUT'});
});

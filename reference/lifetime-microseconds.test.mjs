import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {readFileSync} from 'node:fs';
import {assessRawErs} from './raw-ers.mjs';
import {assessRawTimestamp} from './raw-timestamp.mjs';
import {assertPreservationLifetimesMicros} from './lifetimes.mjs';

const load = name => JSON.parse(readFileSync(new URL(`../vectors/${name}`, import.meta.url)));
const frozen = load('lifetime-microseconds.json');
const corpus = load('raw-ers-der.json');
const rawCases = load('raw-ers-cases.json');
const timestampCorpus = load('raw-timestamp-der.json');
const timestampCases = load('raw-timestamp-cases.json');
const catalog = JSON.parse(readFileSync(new URL('../cases.json', import.meta.url)));
const bytes = id => Buffer.from(corpus.objects[id].base64, 'base64');
const sha256 = value => createHash('sha256').update(value).digest('hex');

test('original signed ERS claims anchor the exact microsecond vectors', () => {
  assert.equal(frozen.format, 'original-rfc3161-ers-preservation-microseconds-v1');
  for (const source of Object.values(frozen.sources)) {
    const raw = rawCases.cases.find(item => item.id === source.rawCase);
    assert(raw && raw.expected === 'BOUND_CLAIMS');
    const record = bytes(raw.record);
    assert.equal(sha256(record), source.recordSha256);
    const policy = {tsaSha256: corpus.objects[rawCases.defaults.tsa].sha256,
      issuerSha256: corpus.objects[rawCases.defaults.issuer].sha256,
      policyOid: rawCases.defaults.policyOid,
      maxAccuracyMicros: rawCases.defaults.maxAccuracyMicros};
    const timestampEvidence = rawCases.requestSets[raw.requestSet].map(row =>
      row.map(id => ({requestDer: bytes(id),
        tsaDer: bytes(rawCases.defaults.tsa),
        issuerDer: bytes(rawCases.defaults.issuer), policy})));
    const bound = assessRawErs({evidenceDer: record,
      objectDer: bytes(rawCases.defaults.object), timestampEvidence});
    assert.equal(bound.decision, 'BOUND_CLAIMS');
    assert.equal(bound.evidenceSha256, source.recordSha256);
    assert.equal(bound.observations.length, source.records.length);
    for (let i = 0; i < source.records.length; i++) {
      const signed = bound.observations[i], admitted = source.records[i];
      assert.equal(signed.chain, admitted.chain);
      assert.equal(signed.genTimeMicros, admitted.genTimeMicros);
      assert.equal(signed.claimedUpperBoundMicros, admitted.poeUpperBoundMicros);
      assert.equal(BigInt(signed.claimedUpperBoundMicros) -
        BigInt(signed.genTimeMicros), BigInt(admitted.accuracyMicros));
    }
  }
});

test('original signed fractional RFC 3161 claim anchors the one-microsecond boundary', () => {
  const source = frozen.fractionalTimestamp;
  const raw = timestampCases.cases.find(item => item.id === source.rawCase);
  assert(raw && raw.expected === 'SIGNED_CLAIM');
  const original = id => Buffer.from(timestampCorpus.objects[id].base64, 'base64');
  const defaults = timestampCases.defaults;
  const response = original(raw.response);
  assert.equal(sha256(response), source.responseSha256);
  const claim = assessRawTimestamp({responseDer: response,
    requestDer: original(defaults.request), coveredDer: original(defaults.covered),
    tsaDer: original(defaults.tsa), issuerDer: original(defaults.issuer),
    policy: {tsaSha256: timestampCorpus.objects[defaults.tsa].sha256,
      issuerSha256: timestampCorpus.objects[defaults.issuer].sha256,
      policyOid: defaults.policyOid,
      maxAccuracyMicros: defaults.maxAccuracyMicros}});
  assert.equal(claim.decision, 'SIGNED_CLAIM');
  assert.equal(claim.recordSha256, source.responseSha256);
  assert.equal(claim.genTimeMicros, source.record.genTimeMicros);
  assert.equal(claim.accuracyMicros.toString(), source.record.accuracyMicros);
  assert.equal(claim.claimedUpperBoundMicros, source.record.poeUpperBoundMicros);
});

for (const vector of frozen.cases) {
  test(vector.id, () => {
    assert.equal(catalog.cases.find(item => item.id === vector.id)?.expected,
      vector.expected);
    const records = structuredClone(vector.source === 'fractionalTimestamp' ?
      [frozen.fractionalTimestamp.record] : frozen.sources[vector.source].records);
    const policy = {...structuredClone(frozen.policy),
      ...structuredClone(vector.policyPatch ?? {})};
    if (vector.recordPatch) {
      const {index, field, value} = vector.recordPatch;
      records[index][field] = value;
    }
    if (vector.expected === 'SATISFIED')
      assert.equal(assertPreservationLifetimesMicros(records, policy), true);
    else assert.throws(() => assertPreservationLifetimesMicros(records, policy),
      {code: vector.expected});
  });
}

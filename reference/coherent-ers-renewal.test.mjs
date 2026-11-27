import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {readFileSync} from 'node:fs';
import {children, one, raw} from './der.mjs';
import {assessRawTimestamp} from './raw-timestamp.mjs';
import {assessRawErs} from './raw-ers.mjs';

const coherent = JSON.parse(readFileSync(new URL(
  '../vectors/coherent-document-evidence.json', import.meta.url)));
const vectors = JSON.parse(readFileSync(new URL(
  '../vectors/coherent-ers-renewal.json', import.meta.url)));
const sha = bytes => createHash('sha256').update(bytes).digest('hex');
const frozen = (item, field = 'base64') => {
  const bytes = Buffer.from(item[field], 'base64');
  assert.equal(sha(bytes), item.sha256);
  if (item.bytes !== undefined) assert.equal(bytes.length, item.bytes);
  return bytes;
};
const {original_core: core, ers, timestamp} = coherent;
const original = ers.objects.document;
const document = frozen(core.objects.document);
const signature = frozen(core.objects.signature);
const oldToken = frozen(original.token);
const oldEvidence = frozen(original.evidence);
const oldAts = frozen(vectors.initialArchiveTimestamp);
const tsaDer = frozen(timestamp.objects.tsa, 'derBase64');
const issuerDer = frozen(timestamp.objects.issuer, 'derBase64');
const policy = ers.policy;
const supplied = requestDer => ({requestDer, tsaDer, issuerDer, policy});
const stamp = (row, source) => assessRawTimestamp({
  responseDer: frozen(row.response), requestDer: frozen(row.request),
  coveredDer: source, tsaDer, issuerDer, policy,
});
const tokenFromResponse = responseDer => raw(children(one(responseDer, 0x30))[1]);
const firstAts = evidenceDer => {
  const chains = children(children(one(evidenceDer, 0x30)).at(-1));
  return raw(children(chains[0])[0]);
};

test('same-document renewal originals preserve the prior ATS and response tokens', () => {
  assert.equal(vectors.format, 'original-coherent-document-ers-renewal-v1');
  assert.equal(vectors.sourceCorpus, 'vectors/coherent-document-evidence.json');
  assert.equal(vectors.cases.length, 3);
  assert.deepEqual(vectors.source, {
    documentSha256: sha(document),
    initialEvidenceSha256: sha(oldEvidence),
    initialTokenSha256: sha(oldToken),
  });
  assert.deepEqual(firstAts(oldEvidence), oldAts);
  for (const id of ['renewal', 'wrongWholeAts']) {
    const row = vectors[id];
    const response = frozen(row.response);
    assert.deepEqual(tokenFromResponse(response), frozen(row.token));
    assert.deepEqual(firstAts(frozen(row.evidence)), oldAts);
    frozen(row.request);
  }
});

test('new RFC 3161 responses are signed for different exact preimages', () => {
  assert.equal(stamp(vectors.renewal, oldToken).decision, 'SIGNED_CLAIM');
  assert.equal(stamp(vectors.wrongWholeAts, oldAts).decision, 'SIGNED_CLAIM');
  assert.deepEqual(stamp(vectors.renewal, oldAts).reasons,
    ['TIMESTAMP_IMPRINT_MISMATCH']);
  assert.deepEqual(stamp(vectors.wrongWholeAts, oldToken).reasons,
    ['TIMESTAMP_IMPRINT_MISMATCH']);
});

test('same-document ERS renewal binds only the exact prior token and original object', async t => {
  for (const vector of vectors.cases) {
    await t.test(vector.id, () => {
      const row = vectors[vector.record];
      const objectDer = vector.object === 'document' ? document : signature;
      const actual = assessRawErs({
        evidenceDer: frozen(row.evidence), objectDer,
        timestampEvidence: [[supplied(frozen(original.request)),
          supplied(frozen(row.request))]],
      });
      assert.equal(actual.decision, vector.expected);
      assert.deepEqual(actual.reasons, vector.reason ? [vector.reason] : []);
      assert.equal(actual.evidenceSha256, row.evidence.sha256);
      for (const forbidden of ['VALID', 'documentValidity', 'poeUpperBoundMicros'])
        assert.ok(!Object.hasOwn(actual, forbidden));
      if (actual.decision === 'BOUND_CLAIMS') {
        assert.equal(actual.observations.length, vector.observationCount);
        assert.deepEqual(actual.observations.map(item => item.tokenSha256),
          [original.token.sha256, row.token.sha256]);
        assert.deepEqual(actual.observations.map(item => item.requestBinding),
          ['CHECKED', 'CHECKED']);
        assert(BigInt(actual.observations[0].genTimeMicros) <=
          BigInt(actual.observations[1].genTimeMicros));
      }
      if (vector.signedControl) {
        assert.equal(vector.signedControl, 'initialArchiveTimestamp');
        assert.equal(stamp(row, oldAts).decision, 'SIGNED_CLAIM');
      }
    });
  }
});

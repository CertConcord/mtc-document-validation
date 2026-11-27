import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {readFileSync} from 'node:fs';
import {parseMtcLandmarkPublication,
  selectMtcLandmarkSubtree} from './raw-mtc-landmark.mjs';

const vectors = JSON.parse(readFileSync(new URL(
  '../vectors/raw-mtc-landmark-publication.json', import.meta.url)));

test('original landmark publication bytes remain parsing claims', async t => {
  assert.equal(vectors.format,
    'original-mtc07-landmark-publication-cases-v1');
  for (const vector of vectors.cases) {
    await t.test(vector.id, () => {
      const bytes = Buffer.from(vector.rawBase64, 'base64');
      assert.equal(createHash('sha256').update(bytes).digest('hex'),
        vector.sha256);
      if (vector.expected === 'PARSED') {
        const result = parseMtcLandmarkPublication(bytes,
          vector.admittedAt);
        assert.equal(result.publicationSha256, vector.sha256);
        assert.equal(result.latest, vector.latest);
        assert.equal(result.rows.length, vector.rowCount);
        for (const forbidden of ['trusted', 'trustedSubtree', 'sourceComplete',
          'documentValidity']) assert(!Object.hasOwn(result, forbidden));
      } else assert.throws(() => parseMtcLandmarkPublication(bytes,
        vector.admittedAt), {code: vector.expected});
    });
  }
});

test('landmark publication does not supply its own time', () => {
  const bytes = Buffer.from(vectors.cases[0].rawBase64, 'base64');
  assert.throws(() => parseMtcLandmarkPublication(bytes, 150),
    {code: 'MTC_LANDMARK_FORMAT'});
  assert.throws(() => parseMtcLandmarkPublication(bytes, '0'),
    {code: 'MTC_LANDMARK_FORMAT'});
});

test('original landmark selection cases require a preceding boundary', async t => {
  const publications = new Map(vectors.cases.filter(x =>
    x.expected === 'PARSED').map(x => [x.id, parseMtcLandmarkPublication(
    Buffer.from(x.rawBase64, 'base64'), x.admittedAt)]));
  for (const vector of vectors.selectionCases) {
    await t.test(vector.id, () => {
      const publication = publications.get(vector.publication);
      if (vector.expected === 'SELECTED') {
        const result = selectMtcLandmarkSubtree(publication, vector.index);
        assert.equal(result.landmarkNumber, vector.landmarkNumber);
        assert.deepEqual(result.subtree, vector.subtree);
      } else assert.throws(() => selectMtcLandmarkSubtree(publication,
        vector.index), {code: vector.expected});
    });
  }
});

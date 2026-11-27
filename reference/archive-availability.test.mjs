import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {assessRetainedAvailability} from './archive-availability.mjs';

const corpus = JSON.parse(readFileSync(new URL('../vectors/archive-availability.json', import.meta.url), 'utf8'));
const indexed = JSON.parse(readFileSync(new URL('../cases.json', import.meta.url), 'utf8')).cases;
for (const vector of corpus.cases) {
  const indexedExpected = vector.expected.error ??
    {batchHeads: vector.expected.batchHeads.decision, documentEvidence: vector.expected.documentEvidence.decision};
  assert.deepEqual(indexed.find(item => item.id === vector.id)?.expected, indexedExpected, vector.id);
  test(vector.id, () => {
    const observations = vector.observationIds.map(id => corpus.observations[id]);
    assert(observations.every(Boolean), 'all observation IDs resolve');
    const policy = structuredClone(corpus.policy);
    if (Object.hasOwn(vector, 'inventoryCompleteThrough'))
      policy.headInventory.completeThrough = vector.inventoryCompleteThrough;
    if (Object.hasOwn(vector, 'issuerRetiredAt'))
      policy.issuerRetiredAt = vector.issuerRetiredAt;
    if (Object.hasOwn(vector, 'documentThrough'))
      policy.documentThrough = vector.documentThrough;
    if (Object.hasOwn(vector, 'documentRequiredIds'))
      policy.documentRequired = policy.documentRequired.filter(item => vector.documentRequiredIds.includes(item.id));
    if (vector.expected.error)
      assert.throws(() => assessRetainedAvailability({at: vector.at, policy, observations}),
        {code: vector.expected.error});
    else
      assert.deepEqual(assessRetainedAvailability({at: vector.at, policy, observations}), vector.expected);
  });
}

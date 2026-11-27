import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {assessTransferContinuity} from './transfer-continuity.mjs';

const corpus = JSON.parse(readFileSync(new URL('../vectors/transfer-continuity.json', import.meta.url), 'utf8'));
assert.equal(new Set(corpus.cases.map(c => c.id)).size, corpus.cases.length);

for (const vector of corpus.cases) test(vector.id, () => {
  const facts = structuredClone(corpus.base);
  Object.assign(facts.policy, vector.policyEdits ?? {});
  facts.policy.required.push(...structuredClone(vector.additionalRequired ?? []));
  for (const [id, edit] of Object.entries(vector.requiredEdits ?? {})) {
    const target = facts.policy.required.find(x => x.id === id);
    assert.ok(target, `${vector.id}: unknown required item ${id}`);
    Object.assign(target, edit);
  }
  if (Object.hasOwn(vector, 'transfers')) facts.transfers = structuredClone(vector.transfers);
  for (const [id, edit] of Object.entries(vector.transferEdits ?? {})) {
    const target = facts.transfers.find(t => t.id === id);
    assert.ok(target, `${vector.id}: unknown handoff ${id}`);
    Object.assign(target, edit);
  }
  for (const [id, edit] of Object.entries(vector.observationEdits ?? {})) {
    const target = facts.observations.find(o => o.id === id);
    assert.ok(target, `${vector.id}: unknown observation ${id}`);
    Object.assign(target, edit);
  }
  for (const id of vector.removeObservationIds ?? []) {
    assert.ok(facts.observations.some(o => o.id === id), `${vector.id}: unknown observation ${id}`);
    facts.observations = facts.observations.filter(o => o.id !== id);
  }
  facts.observations.push(...structuredClone(vector.additionalObservations ?? []));
  if (vector.expected.error)
    assert.throws(() => assessTransferContinuity(facts), {code: vector.expected.error});
  else assert.deepEqual(assessTransferContinuity(facts), vector.expected);
});

import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {assessHistory} from './history.mjs';

const corpus = JSON.parse(readFileSync(new URL('../vectors/history.json', import.meta.url), 'utf8'));
test('frozen original positive and negative history vectors', () => {
  for (const vector of corpus.cases) {
    const facts = vector.factIds.map(id => {
      assert.ok(Object.hasOwn(corpus.facts, id), `${vector.id}: ${id}`);
      return {...corpus.facts[id]};
    });
    const policy = {...corpus.policy,
      requirements: corpus.policy.requirements.map(row => ({...row}))};
    let policyReads = 0, factReads = 0;
    if (vector.policyControl === 'shrinking-requirements') {
      const full = policy.requirements;
      Object.defineProperty(policy, 'requirements', {get() {
        policyReads++;
        return policyReads <= 3 ? full : [full[1]];
      }});
    }
    if (vector.policyControl === 'alternating-profile')
      Object.defineProperty(policy, 'profileId', {get() {
        policyReads++;
        return policyReads === 2 ? 'documents:v2' : 'documents:v1';
      }});
    if (vector.factControl === 'moving-denial')
      Object.defineProperty(facts[0], 'decision', {get() {
        factReads++;
        return factReads === 1 ? 'DENY' : 'ALLOW';
      }});
    assert.deepEqual(assessHistory({stateAt: vector.stateAt, knownAt: vector.knownAt,
      policy, facts}), vector.expected, vector.id);
    if (vector.policyControl) assert.equal(policyReads, 1, vector.id);
    if (vector.factControl) assert.equal(factReads, 1, vector.id);
  }
});
test('malformed facts and incomplete policy fail explicitly', () => {
  const base = {stateAt: 120, knownAt: 250, policy: corpus.policy,
    facts: [corpus.facts.statusGoodLate, corpus.facts.issuerAllowed]};
  assert.throws(() => assessHistory({...base, knownAt: 2 ** 53}), {code: 'HISTORY_INPUT'});
  assert.throws(() => assessHistory({...base, policy: {...corpus.policy, requirements: []}}),
    {code: 'HISTORY_INPUT'});
  assert.throws(() => assessHistory({...base, facts: [{...corpus.facts.statusGoodLate,
    knowledgeThrough: 200}, corpus.facts.issuerAllowed]}), {code: 'HISTORY_FACTS'});
});

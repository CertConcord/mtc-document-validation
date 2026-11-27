import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {assertPreservationLifetimes} from './lifetimes.mjs';

const corpus = JSON.parse(readFileSync(new URL('../vectors/lifetime-chain-hash.json', import.meta.url), 'utf8'));
const cases = JSON.parse(readFileSync(new URL('../cases.json', import.meta.url), 'utf8')).cases;
for (const vector of corpus.cases)
  assert.equal(cases.find(item => item.id === vector.id)?.expected, vector.expected, vector.id);
for (const vector of corpus.cases) {
  test(vector.id, () => {
    if (vector.expected === 'VALID')
      assert.equal(assertPreservationLifetimes(vector.records, vector.policy), true);
    else
      assert.throws(() => assertPreservationLifetimes(vector.records, vector.policy),
        {code: vector.expected});
  });
}

test('a returning failure callback cannot admit a changed same-chain hash', () => {
  const vector = corpus.cases.find(item => item.id === 'same-chain-hash-changed');
  const failures = [];
  assert.throws(() => assertPreservationLifetimes(vector.records, vector.policy,
    code => { failures.push(code); }), {code: vector.expected});
  assert.deepEqual(failures, [vector.expected]);
});

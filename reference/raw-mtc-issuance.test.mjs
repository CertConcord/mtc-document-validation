import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {readFileSync} from 'node:fs';
import {assessRawMtcIssuance,
  evaluateMtcSubtreeProof} from './raw-mtc-issuance.mjs';

const corpus = JSON.parse(readFileSync(new URL('../vectors/raw-mtc-der.json', import.meta.url)));
const vectors = JSON.parse(readFileSync(new URL('../vectors/raw-mtc-cases.json', import.meta.url)));
const bytes = id => Buffer.from(corpus.objects[id].base64, 'base64');
const sha = raw => createHash('sha256').update(raw).digest('hex');

test('frozen original MTC revision-07 certificate bytes and test-only public keys', () => {
  assert.equal(corpus.format, 'frozen-original-mtc07-der-corpus-v1');
  assert.equal(vectors.format, 'original-mtc07-issuance-cases-v1');
  for (const [id, item] of Object.entries(corpus.objects)) {
    const raw = bytes(id);
    assert.equal(raw.length, item.bytes, id);
    assert.equal(sha(raw), item.sha256, id);
  }
});

test('original standalone MTC proof positive and negative controls', async t => {
  for (const vector of vectors.cases) {
    await t.test(vector.id, () => {
      const result = assessRawMtcIssuance({certificateDer: bytes(vector.certificate),
        policy: corpus.policies[vector.policy]});
      assert.equal(result.certificateSha256,
        corpus.objects[vector.certificate].sha256, vector.id);
      if (vector.expected === 'ISSUANCE_PROVEN') {
        assert.equal(result.decision, 'ISSUANCE_PROVEN', vector.id);
        assert.equal(result.reason, null, vector.id);
        assert.ok(result.admittedRoles.includes('ca'), vector.id);
      } else {
        assert.notEqual(result.decision, 'ISSUANCE_PROVEN', vector.id);
        assert.equal(result.reason, vector.expected, vector.id);
      }
      for (const forbidden of ['VALID', 'documentValidity', 'knowledgeThrough',
        'documentSignature', 'historicalStatus'])
        assert.ok(!Object.hasOwn(result, forbidden), `${vector.id}: ${forbidden}`);
    });
  }
});

test('an archive cannot appoint an MTC CA or cosigner policy', () => {
  const original = corpus.policies.caOnly;
  const input = {certificateDer: bytes('standalone-one')};
  assert.throws(() => assessRawMtcIssuance(input), {code: 'MTC_POLICY'});
  assert.throws(() => assessRawMtcIssuance({...input,
    policy: {...original, cosigners: []}}), {code: 'MTC_POLICY'});
  assert.throws(() => assessRawMtcIssuance({...input,
    policy: {...original, requiredRoles: []}}), {code: 'MTC_POLICY'});
  assert.throws(() => assessRawMtcIssuance({...input,
    policy: {...original, representation: 'relative'}}), {code: 'MTC_POLICY'});
  assert.throws(() => assessRawMtcIssuance({...input,
    policy: {...original, mtcRevision: '08'}}), {code: 'MTC_UNSUPPORTED'});
  assert.throws(() => assessRawMtcIssuance({...input,
    policy: {...original, logHash: 'sha512'}}), {code: 'MTC_UNSUPPORTED'});
});

test('selected draft-07 accumulated subtree and inclusion vectors through 130 leaves', () => {
  const digest = (...parts) => createHash('sha256')
    .update(Buffer.concat(parts)).digest();
  const cache = new Map();
  const tree = (start, end) => {
    const id = `${start}:${end}`;
    if (cache.has(id)) return cache.get(id);
    const size = end - start;
    let result;
    if (size === 0) result = digest(Buffer.alloc(0));
    else if (size === 1) result = digest(Buffer.from([0, start]));
    else {
      const split = 2 ** Math.floor(Math.log2(size - 1));
      result = digest(Buffer.from([1]), tree(start, start + split),
        tree(start + split, end));
    }
    cache.set(id, result);
    return result;
  };
  const proof = (start, end, index) => {
    if (end - start === 1) return [];
    const split = start + 2 ** Math.floor(Math.log2(end - start - 1));
    return index < split
      ? [...proof(start, split, index), tree(split, end)]
      : [...proof(split, end, index), tree(start, split)];
  };
  const roots = createHash('sha256'), proofs = createHash('sha256');
  for (let end = 0; end <= 130; end++) {
    for (let start = 0; start <= end; start++) {
      const size = end - start;
      const alignment = 2 ** Math.ceil(Math.log2(Math.max(size, 1)));
      if (start % alignment) continue;
      const root = tree(start, end);
      roots.update(`[${start}, ${end}) ${root.toString('hex')}\n`);
      for (let index = start; index < end; index++) {
        const path = proof(start, end, index);
        proofs.update(`${index} [${start}, ${end})${path.map(x =>
          ` ${x.toString('hex')}`).join('')}\n`);
        assert.deepEqual(evaluateMtcSubtreeProof(tree(index, index + 1),
          index, start, end, Buffer.concat(path)), root);
      }
    }
  }
  assert.equal(roots.digest('hex'),
    'b82806ad4265bb151c1119c0f4db437bb4d1a1f887b3a7fba1cd4ebf552e3e81');
  assert.equal(proofs.digest('hex'),
    'ac2a8f989e44d99e399db448050ff5f19757df53cfb716aa81015d3955d8163f');
});

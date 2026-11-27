import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {readFileSync} from 'node:fs';
import {selectMtcCoveringSubtrees,
  verifyMtcSubtreeConsistencyProof} from './raw-mtc-consistency.mjs';

const vectors = JSON.parse(readFileSync(new URL(
  '../vectors/raw-mtc-consistency.json', import.meta.url)));
const digest = (...parts) => createHash('sha256')
  .update(Buffer.concat(parts)).digest();

test('original raw subtree consistency cases', async t => {
  assert.equal(vectors.format, 'original-mtc07-subtree-consistency-cases-v1');
  for (const item of vectors.leafInputs) {
    const bytes = Buffer.from(item.base64, 'base64');
    assert.equal(digest(Buffer.from([0]), bytes).toString('hex'), item.sha256);
  }
  for (const vector of vectors.cases) {
    await t.test(vector.id, () => {
      const input = {start: vector.start, end: vector.end,
        treeSize: vector.treeSize,
        subtreeHash: Buffer.from(vector.subtreeHashHex, 'hex'),
        rootHash: Buffer.from(vector.rootHashHex, 'hex'),
        proof: Buffer.from(vector.proofHex, 'hex')};
      if (vector.expected === 'VERIFIED')
        assert.equal(verifyMtcSubtreeConsistencyProof(input), true);
      else assert.throws(() => verifyMtcSubtreeConsistencyProof(input),
        {code: vector.expected});
    });
  }
});

test('selected MTC-07 Appendix C.1.3 consistency proofs through 130 leaves', () => {
  const cache = new Map();
  const tree = (start, end) => {
    const id = `${start}:${end}`;
    if (cache.has(id)) return cache.get(id);
    const size = end - start;
    let root;
    if (size === 0) root = digest(Buffer.alloc(0));
    else if (size === 1) root = digest(Buffer.from([0, start]));
    else {
      const split = 2 ** Math.floor(Math.log2(size - 1));
      root = digest(Buffer.from([1]), tree(start, start + split),
        tree(start + split, end));
    }
    cache.set(id, root);
    return root;
  };
  const proof = (start, end, base, size, omit = true) => {
    if (start === end) return [];
    if (start === 0 && end === size)
      return omit ? [] : [tree(base, base + size)];
    const split = 2 ** Math.floor(Math.log2(size - 1));
    if (end <= split)
      return [...proof(start, end, base, split, omit),
        tree(base + split, base + size)];
    if (split <= start)
      return [...proof(start - split, end - split, base + split,
        size - split, omit), tree(base, base + split)];
    assert.equal(start, 0);
    return [...proof(0, end - split, base + split, size - split, false),
      tree(base, base + split)];
  };
  const accumulated = createHash('sha256');
  for (let treeSize = 0; treeSize <= 130; treeSize++) {
    for (let end = 0; end <= treeSize; end++) {
      for (let start = 0; start <= end; start++) {
        const size = end - start;
        const alignment = 2 ** Math.ceil(Math.log2(Math.max(size, 1)));
        if (start % alignment) continue;
        const nodes = proof(start, end, 0, treeSize);
        accumulated.update(`[${start}, ${end}) ${treeSize}${nodes.map(x =>
          ` ${x.toString('hex')}`).join('')}\n`);
        const input = {start, end, treeSize, subtreeHash: tree(start, end),
          rootHash: tree(0, treeSize), proof: Buffer.concat(nodes)};
        assert.equal(verifyMtcSubtreeConsistencyProof(input), true);
        if (nodes.length) {
          const changed = Buffer.from(input.proof);
          changed[0] ^= 1;
          assert.throws(() => verifyMtcSubtreeConsistencyProof({
            ...input, proof: changed}), {code: 'MTC_CONSISTENCY'});
        }
      }
    }
  }
  assert.equal(accumulated.digest('hex'),
    '10fa99b37bf9bf9ffa26b412fbd98bd75363256d0b75d61bc4538b9c9c5a0a74');
});

test('original interval covering cases', async t => {
  for (const vector of vectors.coveringCases) {
    await t.test(vector.id, () => {
      if (vector.expected === 'MTC_COVERING') {
        assert.throws(() => selectMtcCoveringSubtrees(vector.start, vector.end),
          {code: 'MTC_COVERING'});
      } else {
        assert.deepEqual(selectMtcCoveringSubtrees(vector.start, vector.end),
          [vector.left, vector.right]);
      }
    });
  }
});

test('selected MTC-07 Appendix C.1.4 and C.2.4 interval coverage', () => {
  const accumulated = createHash('sha256');
  for (let end = 0; end <= 130; end++) {
    for (let start = 0; start <= end; start++) {
      const [left, right] = selectMtcCoveringSubtrees(start, end);
      accumulated.update(`[${left.start}, ${left.end}) ` +
        `[${right.start}, ${right.end})\n`);
      assert(left.start <= start && start <= left.end);
      assert.equal(left.end, right.start);
      assert(right.start <= end && end <= right.end);
      assert.equal(end, right.end);
    }
  }
  assert.equal(accumulated.digest('hex'),
    '7fd9c8b926e9d2b5cf831560e8ce295a5ef97ad5c5ede4ea0dea28a8c8fc8bb0');
  for (const [start, end, expected] of [
    [0, 0x800000000000,
      [{start: 0, end: 0x400000000000},
        {start: 0x400000000000, end: 0x800000000000}]],
    [0x500000000000, 0xd00000000000,
      [{start: 0x400000000000, end: 0x800000000000},
        {start: 0x800000000000, end: 0xd00000000000}]],
    [0x7fffffffffff, 0x800000000001,
      [{start: 0x7fffffffffff, end: 0x800000000000},
        {start: 0x800000000000, end: 0x800000000001}]],
    [0xfffffffffffe, 0xffffffffffff,
      [{start: 0xfffffffffffe, end: 0xffffffffffff},
        {start: 0xffffffffffff, end: 0xffffffffffff}]]
  ]) assert.deepEqual(selectMtcCoveringSubtrees(start, end), expected);
});

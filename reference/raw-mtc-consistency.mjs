import {createHash} from 'node:crypto';
import {DerError} from './der.mjs';

const fail = () => { throw new DerError('MTC_CONSISTENCY'); };
const failCovering = () => { throw new DerError('MTC_COVERING'); };
const hash = (...parts) => createHash('sha256').update(Buffer.concat(parts)).digest();
const branch = (left, right) => hash(Buffer.from([1]), left, right);

// MTC -07 section 4.5.1. Use BigInt for bit positions; JavaScript bitwise
// operators would truncate valid 48-bit log indexes to 32 bits.
export function selectMtcCoveringSubtrees(start, end) {
  if (![start, end].every(x => Number.isSafeInteger(x) &&
      x >= 0 && x < 2 ** 48) || start > end) failCovering();
  if (end - start <= 1)
    return [{start, end}, {start: end, end}];
  const first = BigInt(start), last = BigInt(end - 1);
  let difference = first ^ last, split = 0n;
  while (difference > 1n) {
    difference >>= 1n;
    split++;
  }
  const mask = (1n << split) - 1n;
  const middle = last & ~mask;
  let zeroBits = (~first) & mask, leftSplit = 0n;
  while (zeroBits > 0n) {
    zeroBits >>= 1n;
    leftSplit++;
  }
  const leftStart = first & ~((1n << leftSplit) - 1n);
  return [{start: Number(leftStart), end: Number(middle)},
    {start: Number(middle), end}];
}

// MTC -07 section 4.4.3. An accepted proof binds the supplied subtree hash to
// the supplied full-tree root; it does not authenticate either input or a CA.
export function verifyMtcSubtreeConsistencyProof({start, end, treeSize,
  subtreeHash, rootHash, proof}) {
  if (![start, end, treeSize].every(x => Number.isSafeInteger(x) &&
      x >= 0 && x < 2 ** 48) || !Buffer.isBuffer(subtreeHash) ||
      subtreeHash.length !== 32 || !Buffer.isBuffer(rootHash) ||
      rootHash.length !== 32 || !Buffer.isBuffer(proof) ||
      proof.length % 32 !== 0 || start > end || end > treeSize)
    fail();
  const size = end - start;
  let alignment = 1;
  while (alignment < size) alignment *= 2;
  if (start % alignment !== 0) fail();
  if (start === end) {
    if (proof.length || !subtreeHash.equals(hash(Buffer.alloc(0)))) fail();
    return true;
  }

  let fn = start, sn = end - 1, tn = treeSize - 1;
  const shift = () => {
    fn = Math.floor(fn / 2);
    sn = Math.floor(sn / 2);
    tn = Math.floor(tn / 2);
  };
  if (sn === tn) {
    while (fn !== sn) shift();
  } else {
    while (fn !== sn && sn % 2 === 1) shift();
  }
  let at = 0, fr, sr;
  if (fn === sn) fr = sr = subtreeHash;
  else {
    if (!proof.length) fail();
    fr = sr = proof.subarray(0, 32);
    at = 32;
  }
  for (; at < proof.length; at += 32) {
    if (tn === 0) fail();
    const sibling = proof.subarray(at, at + 32);
    if (sn % 2 === 1 || sn === tn) {
      if (fn < sn) fr = branch(sibling, fr);
      sr = branch(sibling, sr);
      while (sn % 2 === 0) shift();
    } else sr = branch(sr, sibling);
    shift();
  }
  if (tn !== 0 || !fr.equals(subtreeHash) || !sr.equals(rootHash)) fail();
  return true;
}

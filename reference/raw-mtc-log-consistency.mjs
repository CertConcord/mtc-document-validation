import {createHash} from 'node:crypto';
import {DerError} from './der.mjs';

const fail = () => { throw new DerError('MTC_LOG_CONSISTENCY'); };
const branch = (left, right) => createHash('sha256').update(Buffer.from([1]))
  .update(left).update(right).digest();
const size = value => Number.isSafeInteger(value) && value > 0 && value < 2 ** 48;

// RFC 9162 section 2.1.4.2, applied to MTC -07 SHA-256 checkpoint roots.
// The raw path is concatenated 32-byte hashes in the RFC proof order. This
// checks an append-only edge only; neither checkpoint is authenticated here.
export function verifyMtcLogConsistencyProof({firstSize, secondSize,
  firstRoot, secondRoot, proof}) {
  if (!size(firstSize) || !size(secondSize) || firstSize >= secondSize ||
      !Buffer.isBuffer(firstRoot) || firstRoot.length !== 32 ||
      !Buffer.isBuffer(secondRoot) || secondRoot.length !== 32 ||
      !Buffer.isBuffer(proof) || proof.length === 0 ||
      proof.length % 32 !== 0) fail();
  // RFC 9162 bounds PROOF(m, D_n) by ceil(log2(n)) + 1 hashes.
  const maxNodes = (BigInt(secondSize) - 1n).toString(2).length + 1;
  if (proof.length / 32 > maxNodes) fail();
  const path = [];
  for (let at = 0; at < proof.length; at += 32)
    path.push(proof.subarray(at, at + 32));
  const first = BigInt(firstSize);
  if ((first & (first - 1n)) === 0n) path.unshift(firstRoot);
  let fn = firstSize - 1, sn = secondSize - 1;
  const shift = () => {
    fn = Math.floor(fn / 2);
    sn = Math.floor(sn / 2);
  };
  while (fn % 2 === 1) shift();
  let fr = path[0], sr = path[0];
  for (const node of path.slice(1)) {
    if (sn === 0) fail();
    if (fn % 2 === 1 || fn === sn) {
      fr = branch(node, fr);
      sr = branch(node, sr);
      if (fn % 2 === 0)
        while (fn !== 0 && fn % 2 === 0) shift();
    } else sr = branch(sr, node);
    shift();
  }
  if (sn !== 0 || !fr.equals(firstRoot) || !sr.equals(secondRoot)) fail();
  return true;
}

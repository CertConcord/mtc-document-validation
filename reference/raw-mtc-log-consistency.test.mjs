import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {readFileSync} from 'node:fs';
import {verifyMtcLogConsistencyProof} from './raw-mtc-log-consistency.mjs';

const corpus = JSON.parse(readFileSync(new URL(
  '../vectors/raw-mtc-log-consistency.json', import.meta.url)));
const hash = (...parts) => createHash('sha256')
  .update(Buffer.concat(parts)).digest();
const branch = (left, right) => hash(Buffer.from([1]), left, right);
const split = n => 2 ** Math.floor(Math.log2(n - 1));
const tree = nodes => nodes.length === 1 ? nodes[0] :
  branch(tree(nodes.slice(0, split(nodes.length))),
    tree(nodes.slice(split(nodes.length))));
const subproof = (m, nodes, complete) => {
  if (m === nodes.length) return complete ? [] : [tree(nodes)];
  const k = split(nodes.length);
  return m <= k
    ? [...subproof(m, nodes.slice(0, k), complete), tree(nodes.slice(k))]
    : [...subproof(m - k, nodes.slice(k), false), tree(nodes.slice(0, k))];
};

for (const vector of corpus.cases) test(vector.id, () => {
  const input = {firstSize:vector.firstSize, secondSize:vector.secondSize,
    firstRoot:Buffer.from(vector.firstRootHex,'hex'),
    secondRoot:Buffer.from(vector.secondRootHex,'hex'),
    proof:Buffer.from(vector.proofHex,'hex')};
  if(vector.expected === 'VERIFIED')
    assert.equal(verifyMtcLogConsistencyProof(input),true);
  else assert.throws(()=>verifyMtcLogConsistencyProof(input),
    {code:vector.expected});
});

test('RFC 9162 section 2.1.5 seven-leaf proof shapes',()=>{
  assert.equal(corpus.cases.find(x=>x.id==='three-to-seven-rfc-shape')
    .proofHex.length/64,4);
  assert.equal(corpus.cases.find(x=>x.id==='four-to-seven-power-of-two')
    .proofHex.length/64,1);
  assert.equal(corpus.cases.find(x=>x.id==='six-to-seven-rfc-shape')
    .proofHex.length/64,3);
});

test('all original-prefix extensions through 32 leaves and first-node mutations',()=>{
  const leaves=Array.from({length:32},(_,i)=>hash(Buffer.from([0]),
    Buffer.from(`original MTC prefix sample ${i}`,'ascii')));
  let checked=0;
  for(let n=2;n<=leaves.length;n++)for(let m=1;m<n;m++){
    const proof=Buffer.concat(subproof(m,leaves.slice(0,n),true));
    const input={firstSize:m,secondSize:n,
      firstRoot:tree(leaves.slice(0,m)),secondRoot:tree(leaves.slice(0,n)),proof};
    assert.equal(verifyMtcLogConsistencyProof(input),true,`${m}->${n}`);
    const changed=Buffer.from(proof);changed[0]^=1;
    assert.throws(()=>verifyMtcLogConsistencyProof({...input,proof:changed}),
      {code:'MTC_LOG_CONSISTENCY'},`${m}->${n}`);
    checked++;
  }
  assert.equal(checked,496);
});

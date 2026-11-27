import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {readFileSync} from 'node:fs';
import {assessRawMtcRelativeIssuance} from './raw-mtc-relative.mjs';
import {parseRawMtcCertificateCandidate} from './raw-mtc-issuance.mjs';

const corpus=JSON.parse(readFileSync(new URL(
  '../vectors/raw-mtc-relative-multileaf.json',import.meta.url)));
const vectors=JSON.parse(readFileSync(new URL(
  '../vectors/raw-mtc-relative-multileaf-cases.json',import.meta.url)));
const decode=item=>Buffer.from(item.base64,'base64');

test('original five-entry log reconstructs the distinct signed root',()=>{
  const node=(left,right)=>createHash('sha256').update(Buffer.from([1]))
    .update(left).update(right).digest();
  const leaves=corpus.logEntries.map(entry=>{
    const actual=createHash('sha256').update(Buffer.from([0]))
      .update(decode(entry)).digest();
    assert.equal(actual.toString('hex'),entry.leafSha256);
    return actual;
  });
  assert.equal(node(leaves[2],leaves[3]).toString('hex'),
    corpus.selectedSubtree.rootSha256);
  const left=node(node(leaves[0],leaves[1]),node(leaves[2],leaves[3]));
  assert.equal(node(left,leaves[4]).toString('hex'),
    corpus.reference.rootSha256);
  assert.notEqual(corpus.selectedSubtree.rootSha256,
    corpus.reference.rootSha256);
});

for(const vector of vectors.cases)test(vector.id,()=>{
  const policy=structuredClone(corpus.policy);
  if(vector.minimumTrustedTreeSize)
    policy.minimumTrustedTreeSize=vector.minimumTrustedTreeSize;
  if(vector.landmarkLogOrigin)policy.landmarkLogOrigin=vector.landmarkLogOrigin;
  const certificateDer=decode(corpus.certificate);
  if(vector.mutateCertificatePath){
    const peer=Buffer.from(corpus.logEntries[3].leafSha256,'hex');
    const at=certificateDer.indexOf(peer);
    assert(at>=0);
    certificateDer[at]^=1;
  }
  const landmarkPublication=decode(corpus.publication);
  if(vector.mutatePublication){
    const at=landmarkPublication.indexOf(Buffer.from('1830297600','ascii'));
    assert(at>=0);
    landmarkPublication[at+9]=0x31;
  }
  const checkpointSignatures=['ca',...(vector.omitMirror?[]:['mirror'])].map(id=>{
    const record=corpus.checkpoints[id];
    return {idHex:record.idHex,message:decode(record.message),
      signature:decode(record.signature)};
  });
  const subtreeConsistencyProof=Buffer.from(corpus.selectedSubtree.proofHex,'hex');
  if(vector.mutateSubtreeProof)subtreeConsistencyProof[0]^=1;
  const result=assessRawMtcRelativeIssuance({certificateDer,policy,
    landmarkPublication,checkpointSignatures,subtreeConsistencyProof});
  assert.equal(result.reason??result.decision,vector.expected);
  if(vector.expected==='RELATIVE_ISSUANCE_BOUND'){
    const candidate=parseRawMtcCertificateCandidate({certificateDer,policy});
    assert(candidate.parsed.path.length>0);
    assert(subtreeConsistencyProof.length>0);
    assert.notEqual(corpus.selectedSubtree.rootSha256,corpus.reference.rootSha256);
    assert.equal(result.landmarkNumber,2);
    assert.equal(result.index,2);
    assert.equal(result.subtreeSha256,corpus.selectedSubtree.rootSha256);
    assert.equal(result.referenceTreeSize,5);
    assert.equal(result.referenceRootSha256,corpus.reference.rootSha256);
    assert.deepEqual(result.admittedRoles,['ca','mirror']);
  }
});

import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash,createPublicKey,verify} from 'node:crypto';
import {types} from 'node:util';
import {readFileSync} from 'node:fs';
import {assessRawMtcActiveSubtreeSet} from './raw-mtc-active-subtrees.mjs';

const load=name=>JSON.parse(readFileSync(new URL(`../vectors/${name}`,import.meta.url)));
const frozen=load('raw-mtc-active-subtree-set.json');
const vectors=load('raw-mtc-active-subtree-cases.json');
const five=load('raw-mtc-relative-multileaf.json');
const seven=load('raw-mtc-later-checkpoint.json');
const corpus=name=>name==='raw-mtc-relative-multileaf.json'?five:seven;
const decode=item=>Buffer.from(item.base64,'base64');
const hash=bytes=>createHash('sha256').update(bytes).digest();
const node=(left,right)=>hash(Buffer.concat([Buffer.from([1]),left,right]));
const leaves=source=>source.logEntries.map(entry=>{
  const actual=hash(Buffer.concat([Buffer.from([0]),decode(entry)]));
  assert.equal(actual.toString('hex'),entry.leafSha256);
  return actual;
});
const fakeBufferPrototype=()=>{
  const fake=Object.create(Buffer.prototype);
  assert.equal(Buffer.isBuffer(fake),true);
  assert.equal(types.isUint8Array(fake),false);
  return fake;
};
const spoofNativeBytes=(original,mode,target)=>{
  const good=Buffer.from(original),bad=Buffer.from(good);
  if(target==='publication'){
    const at=bad.indexOf(Buffer.from('1830297600','ascii'));
    assert(at>=0);
    bad[at+9]=0x31;
  }else bad[0]^=1;
  const native=mode==='native-good-converted-bad'?good:bad;
  const converted=mode==='native-good-converted-bad'?bad:good;
  Object.defineProperties(native,{
    length:{get:()=>converted.length},
    byteLength:{get:()=>converted.length},
    byteOffset:{get:()=>converted.byteOffset},
    buffer:{get:()=>converted.buffer},
    valueOf:{value:()=>converted}
  });
  assert.deepEqual(Buffer.from(native),converted);
  assert.notDeepEqual(Uint8Array.prototype.slice.call(native),converted);
  return native;
};

test('original entries, signed roots, two-sided proofs and empty hash',()=>{
  const a=leaves(five),b=leaves(seven);
  assert.deepEqual(b.slice(0,5),a);
  const root01=node(a[0],a[1]),root23=node(a[2],a[3]);
  const root4=node(root01,root23),root45=node(b[4],b[5]);
  const root5=node(root4,a[4]),root6=node(root4,root45);
  const expected={
    fiveTwoActive:[
      [root23,[root01,a[4]]],[a[4],[root4]],
      [a[0],[a[1],root23,a[4]]],[a[1],[a[0],root23,a[4]]]],
    fiveOneEntry:[
      [a[0],[a[1],root23,a[4]]],[hash(Buffer.alloc(0)),[]]],
    sixThreeActive:[
      [b[5],[b[4],root4]],[hash(Buffer.alloc(0)),[]],
      [root23,[root01,root45]],[b[4],[b[5],root4]],
      [b[0],[b[1],root23,root45]],[b[1],[b[0],root23,root45]]],
    sixNewestWithExpiredFive:[
      [b[5],[b[4],root4]],[hash(Buffer.alloc(0)),[]]]
  };
  assert.equal(root5.toString('hex'),five.reference.rootSha256);
  assert.equal(root6.toString('hex'),seven.laterRoots.six);
  for(const [name,rows] of Object.entries(expected)){
    const item=frozen.publications[name];
    const bytes=decode(item);
    assert.equal(bytes.length,item.bytes);
    assert.equal(hash(bytes).toString('hex'),item.sha256);
    assert.equal(item.subtrees.length,rows.length);
    for(let i=0;i<rows.length;i++){
      const [root,proof]=rows[i];
      assert.equal(item.subtrees[i].subtreeHashHex,root.toString('hex'));
      assert.equal(item.subtrees[i].proofHex,
        Buffer.concat(proof).toString('hex'));
    }
  }
  const seen=new Set();
  for(const item of [five,seven])for(const record of Object.values(item.checkpoints)){
    if(seen.has(record.message.sha256))continue;
    seen.add(record.message.sha256);
    const signer=item.policy.cosigners.find(x=>x.idHex===record.idHex);
    const key=createPublicKey({key:Buffer.from(signer.publicKeySpkiBase64,'base64'),
      type:'spki',format:'der'});
    assert(verify(null,decode(record.message),key,decode(record.signature)));
  }
  const sixToSeven=frozen.publications.sixThreeActive.laterConsistencyProofHex;
  assert.equal(sixToSeven,Buffer.concat([
    node(b[4],b[5]),b[6],root4]).toString('hex'));
});

for(const vector of vectors.cases)test(vector.id,()=>{
  const publication=frozen.publications[vector.publication];
  const evidence=frozen.publications[vector.evidenceSet??vector.publication];
  const sourceCorpus=corpus(publication.sourceCorpus);
  const evidenceCorpus=corpus(evidence.sourceCorpus);
  const policy=structuredClone(sourceCorpus.policy);
  const sourceAdmission={sourceId:'original-mtc07-publication',
    caIdHex:policy.caIdHex,logNumber:1,logOrigin:'1.2.0.1',
    publicationSha256:publication.sha256,admittedAt:'1780000000',
    evaluatedAt:vector.evaluatedAt??'1780000000',
    freshThrough:vector.freshThrough??'1780000100',
    previousLatest:vector.previousLatest??null,
    previousPublicationSha256:vector.previousPublication?
      frozen.publications[vector.previousPublication].sha256:null,
    minimumTrustedTreeSize:vector.minimumTrustedTreeSize??'5',
    maxActiveLandmarksForLog:vector.maxActiveLandmarksForLog??3};
  if(vector.mutateRequiredRolesAtSourceRead)
    Object.defineProperty(sourceAdmission,'publicationSha256',{get(){
      policy.requiredRoles.splice(1);
      return publication.sha256;
    }});
  if(vector.wrongLogOrigin)sourceAdmission.logOrigin='1.2.0.2';
  let landmarkPublication=decode(publication);
  if(vector.mutatePublication){
    const at=landmarkPublication.indexOf(Buffer.from('1830297600','ascii'));
    assert(at>=0);
    landmarkPublication[at+9]^=1;
  }
  if(vector.nativeInput?.target==='publication')
    landmarkPublication=spoofNativeBytes(landmarkPublication,
      vector.nativeInput.mode,'publication');
  if(vector.fakeBuffer==='publication')
    landmarkPublication=fakeBufferPrototype();
  const referenceCheckpoint={treeSize:evidence.referenceTreeSize,
    rootHash:Buffer.from(evidence.referenceRootHex,'hex')};
  if(vector.mutateReferenceRoot)referenceCheckpoint.rootHash[0]^=1;
  const checkpointSignatures=evidence.checkpointKeys
    .filter(key=>!(vector.omitMirror&&key.toLowerCase().includes('mirror')))
    .map(key=>{
      const record=evidenceCorpus.checkpoints[key];
      const item={idHex:record.idHex,message:decode(record.message),
        signature:decode(record.signature)};
      if(key==='mirrorLater7')item.consistencyProof=Buffer.from(
        evidence.laterConsistencyProofHex,'hex');
      return item;
    });
  const subtreeProofs=vector.acceptedHeadNumber===null?[]:
    evidence.subtrees.map(row=>({landmarkNumber:row.landmarkNumber,
      position:row.position,start:row.start,end:row.end,
      subtreeHash:Buffer.from(row.subtreeHashHex,'hex'),
      proof:Buffer.from(row.proofHex,'hex')}));
  if(vector.omitSubtree!==undefined)subtreeProofs.splice(vector.omitSubtree,1);
  if(vector.omitMiddlePair)subtreeProofs.splice(2,2);
  if(vector.mutateProof!==undefined)subtreeProofs[vector.mutateProof].proof[0]^=1;
  if(vector.mutateHash!==undefined)subtreeProofs[vector.mutateHash].subtreeHash[0]^=1;
  if(vector.appendProof!==undefined)subtreeProofs[vector.appendProof]
    .proof=Buffer.alloc(32,0x42);
  if(vector.wrongRange!==undefined)subtreeProofs[vector.wrongRange].start++;
  if(vector.nativeInput?.target!=='publication'&&vector.nativeInput){
    const {target,index,mode}=vector.nativeInput;
    subtreeProofs[index][target]=spoofNativeBytes(
      subtreeProofs[index][target],mode,target);
  }
  if(vector.fakeBuffer&&vector.fakeBuffer!=='publication')
    subtreeProofs[vector.fakeIndex][vector.fakeBuffer]=fakeBufferPrototype();
  const result=assessRawMtcActiveSubtreeSet({policy,sourceAdmission,
    landmarkPublication,acceptedHeadNumber:vector.acceptedHeadNumber,
    referenceCheckpoint,checkpointSignatures,subtreeProofs});
  assert.equal(result.reason??result.decision,vector.expected);
  if(vector.expected==='ACTIVE_SUBTREE_SET_BOUND'||
      vector.expected==='ACTIVE_SUBTREE_SUFFIX_BOUND'){
    assert.equal(result.source.publicationSha256,publication.sha256);
    assert.equal(result.source.logOrigin,'1.2.0.1');
    assert.equal(result.referenceTreeSize,evidence.referenceTreeSize);
    assert.equal(result.referenceRootSha256,evidence.referenceRootHex);
    assert.deepEqual(result.admittedRoles,['ca','mirror']);
    assert.equal(result.subtrees.length,evidence.subtrees.length);
    for(let i=0;i<result.subtrees.length;i++){
      const actual=result.subtrees[i],original=evidence.subtrees[i];
      assert.equal(actual.landmarkNumber,original.landmarkNumber);
      assert.equal(actual.position,original.position);
      assert.equal(actual.start,original.start);
      assert.equal(actual.end,original.end);
      assert.equal(actual.subtreeSha256,original.subtreeHashHex);
      assert.equal(actual.proofSha256,hash(Buffer.from(original.proofHex,'hex'))
        .toString('hex'));
    }
    assert(!result.subtrees.some(x=>x.landmarkNumber===0));
    if(vector.expected==='ACTIVE_SUBTREE_SUFFIX_BOUND'){
      assert.deepEqual(result.acceptedLandmarks,[2,1]);
      assert.deepEqual(result.droppedLatestLandmarks,[3]);
      assert.equal(result.publishedLatest,3);
    }else assert.deepEqual(result.droppedLatestLandmarks,[]);
    if(vector.publication==='fiveOneEntry'){
      assert.equal(result.subtrees[1].certificateEligible,false);
      assert.equal(result.subtrees[1].start,result.subtrees[1].end);
    }
    if(vector.publication==='sixNewestWithExpiredFive'){
      assert.deepEqual(result.activeLandmarks,[3]);
      assert.deepEqual(result.acceptedLandmarks,[3]);
      assert.equal(result.subtrees.length,2);
      assert(result.subtrees.every(x=>x.previousTreeSize===5));
    }
  }
  if(vector.expected==='NO_ADMITTED_SUBTREES'){
    assert.deepEqual(result.acceptedLandmarks,[]);
    assert.deepEqual(result.droppedLatestLandmarks,
      vector.publication==='zeroOnly'?[]:[3,2,1]);
  }
});

import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash,createPublicKey,verify} from 'node:crypto';
import {readFileSync} from 'node:fs';
import {assessRawPublicationWitness} from './raw-publication-witness.mjs';

const corpus=JSON.parse(readFileSync(new URL('../vectors/raw-publication-witness.json',import.meta.url)));
const vectors=JSON.parse(readFileSync(new URL('../vectors/raw-publication-witness-cases.json',import.meta.url)));
const source=JSON.parse(readFileSync(new URL('../vectors/raw-authority-bytes.json',import.meta.url)));
const sha=bytes=>createHash('sha256').update(bytes).digest('hex');
const raw=item=>({raw:Buffer.from(item.rawBase64,'base64'),
  signature:Buffer.from(item.signatureBase64,'base64')});

test('original entries retain the source signed bytes and independent log signatures',()=>{
  for(const entry of corpus.entries){
    const claim=source.objects[entry.id];
    const bytes=Buffer.concat([Buffer.from(claim.rawBase64,'base64'),
      Buffer.from(claim.signatureBase64,'base64')]);
    assert.equal(bytes.toString('base64'),entry.base64);
    assert.equal(sha(bytes),entry.sha256);
    const spki=entry.id.startsWith('samecut-')?source.sameSecondIssuerPublicKeySpkiBase64:
      source.policy.requirements.find(x=>x.role===
        (entry.id.startsWith('issuer')?'issuer-authorization':'document-action'))
        .publicKeySpkiBase64;
    const key=createPublicKey({key:Buffer.from(spki,'base64'),format:'der',type:'spki'});
    assert(verify(null,Buffer.concat([Buffer.from('MTC-DV-AUTHORITY-HISTORY-v1\0'),
      Buffer.from(claim.rawBase64,'base64')]),key,
      Buffer.from(claim.signatureBase64,'base64')),entry.id);
  }
});

for(const vector of vectors.cases)test(vector.id,()=>{
  let entries=corpus.entries.slice(0,vector.head==='four'?4:5)
    .map(x=>Buffer.from(x.base64,'base64'));
  const expectedEntries=entries.map(x=>Buffer.from(x));
  if(vector.omitLastEntry)entries.pop();
  if(vector.mutateEntry)entries[0][0]^=1;
  let speciesCalls=0;
  if(vector.speciesMutation){
    const native=Buffer.from(entries[0]);
    if(vector.speciesMutation==='native-bad')native[0]^=1;
    Object.defineProperty(native,'constructor',{value:{[Symbol.species]:function(length){
      speciesCalls++;
      native[0]^=1;
      return new Uint8Array(length);
    }}});
    entries[0]=native;
  }
  if(vector.shadowMap){
    entries[0][0]^=1;
    entries.map=()=>expectedEntries;
  }
  let lengthReads=0;
  if(vector.countLengthReads){
    entries=new Proxy(entries,{get(target,property,receiver){
      if(property==='length')lengthReads++;
      return Reflect.get(target,property,receiver);
    }});
  }
  const head=raw(corpus.heads[vector.head]);
  const monitor=raw(corpus.observations[vector.monitor??vector.head]);
  const anchor=structuredClone(corpus.anchor);
  const policy=structuredClone(corpus.policy);
  const proof=Buffer.from(corpus.proofs[vector.head],'hex');
  if(vector.mutateHeadSignature)head.signature[0]^=1;
  if(vector.mutateMonitorSignature)monitor.signature[0]^=1;
  if(vector.mutateAnchor)anchor.rootSha256='00'.repeat(32);
  if(vector.mutateProof)proof[0]^=1;
  if(vector.switchPolicyLogId){
    let reads=0;
    Object.defineProperty(policy,'logId',{get(){
      return ++reads===1?'unadmitted-log':corpus.policy.logId;
    }});
  }
  if(vector.switchAnchorSize){
    let reads=0;
    Object.defineProperty(anchor,'treeSize',{get(){return ++reads===1?0:2;}});
  }
  if(vector.switchAnchorRoot){
    let reads=0;
    Object.defineProperty(anchor,'rootSha256',{get(){
      return ++reads===1?'00'.repeat(32):corpus.anchor.rootSha256;
    }});
  }
  if(vector.sameKeys)
    policy.monitorPublicKeySpkiBase64=policy.logPublicKeySpkiBase64;
  const call=()=>assessRawPublicationWitness({policy,entries,head,
    monitor,anchor,proof,knownAt:vector.knownAt??corpus.knownAt});
  if(vector.expected==='MONITORED_STREAM_THROUGH'){
    const result=call();
    assert.equal(result.decision,vector.expected);
    assert.equal(result.treeSize,expectedEntries.length);
    assert.deepEqual(result.entrySha256,expectedEntries.map(sha));
    assert(!Object.hasOwn(result,'historyResolvedThrough'));
    assert(!Object.hasOwn(result,'documentValid'));
    if(vector.head==='four')
      assert(!result.entrySha256.includes(corpus.entries[4].sha256));
  }else assert.throws(call,{code:vector.expected});
  if(vector.speciesMutation)assert.equal(speciesCalls,0);
  if(vector.countLengthReads)assert.equal(lengthReads,1);
});

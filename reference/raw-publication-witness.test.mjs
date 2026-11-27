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
  const entries=corpus.entries.slice(0,vector.head==='four'?4:5)
    .map(x=>Buffer.from(x.base64,'base64'));
  if(vector.omitLastEntry)entries.pop();
  if(vector.mutateEntry)entries[0][0]^=1;
  const head=raw(corpus.heads[vector.head]);
  const monitor=raw(corpus.observations[vector.monitor??vector.head]);
  const anchor=structuredClone(corpus.anchor);
  const proof=Buffer.from(corpus.proofs[vector.head],'hex');
  if(vector.mutateHeadSignature)head.signature[0]^=1;
  if(vector.mutateMonitorSignature)monitor.signature[0]^=1;
  if(vector.mutateAnchor)anchor.rootSha256='00'.repeat(32);
  if(vector.mutateProof)proof[0]^=1;
  const call=()=>assessRawPublicationWitness({policy:corpus.policy,entries,head,
    monitor,anchor,proof,knownAt:vector.knownAt??corpus.knownAt});
  if(vector.expected==='MONITORED_STREAM_THROUGH'){
    const result=call();
    assert.equal(result.decision,vector.expected);
    assert.equal(result.treeSize,entries.length);
    assert.deepEqual(result.entrySha256,entries.map(sha));
    assert(!Object.hasOwn(result,'historyResolvedThrough'));
    assert(!Object.hasOwn(result,'documentValid'));
    if(vector.head==='four')
      assert(!result.entrySha256.includes(corpus.entries[4].sha256));
  }else assert.throws(call,{code:vector.expected});
});

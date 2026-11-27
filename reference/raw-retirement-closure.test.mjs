import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash,createPublicKey,verify} from 'node:crypto';
import {readFileSync} from 'node:fs';
import {assessRawRetirementClosure} from './raw-retirement-closure.mjs';

const json=name=>JSON.parse(readFileSync(new URL(`../vectors/${name}.json`,import.meta.url)));
const corpus=json('raw-retirement-closure');
const vectors=json('raw-retirement-closure-cases');
const publicationCorpus=json('raw-publication-witness');
const authority=json('raw-authority-bytes');
const mtc=json('raw-mtc-der');
const status=json('raw-status-der');
const ers=json('raw-ers-der');
const sha=bytes=>createHash('sha256').update(bytes).digest('hex');
const decode=item=>Buffer.from(item.base64,'base64');
const envelope=item=>({raw:Buffer.from(item.rawBase64,'base64'),
  signature:Buffer.from(item.signatureBase64,'base64')});
const published=name=>{
  const count=name==='four'?4:5;
  return {entries:publicationCorpus.entries.slice(0,count).map(decode),
    head:envelope(publicationCorpus.heads[name]),
    monitor:envelope(publicationCorpus.observations[name]),
    anchor:structuredClone(publicationCorpus.anchor),
    proof:Buffer.from(publicationCorpus.proofs[name],'hex')};
};
const originals=(name,publication)=>{
  const objects=Object.fromEntries(Object.entries(corpus.objects).map(([id,item])=>
    [id,decode(item)]));
  objects['publication-head']=Buffer.concat([publication.head.raw,
    publication.head.signature]);
  objects['monitor-observation']=Buffer.concat([publication.monitor.raw,
    publication.monitor.signature]);
  objects['consistency-proof']=publication.proof;
  for(const [index,entry] of publication.entries.entries())
    objects[`log-entry:${index}`]=entry;
  return objects;
};

test('retained original objects and detached document signature match source corpora',()=>{
  assert(decode(corpus.objects.document).equals(Buffer.from(ers.objects.document.base64,'base64')));
  assert(decode(corpus.objects['mtc-certificate']).equals(
    Buffer.from(mtc.objects['standalone-one'].base64,'base64')));
  assert(decode(corpus.objects['historical-status']).equals(
    Buffer.from(status.objects['good-ca'].derBase64,'base64')));
  assert(decode(corpus.objects['preservation-evidence']).equals(
    Buffer.from(ers.objects['ers-initial'].base64,'base64')));
  assert(decode(corpus.objects['authority-history']).equals(Buffer.concat(
    ['samecut-1','samecut-2'].flatMap(id=>[
      Buffer.from(authority.objects[id].rawBase64,'base64'),
      Buffer.from(authority.objects[id].signatureBase64,'base64')]))));
  const key=createPublicKey({key:Buffer.from(corpus.documentSignerPublicKeySpkiBase64,'base64'),
    format:'der',type:'spki'});
  assert(verify(null,decode(corpus.objects.document),key,
    decode(corpus.objects['document-signature'])));
  for(const [id,item] of Object.entries(corpus.objects)){
    const original=decode(item);
    assert.equal(original.length,item.bytes,id);
    assert.equal(sha(original),item.sha256,id);
  }
});

test('original inventory and archive signatures verify independently',()=>{
  const inventoryKey=createPublicKey({key:Buffer.from(corpus.policy.inventoryPublicKeySpkiBase64,'base64'),
    format:'der',type:'spki'});
  const archiveKey=createPublicKey({key:Buffer.from(corpus.policy.archivePublicKeySpkiBase64,'base64'),
    format:'der',type:'spki'});
  for(const [name,bundle] of Object.entries(corpus.bundles)){
    const manifest=envelope(bundle.manifest);
    assert(verify(null,Buffer.concat([Buffer.from('MTC-DV-RETIREMENT-MANIFEST-v1\0'),
      manifest.raw]),inventoryKey,manifest.signature),name);
    const parsed=JSON.parse(manifest.raw.toString('utf8'));
    assert.equal(parsed.items.length,name==='four'?13:14);
    for(const [id,item] of Object.entries(bundle.receipts)){
      const receipt=envelope(item);
      assert(verify(null,Buffer.concat([Buffer.from('MTC-DV-ARCHIVE-RETRIEVAL-v1\0'),
        receipt.raw]),archiveKey,receipt.signature),id);
    }
  }
});

test('retrieval ID is captured once from original signed bundle',()=>{
  const publication=published('five');
  const original=originals('five',publication);
  const bundle=corpus.bundles.five;
  const retrieved=Object.entries(bundle.receipts).map(([id,item])=>({id,
    bytes:Buffer.from(original[id]),receipt:envelope(item)}));
  const status=retrieved.find(x=>x.id==='historical-status');
  let reads=0;
  Object.defineProperty(status,'id',{get(){
    reads++;
    return reads===1?'historical-status':'unselected';
  }});
  const result=assessRawRetirementClosure({policy:structuredClone(corpus.policy),
    publication,manifest:envelope(bundle.manifest),retrieved,checkAt:corpus.checkAt});
  assert.equal(result.decision,'BOUND_RETIREMENT_RETRIEVAL_CLAIMS');
  assert.equal(reads,1);
});

for(const vector of vectors.cases)test(vector.id,()=>{
  const policy=structuredClone(corpus.policy);
  const publication=published(vector.bundle);
  const bundle=corpus.bundles[vector.bundle];
  const manifest=envelope(corpus.controls[vector.manifestControl]??bundle.manifest);
  const original=originals(vector.bundle,publication);
  const retrieved=Object.entries(bundle.receipts).map(([id,item])=>({id,
    bytes:Buffer.from(original[id]),receipt:envelope(item)}));
  if(vector.omit)retrieved.splice(retrieved.findIndex(x=>x.id===vector.omit),1);
  if(vector.omitBytes)delete retrieved.find(x=>x.id===vector.omitBytes).bytes;
  if(vector.malformedBytes)retrieved.find(x=>x.id===vector.malformedBytes).bytes='not raw bytes';
  if(vector.mutate)retrieved.find(x=>x.id===vector.mutate).bytes[0]^=1;
  if(vector.mutateArchiveAnchor)publication.anchor.rootSha256='00'.repeat(32);
  if(vector.mutateSelectedAnchor)policy.publicationAnchor.rootSha256='00'.repeat(32);
  if(vector.omitSelectedAnchor)delete policy.publicationAnchor;
  if(vector.omitReceipt)retrieved.find(x=>x.id===vector.omitReceipt).receipt=null;
  if(vector.malformedReceipt)
    retrieved.find(x=>x.id===vector.malformedReceipt).receipt=vector.receiptValue;
  if(vector.receiptControl)
    retrieved.find(x=>x.id==='historical-status').receipt=envelope(corpus.controls[vector.receiptControl]);
  if(vector.mutateReceiptSignature)
    retrieved.find(x=>x.id===vector.mutateReceiptSignature).receipt.signature[0]^=1;
  if(vector.mutateManifestSignature)manifest.signature[0]^=1;
  if(vector.sameInventoryLogKey)
    policy.inventoryPublicKeySpkiBase64=policy.publicationPolicy.logPublicKeySpkiBase64;
  if(vector.mutateProof)publication.proof[0]^=1;
  let speciesCalls=0;
  if(vector.speciesMutation){
    const item=retrieved.find(x=>x.id==='historical-status');
    if(vector.speciesMutation==='native-bad')item.bytes[0]^=1;
    Object.defineProperty(item.bytes,'constructor',{value:{[Symbol.species]:function(length){
      speciesCalls++;
      item.bytes[0]^=1;
      return new Uint8Array(length);
    }}});
  }
  const call=()=>assessRawRetirementClosure({policy,publication,manifest,retrieved,
    checkAt:vector.checkAt??corpus.checkAt});
  if(['BOUND_RETIREMENT_RETRIEVAL_CLAIMS','INDETERMINATE','REJECTED','OUT_OF_SCOPE'].includes(vector.expected)){
    const result=call();
    assert.equal(result.decision,vector.expected);
    assert.equal(result.publication,'MONITORED_STREAM_THROUGH');
    assert.equal(result.claimedFinalHeadSha256,
      publicationCorpus.heads[vector.bundle].rawSha256);
    assert(!Object.hasOwn(result,'historyResolvedThrough'));
    assert(!Object.hasOwn(result,'documentValid'));
    if(vector.reason)assert(result.reasons.some(x=>x.code===vector.reason));
    if(vector.bundle==='four')
      assert(!JSON.parse(manifest.raw.toString()).items.some(x=>
        x.sha256===publicationCorpus.entries[4].sha256));
  }else assert.throws(call,{code:vector.expected});
  if(vector.speciesMutation)assert.equal(speciesCalls,0);
});

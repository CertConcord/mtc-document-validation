import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash,createPublicKey,verify} from 'node:crypto';
import {readFileSync} from 'node:fs';
import {assessRawMtcRelativeIssuance} from './raw-mtc-relative.mjs';
import {parseRawMtcCertificateCandidate} from './raw-mtc-issuance.mjs';

const corpus=JSON.parse(readFileSync(new URL(
  '../vectors/raw-mtc-later-checkpoint.json',import.meta.url)));
const vectors=JSON.parse(readFileSync(new URL(
  '../vectors/raw-mtc-later-checkpoint-cases.json',import.meta.url)));
const decode=item=>Buffer.from(item.base64,'base64');
const branch=(left,right)=>createHash('sha256').update(Buffer.from([1]))
  .update(left).update(right).digest();
const split=n=>2**Math.floor(Math.log2(n-1));
const tree=nodes=>nodes.length===1?nodes[0]:
  branch(tree(nodes.slice(0,split(nodes.length))),
    tree(nodes.slice(split(nodes.length))));
const proof=(m,nodes,complete=true)=>{
  if(m===nodes.length)return complete?[]:[tree(nodes)];
  const k=split(nodes.length);
  return m<=k
    ?[...proof(m,nodes.slice(0,k),complete),tree(nodes.slice(k))]
    :[...proof(m-k,nodes.slice(k),false),tree(nodes.slice(0,k))];
};

test('original seven-entry log, growth paths and signed controls',()=>{
  const leaves=corpus.logEntries.map(entry=>{
    const leaf=createHash('sha256').update(Buffer.from([0]))
      .update(decode(entry)).digest();
    assert.equal(leaf.toString('hex'),entry.leafSha256);
    return leaf;
  });
  assert.equal(tree(leaves.slice(2,4)).toString('hex'),
    corpus.selectedSubtree.rootSha256);
  assert.equal(tree(leaves.slice(0,5)).toString('hex'),
    corpus.reference.rootSha256);
  assert.equal(tree(leaves.slice(0,6)).toString('hex'),
    corpus.laterRoots.six);
  assert.equal(tree(leaves).toString('hex'),corpus.laterRoots.seven);
  assert.equal(Buffer.concat(proof(5,leaves.slice(0,6))).toString('hex'),
    corpus.logConsistency.fiveToSixHex);
  assert.equal(Buffer.concat(proof(5,leaves)).toString('hex'),
    corpus.logConsistency.fiveToSevenHex);
  assert.notEqual(corpus.reference.rootSha256,corpus.laterRoots.seven);
  for(const [name,record] of Object.entries(corpus.checkpoints)){
    const admitted=corpus.policy.cosigners.find(x=>x.idHex===record.idHex);
    assert(admitted,name);
    const key=createPublicKey({key:Buffer.from(admitted.publicKeySpkiBase64,'base64'),
      format:'der',type:'spki'});
    assert(verify(null,decode(record.message),key,decode(record.signature)),name);
  }
});

for(const vector of vectors.cases)test(vector.id,()=>{
  const policy=structuredClone(corpus.policy);
  if(vector.minimumTrustedTreeSize)
    policy.minimumTrustedTreeSize=vector.minimumTrustedTreeSize;
  const landmarkPublication=decode(corpus.publication);
  if(vector.mutatePublication){
    const offset=landmarkPublication.indexOf(Buffer.from('1830297600','ascii'));
    assert(offset>=0);
    landmarkPublication[offset+9]=0x31;
  }
  const root=Buffer.from(corpus.reference.rootSha256,'hex');
  if(vector.mutateReferenceRoot)root[0]^=1;
  let referenceCheckpoint=vector.omitReference?undefined:
    {treeSize:corpus.reference.treeSize,rootHash:root};
  let referenceRootReads=0,referenceSizeReads=0;
  if(vector.referenceRootSequence){
    const badRoot=Buffer.from(root);badRoot[0]^=1;
    referenceCheckpoint={
      get treeSize(){referenceSizeReads++;
        return referenceSizeReads===1?corpus.reference.treeSize:7;},
      get rootHash(){referenceRootReads++;
        const first=vector.referenceRootSequence==='good-then-bad'?root:badRoot;
        const later=vector.referenceRootSequence==='good-then-bad'?badRoot:root;
        return referenceRootReads===1?first:later;}
    };
  }
  const mutationWitnesses=[],messageReads=[];
  const checkpointSignatures=vector.signatures.map(spec=>{
    const frozen=corpus.checkpoints[spec.key];
    const signature=decode(frozen.signature);
    if(vector.mutateSignature===spec.key)signature[0]^=1;
    const message=decode(frozen.message);
    const item={idHex:frozen.idHex,message,signature};
    if(vector.messageSequenceKey===spec.key){
      const badMessage=Buffer.from(message);
      badMessage[badMessage.length-1]^=1;
      let reads=0;
      Object.defineProperty(item,'message',{get(){reads++;
        if(vector.messageSequence==='good-then-bad')
          return reads===1?message:badMessage;
        return reads===1?badMessage:message;
      }});
      messageReads.push(()=>reads);
    }
    if(vector.mutateMessageAtSignature===spec.key ||
        vector.mutateReferenceAtSignature===spec.key){
      Object.defineProperty(item,'signature',{get(){
        if(vector.mutateMessageAtSignature===spec.key){
          message[message.length-1]=decode(frozen.message).at(-1)^1;
          mutationWitnesses.push(()=>assert.notDeepEqual(message,
            decode(frozen.message)));
        }
        if(vector.mutateReferenceAtSignature===spec.key){
          root[0]=Buffer.from(corpus.reference.rootSha256,'hex')[0]^1;
          mutationWitnesses.push(()=>assert.notEqual(root.toString('hex'),
            corpus.reference.rootSha256));
        }
        return signature;
      }});
    }
    if(spec.proof){
      item.consistencyProof=Buffer.from(corpus.logConsistency[spec.proof],'hex');
      if(vector.mutateProof===spec.key)item.consistencyProof[0]^=1;
    }
    if(spec.emptyProof)item.consistencyProof=Buffer.alloc(0);
    return item;
  });
  const subtreeConsistencyProof=Buffer.from(corpus.selectedSubtree.proofHex,'hex');
  if(vector.mutateSubtreeProof)subtreeConsistencyProof[0]^=1;
  const result=assessRawMtcRelativeIssuance({certificateDer:decode(corpus.certificate),
    policy,landmarkPublication,referenceCheckpoint,checkpointSignatures,
    subtreeConsistencyProof});
  assert.equal(result.reason??result.decision,vector.expected);
  if(vector.referenceRootSequence){
    assert.equal(referenceRootReads,1);
    assert.equal(referenceSizeReads,1);
  }
  for(const count of messageReads)assert.equal(count(),1);
  for(const witness of mutationWitnesses)witness();
  if(vector.expected==='RELATIVE_ISSUANCE_BOUND'){
    const candidate=parseRawMtcCertificateCandidate({certificateDer:decode(corpus.certificate),
      policy});
    assert(candidate.parsed.path.length>0);
    assert(subtreeConsistencyProof.length>0);
    assert.equal(result.certificateSha256,corpus.certificate.sha256);
    assert.equal(result.landmarkNumber,2);
    assert.equal(result.index,2);
    assert.equal(result.subtreeSha256,corpus.selectedSubtree.rootSha256);
    assert.equal(result.referenceTreeSize,5);
    assert.equal(result.referenceRootSha256,corpus.reference.rootSha256);
    assert.deepEqual(result.admittedRoles,['ca','mirror']);
  }
});

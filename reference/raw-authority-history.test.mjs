import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {readFileSync} from 'node:fs';
import {assessRawAuthorityHistory} from './raw-authority-history.mjs';

const bytes = JSON.parse(readFileSync(new URL('../vectors/raw-authority-bytes.json',import.meta.url)));
const vectors = JSON.parse(readFileSync(new URL('../vectors/raw-authority-cases.json',import.meta.url)));
const document = Buffer.from(bytes.document.base64,'base64');
const sha = b => createHash('sha256').update(b).digest('hex');

test('frozen original messages, signatures and document binding', () => {
  assert.equal(sha(document),bytes.document.sha256);
  assert.equal(bytes.policy.requirements.find(x=>x.role==='document-action').scope,
    `sha256:${sha(document)}`);
  for(const [id,item] of Object.entries(bytes.objects)) {
    const raw=Buffer.from(item.rawBase64,'base64');
    const signature=Buffer.from(item.signatureBase64,'base64');
    assert.equal(raw.length,item.rawBytes,id);
    assert.equal(sha(raw),item.rawSha256,id);
    assert.equal(sha(signature),item.signatureSha256,id);
    assert.equal(signature.length,64,id);
  }
});

test('signed original positive and negative authority-history controls', () => {
  for(const v of vectors.cases) {
    const records=v.records.map(id=>{
      assert.ok(Object.hasOwn(bytes.objects,id),`${v.id}: ${id}`);
      const {rawBase64,signatureBase64}=bytes.objects[id];
      return {rawBase64,signatureBase64};
    });
    const policy={...bytes.policy,requirements:bytes.policy.requirements.map(x=>
      x.role==='issuer-authorization' && v.issuerKey ? {...x,
        publicKeySpkiBase64:bytes[v.issuerKey]} : {...x})};
    if(v.extraRequirement==='backup-issuer-registry')
      policy.requirements.push({...policy.requirements[0],
        sourceId:'backup-issuer-registry'});
    let suppliedDocument=Buffer.from(document);
    if(v.documentControl==='shared-backing'){
      const shared=new SharedArrayBuffer(document.length);
      suppliedDocument=Buffer.from(shared);
      Uint8Array.prototype.set.call(suppliedDocument,document);
    }
    let policyReads=0;
    if(v.policyControl==='moving-profile')
      Object.defineProperty(policy,'profileId',{get(){
        policyReads++;
        return policyReads<=3 ? 'documents:v1' : 'documents:substituted';
      }});
    if(v.policyControl==='moving-issuer-source')
      Object.defineProperty(policy.requirements[0],'sourceId',
        {enumerable:true,get(){
          policyReads++;
          return policyReads<=2 ? 'issuer-registry' : 'substituted-registry';
        }});
    if(v.policyControl==='moving-requirements'){
      const full=policy.requirements;
      Object.defineProperty(policy,'requirements',{get(){
        policyReads++;
        return policyReads<=3 ? [full[0]] : full;
      }});
    }
    if(v.policyControl==='mutating-document')
      Object.defineProperty(policy,'profileId',{get(){
        policyReads++;
        suppliedDocument[0]^=1;
        return 'documents:v1';
      }});
    if(v.policyControl==='moving-requirement-length') {
      const selected=policy.requirements;
      policy.requirements=new Proxy(selected,{get(target,key,receiver){
        if(key==='length'){
          policyReads++;
          return policyReads===1 ? 1 : 2;
        }
        return Reflect.get(target,key,receiver);
      }});
    }
    const input={stateAt:v.stateAt,knownAt:v.knownAt,policy,records,
      document:suppliedDocument};
    let inputReads=0;
    if(v.inputControl==='policy-mutates-document')
      Object.defineProperty(input,'policy',{get(){
        inputReads++;
        suppliedDocument[0]^=1;
        return policy;
      }});
    if(v.error)assert.throws(()=>assessRawAuthorityHistory(input),{code:v.error},v.id);
    else {
      const actual=assessRawAuthorityHistory(input);
      assert.equal(actual.decision,v.expected,v.id);
      if(v.reason)assert.ok(actual.reasons.some(x=>x.code===v.reason),v.id);
      if(v.expectedClaimProfileId)
        assert(actual.claims.every(x=>x.profileId===v.expectedClaimProfileId),v.id);
      if(v.expectedIssuerSourceId)
        assert.equal(actual.claims.find(x=>x.role==='issuer-authorization')?.sourceId,
          v.expectedIssuerSourceId,v.id);
      if(v.expected==='BOUND_CLAIMS') {
        assert.deepEqual(actual.reasons,[],v.id);
        assert.equal(actual.claims.length,2,v.id);
      }
    }
    if(v.policyControl)assert.equal(policyReads,1,v.id);
    if(v.inputControl)assert.equal(inputReads,1,v.id);
  }
});

test('document substitution and unadmitted key cannot reuse claims', () => {
  const v=vectors.cases[0];
  const records=v.records.map(id=>{
    const {rawBase64,signatureBase64}=bytes.objects[id];
    return {rawBase64,signatureBase64};
  });
  assert.throws(()=>assessRawAuthorityHistory({stateAt:120,knownAt:205,
    policy:bytes.policy,records,document:Buffer.from('substitute')}),
  {code:'AUTHORITY_DOCUMENT'});
  assert.throws(()=>assessRawAuthorityHistory({stateAt:120,knownAt:205,
    policy:{...bytes.policy,requirements:[...bytes.policy.requirements,
      bytes.policy.requirements[0]]},records,document}),{code:'AUTHORITY_INPUT'});
  assert.throws(()=>assessRawAuthorityHistory({stateAt:120,knownAt:205,
    policy:{...bytes.policy,requirements:[bytes.policy.requirements[0]]},records,document}),
  {code:'AUTHORITY_INPUT'});
});

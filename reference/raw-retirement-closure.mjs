import {createHash,createPublicKey,verify} from 'node:crypto';
import {TextDecoder,types} from 'node:util';
import {assessRawPublicationWitness} from './raw-publication-witness.mjs';

const MANIFEST_DOMAIN=Buffer.from('MTC-DV-RETIREMENT-MANIFEST-v1\0','ascii');
const RECEIPT_DOMAIN=Buffer.from('MTC-DV-ARCHIVE-RETRIEVAL-v1\0','ascii');
const manifestKeys=['version','profileId','issuerId','logId','retiredAt',
  'documentThrough','declaredAt','claimedFinalHeadSha256','items'];
const itemKeys=['id','role','sha256','retainThrough'];
const receiptKeys=['version','archiveId','itemId','sha256','observedAt'];
const requiredRoles=['original-document','detached-signature','mtc-certificate',
  'historical-status','authority-history','preservation-evidence'];
const nativeArray=Object.getPrototypeOf(Uint8Array.prototype);
const getBuffer=Object.getOwnPropertyDescriptor(nativeArray,'buffer').get;
const getByteOffset=Object.getOwnPropertyDescriptor(nativeArray,'byteOffset').get;
const getByteLength=Object.getOwnPropertyDescriptor(nativeArray,'byteLength').get;
const fail=code=>{const error=new Error(code);error.code=code;throw error;};
const sha=bytes=>createHash('sha256').update(bytes).digest('hex');
const label=value=>typeof value==='string'&&/^[\x21-\x7e]+$/.test(value);
const hex=value=>typeof value==='string'&&/^[a-f0-9]{64}$/.test(value);
const time=value=>Number.isSafeInteger(value)&&value>=0;

function bytes(value,code){
  if(!types.isUint8Array(value))fail(code);
  try{
    const backing=getBuffer.call(value);
    const offset=getByteOffset.call(value);
    const length=getByteLength.call(value);
    const owned=Buffer.alloc(length);
    Uint8Array.prototype.set.call(owned,new Uint8Array(backing,offset,length));
    return owned;
  }catch{fail(code);}
}
function base64(value){
  if(typeof value!=='string'||
     !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value))
    fail('RETIREMENT_KEY');
  return Buffer.from(value,'base64');
}
function key(value){
  const der=base64(value);
  let parsed;
  try{parsed=createPublicKey({key:der,format:'der',type:'spki'});}
  catch{fail('RETIREMENT_KEY');}
  if(parsed.asymmetricKeyType!=='ed25519'||
     !parsed.export({format:'der',type:'spki'}).equals(der))fail('RETIREMENT_KEY');
  return {parsed,der};
}
function record(raw,keys,code){
  let parsed;
  try{parsed=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(raw));}
  catch{fail(code);}
  if(!parsed||typeof parsed!=='object'||Array.isArray(parsed)||
     JSON.stringify(Object.keys(parsed))!==JSON.stringify(keys)||
     !raw.equals(Buffer.from(JSON.stringify(parsed),'utf8')))fail(code);
  return parsed;
}
function signed(envelope,domain,publicKey,keys,code){
  if(!envelope||typeof envelope!=='object')fail(code);
  const raw=bytes(envelope.raw,code);
  const signature=bytes(envelope.signature,code);
  if(signature.length!==64||
     !verify(null,Buffer.concat([domain,raw]),publicKey,signature))fail(code);
  return {record:record(raw,keys,code),raw,signature};
}
function snapshotPublication(value){
  if(!value)fail('RETIREMENT_INPUT');
  const sourceEntries=value.entries;
  const sourceHead=value.head;
  const sourceMonitor=value.monitor;
  const sourceProof=value.proof;
  if(!Array.isArray(sourceEntries)||!sourceHead||!sourceMonitor)
    fail('RETIREMENT_INPUT');
  const count=sourceEntries.length;
  const entries=[];
  for(let i=0;i<count;i++)entries.push(bytes(sourceEntries[i],'RETIREMENT_INPUT'));
  const head={raw:bytes(sourceHead.raw,'RETIREMENT_INPUT'),
    signature:bytes(sourceHead.signature,'RETIREMENT_INPUT')};
  const monitor={raw:bytes(sourceMonitor.raw,'RETIREMENT_INPUT'),
    signature:bytes(sourceMonitor.signature,'RETIREMENT_INPUT')};
  const proof=bytes(sourceProof,'RETIREMENT_INPUT');
  return {entries,head,monitor,proof};
}
function expectedPublicationItems(publication){
  const expected=new Map();
  const add=(id,role,original)=>expected.set(id,{role,sha256:sha(original)});
  add('publication-head','publication-head',Buffer.concat([
    publication.head.raw,publication.head.signature]));
  add('monitor-observation','monitor-observation',Buffer.concat([
    publication.monitor.raw,publication.monitor.signature]));
  add('consistency-proof','consistency-proof',publication.proof);
  for(const [index,entry] of publication.entries.entries())
    add(`log-entry:${index}`,'publication-entry',entry);
  return expected;
}

// An independently signed inventory binds a declared byte set to an already
// witnessed log prefix. Signed archive receipts and supplied original bytes
// can establish availability of that set at one claimed check time only.
// Neither the inventory nor the claimed final head proves all real actions.
export function assessRawRetirementClosure({policy,publication,manifest,retrieved,checkAt}){
  if(!policy||!Array.isArray(retrieved))
    fail('RETIREMENT_INPUT');
  const selectedRequired=policy.required;
  if(!Array.isArray(selectedRequired))fail('RETIREMENT_INPUT');
  const profileId=policy.profileId,issuerId=policy.issuerId;
  const retiredAt=policy.retiredAt,documentThrough=policy.documentThrough;
  const archiveId=policy.archiveId;
  const inventorySpki=policy.inventoryPublicKeySpkiBase64;
  const archiveSpki=policy.archivePublicKeySpkiBase64;
  const publicationPolicy=policy.publicationPolicy;
  const selectedAnchor=policy.publicationAnchor;
  if(!publicationPolicy||!selectedAnchor)fail('RETIREMENT_INPUT');
  const anchor={treeSize:selectedAnchor.treeSize,
    rootSha256:selectedAnchor.rootSha256};
  const logId=publicationPolicy.logId,monitorId=publicationPolicy.monitorId;
  const logSpki=publicationPolicy.logPublicKeySpkiBase64;
  const monitorSpki=publicationPolicy.monitorPublicKeySpkiBase64;
  const required=[];
  const requiredCount=selectedRequired.length;
  for(let i=0;i<requiredCount;i++){
    const item=selectedRequired[i];
    if(!item)fail('RETIREMENT_INPUT');
    required.push({id:item.id,role:item.role});
  }
  if(![profileId,issuerId,archiveId,logId,monitorId].every(label)||
     !time(retiredAt)||!time(documentThrough)||documentThrough<retiredAt||
     !time(checkAt)||checkAt<retiredAt||
     !requiredRoles.every(role=>required.some(x=>x.role===role))||
     required.some(x=>!label(x.id)||!label(x.role))||
     new Set(required.map(x=>x.id)).size!==required.length)
    fail('RETIREMENT_INPUT');
  const inventoryKey=key(inventorySpki),archiveKey=key(archiveSpki);
  const logKey=key(logSpki),monitorKey=key(monitorSpki);
  const keys=[inventoryKey.der,archiveKey.der,logKey.der,monitorKey.der];
  for(let i=0;i<keys.length;i++)for(let j=0;j<i;j++)
    if(keys[i].equals(keys[j]))fail('RETIREMENT_KEY');
  const original=snapshotPublication(publication);
  const witness=assessRawPublicationWitness({
    policy:{logId,monitorId,logPublicKeySpkiBase64:logSpki,
      monitorPublicKeySpkiBase64:monitorSpki},...original,anchor,knownAt:checkAt});
  const claim=signed(manifest,MANIFEST_DOMAIN,inventoryKey.parsed,
    manifestKeys,'RETIREMENT_MANIFEST');
  const m=claim.record;
  if(m.version!==1||m.profileId!==profileId||m.issuerId!==issuerId||
     m.logId!==logId||m.retiredAt!==retiredAt||
     m.documentThrough!==documentThrough||!time(m.declaredAt)||
     m.declaredAt<retiredAt||m.declaredAt<witness.observedAt||
     m.declaredAt>checkAt||
     m.claimedFinalHeadSha256!==witness.headSha256||!Array.isArray(m.items))
    fail('RETIREMENT_MANIFEST');
  const expected=expectedPublicationItems(original);
  for(const item of required){
    if(expected.has(item.id))fail('RETIREMENT_INPUT');
    expected.set(item.id,{role:item.role});
  }
  if(m.items.length!==expected.size)fail('RETIREMENT_MANIFEST_SCOPE');
  const byId=new Map();
  let prior='';
  for(const item of m.items){
    if(!item||JSON.stringify(Object.keys(item))!==JSON.stringify(itemKeys)||
       !label(item.id)||!label(item.role)||!hex(item.sha256)||
       !time(item.retainThrough)||item.retainThrough<documentThrough||
       item.id<=prior)fail('RETIREMENT_MANIFEST_SCOPE');
    const selected=expected.get(item.id);
    if(!selected||selected.role!==item.role||
       (selected.sha256&&selected.sha256!==item.sha256))
      fail('RETIREMENT_MANIFEST_SCOPE');
    byId.set(item.id,item);
    prior=item.id;
  }
  if(checkAt>documentThrough)return {decision:'OUT_OF_SCOPE',
    publication:witness.decision,claimedFinalHeadSha256:witness.headSha256,
    manifestSha256:sha(claim.raw),checkAt,reasons:[]};
  const provided=new Map();
  const retrievedCount=retrieved.length;
  for(let i=0;i<retrievedCount;i++){
    const item=retrieved[i];
    const id=item?.id;
    if(!label(id)||!byId.has(id)||provided.has(id))
      fail('RETIREMENT_RETRIEVAL');
    const originalBytes=item.bytes;
    provided.set(id,{bytes:originalBytes==null?null:
      bytes(originalBytes,'RETIREMENT_RETRIEVAL'),
      receipt:item.receipt});
  }
  const reasons=[];
  for(const [id,item] of byId){
    const found=provided.get(id);
    if(!found||found.bytes===null){
      reasons.push({id,code:'RETIREMENT_BYTES_MISSING'});
      continue;
    }
    const actual=sha(found.bytes);
    if(actual!==item.sha256){
      reasons.push({id,code:'RETIREMENT_BYTES_MISMATCH'});
      continue;
    }
    if(!found.receipt){
      reasons.push({id,code:'RETIREMENT_RECEIPT_MISSING'});
      continue;
    }
    const receipt=signed(found.receipt,RECEIPT_DOMAIN,archiveKey.parsed,
      receiptKeys,'RETIREMENT_RECEIPT');
    const r=receipt.record;
    if(r.version!==1||r.archiveId!==archiveId||r.itemId!==id||
       r.sha256!==actual||!time(r.observedAt)||r.observedAt!==checkAt)
      reasons.push({id,code:'RETIREMENT_RECEIPT_SCOPE'});
  }
  return {decision:reasons.some(x=>x.code==='RETIREMENT_BYTES_MISMATCH')?
    'REJECTED':reasons.length?'INDETERMINATE':'BOUND_RETIREMENT_RETRIEVAL_CLAIMS',
  publication:witness.decision,claimedFinalHeadSha256:witness.headSha256,
  manifestSha256:sha(claim.raw),checkAt,itemCount:byId.size,reasons};
}

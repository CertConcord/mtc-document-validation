import {createHash,createPublicKey,verify} from 'node:crypto';
import {TextDecoder,types} from 'node:util';
import {verifyMtcLogConsistencyProof} from './raw-mtc-log-consistency.mjs';

const HEAD_DOMAIN=Buffer.from('MTC-DV-PUBLICATION-HEAD-v1\0','ascii');
const MONITOR_DOMAIN=Buffer.from('MTC-DV-PUBLICATION-MONITOR-v1\0','ascii');
const headKeys=['version','logId','treeSize','rootSha256','issuedAt'];
const monitorKeys=['version','monitorId','logId','headSha256','observedAt'];
const fail=code=>{const error=new Error(code);error.code=code;throw error;};
const sha=bytes=>createHash('sha256').update(bytes).digest();
const hex=value=>typeof value==='string'&&/^[a-f0-9]{64}$/.test(value);
const label=value=>typeof value==='string'&&/^[\x21-\x7e]+$/.test(value);
const instant=value=>Number.isSafeInteger(value)&&value>=0;
const treeSize=value=>Number.isSafeInteger(value)&&value>0&&value<2**48;
const nativeArray=Object.getPrototypeOf(Uint8Array.prototype);
const getBuffer=Object.getOwnPropertyDescriptor(nativeArray,'buffer').get;
const getByteOffset=Object.getOwnPropertyDescriptor(nativeArray,'byteOffset').get;
const getByteLength=Object.getOwnPropertyDescriptor(nativeArray,'byteLength').get;

function nativeBytes(value,code){
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
function strictBase64(value,code){
  if(typeof value!=='string'||
     !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value))fail(code);
  return Buffer.from(value,'base64');
}
function key(value){
  const der=strictBase64(value,'PUBLICATION_KEY');
  let parsed;
  try{parsed=createPublicKey({key:der,format:'der',type:'spki'});}
  catch{fail('PUBLICATION_KEY');}
  if(parsed.asymmetricKeyType!=='ed25519'||
     !parsed.export({format:'der',type:'spki'}).equals(der))fail('PUBLICATION_KEY');
  return parsed;
}
function record(raw,keys,code){
  let value;
  try{value=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(raw));}
  catch{fail(code);}
  if(!value||typeof value!=='object'||Array.isArray(value)||
     JSON.stringify(Object.keys(value))!==JSON.stringify(keys)||
     !raw.equals(Buffer.from(JSON.stringify(value),'utf8')))fail(code);
  return value;
}
function envelope(value,keys,domain,publicKey,code){
  if(!value||typeof value!=='object')fail(code);
  const raw=nativeBytes(value.raw,code);
  const signature=nativeBytes(value.signature,code);
  if(signature.length!==64)fail(code);
  const parsed=record(raw,keys,code);
  if(!verify(null,Buffer.concat([domain,raw]),publicKey,signature))fail(code);
  return {parsed,raw};
}
const branch=(left,right)=>sha(Buffer.concat([Buffer.from([1]),left,right]));
function root(nodes){
  if(nodes.length===1)return nodes[0];
  const split=2**Math.floor(Math.log2(nodes.length-1));
  return branch(root(nodes.slice(0,split)),root(nodes.slice(split)));
}

// Application profile using RFC 9162's SHA-256 tree construction. These are
// CertConcord signed records, not RFC 9162 CT signed tree heads or SCITT receipts.
// The result covers logged bytes at this head only; submission and clock truth
// remain independent obligations.
export function assessRawPublicationWitness({policy,entries,head,monitor,anchor,proof,knownAt}){
  if(!policy||!anchor||!Array.isArray(entries))fail('PUBLICATION_INPUT');
  const logId=policy.logId;
  const monitorId=policy.monitorId;
  const logKeySpki=policy.logPublicKeySpkiBase64;
  const monitorKeySpki=policy.monitorPublicKeySpkiBase64;
  const anchorSize=anchor.treeSize;
  const anchorRoot=anchor.rootSha256;
  const entryCount=entries.length;
  if(!label(logId)||!label(monitorId)||!instant(knownAt)||
     !treeSize(entryCount)||!Number.isSafeInteger(anchorSize)||anchorSize<0||
     anchorSize>=entryCount||!hex(anchorRoot))fail('PUBLICATION_INPUT');
  const logKey=key(logKeySpki);
  const monitorKey=key(monitorKeySpki);
  if(logKey.export({format:'der',type:'spki'}).equals(
       monitorKey.export({format:'der',type:'spki'})))fail('PUBLICATION_KEY');
  const original=[];
  for(let index=0;index<entryCount;index++)
    original.push(nativeBytes(entries[index],'PUBLICATION_ENTRY'));
  const leaves=original.map(entry=>sha(Buffer.concat([Buffer.from([0]),entry])));
  const computed=root(leaves).toString('hex');
  const signedHead=envelope(head,headKeys,HEAD_DOMAIN,logKey,'PUBLICATION_HEAD');
  const h=signedHead.parsed;
  if(h.version!==1||h.logId!==logId||h.treeSize!==entryCount||
     !hex(h.rootSha256)||h.rootSha256!==computed||!instant(h.issuedAt))
    fail('PUBLICATION_HEAD');
  const priorRoot=anchorSize===0?sha(Buffer.alloc(0)).toString('hex'):
    root(leaves.slice(0,anchorSize)).toString('hex');
  if(anchorRoot!==priorRoot)fail('PUBLICATION_ANCHOR');
  const path=nativeBytes(proof,'PUBLICATION_CONSISTENCY');
  if(anchorSize===0){if(path.length)fail('PUBLICATION_CONSISTENCY');}
  else{
    try{verifyMtcLogConsistencyProof({firstSize:anchorSize,
      secondSize:h.treeSize,firstRoot:Buffer.from(anchorRoot,'hex'),
      secondRoot:Buffer.from(computed,'hex'),proof:path});}
    catch{fail('PUBLICATION_CONSISTENCY');}
  }
  const witnessed=envelope(monitor,monitorKeys,MONITOR_DOMAIN,monitorKey,'PUBLICATION_MONITOR');
  const m=witnessed.parsed;
  if(m.version!==1||m.monitorId!==monitorId||m.logId!==logId||
     m.headSha256!==sha(signedHead.raw).toString('hex')||
     !instant(m.observedAt)||m.observedAt<h.issuedAt||m.observedAt>knownAt)
    fail('PUBLICATION_MONITOR');
  return {decision:'MONITORED_STREAM_THROUGH',logId:h.logId,treeSize:h.treeSize,
    rootSha256:computed,headSha256:sha(signedHead.raw).toString('hex'),
    observedAt:m.observedAt,entrySha256:original.map(x=>sha(x).toString('hex'))};
}

import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {readFileSync,readdirSync} from 'node:fs';
import {resolve,dirname,join} from 'node:path';
import {fileURLToPath} from 'node:url';
const root=resolve(dirname(fileURLToPath(import.meta.url)),'..');
const json=p=>JSON.parse(readFileSync(join(root,p),'utf8'));
assert.equal(json('draft.json').stable,false);
assert.equal(json('package.json').private,true);
assert.equal(new Set(json('cases.json').cases.map(x=>x.id)).size,json('cases.json').cases.length);
const history = json('vectors/history.json');
const historyCases = json('cases.json').cases.filter(x=>x.component==='history');
assert.equal(history.format,'original-synthetic-authenticated-facts-v1');
assert.deepEqual(historyCases.map(x=>[x.id,x.expected]),
  history.cases.map(x=>[x.id,x.expected.decision]));
for(const v of history.cases){for(const id of v.factIds)assert(Object.hasOwn(history.facts,id),id);}
const rawStatus = json('vectors/raw-status-cases.json');
const rawStatusCases = json('cases.json').cases.filter(x=>x.component==='raw-status');
assert.equal(rawStatus.format,'original-der-status-observation-cases-v1');
assert.deepEqual(rawStatusCases.map(x=>[x.id,x.expected]),
  rawStatus.cases.map(x=>[x.id,x.expected]));
const rawDer = json('vectors/raw-status-der.json');
assert.equal(rawDer.format,'frozen-der-status-corpus-v1');
for(const [id,item] of Object.entries(rawDer.objects)){
  const bytes=Buffer.from(item.derBase64,'base64');
  assert.equal(bytes.length,item.bytes,id);
  assert.equal(createHash('sha256').update(bytes).digest('hex'),item.sha256,id);
}
for(const v of rawStatus.cases){
  for(const id of [v.record,v.target,v.issuer,v.responder,v.request,v.policyIssuer,v.receiptRecord])
    if(id!==undefined)assert(Object.hasOwn(rawDer.objects,id),`${v.id}: ${id}`);
}
const timestampVectors=json('vectors/raw-timestamp-cases.json');
const timestampCases=json('cases.json').cases.filter(x=>x.component==='raw-timestamp');
assert.equal(timestampVectors.format,'original-der-timestamp-observation-cases-v1');
assert.deepEqual(timestampCases.map(x=>[x.id,x.expected]),
  timestampVectors.cases.map(x=>[x.id,x.expected]));
const timestampDer=json('vectors/raw-timestamp-der.json');
assert.equal(timestampDer.format,'frozen-rfc3161-der-corpus-v1');
for(const [id,item] of Object.entries(timestampDer.objects)){
  const bytes=Buffer.from(item.base64,'base64');
  assert.equal(bytes.length,item.bytes,id);
  assert.equal(createHash('sha256').update(bytes).digest('hex'),item.sha256,id);
}
for(const v of timestampVectors.cases){
  for(const id of [v.response,v.covered,v.tsa,v.issuer,v.policyTsa,v.policyIssuer])
    if(id!==undefined)assert(Object.hasOwn(timestampDer.objects,id),`${v.id}: ${id}`);
  if(v.request!==undefined&&v.request!==null)
    assert(Object.hasOwn(timestampDer.objects,v.request),`${v.id}: ${v.request}`);
}
const ersVectors=json('vectors/raw-ers-cases.json');
const ersCases=json('cases.json').cases.filter(x=>x.component==='raw-ers');
assert.equal(ersVectors.format,'original-rfc4998-one-object-cases-v1');
assert.deepEqual(ersCases.map(x=>[x.id,x.expected]),
  ersVectors.cases.map(x=>[x.id,x.expected]));
const ersDer=json('vectors/raw-ers-der.json');
assert.equal(ersDer.format,'frozen-rfc4998-original-der-corpus-v1');
for(const [id,item] of Object.entries(ersDer.objects)){
  const bytes=Buffer.from(item.base64,'base64');
  assert.equal(bytes.length,item.bytes,id);
  assert.equal(createHash('sha256').update(bytes).digest('hex'),item.sha256,id);
}
for(const v of ersVectors.cases){
  for(const id of [v.record,v.object??ersVectors.defaults.object,
      v.policyTsa??ersVectors.defaults.tsa,v.policyIssuer??ersVectors.defaults.issuer])
    assert(Object.hasOwn(ersDer.objects,id),`${v.id}: ${id}`);
  assert(Object.hasOwn(ersVectors.requestSets,v.requestSet),`${v.id}: requestSet`);
  for(const row of ersVectors.requestSets[v.requestSet])for(const id of row)
    if(id!==null)assert(Object.hasOwn(ersDer.objects,id),`${v.id}: ${id}`);
  if(v.signedControl)assert(Object.hasOwn(ersDer.objects,v.signedControl.preimage),
    `${v.id}: signed control`);
}
const rawAuthority=json('vectors/raw-authority-cases.json');
const authorityBytes=json('vectors/raw-authority-bytes.json');
assert.equal(rawAuthority.format,'original-signed-authority-history-cases-v1');
assert.equal(authorityBytes.format,'frozen-original-ed25519-authority-claims-v1');
assert.deepEqual(json('cases.json').cases.filter(x=>x.component==='raw-authority-history')
  .map(x=>[x.id,x.expected]),rawAuthority.cases.map(x=>[x.id,x.error??x.expected]));
for(const [id,item] of Object.entries(authorityBytes.objects)){
  const raw=Buffer.from(item.rawBase64,'base64');
  const sig=Buffer.from(item.signatureBase64,'base64');
  assert.equal(raw.length,item.rawBytes,id);
  assert.equal(createHash('sha256').update(raw).digest('hex'),item.rawSha256,id);
  assert.equal(createHash('sha256').update(sig).digest('hex'),item.signatureSha256,id);
}
for(const v of rawAuthority.cases)for(const id of v.records)
  assert(Object.hasOwn(authorityBytes.objects,id),`${v.id}: ${id}`);
for(const s of json('sources.json').sources){assert(s.url.startsWith('https://'));assert(/^[a-f0-9]{64}$/.test(s.sha256));}
function walk(dir=''){for(const e of readdirSync(join(root,dir),{withFileTypes:true})){if(['.git','.runtime','node_modules'].includes(e.name))continue;const p=join(dir,e.name);if(e.isDirectory())walk(p);else{const t=readFileSync(join(root,p),'utf8');assert(!/\p{Script=Han}/u.test(t),p);assert(!/-----BEGIN (?:RSA |EC )?PRIVATE KEY-----/.test(t),p);assert(!/github_pat_[A-Za-z0-9_]{40,}|gh[pousr]_[A-Za-z0-9]{30,}/.test(t),p);}}}
walk();console.log('Draft sources, cases and publication content verified');

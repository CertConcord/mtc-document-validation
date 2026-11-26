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
for(const s of json('sources.json').sources){assert(s.url.startsWith('https://'));assert(/^[a-f0-9]{64}$/.test(s.sha256));}
function walk(dir=''){for(const e of readdirSync(join(root,dir),{withFileTypes:true})){if(['.git','.runtime','node_modules'].includes(e.name))continue;const p=join(dir,e.name);if(e.isDirectory())walk(p);else{const t=readFileSync(join(root,p),'utf8');assert(!/\p{Script=Han}/u.test(t),p);assert(!/-----BEGIN (?:RSA |EC )?PRIVATE KEY-----/.test(t),p);assert(!/github_pat_[A-Za-z0-9_]{40,}|gh[pousr]_[A-Za-z0-9]{30,}/.test(t),p);}}}
walk();console.log('Draft sources, cases and publication content verified');

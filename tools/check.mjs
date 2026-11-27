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
const exactTime=json('vectors/lifetime-microseconds.json');
assert.equal(exactTime.format,'original-rfc3161-ers-preservation-microseconds-v1');
assert.deepEqual(json('cases.json').cases.filter(x=>x.component==='lifetime-microseconds')
  .map(x=>[x.id,x.expected]),exactTime.cases.map(x=>[x.id,x.expected]));
for(const [id,source] of Object.entries(exactTime.sources)){
  const original=ersVectors.cases.find(x=>x.id===source.rawCase);
  assert(original&&original.expected==='BOUND_CLAIMS',id);
  assert.equal(ersDer.objects[original.record].sha256,source.recordSha256,id);
  assert.equal(source.records.length,original.observationCount,id);
}
for(const vector of exactTime.cases)
  assert(Object.hasOwn(exactTime.sources,vector.source)||
    vector.source==='fractionalTimestamp',vector.id);
const fractional=timestampVectors.cases.find(x=>
  x.id===exactTime.fractionalTimestamp.rawCase);
assert(fractional&&fractional.expected==='SIGNED_CLAIM');
assert.equal(timestampDer.objects[fractional.response].sha256,
  exactTime.fractionalTimestamp.responseSha256);
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
const witness=json('vectors/raw-publication-witness.json');
const witnessCases=json('vectors/raw-publication-witness-cases.json');
assert.equal(witness.format,'frozen-original-publication-witness-v1');
assert.equal(witnessCases.format,'original-publication-witness-cases-v1');
assert.deepEqual(json('cases.json').cases.filter(x=>x.component==='raw-publication-witness')
  .map(x=>[x.id,x.expected]),witnessCases.cases.map(x=>[x.id,x.expected]));
for(const entry of witness.entries){
  const original=authorityBytes.objects[entry.id];
  assert(original,entry.id);
  const bytes=Buffer.from(entry.base64,'base64');
  assert.equal(bytes.toString('base64'),entry.base64,entry.id);
  assert.equal(bytes.length,entry.bytes,entry.id);
  assert.equal(createHash('sha256').update(bytes).digest('hex'),entry.sha256,entry.id);
  assert(bytes.equals(Buffer.concat([Buffer.from(original.rawBase64,'base64'),
    Buffer.from(original.signatureBase64,'base64')])),entry.id);
}
for(const [kind,records] of [['heads',witness.heads],
    ['observations',witness.observations]])
  for(const [name,item] of Object.entries(records)){
    const raw=Buffer.from(item.rawBase64,'base64');
    const signature=Buffer.from(item.signatureBase64,'base64');
    assert.equal(raw.length,item.rawBytes,`${kind}: ${name}`);
    assert.equal(createHash('sha256').update(raw).digest('hex'),item.rawSha256,
      `${kind}: ${name}`);
    assert.equal(createHash('sha256').update(signature).digest('hex'),
      item.signatureSha256,`${kind}: ${name}`);
  }
const retirement=json('vectors/raw-retirement-closure.json');
const retirementCases=json('vectors/raw-retirement-closure-cases.json');
assert.equal(retirement.format,'frozen-original-retirement-closure-v1');
assert.equal(retirementCases.format,'original-retirement-closure-cases-v1');
assert.deepEqual(retirement.policy.publicationAnchor,witness.anchor);
assert.deepEqual(json('cases.json').cases.filter(x=>x.component==='raw-retirement-closure')
  .map(x=>[x.id,x.expected]),retirementCases.cases.map(x=>[x.id,x.expected]));
const retirementObjectSources={
  document:ersDer.objects.document.sha256,
  'mtc-certificate':json('vectors/raw-mtc-der.json').objects['standalone-one'].sha256,
  'historical-status':rawDer.objects['good-ca'].sha256,
  'preservation-evidence':ersDer.objects['ers-initial'].sha256
};
for(const [id,item] of Object.entries(retirement.objects)){
  const raw=Buffer.from(item.base64,'base64');
  assert.equal(raw.toString('base64'),item.base64,id);
  assert.equal(raw.length,item.bytes,id);
  assert.equal(createHash('sha256').update(raw).digest('hex'),item.sha256,id);
  if(retirementObjectSources[id])assert.equal(item.sha256,retirementObjectSources[id],id);
}
const authorityPair=Buffer.concat(['samecut-1','samecut-2'].flatMap(id=>[
  Buffer.from(authorityBytes.objects[id].rawBase64,'base64'),
  Buffer.from(authorityBytes.objects[id].signatureBase64,'base64')]));
assert.equal(createHash('sha256').update(authorityPair).digest('hex'),
  retirement.objects['authority-history'].sha256);
const checkSigned=(item,id)=>{
  const raw=Buffer.from(item.rawBase64,'base64');
  const signature=Buffer.from(item.signatureBase64,'base64');
  assert.equal(raw.length,item.rawBytes,id);
  assert.equal(createHash('sha256').update(raw).digest('hex'),item.rawSha256,id);
  assert.equal(createHash('sha256').update(signature).digest('hex'),
    item.signatureSha256,id);
};
for(const [name,bundle] of Object.entries(retirement.bundles)){
  checkSigned(bundle.manifest,`${name}: manifest`);
  for(const [id,item] of Object.entries(bundle.receipts))
    checkSigned(item,`${name}: ${id}`);
}
for(const [id,item] of Object.entries(retirement.controls))
  checkSigned(item,`control: ${id}`);
const mtcVectors=json('vectors/raw-mtc-cases.json');
const mtcDer=json('vectors/raw-mtc-der.json');
assert.equal(mtcVectors.format,'original-mtc07-issuance-cases-v1');
assert.equal(mtcDer.format,'frozen-original-mtc07-der-corpus-v1');
assert.deepEqual(json('cases.json').cases.filter(x=>x.component==='raw-mtc-issuance')
  .map(x=>[x.id,x.expected]),mtcVectors.cases.map(x=>[x.id,x.expected]));
assert.deepEqual(json('cases.json').cases.filter(x=>x.component==='raw-mtc-log-id')
  .map(x=>[x.id,x.expected]),mtcVectors.logIdCases.map(x=>[x.id,x.expected]));
for(const v of mtcVectors.logIdCases){
  assert(/^(?:[a-f0-9]{2})+$/.test(v.caIdHex),v.id);
  if(v.expected==='ADMITTED')
    assert.equal(Buffer.from(v.expectedBinaryHex,'hex').length,32,v.id);
}
for(const [id,item] of Object.entries(mtcDer.objects)){
  const bytes=Buffer.from(item.base64,'base64');
  assert.equal(bytes.length,item.bytes,id);
  assert.equal(createHash('sha256').update(bytes).digest('hex'),item.sha256,id);
}
for(const v of mtcVectors.cases){
  assert(Object.hasOwn(mtcDer.objects,v.certificate),`${v.id}: certificate`);
  assert(Object.hasOwn(mtcDer.policies,v.policy),`${v.id}: policy`);
}
const mtcConsistency=json('vectors/raw-mtc-consistency.json');
assert.equal(mtcConsistency.format,'original-mtc07-subtree-consistency-cases-v1');
assert.deepEqual(json('cases.json').cases.filter(x=>x.component==='raw-mtc-consistency')
  .map(x=>[x.id,x.expected]),mtcConsistency.cases.map(x=>[x.id,x.expected]));
assert.deepEqual(json('cases.json').cases.filter(x=>x.component==='raw-mtc-covering')
  .map(x=>[x.id,x.expected]),mtcConsistency.coveringCases.map(x=>[x.id,x.expected]));
for(const leaf of mtcConsistency.leafInputs){
  const original=Buffer.from(leaf.base64,'base64');
  assert.equal(createHash('sha256').update(Buffer.concat([Buffer.from([0]),original]))
    .digest('hex'),leaf.sha256,leaf.id);
}
for(const v of mtcConsistency.cases){
  for(const field of ['subtreeHashHex','rootHashHex'])
    assert(/^[a-f0-9]{64}$/.test(v[field]),v.id);
  assert(/^(?:[a-f0-9]{2})*$/.test(v.proofHex),v.id);
  if(v.expected==='VERIFIED')
    assert.equal(Buffer.from(v.proofHex,'hex').length%32,0,v.id);
}
const mtcLandmark=json('vectors/raw-mtc-landmark-publication.json');
assert.equal(mtcLandmark.format,'original-mtc07-landmark-publication-cases-v1');
assert.deepEqual(json('cases.json').cases.filter(x=>x.component==='raw-mtc-landmark-publication')
  .map(x=>[x.id,x.expected]),mtcLandmark.cases.map(x=>[x.id,x.expected]));
assert.deepEqual(json('cases.json').cases.filter(x=>x.component==='raw-mtc-landmark-selection')
  .map(x=>[x.id,x.expected]),mtcLandmark.selectionCases.map(x=>[x.id,x.expected]));
for(const v of mtcLandmark.cases){
  const raw=Buffer.from(v.rawBase64,'base64');
  assert.equal(createHash('sha256').update(raw).digest('hex'),v.sha256,v.id);
}
const mtcRelative=json('vectors/raw-mtc-relative.json');
const mtcRelativeCases=json('vectors/raw-mtc-relative-cases.json');
assert.equal(mtcRelative.format,'frozen-original-mtc07-relative-proof-corpus-v1');
assert.equal(mtcRelativeCases.format,'original-mtc07-relative-issuance-cases-v1');
assert.deepEqual(json('cases.json').cases.filter(x=>x.component==='raw-mtc-relative-issuance')
  .map(x=>[x.id,x.expected]),mtcRelativeCases.cases.map(x=>[x.id,x.expected]));
const checkRelativeBytes=(item,id)=>{
  const raw=Buffer.from(item.base64,'base64');
  assert.equal(raw.toString('base64'),item.base64,id);
  assert.equal(raw.length,item.bytes,id);
  assert.equal(createHash('sha256').update(raw).digest('hex'),item.sha256,id);
};
for(const [id,item] of Object.entries(mtcRelative.objects))
  checkRelativeBytes(item,id);
checkRelativeBytes(mtcRelative.publication,'publication');
for(const [id,item] of Object.entries(mtcRelative.checkpoints)){
  checkRelativeBytes(item.message,`${id}: message`);
  checkRelativeBytes(item.signature,`${id}: signature`);
}
assert.equal(mtcRelative.policy.landmarkPublicationSha256,
  mtcRelative.publication.sha256);
for(const v of mtcRelativeCases.cases){
  if(v.certificate)assert(Object.hasOwn(mtcRelative.objects,v.certificate),v.id);
  for(const key of v.checkpointKeys??['ca','mirror'])
    assert(Object.hasOwn(mtcRelative.checkpoints,key),v.id);
}
const mtcMultileaf=json('vectors/raw-mtc-relative-multileaf.json');
const mtcMultileafCases=json('vectors/raw-mtc-relative-multileaf-cases.json');
assert.equal(mtcMultileaf.format,'frozen-original-mtc07-relative-multileaf-direct-v1');
assert.equal(mtcMultileafCases.format,'original-mtc07-relative-multileaf-direct-cases-v1');
assert.deepEqual(json('cases.json').cases.filter(x=>x.component==='raw-mtc-relative-multileaf')
  .map(x=>[x.id,x.expected]),mtcMultileafCases.cases.map(x=>[x.id,x.expected]));
checkRelativeBytes(mtcMultileaf.certificate,'multileaf certificate');
checkRelativeBytes(mtcMultileaf.publication,'multileaf publication');
assert.equal(mtcMultileaf.policy.landmarkPublicationSha256,
  mtcMultileaf.publication.sha256);
for(const entry of mtcMultileaf.logEntries){
  checkRelativeBytes(entry,entry.id);
  assert.equal(createHash('sha256').update(Buffer.concat([Buffer.from([0]),
    Buffer.from(entry.base64,'base64')])).digest('hex'),entry.leafSha256,entry.id);
}
for(const [id,item] of Object.entries(mtcMultileaf.checkpoints)){
  checkRelativeBytes(item.message,`${id}: message`);
  checkRelativeBytes(item.signature,`${id}: signature`);
}
assert.notEqual(mtcMultileaf.selectedSubtree.rootSha256,
  mtcMultileaf.reference.rootSha256);
assert(/^(?:[a-f0-9]{64})+$/.test(mtcMultileaf.selectedSubtree.proofHex));
const mtcLogConsistency=json('vectors/raw-mtc-log-consistency.json');
assert.equal(mtcLogConsistency.format,'frozen-original-rfc9162-mtc-log-consistency-v1');
assert.deepEqual(json('cases.json').cases.filter(x=>x.component==='raw-mtc-log-consistency')
  .map(x=>[x.id,x.expected]),mtcLogConsistency.cases.map(x=>[x.id,x.expected]));
for(const item of mtcLogConsistency.leafInputs){
  const raw=Buffer.from(item.base64,'base64');
  assert.equal(raw.toString('base64'),item.base64,item.id);
  assert.equal(raw.length,item.bytes,item.id);
  assert.equal(createHash('sha256').update(Buffer.concat([Buffer.from([0]),raw]))
    .digest('hex'),item.leafSha256,item.id);
}
for(const item of mtcLogConsistency.cases){
  for(const field of ['firstRootHex','secondRootHex'])
    assert(/^[a-f0-9]{64}$/.test(item[field]),item.id);
  assert(/^(?:[a-f0-9]{2})*$/.test(item.proofHex),item.id);
}
const mtcLater=json('vectors/raw-mtc-later-checkpoint.json');
const mtcLaterCases=json('vectors/raw-mtc-later-checkpoint-cases.json');
assert.equal(mtcLater.format,'frozen-original-mtc07-later-checkpoint-corpus-v1');
assert.equal(mtcLaterCases.format,'original-mtc07-later-checkpoint-cases-v1');
assert.deepEqual(json('cases.json').cases.filter(x=>x.component==='raw-mtc-later-checkpoint')
  .map(x=>[x.id,x.expected]),mtcLaterCases.cases.map(x=>[x.id,x.expected]));
checkRelativeBytes(mtcLater.certificate,'later certificate');
checkRelativeBytes(mtcLater.publication,'later publication');
assert.equal(mtcLater.policy.landmarkPublicationSha256,
  mtcLater.publication.sha256);
for(const entry of mtcLater.logEntries){
  checkRelativeBytes(entry,entry.id);
  assert.equal(createHash('sha256').update(Buffer.concat([Buffer.from([0]),
    Buffer.from(entry.base64,'base64')])).digest('hex'),entry.leafSha256,entry.id);
}
for(const [id,item] of Object.entries(mtcLater.checkpoints)){
  checkRelativeBytes(item.message,`${id}: message`);
  checkRelativeBytes(item.signature,`${id}: signature`);
}
for(const [id,hex] of Object.entries(mtcLater.logConsistency))
  assert(/^(?:[a-f0-9]{64})+$/.test(hex),id);
for(const vector of mtcLaterCases.cases){
  for(const item of vector.signatures){
    assert(Object.hasOwn(mtcLater.checkpoints,item.key),vector.id);
    if(item.proof)assert(Object.hasOwn(mtcLater.logConsistency,item.proof),vector.id);
  }
}
const activeSet=json('vectors/raw-mtc-active-subtree-set.json');
const activeCases=json('vectors/raw-mtc-active-subtree-cases.json');
assert.equal(activeSet.format,'frozen-original-mtc07-active-subtree-set-v1');
assert.equal(activeCases.format,'original-mtc07-active-subtree-admission-cases-v1');
assert.deepEqual(json('cases.json').cases.filter(x=>x.component==='raw-mtc-active-subtrees')
  .map(x=>[x.id,x.expected]),activeCases.cases.map(x=>[x.id,x.expected]));
for(const [id,item] of Object.entries(activeSet.publications)){
  checkRelativeBytes(item,`${id}: publication`);
  assert(activeSet.sourceCorpora.includes(item.sourceCorpus),id);
  assert(/^[a-f0-9]{64}$/.test(item.referenceRootHex),id);
  const source=item.sourceCorpus==='raw-mtc-later-checkpoint.json'?
    mtcLater:mtcMultileaf;
  for(const key of item.checkpointKeys)
    assert(Object.hasOwn(source.checkpoints,key),`${id}: ${key}`);
  for(const row of item.subtrees){
    assert(/^[a-f0-9]{64}$/.test(row.subtreeHashHex),id);
    assert(/^(?:[a-f0-9]{64})*$/.test(row.proofHex),id);
  }
}
for(const vector of activeCases.cases){
  assert(Object.hasOwn(activeSet.publications,vector.publication),vector.id);
  for(const field of ['evidenceSet','previousPublication','previousEvidenceSet'])
    if(vector[field])assert(Object.hasOwn(activeSet.publications,vector[field]),vector.id);
}
for(const s of json('sources.json').sources){assert(s.url.startsWith('https://'));assert(/^[a-f0-9]{64}$/.test(s.sha256));}
function walk(dir=''){for(const e of readdirSync(join(root,dir),{withFileTypes:true})){if(['.git','.runtime','node_modules'].includes(e.name))continue;const p=join(dir,e.name);if(e.isDirectory())walk(p);else{const t=readFileSync(join(root,p),'utf8');assert(!/\p{Script=Han}/u.test(t),p);assert(!/-----BEGIN (?:RSA |EC )?PRIVATE KEY-----/.test(t),p);assert(!/github_pat_[A-Za-z0-9_]{40,}|gh[pousr]_[A-Za-z0-9]{30,}/.test(t),p);}}}
walk();console.log('Draft sources, cases and publication content verified');

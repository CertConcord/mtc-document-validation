import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash, createPublicKey, verify} from 'node:crypto';
import {readFileSync} from 'node:fs';
import {assessRawTransferClaims} from './raw-transfer-claims.mjs';

const fixture = JSON.parse(readFileSync(new URL(
  '../vectors/raw-transfer-set-evolution.json', import.meta.url)));
const corpus = JSON.parse(readFileSync(new URL(
  '../vectors/coherent-document-evidence.json', import.meta.url)));
const base = JSON.parse(readFileSync(new URL(
  '../vectors/raw-transfer-claims.json', import.meta.url)));
const sha = value => createHash('sha256').update(value).digest('hex');
const decode = value => Buffer.from(value.base64, 'base64');
const original = value => Buffer.from(value.base64, 'base64');
const signed = value => Buffer.concat([
  Buffer.from(value.rawBase64, 'base64'),
  Buffer.from(value.signatureBase64, 'base64')]);
const oldSetRaw = decode(fixture.oldSet);
const newSetRaw = decode(fixture.newSet);
const oldSet = JSON.parse(oldSetRaw.toString('utf8'));
const newSet = JSON.parse(newSetRaw.toString('utf8'));
const manifestOriginal = decode(fixture.manifestOriginal);
const newItem = newSet.items.find(item => item.id === 'retirement-manifest');
const policy = {initialCustodianId: 'mtc-issuer', observerId: 'observer',
  selectedAt: oldSet.selectedAt,
  retiredAt: corpus.retirement.policy.retiredAt,
  documentThrough: corpus.retirement.policy.documentThrough,
  requiredSetSha256: fixture.oldSet.sha256,
  custodianKeys: ['mtc-issuer', 'archive-A', 'archive-B'].map(id =>
    ({id, publicKeySpkiBase64: fixture.policyKeys[id]})),
  observerPublicKeySpkiBase64: fixture.policyKeys.observer,
  successorSet: {selectedAt: newSet.selectedAt,
    requiredSetSha256: fixture.newSet.sha256,
    admittedNewItems: [{id: newItem.id, sha256: newItem.sha256,
      admittedAt: fixture.claimedTimes.manifestDeclaration}]}};
const originals = {...Object.fromEntries(Object.entries(
  corpus.retirement.originals).map(([id, value]) => [id, original(value)])),
  'publication-head': signed(corpus.retirement.publication.head),
  'monitor-observation': signed(corpus.retirement.publication.monitor),
  'consistency-proof': original(corpus.retirement.publication.proof),
  'retirement-manifest': manifestOriginal};
for (const [index, item] of corpus.retirement.publication.entries.entries())
  originals[`log-entry:${index}`] = original(item);

function checked(value) {
  const bytes = decode(value);
  assert.equal(bytes.length, value.bytes);
  assert.equal(sha(bytes), value.sha256);
  return bytes;
}
function handoff(name) {
  const item = fixture.signedRecords[name];
  return {raw: checked(item.raw),
    predecessorSignature: checked(item.predecessorSignature),
    successorSignature: checked(item.successorSignature)};
}
function observation(name) {
  const item = fixture.signedRecords[name];
  return {raw: checked(item.raw), signature: checked(item.signature)};
}
function replay(vector, override = {}) {
  const handoffs = vector.handoffs.map(handoff);
  const observations = vector.observations.map(observation);
  const supplied = [];
  for (const [index, envelope] of handoffs.entries()) {
    const row = JSON.parse(envelope.raw.toString('utf8'));
    for (const item of (index === 0 ? oldSet : newSet).items) {
      if (index === 1 && item.id === vector.missingAtSecond) continue;
      const bytes = Buffer.from(originals[item.id]);
      if (index === 1 && item.id === vector.substituteAtSecond)
        bytes[0] ^= 1;
      supplied.push({handoffId: row.id, itemId: item.id, bytes});
    }
  }
  return assessRawTransferClaims({policy: override.policy ?? policy,
    requiredSetRaw: oldSetRaw,
    successorSetRaw: override.successorSetRaw ?? newSetRaw,
    handoffs, observations, supplied});
}

test('original 23-to-24 item corpus, independent anchors and signatures', () => {
  assert.equal(fixture.format, 'original-signed-transfer-set-evolution-v1');
  assert.equal(fixture.sourceCorpus, 'vectors/coherent-document-evidence.json');
  assert.equal(sha(oldSetRaw), fixture.oldSet.sha256);
  assert.equal(sha(newSetRaw), fixture.newSet.sha256);
  assert.equal(oldSetRaw.toString('base64'), base.requiredSetRawBase64);
  assert.equal(newSet.previousSetSha256, fixture.oldSet.sha256);
  assert.equal(oldSet.items.length, 23);
  assert.equal(newSet.items.length, 24);
  assert.equal(sha(manifestOriginal), newItem.sha256);
  assert(manifestOriginal.equals(signed(corpus.retirement.manifest)));
  const manifest = corpus.retirement.manifest;
  const key = createPublicKey({key: Buffer.from(
    corpus.retirement.policy.inventoryPublicKeySpkiBase64, 'base64'),
    format: 'der', type: 'spki'});
  assert(verify(null, Buffer.concat([
    Buffer.from('MTC-DV-RETIREMENT-MANIFEST-v1\0', 'ascii'),
    Buffer.from(manifest.rawBase64, 'base64')]), key,
  Buffer.from(manifest.signatureBase64, 'base64')));
  assert.deepEqual(newSet.items.filter(item => item.id !== newItem.id),
    oldSet.items);
  assert.equal(fixture.claimedTimes.firstAcceptance,
    JSON.parse(checked(fixture.signedRecords.first.raw)).acceptedAt);
  assert(fixture.claimedTimes.manifestDeclaration < newSet.selectedAt);
  assert(newSet.selectedAt < fixture.claimedTimes.secondAcceptance);
  for (const item of newSet.items)
    assert.equal(sha(originals[item.id]), item.sha256, item.id);
  for (const [name, row] of Object.entries(fixture.signedRecords)) {
    const raw = checked(row.raw);
    const value = JSON.parse(raw.toString('utf8'));
    const domain = Buffer.from(`MTC-DV-TRANSFER-${
      row.signature ? 'OBSERVATION' : 'HANDOFF'}-v1\0`, 'ascii');
    const message = Buffer.concat([domain, raw]);
    if (row.signature) {
      const signer = createPublicKey({key: Buffer.from(
        fixture.policyKeys.observer, 'base64'), format: 'der', type: 'spki'});
      assert(verify(null, message, signer, checked(row.signature)), name);
    } else {
      for (const [id, signature] of [[value.fromId,
        row.predecessorSignature], [value.toId, row.successorSignature]]) {
        const signer = createPublicKey({key: Buffer.from(
          fixture.policyKeys[id], 'base64'), format: 'der', type: 'spki'});
        assert(verify(null, message, signer, checked(signature)), name);
      }
    }
  }
});

for (const vector of fixture.cases) test(vector.id, () => {
  const result = replay(vector);
  assert.equal(result.responsibility.decision,
    vector.expectedResponsibility);
  assert.equal(result.observationClaims.decision, vector.expectedBytes);
  assert.equal(result.requiredItemCount, 24);
  assert.equal(result.handoffCount, 2);
  assert.equal(result.successorSetSha256, fixture.newSet.sha256);
  assert(!Object.hasOwn(result, 'documentValid'));
});

for (const vector of fixture.setControls) test(vector.id, () => {
  const raw = Buffer.from(vector.rawBase64, 'base64');
  assert.equal(raw.length, vector.rawBytes);
  assert.equal(sha(raw), vector.independentlyAdmittedSha256);
  const selectedAt = JSON.parse(raw.toString('utf8')).selectedAt;
  const changed = {...policy, successorSet: {...policy.successorSet,
    selectedAt, requiredSetSha256: vector.independentlyAdmittedSha256}};
  assert.throws(() => replay(fixture.cases[0],
    {policy: changed, successorSetRaw: raw}), {code: vector.expected});
});

for (const vector of fixture.inputControls) test(vector.id, () => {
  let changed;
  if (vector.id === 'unadmitted-successor-set')
    changed = {...policy, successorSet: undefined};
  else if (vector.id === 'independent-successor-anchor-mismatch')
    changed = {...policy, successorSet: {...policy.successorSet,
      requiredSetSha256: '0'.repeat(64)}};
  else if (vector.id === 'new-item-admitted-before-first-handoff')
    changed = {...policy, successorSet: {...policy.successorSet,
      admittedNewItems: [{...policy.successorSet.admittedNewItems[0],
        admittedAt: fixture.claimedTimes.firstAcceptance}]}};
  else assert.fail(`unknown input control: ${vector.id}`);
  assert.throws(() => replay(fixture.cases[0], {policy: changed}),
    {code: vector.expected});
});

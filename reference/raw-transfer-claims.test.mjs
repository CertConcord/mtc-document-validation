import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {readFileSync} from 'node:fs';
import {assessRawTransferClaims} from './raw-transfer-claims.mjs';

const fixture = JSON.parse(readFileSync(new URL(
  '../vectors/raw-transfer-claims.json', import.meta.url)));
const corpus = JSON.parse(readFileSync(new URL(
  '../vectors/coherent-document-evidence.json', import.meta.url)));
const {retirement} = corpus;
const sha = bytes => createHash('sha256').update(bytes).digest('hex');
const decode = item => Buffer.from(item.base64, 'base64');
const signed = item => Buffer.concat([
  Buffer.from(item.rawBase64, 'base64'),
  Buffer.from(item.signatureBase64, 'base64')]);
const originals = {...Object.fromEntries(Object.entries(retirement.originals)
  .map(([id, item]) => [id, decode(item)])),
  'publication-head': signed(retirement.publication.head),
  'monitor-observation': signed(retirement.publication.monitor),
  'consistency-proof': decode(retirement.publication.proof)};
for (const [index, item] of retirement.publication.entries.entries())
  originals[`log-entry:${index}`] = decode(item);
const requiredSetRaw = Buffer.from(fixture.requiredSetRawBase64, 'base64');
const policy = {initialCustodianId: 'mtc-issuer',
  observerId: 'observer', selectedAt: fixture.requiredSet.selectedAt,
  retiredAt: retirement.policy.retiredAt,
  documentThrough: retirement.policy.documentThrough,
  requiredSetSha256: fixture.requiredSetSha256,
  custodianKeys: ['mtc-issuer', 'archive-A', 'archive-B'].map(id =>
    ({id, publicKeySpkiBase64: fixture.policy[id]})),
  observerPublicKeySpkiBase64: fixture.policy.observer};
const envelope = item => ({raw: Buffer.from(item.rawBase64, 'base64'),
  predecessorSignature: Buffer.from(item.predecessorSignatureBase64, 'base64'),
  successorSignature: Buffer.from(item.successorSignatureBase64, 'base64')});
const observation = item => ({raw: Buffer.from(item.rawBase64, 'base64'),
  signature: Buffer.from(item.signatureBase64, 'base64')});
const control = name => {const item = fixture.controls[name];
  const bytes = Buffer.from(item.base64, 'base64');
  assert.equal(bytes.length, item.bytes);
  assert.equal(sha(bytes), item.sha256);
  return bytes;};

test('frozen originals and preselected set match the later retirement declaration', () => {
  assert.equal(fixture.format, 'original-signed-transfer-claims-v1');
  assert.equal(fixture.sourceCorpus, 'vectors/coherent-document-evidence.json');
  assert.equal(fixture.requiredSet.items.length, 23);
  assert.equal(requiredSetRaw.length, fixture.requiredSetRawBytes);
  assert.equal(requiredSetRaw.toString('utf8'),
    JSON.stringify(fixture.requiredSet));
  assert.equal(sha(requiredSetRaw), fixture.requiredSetSha256);
  assert.equal(sha(Buffer.from(retirement.manifest.rawBase64, 'base64')),
    fixture.manifestSha256);
  const manifest = JSON.parse(Buffer.from(retirement.manifest.rawBase64,
    'base64').toString('utf8'));
  assert.deepEqual(fixture.requiredSet.items, manifest.items);
  assert(fixture.requiredSet.selectedAt < retirement.policy.retiredAt);
  assert(retirement.policy.retiredAt < manifest.declaredAt);
  for (const item of fixture.requiredSet.items)
    assert.equal(sha(originals[item.id]), item.sha256, item.id);
  for (const [id, item] of Object.entries(fixture.originals)) {
    const raw = Buffer.from(item.rawBase64, 'base64');
    assert.equal(raw.length, item.rawBytes, id);
    assert.equal(sha(raw), item.rawSha256, id);
    if (item.signatureBase64) {
      const signature = Buffer.from(item.signatureBase64, 'base64');
      assert.equal(signature.length, 64, id);
      assert.equal(sha(signature), item.signatureSha256, id);
    } else {
      assert.equal(Buffer.from(item.predecessorSignatureBase64,
        'base64').length, 64, id);
      assert.equal(Buffer.from(item.successorSignatureBase64,
        'base64').length, 64, id);
    }
  }
  assert.notEqual(sha(control('substitutedAuthorityOriginal')),
    fixture.requiredSet.items.find(item =>
      item.id === 'authority-history').sha256);
});

function replay(vector) {
  const handoffs = vector.handoffs.map(name =>
    envelope(fixture.originals[name]));
  const observations = vector.observations.map(name =>
    observation(fixture.originals[name]));
  const secondHandoffId = handoffs[1] ?
    JSON.parse(handoffs[1].raw.toString('utf8')).id : null;
  const supplied = [];
  for (const name of vector.observations) {
    const record = JSON.parse(Buffer.from(
      fixture.originals[name].rawBase64, 'base64').toString('utf8'));
    for (const item of record.items) {
      if (record.handoffId === secondHandoffId &&
          item.id === vector.missingAtSecond) continue;
      const bytes = record.handoffId === secondHandoffId &&
        item.id === vector.substituteAtSecond ?
        control('substitutedAuthorityOriginal') :
        originals[item.id];
      supplied.push({handoffId: record.handoffId,
        itemId: item.id, bytes});
    }
  }
  if (vector.extraAtSecond === 'retirement-manifest')
    supplied.push({handoffId: secondHandoffId,
      itemId: vector.extraAtSecond,
      bytes: signed(retirement.manifest)});
  const selectedPolicy = {...policy};
  if (vector.badSetAnchor)
    selectedPolicy.requiredSetSha256 =
      fixture.controls.unadmittedSetAnchorSha256;
  if (vector.swapCustodianKeys) {
    selectedPolicy.custodianKeys = structuredClone(policy.custodianKeys);
    const firstKey = selectedPolicy.custodianKeys[1].publicKeySpkiBase64;
    selectedPolicy.custodianKeys[1].publicKeySpkiBase64 =
      selectedPolicy.custodianKeys[2].publicKeySpkiBase64;
    selectedPolicy.custodianKeys[2].publicKeySpkiBase64 = firstKey;
  }
  if (vector.badSuccessorSignature)
    handoffs[0].successorSignature = control('badSuccessorSignature');
  if (vector.badObserverSignature)
    observations[1].signature = control('badObserverSignature');
  return assessRawTransferClaims({policy: selectedPolicy, requiredSetRaw,
    handoffs, observations, supplied});
}
for (const vector of fixture.cases) test(vector.id, () => {
  if (vector.expectedError)
    assert.throws(() => replay(vector), {code: vector.expectedError});
  else {
    const result = replay(vector);
    assert.equal(result.responsibility.decision,
      vector.expectedResponsibility);
    assert.equal(result.observationClaims.decision, vector.expectedBytes);
    const axes = [vector.expectedResponsibility, vector.expectedBytes];
    assert.equal(result.decision, axes.includes('REJECTED') ? 'REJECTED' :
      axes.includes('INDETERMINATE') ? 'INDETERMINATE' : 'BOUND_CLAIMS');
    assert.equal(result.handoffCount, vector.handoffs.length);
    assert.equal(result.requiredItemCount, 23);
    assert(!Object.hasOwn(result, 'documentValid'));
    if (vector.expectedReason)
      assert([...result.responsibility.reasons,
        ...result.observationClaims.reasons].some(item =>
        item.code === vector.expectedReason), vector.id);
  }
});

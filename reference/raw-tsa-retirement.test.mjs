import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {readFileSync} from 'node:fs';
import {certificate, OID} from './cert-der.mjs';
import {parseCrl} from './crl-der.mjs';
import {assessRawTsaRetirement} from './raw-tsa-retirement.mjs';

const coherent = JSON.parse(readFileSync(new URL(
  '../vectors/coherent-document-evidence.json', import.meta.url)));
const renewal = JSON.parse(readFileSync(new URL(
  '../vectors/coherent-ers-renewal.json', import.meta.url)));
const vectors = JSON.parse(readFileSync(new URL(
  '../vectors/raw-tsa-retirement.json', import.meta.url)));
const sha = bytes => createHash('sha256').update(bytes).digest('hex');
const frozen = (item, field = 'base64') => {
  const bytes = Buffer.from(item[field], 'base64');
  if (item.bytes !== undefined) assert.equal(bytes.length, item.bytes);
  assert.equal(sha(bytes), item.sha256);
  return bytes;
};
const {objects, policy: timestampPolicy} = coherent.timestamp;
const tsaDer = frozen(objects.tsa, 'derBase64');
const issuerDer = frozen(objects.issuer, 'derBase64');
const originalSignature = frozen(coherent.original_core.objects.signature);
const originalDocument = frozen(coherent.original_core.objects.document);
const priorToken = frozen(coherent.ers.objects.document.token);
const sourcePolicy = {issuerSha256: timestampPolicy.issuerSha256,
  sourceId: vectors.sourceId, scope: 'DIRECT_ISSUER_COMPLETE_NO_CDP'};
const signed = {
  initial: {responseDer: frozen(objects.response, 'derBase64'),
    requestDer: frozen(objects.request, 'derBase64'),
    coveredDer: originalSignature},
  renewal: {responseDer: frozen(renewal.renewal.response),
    requestDer: frozen(renewal.renewal.request), coveredDer: priorToken},
};

test('frozen CRLs are original signed controls for the same no-CDP TSA', () => {
  assert.equal(vectors.format, 'original-rfc3161-tsa-retirement-crl-v1');
  assert.equal(vectors.sourceCorpus, 'vectors/coherent-document-evidence.json');
  assert.equal(vectors.renewalCorpus, 'vectors/coherent-ers-renewal.json');
  assert.equal(Object.keys(vectors.crls).length, 10);
  assert.equal(vectors.cases.length, 19);
  const tsa = certificate(tsaDer);
  const issuer = certificate(issuerDer);
  assert(!tsa.extensions.has(OID.crlDistributionPoints));
  assert.equal(tsa.issuer.equals(issuer.subject), true);
  assert.equal(tsa.x509.verify(issuer.x509.publicKey), true);
  for (const [name, item] of Object.entries(vectors.crls)) {
    const bytes = frozen(item, 'derBase64');
    assert.throws(() => parseCrl({recordDer: bytes, target: tsa, issuer}),
      {code: 'CRL_TARGET_SCOPE_UNPROVEN'}, name);
    const parsed = parseCrl({recordDer: bytes, target: tsa, issuer,
      allowNoDistributionPoint: true});
    assert.equal(parsed.distributionPoint, null, name);
    assert.equal(parsed.targetSerial, tsa.serial, name);
    assert.equal(parsed.recordSha256, item.sha256, name);
  }
});

test('signed timestamp and CRL reasons remain bounded observations', async t => {
  for (const vector of vectors.cases) {
    await t.test(vector.id, () => {
      const crlDer = frozen(vectors.crls[vector.crl], 'derBase64');
      const received = Buffer.from(crlDer);
      const source = {...sourcePolicy};
      const receipt = {recordSha256: sha(received), sourceId: vectors.sourceId,
        observedAt: vectors.observedAt};
      let knownAt = vectors.knownAt;
      const token = {...signed[vector.timestamp]};
      switch (vector.id) {
        case 'receipt-missing': break;
        case 'receipt-wrong-source': receipt.sourceId = 'unadmitted'; break;
        case 'receipt-wrong-record':
          receipt.recordSha256 = vectors.crls.compromise.sha256; break;
        case 'receipt-before-crl': receipt.observedAt = 0; break;
        case 'crl-not-yet-known': knownAt = 1795814520; break;
        case 'crl-signature-tampered': received[received.length - 1] ^= 1; break;
        case 'timestamp-covered-bytes-wrong': token.coveredDer = originalDocument; break;
        case 'source-issuer-unadmitted': source.issuerSha256 = '0'.repeat(64); break;
      }
      const actual = assessRawTsaRetirement({...token,
        tsaDer, issuerDer, crlDer: received, timestampPolicy,
        sourcePolicy: source,
        admittedReceipt: vector.id === 'receipt-missing' ? null : receipt,
        knownAt});
      assert.equal(actual.decision, vector.expected);
      assert.deepEqual(actual.reasons, vector.reason ? [vector.reason] : []);
      assert.equal(actual.crlSha256, sha(received));
      for (const forbidden of ['VALID', 'knowledgeThrough', 'documentValidity',
        'poeUpperBoundMicros'])
        assert(!Object.hasOwn(actual, forbidden));
      if (actual.decision === 'BOUNDED_PRE_REVOCATION_CLAIM')
        assert(BigInt(actual.claimedUpperBoundMicros) <
          BigInt(actual.revocationTime) * 1_000_000n);
    });
  }
});

test('a caller cannot silently activate no-CDP scope or replace signed bytes', () => {
  const crlDer = frozen(vectors.crls.cessation, 'derBase64');
  const base = {...signed.initial, tsaDer, issuerDer, crlDer,
    timestampPolicy, sourcePolicy,
    admittedReceipt: {recordSha256: sha(crlDer), sourceId: vectors.sourceId,
      observedAt: vectors.observedAt}, knownAt: vectors.knownAt};
  assert.throws(() => assessRawTsaRetirement({...base,
    sourcePolicy: {...sourcePolicy, scope: 'DIRECT_ISSUER'}}),
    {code: 'TSA_RETIREMENT_INPUT'});
  assert.throws(() => assessRawTsaRetirement({...base, crlDer: new Uint16Array(2)}),
    {code: 'TSA_RETIREMENT_INPUT'});
});

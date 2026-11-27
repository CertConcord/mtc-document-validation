import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {readFileSync} from 'node:fs';
import {assessRawMtcRelativeIssuance} from './raw-mtc-relative.mjs';

const corpus = JSON.parse(readFileSync(new URL('../vectors/raw-mtc-relative.json',
  import.meta.url)));
const vectors = JSON.parse(readFileSync(new URL('../vectors/raw-mtc-relative-cases.json',
  import.meta.url)));
const decode = item => Buffer.from(item.base64, 'base64');
const sha = bytes => createHash('sha256').update(bytes).digest('hex');

for (const vector of vectors.cases) test(vector.id, () => {
  const policy = structuredClone(corpus.policy);
  if (vector.minimumTrustedTreeSize)
    policy.minimumTrustedTreeSize = vector.minimumTrustedTreeSize;
  if (vector.landmarkLogOrigin)
    policy.landmarkLogOrigin = vector.landmarkLogOrigin;
  if (vector.removeMirrorKey)
    policy.cosigners = policy.cosigners.filter(item => item.role !== 'mirror');
  const landmarkPublication = vector.publicationText
    ? Buffer.from(vector.publicationText, 'ascii')
    : decode(corpus.publication);
  if (vector.admitPublication)
    policy.landmarkPublicationSha256 = sha(landmarkPublication);
  const checkpointSignatures = (vector.checkpointKeys ?? ['ca', 'mirror'])
    .map(name => {
      const frozen = corpus.checkpoints[name];
      const signature = decode(frozen.signature);
      if (name === vector.mutateSignature) signature[0] ^= 1;
      return {idHex: frozen.idHex, message: decode(frozen.message), signature};
    });
  const result = assessRawMtcRelativeIssuance({
    certificateDer: decode(corpus.objects[vector.certificate ?? 'relative-one']),
    policy, landmarkPublication, checkpointSignatures,
    subtreeConsistencyProof: Buffer.from(vector.subtreeProofHex ??
      corpus.subtreeProofHex, 'hex')
  });
  assert.equal(result.reason ?? result.decision, vector.expected);
  if (vector.expected === 'RELATIVE_ISSUANCE_BOUND') {
    assert.equal(result.certificateSha256, corpus.objects['relative-one'].sha256);
    assert.equal(result.subtreeSha256, corpus.expectedLeafSha256);
    assert.equal(result.landmarkPublicationSha256, corpus.publication.sha256);
    assert.equal(result.landmarkNumber, 1);
    assert.equal(result.referenceTreeSize, 1);
    assert.deepEqual(result.admittedRoles, ['ca', 'mirror']);
  }
});

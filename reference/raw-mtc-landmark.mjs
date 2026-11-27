import {createHash} from 'node:crypto';
import {DerError} from './der.mjs';
import {selectMtcCoveringSubtrees} from './raw-mtc-consistency.mjs';

const bad = () => { throw new DerError('MTC_LANDMARK_FORMAT'); };
const decimal = value => /^(?:[0-9]+)$/.test(value);
const maximum = (1n << 48n) - 1n;

// MTC -07 section 6.4.3 publication syntax. The result is parsed source
// claims, not an authenticated trusted-subtree admission.
export function parseMtcLandmarkPublication(bytes, admittedAt) {
  if (!Buffer.isBuffer(bytes) || bytes.length === 0 || bytes.length > 1048576 ||
      bytes.some(byte => byte > 0x7f) || typeof admittedAt !== 'string' ||
      !decimal(admittedAt) || BigInt(admittedAt) === 0n) bad();
  const raw = bytes.toString('ascii');
  if (!raw.endsWith('\n') || raw.includes('\r')) bad();
  const lines = raw.slice(0, -1).split('\n');
  if (lines.length < 2 || !decimal(lines[0])) bad();
  const latest = BigInt(lines[0]);
  if (latest > maximum || BigInt(lines.length - 1) > latest + 1n) bad();
  const time = BigInt(admittedAt);
  const rows = [];
  for (let i = 1; i < lines.length; i++) {
    const fields = lines[i].split(' ');
    if (fields.length !== 2 || !fields.every(decimal)) bad();
    const size = BigInt(fields[0]), expiration = BigInt(fields[1]);
    if (size > maximum) bad();
    const number = latest - BigInt(i - 1);
    if (number === 0n ? (size !== 0n || expiration !== 0n) : size === 0n)
      bad();
    if (rows.length && (size >= rows.at(-1).treeSize ||
        expiration > rows.at(-1).expiration)) bad();
    if (i < lines.length - 1 ? expiration <= time : expiration >= time) bad();
    rows.push({number: Number(number), treeSize: Number(size), expiration});
  }
  return {latest: Number(latest), rows,
    publicationSha256: createHash('sha256').update(bytes).digest('hex')};
}

// The publication still needs an independent source admission. This only
// identifies the lowest listed landmark covering the entry and its subtree.
export function selectMtcLandmarkSubtree(publication, index) {
  if (!Number.isSafeInteger(index) || index < 0 || index >= 2 ** 48 ||
      !publication || !Array.isArray(publication.rows))
    throw new DerError('MTC_LANDMARK_RANGE');
  for (let i = 0; i + 1 < publication.rows.length; i++) {
    const selected = publication.rows[i], previous = publication.rows[i + 1];
    if (previous.treeSize <= index && index < selected.treeSize) {
      const subtrees = selectMtcCoveringSubtrees(previous.treeSize,
        selected.treeSize);
      const subtree = subtrees.find(({start, end}) =>
        start <= index && index < end);
      if (!subtree) break;
      return {landmarkNumber: selected.number,
        landmarkTreeSize: selected.treeSize,
        landmarkExpiration: selected.expiration,
        previousTreeSize: previous.treeSize, subtree};
    }
  }
  throw new DerError('MTC_LANDMARK_RANGE');
}

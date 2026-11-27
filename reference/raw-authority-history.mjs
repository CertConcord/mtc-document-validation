import {createHash, createPublicKey, verify} from 'node:crypto';
import {TextDecoder} from 'node:util';

const DOMAIN = Buffer.from('MTC-DV-AUTHORITY-HISTORY-v1\0', 'ascii');
const LINK = Buffer.from('MTC-DV-AUTHORITY-LINK-v1\0', 'ascii');
const eventKeys = ['version','kind','sourceId','sequence','previousSha256','profileId',
  'role','subjectId','scope','announcedAt','stateFrom','stateUntil','decision'];
const sealKeys = ['version','kind','sourceId','sequence','previousSha256','profileId',
  'role','subjectId','scope','announcedAt','through'];
const printable = value => typeof value === 'string' && /^[\x21-\x7e]+$/.test(value);
const instant = value => Number.isSafeInteger(value) && value >= 0;
const hex = value => typeof value === 'string' && /^[a-f0-9]{64}$/.test(value);
const error = code => {const e = new Error(code); e.code = code; throw e;};
const sha = bytes => createHash('sha256').update(bytes).digest('hex');
const same = (a,b) => JSON.stringify(a) === JSON.stringify(b);

function strictBase64(value) {
  if (typeof value !== 'string' || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value))
    error('AUTHORITY_ENCODING');
  return Buffer.from(value, 'base64');
}

function parseRecord(raw) {
  let record;
  try {record = JSON.parse(new TextDecoder('utf-8', {fatal:true}).decode(raw));}
  catch {error('AUTHORITY_ENCODING');}
  if (!record || typeof record !== 'object' || Array.isArray(record)) error('AUTHORITY_ENCODING');
  const keys = record.kind === 'event' ? eventKeys : record.kind === 'seal' ? sealKeys : null;
  if (!keys || !same(Object.keys(record), keys) ||
      !raw.equals(Buffer.from(JSON.stringify(record), 'utf8')))
    error('AUTHORITY_ENCODING');
  if (record.version !== 1 ||
      ![record.sourceId,record.profileId,record.role,record.subjectId,record.scope].every(printable) ||
      !Number.isSafeInteger(record.sequence) || record.sequence < 1 ||
      !(record.previousSha256 === null || hex(record.previousSha256)) ||
      !instant(record.announcedAt)) error('AUTHORITY_RECORD');
  if (record.kind === 'event' &&
      (!instant(record.stateFrom) || !instant(record.stateUntil) ||
       record.stateFrom >= record.stateUntil ||
       !['ALLOW','DENY','UNKNOWN'].includes(record.decision))) error('AUTHORITY_RECORD');
  if (record.kind === 'seal' &&
      (!instant(record.through) || record.through > record.announcedAt)) error('AUTHORITY_RECORD');
  return record;
}

function admittedKey(derBase64) {
  const der = strictBase64(derBase64);
  let key;
  try {key = createPublicKey({key:der, format:'der', type:'spki'});}
  catch {error('AUTHORITY_KEY');}
  if (key.asymmetricKeyType !== 'ed25519' ||
      !key.export({format:'der', type:'spki'}).equals(der)) error('AUTHORITY_KEY');
  return key;
}

function link(raw, signature) {
  return createHash('sha256').update(LINK).update(raw).update(signature).digest('hex');
}

// Authenticity and internal continuity of source claims only. External source
// admission, clock evidence, actual completeness and document coverage remain separate.
export function assessRawAuthorityHistory({stateAt, knownAt, policy, records, document}) {
  if (!instant(stateAt) || !instant(knownAt) || knownAt < stateAt ||
      !policy || !printable(policy.profileId) || !Array.isArray(policy.requirements) ||
      policy.requirements.length === 0 || !Array.isArray(records) || !Buffer.isBuffer(document))
    error('AUTHORITY_INPUT');
  const requirements = new Map();
  for (const requirement of policy.requirements) {
    if (!requirement ||
        ![requirement.role,requirement.subjectId,requirement.scope,requirement.sourceId].every(printable) ||
        !['issuer-authorization','document-action'].includes(requirement.role)) error('AUTHORITY_INPUT');
    if (requirement.role === 'document-action' &&
        requirement.scope !== `sha256:${sha(document)}`) error('AUTHORITY_DOCUMENT');
    const id = JSON.stringify([policy.profileId,requirement.role,requirement.subjectId,
      requirement.scope,requirement.sourceId]);
    if (requirements.has(id)) error('AUTHORITY_INPUT');
    requirements.set(id, {...requirement, key:admittedKey(requirement.publicKeySpkiBase64), chain:[]});
  }
  if (!['issuer-authorization','document-action'].every(role =>
    policy.requirements.some(x => x.role === role))) error('AUTHORITY_INPUT');
  for (const envelope of records) {
    if (!envelope || typeof envelope !== 'object') error('AUTHORITY_INPUT');
    const raw = strictBase64(envelope.rawBase64);
    const signature = strictBase64(envelope.signatureBase64);
    if (signature.length !== 64) error('AUTHORITY_SIGNATURE');
    const record = parseRecord(raw);
    const id = JSON.stringify([record.profileId,record.role,record.subjectId,
      record.scope,record.sourceId]);
    const stream = requirements.get(id);
    if (!stream) continue;
    if (!verify(null, Buffer.concat([DOMAIN,raw]), stream.key, signature))
      error('AUTHORITY_SIGNATURE');
    stream.chain.push({record, digest:link(raw,signature)});
  }
  const claims = [], reasons = [];
  for (const stream of requirements.values()) {
    const context = {profileId:policy.profileId,role:stream.role,
      subjectId:stream.subjectId,scope:stream.scope,sourceId:stream.sourceId};
    const missing = code => reasons.push({...context,code});
    const chain = stream.chain;
    if (!chain.length) {
      missing('AUTHORITY_SOURCE_MISSING');
      continue;
    }
    let previous = null, previousTime = 0;
    for (const [index,item] of chain.entries()) {
      const r = item.record;
      if (r.sequence !== index + 1 || r.previousSha256 !== previous ||
          r.announcedAt < previousTime) error('AUTHORITY_CHAIN');
      previous = item.digest;
      previousTime = r.announcedAt;
    }
    const sealing = chain.filter(x => x.record.kind === 'seal' &&
      x.record.announcedAt <= knownAt && x.record.through >= knownAt).at(-1);
    if (!sealing) {
      missing('AUTHORITY_COVERAGE_MISSING');
      continue;
    }
    const byCutoff = chain.filter(x => x.record.kind === 'event' &&
      x.record.announcedAt <= knownAt);
    const applicable = byCutoff.filter(x =>
      x.record.stateFrom <= stateAt && stateAt < x.record.stateUntil);
    const decisions = new Set(applicable.map(x => x.record.decision));
    if (!decisions.size) missing('AUTHORITY_DECISION_MISSING');
    else if (decisions.has('DENY')) missing('AUTHORITY_DENIED');
    else if (decisions.has('UNKNOWN'))
      missing(decisions.has('ALLOW') ? 'AUTHORITY_CONFLICT' : 'AUTHORITY_UNKNOWN');
    else if (byCutoff.some(x => x.record.sequence > sealing.record.sequence))
      missing('AUTHORITY_UNSEALED_SUFFIX');
    else {
      claims.push({...context,decision:'ALLOW',sealSha256:sealing.digest});
    }
  }
  return {decision:reasons.some(x => ['AUTHORITY_DENIED','AUTHORITY_CONFLICT'].includes(x.code))
    ? 'REJECTED' : reasons.length ? 'INDETERMINATE' : 'BOUND_CLAIMS',
  stateAt, knownAt, claims, reasons};
}

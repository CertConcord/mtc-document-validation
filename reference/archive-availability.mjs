// Evaluates archive availability facts already admitted under external policy.
// SATISFIED here never means that the signed document is valid.
const fail = code => { const error = new Error(code); error.code = code; throw error; };
const time = value => Number.isSafeInteger(value) && value >= 0;
const name = value => typeof value === 'string' && value.length > 0;
const hex = value => typeof value === 'string' && value.length % 2 === 0 && /^[0-9a-f]*$/i.test(value);
const sameBytes = (left, right) => left.toLowerCase() === right.toLowerCase();

function inspectItems(items, observations, at, archiveSources) {
  const reasons = [];
  for (const item of items) {
    const current = observations.filter(o => o.id === item.id && o.at === at);
    const admitted = current.filter(o => archiveSources.includes(o.sourceId));
    if (!admitted.length) {
      const code = current.length ? 'ARCHIVE_SOURCE_UNADMITTED' :
        observations.some(o => o.id === item.id && o.at < at && archiveSources.includes(o.sourceId))
          ? 'ARCHIVE_OBSERVATION_STALE' : 'ARCHIVE_RETRIEVAL_MISSING';
      reasons.push({id: item.id, code});
    } else if (admitted.some(o => !sameBytes(o.bytesHex, item.bytesHex))) {
      reasons.push({id: item.id, code: 'ARCHIVE_BYTES_MISMATCH'});
    }
  }
  return {
    decision: reasons.some(r => r.code === 'ARCHIVE_BYTES_MISMATCH') ? 'REJECTED' :
      reasons.length ? 'INDETERMINATE' : 'SATISFIED',
    reasons
  };
}

export function assessRetainedAvailability({at, policy, observations}) {
  if (!time(at) || !policy || !name(policy.profileId) || !time(policy.issuerRetiredAt) ||
      at < policy.issuerRetiredAt || !time(policy.documentThrough) ||
      !Array.isArray(policy.archiveSources) || !policy.archiveSources.length ||
      policy.archiveSources.some(source => !name(source)) ||
      new Set(policy.archiveSources).size !== policy.archiveSources.length ||
      !policy.headInventory ||
      !(policy.headInventory.completeThrough === null ||
        (time(policy.headInventory.completeThrough) && policy.headInventory.completeThrough <= at)) ||
      !Array.isArray(policy.headInventory.heads) || !policy.headInventory.heads.length ||
      policy.headInventory.heads.some(head => !head || !name(head.id) ||
        !time(head.floorThrough) || !hex(head.bytesHex)) ||
      new Set(policy.headInventory.heads.map(head => head.id)).size !== policy.headInventory.heads.length ||
      !Array.isArray(policy.documentRequired) || !policy.documentRequired.length ||
      policy.documentRequired.some(item => !item || !name(item.id) || !name(item.role) || !hex(item.bytesHex)) ||
      new Set(policy.documentRequired.map(item => item.id)).size !== policy.documentRequired.length)
    fail('ARCHIVE_POLICY');
  if (!Array.isArray(observations) || observations.some(o => !o || !name(o.id) ||
      !name(o.sourceId) || !time(o.at) || !hex(o.bytesHex))) fail('ARCHIVE_FACTS');
  const inventoryUnproven = policy.headInventory.completeThrough === null ||
    policy.headInventory.completeThrough < policy.issuerRetiredAt;
  const activeHeads = policy.headInventory.heads.filter(head => at <= head.floorThrough);
  const batchHeads = inspectItems(activeHeads, observations, at, policy.archiveSources);
  const documentEvidence = at > policy.documentThrough
    ? {decision: 'OUT_OF_SCOPE', reasons: []}
    : inspectItems(policy.documentRequired, observations, at, policy.archiveSources);
  if (inventoryUnproven) {
    batchHeads.reasons.unshift({code: 'ARCHIVE_INVENTORY_UNPROVEN'});
    if (batchHeads.decision !== 'REJECTED') batchHeads.decision = 'INDETERMINATE';
  } else if (!activeHeads.length) batchHeads.decision = 'OUT_OF_SCOPE';
  return {
    at,
    batchHeads,
    documentEvidence
  };
}

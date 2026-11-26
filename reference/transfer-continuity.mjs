// Evaluates independently admitted handoff facts, not receipt signatures or future access.
const fail = code => { const error = new Error(code); error.code = code; throw error; };
const time = n => Number.isSafeInteger(n) && n >= 0;
const name = s => typeof s === 'string' && s.length > 0;
const hex = s => typeof s === 'string' && s.length > 0 && s.length % 2 === 0 && /^[0-9a-f]+$/i.test(s);
const result = reasons => ({
  decision: reasons.some(r => r.code === 'TRANSFER_BYTES_MISMATCH') ? 'REJECTED' :
    reasons.length ? 'INDETERMINATE' : 'SATISFIED',
  reasons
});

export function assessTransferContinuity({policy, transfers, observations}) {
  if (!policy || !name(policy.initialCustodianId) || !time(policy.retiredAt) ||
      !time(policy.documentThrough) || policy.documentThrough < policy.retiredAt ||
      !Array.isArray(policy.required) || !policy.required.length ||
      policy.required.some(x => !x || !name(x.id) || !name(x.role) ||
        !hex(x.bytesHex) || !time(x.createdAt) || x.createdAt > policy.documentThrough) ||
      new Set(policy.required.map(x => x.id)).size !== policy.required.length ||
      !policy.required.some(x => x.role === 'original-object') ||
      !policy.required.some(x => x.role === 'prior-evidence')) fail('TRANSFER_POLICY');
  if (!Array.isArray(transfers) || !Array.isArray(observations) ||
      transfers.some(t => !t || !name(t.id) || !name(t.fromId) || !name(t.toId) ||
        t.fromId === t.toId || !time(t.acceptedAt) || !time(t.responsibleThrough) ||
        !Array.isArray(t.itemIds) || new Set(t.itemIds).size !== t.itemIds.length ||
        t.itemIds.some(id => !name(id))) ||
      new Set(transfers.map(t => t.id)).size !== transfers.length ||
      observations.some(o => !o || !name(o.handoffId) || !name(o.itemId) ||
        !name(o.holderId) || !time(o.at) || !hex(o.bytesHex))) fail('TRANSFER_FACTS');
  if (transfers.some(t =>
    !policy.required.some(x => x.role === 'original-object' && x.createdAt <= t.acceptedAt) ||
    t.itemIds.some(id => policy.required.some(x => x.id === id && x.createdAt > t.acceptedAt))))
    fail('TRANSFER_FACTS');

  const responsibility = [], evidence = [];
  if (!transfers.length) {
    const reason = {code: 'TRANSFER_NOT_RECORDED'};
    return {responsibility: result([reason]), evidence: result([reason])};
  }
  let predecessor = policy.initialCustodianId;
  let coveredThrough = policy.retiredAt;
  let previousAt = -1;
  for (const t of transfers) {
    if (t.acceptedAt <= previousAt) fail('TRANSFER_FACTS');
    if (t.fromId !== predecessor)
      responsibility.push({handoffId: t.id, code: 'TRANSFER_PREDECESSOR_MISMATCH'});
    if (t.acceptedAt > coveredThrough)
      responsibility.push({handoffId: t.id, code: 'TRANSFER_RESPONSIBILITY_GAP'});
    if (t.responsibleThrough < t.acceptedAt)
      responsibility.push({handoffId: t.id, code: 'TRANSFER_TERM_SHORT'});
    for (const item of policy.required.filter(x => x.createdAt <= t.acceptedAt)) {
      if (!t.itemIds.includes(item.id))
        responsibility.push({handoffId: t.id, itemId: item.id, code: 'TRANSFER_SCOPE_MISSING'});
      const matching = observations.filter(o => o.handoffId === t.id && o.itemId === item.id &&
        o.holderId === t.toId && o.at === t.acceptedAt);
      if (!matching.length)
        evidence.push({handoffId: t.id, itemId: item.id, code: 'TRANSFER_ITEM_MISSING'});
      else if (matching.some(o => o.bytesHex.toLowerCase() !== item.bytesHex.toLowerCase()))
        evidence.push({handoffId: t.id, itemId: item.id, code: 'TRANSFER_BYTES_MISMATCH'});
    }
    predecessor = t.toId;
    coveredThrough = t.responsibleThrough;
    previousAt = t.acceptedAt;
  }
  const last = transfers.at(-1);
  if (coveredThrough < policy.documentThrough)
    responsibility.push({handoffId: last.id, code: 'TRANSFER_HORIZON_SHORT'});
  return {responsibility: result(responsibility), evidence: result(evidence)};
}

const fail = code => { const error = new Error(code); error.code = code; throw error; };
const time = value => Number.isSafeInteger(value) && value >= 0;
const name = value => typeof value === 'string' && value.length > 0;

// Operates only on facts already authenticated and resolved under external policy.
// SATISFIED describes this history precondition, never complete document validity.
export function assessHistory({stateAt, knownAt, policy, facts}) {
  if (!time(stateAt) || !time(knownAt) || knownAt < stateAt ||
      !policy || !name(policy.profileId) || !Array.isArray(policy.requirements) ||
      policy.requirements.length === 0 || !Array.isArray(facts)) fail('HISTORY_INPUT');

  const required = new Set();
  for (const r of policy.requirements) {
    if (!r || ![r.role, r.subjectId, r.scope, r.sourceId].every(name)) fail('HISTORY_INPUT');
    const key = JSON.stringify([r.role, r.subjectId, r.scope, r.sourceId]);
    if (required.has(key)) fail('HISTORY_INPUT');
    required.add(key);
  }
  for (const f of facts) {
    if (!f || ![f.profileId, f.role, f.subjectId, f.scope, f.sourceId].every(name) ||
        !time(f.stateFrom) || !time(f.stateUntil) || f.stateFrom >= f.stateUntil ||
        !time(f.knowledgeFrom) ||
        !(f.knowledgeThrough === null ||
          (time(f.knowledgeThrough) && f.knowledgeFrom <= f.knowledgeThrough)) ||
        !['ALLOW', 'DENY', 'UNKNOWN'].includes(f.decision)) fail('HISTORY_FACTS');
  }

  const reasons = [];
  for (const r of policy.requirements) {
    const applicable = facts.filter(f =>
      f.profileId === policy.profileId && f.role === r.role &&
      f.subjectId === r.subjectId && f.scope === r.scope && f.sourceId === r.sourceId &&
      f.stateFrom <= stateAt && stateAt < f.stateUntil &&
      f.knowledgeFrom <= knownAt && f.knowledgeThrough !== null &&
      knownAt <= f.knowledgeThrough);
    const decisions = new Set(applicable.map(f => f.decision));
    if (decisions.size === 0) reasons.push({role: r.role, code: 'HISTORY_COVERAGE_MISSING'});
    else if (decisions.size > 1) reasons.push({role: r.role, code: 'HISTORY_CONFLICT'});
    else if (decisions.has('DENY')) reasons.push({role: r.role, code: 'HISTORY_DENIED'});
    else if (decisions.has('UNKNOWN')) reasons.push({role: r.role, code: 'HISTORY_UNKNOWN'});
  }
  return {
    decision: reasons.some(x => ['HISTORY_CONFLICT', 'HISTORY_DENIED'].includes(x.code))
      ? 'REJECTED' : reasons.length ? 'INDETERMINATE' : 'SATISFIED',
    stateAt, knownAt, reasons
  };
}

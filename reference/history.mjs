const fail = code => { const error = new Error(code); error.code = code; throw error; };
const time = value => Number.isSafeInteger(value) && value >= 0;
const name = value => typeof value === 'string' && value.length > 0;

// Operates only on facts already authenticated and resolved under external policy.
// SATISFIED describes this history precondition, never complete document validity.
export function assessHistory({stateAt, knownAt, policy, facts}) {
  if (!time(stateAt) || !time(knownAt) || knownAt < stateAt ||
      !policy || !Array.isArray(facts)) fail('HISTORY_INPUT');
  const profileId = policy.profileId;
  const selected = policy.requirements;
  if (!name(profileId) || !Array.isArray(selected)) fail('HISTORY_INPUT');
  const requirementCount = selected.length;
  if (requirementCount === 0) fail('HISTORY_INPUT');

  const required = new Set();
  const requirements = [];
  for (let index = 0; index < requirementCount; index++) {
    const source = selected[index];
    if (!source) fail('HISTORY_INPUT');
    const r = {role: source.role, subjectId: source.subjectId,
      scope: source.scope, sourceId: source.sourceId};
    if (![r.role, r.subjectId, r.scope, r.sourceId].every(name)) fail('HISTORY_INPUT');
    const key = JSON.stringify([r.role, r.subjectId, r.scope, r.sourceId]);
    if (required.has(key)) fail('HISTORY_INPUT');
    required.add(key);
    requirements.push(r);
  }
  const factRows = [];
  const factCount = facts.length;
  for (let index = 0; index < factCount; index++) {
    const source = facts[index];
    if (!source) fail('HISTORY_FACTS');
    const f = {profileId: source.profileId, role: source.role,
      subjectId: source.subjectId, scope: source.scope, sourceId: source.sourceId,
      stateFrom: source.stateFrom, stateUntil: source.stateUntil,
      knowledgeFrom: source.knowledgeFrom,
      knowledgeThrough: source.knowledgeThrough, decision: source.decision};
    if (![f.profileId, f.role, f.subjectId, f.scope, f.sourceId].every(name) ||
        !time(f.stateFrom) || !time(f.stateUntil) || f.stateFrom >= f.stateUntil ||
        !time(f.knowledgeFrom) ||
        !(f.knowledgeThrough === null ||
          (time(f.knowledgeThrough) && f.knowledgeFrom <= f.knowledgeThrough)) ||
        !['ALLOW', 'DENY', 'UNKNOWN'].includes(f.decision)) fail('HISTORY_FACTS');
    factRows.push(f);
  }

  const reasons = [];
  for (const r of requirements) {
    const applicable = factRows.filter(f =>
      f.profileId === profileId && f.role === r.role &&
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

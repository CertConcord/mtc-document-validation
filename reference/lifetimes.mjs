const reject = code => { const error = new Error(code); error.code = code; throw error; };
const decimal = value => typeof value === 'string' && /^(0|[1-9][0-9]*)$/.test(value)
  ? BigInt(value) : null;
const seconds = value => Number.isSafeInteger(value) && value >= 0
  ? BigInt(value) * 1_000_000n : null;
const name = value => typeof value === 'string' && value.length > 0;

function check(records, policy, fields, parseTime, fail) {
  const need = (condition, code) => { if (!condition) fail(code); };
  const at = parseTime(policy?.[fields.at]);
  const dataValidUntil = parseTime(policy?.[fields.dataValidUntil]);
  need(at !== null && dataValidUntil !== null && dataValidUntil > 0n &&
    policy?.[fields.hashValidUntil] &&
    typeof policy[fields.hashValidUntil] === 'object' &&
    !Array.isArray(policy[fields.hashValidUntil]) &&
    Array.isArray(records) && records.length > 0, 'ERS_PRESERVATION_POLICY');
  const hashValidUntil = policy[fields.hashValidUntil];
  const admitted = [];
  for (const [index, record] of records.entries()) {
    const r = {
      chain: record?.chain,
      genTime: parseTime(record?.[fields.genTime]),
      accuracy: parseTime(record?.[fields.accuracy]),
      upper: parseTime(record?.[fields.upper]),
      validUntil: parseTime(record?.[fields.validUntil]),
      hashOID: record?.hashOID
    };
    const previous = admitted.at(-1);
    need(Number.isSafeInteger(r.chain) && r.chain >= 0 && name(r.hashOID) &&
      r.genTime !== null && r.accuracy !== null && r.upper !== null &&
      r.validUntil !== null && r.validUntil > 0n &&
      r.upper === r.genTime + r.accuracy &&
      r.upper <= at && r.upper < r.validUntil &&
      (index === 0 ? r.chain === 0 :
        r.chain >= previous.chain && r.chain <= previous.chain + 1),
      'ERS_RECORD_FACTS');
    if (index > 0 && r.chain === previous.chain)
      need(r.hashOID === previous.hashOID, 'ERS_CHAIN_HASH_MISMATCH');
    admitted.push(r);
  }
  need(admitted[0].upper < dataValidUntil, 'ERS_INITIAL_PROTECTION_LATE');
  for (let i = 0; i < admitted.length; i++) {
    const r = admitted[i], next = admitted[i + 1];
    if (next) {
      need(r.upper <= next.genTime - next.accuracy, 'ERS_INTERVAL_ORDER');
      need(next.upper < r.validUntil, 'ERS_RENEWAL_LATE');
    } else need(at < r.validUntil, 'ERS_FINAL_PROTECTION_EXPIRED');
    const nextChain = admitted.find(n => n.chain > r.chain);
    need(Object.hasOwn(hashValidUntil, r.hashOID), 'ERS_HASH_LIFETIME_REQUIRED');
    const hashUntil = parseTime(hashValidUntil[r.hashOID]);
    need(hashUntil !== null && hashUntil > 0n, 'ERS_HASH_LIFETIME_REQUIRED');
    need((nextChain?.upper ?? at) < hashUntil, 'ERS_HASH_RENEWAL_LATE');
  }
  return true;
}

// Exact integral-second facts remain supported. Fractional Number values are
// rejected because their signed microsecond boundaries can be rounded away.
export function assertPreservationLifetimes(records, policy, fail = reject) {
  return check(records, policy, {
    at: 'at', dataValidUntil: 'dataValidUntil', hashValidUntil: 'hashValidUntil',
    genTime: 'genTime', accuracy: 'accuracy', upper: 'poeUpperBound',
    validUntil: 'validUntil'
  }, seconds, fail);
}

// Decimal strings are exact Unix microseconds from independently admitted
// time, TSA and algorithm-protection facts, not raw signed claims alone.
export function assertPreservationLifetimesMicros(records, policy, fail = reject) {
  return check(records, policy, {
    at: 'atMicros', dataValidUntil: 'dataValidUntilMicros',
    hashValidUntil: 'hashValidUntilMicros', genTime: 'genTimeMicros',
    accuracy: 'accuracyMicros', upper: 'poeUpperBoundMicros',
    validUntil: 'validUntilMicros'
  }, decimal, fail);
}

// Strict, bounded DER primitives for the raw-status reference subset.
// Every signed object is checked against its original bytes; this is not a
// general ASN.1 or PKIX implementation.
export class DerError extends Error {
  constructor(code) { super(code); this.code = code; }
}

const bad = code => { throw new DerError(code); };

export function node(bytes, start = 0, limit = bytes.length) {
  if (!Buffer.isBuffer(bytes) || start < 0 || start >= limit || limit > bytes.length)
    bad('DER_MALFORMED');
  const tag = bytes[start];
  if ((tag & 0x1f) === 0x1f) bad('DER_UNSUPPORTED');
  let at = start + 1;
  if (at >= limit) bad('DER_MALFORMED');
  let length = bytes[at++];
  if (length & 0x80) {
    const count = length & 0x7f;
    if (!count || count > 4 || at + count > limit || bytes[at] === 0)
      bad('DER_MALFORMED');
    length = 0;
    for (let i = 0; i < count; i++) length = length * 256 + bytes[at++];
    if (length < 128) bad('DER_MALFORMED');
  }
  const end = at + length;
  if (!Number.isSafeInteger(end) || end > limit) bad('DER_MALFORMED');
  return {bytes, tag, start, valueStart: at, end};
}

export function one(bytes, tag) {
  const value = node(bytes);
  if (value.end !== bytes.length) bad('DER_MALFORMED');
  return expect(value, tag);
}

export function expect(value, tag) {
  if (!value || value.tag !== tag) bad('DER_MALFORMED');
  return value;
}

export const raw = value => value.bytes.subarray(value.start, value.end);
export const content = value => value.bytes.subarray(value.valueStart, value.end);

export function children(value) {
  if (!(value.tag & 0x20)) bad('DER_MALFORMED');
  const result = [];
  for (let at = value.valueStart; at < value.end;) {
    const child = node(value.bytes, at, value.end);
    result.push(child);
    at = child.end;
  }
  return result;
}

export function exactChildren(value, count) {
  const list = children(value);
  if (list.length !== count) bad('DER_MALFORMED');
  return list;
}

export function positiveInteger(value) {
  expect(value, 0x02);
  const bits = content(value);
  if (!bits.length || (bits.length === 1 && bits[0] === 0) || bits[0] & 0x80 ||
      (bits.length > 1 && bits[0] === 0 && !(bits[1] & 0x80))) bad('DER_MALFORMED');
  return bits[0] === 0 ? bits.subarray(1).toString('hex') : bits.toString('hex');
}

export function smallInteger(value, tag = 0x02) {
  expect(value, tag);
  const bits = content(value);
  if (bits.length !== 1 || bits[0] > 127) bad('DER_UNSUPPORTED');
  return bits[0];
}

export function oid(value) {
  expect(value, 0x06);
  const bits = content(value);
  if (!bits.length) bad('DER_MALFORMED');
  const arcs = [];
  let number = 0n;
  let active = false;
  for (const byte of bits) {
    if (!active && byte === 0x80) bad('DER_MALFORMED');
    number = number * 128n + BigInt(byte & 0x7f);
    active = true;
    if (!(byte & 0x80)) {
      arcs.push(number);
      number = 0n;
      active = false;
    }
  }
  if (active) bad('DER_MALFORMED');
  const first = arcs.shift();
  const firstArc = first < 40n ? 0n : first < 80n ? 1n : 2n;
  return [firstArc, first - firstArc * 40n, ...arcs].map(String).join('.');
}

export function bitString(value) {
  expect(value, 0x03);
  const bits = content(value);
  if (!bits.length || bits[0] > 7 ||
      (bits.length === 1 && bits[0] !== 0) ||
      (bits.length > 1 && (bits.at(-1) & ((1 << bits[0]) - 1)))) bad('DER_MALFORMED');
  return {unused: bits[0], bytes: bits.subarray(1)};
}

export function encodedTime(value) {
  if (![0x17, 0x18].includes(value.tag)) bad('DER_MALFORMED');
  const text = content(value).toString('ascii');
  let year, month, day, hour, minute, second;
  if (value.tag === 0x18) {
    if (!/^\d{14}Z$/.test(text)) bad('DER_UNSUPPORTED');
    year = Number(text.slice(0, 4));
    [month, day, hour, minute, second] = [4, 6, 8, 10, 12].map(i => Number(text.slice(i, i + 2)));
  } else {
    if (!/^\d{12}Z$/.test(text)) bad('DER_UNSUPPORTED');
    const yy = Number(text.slice(0, 2));
    year = yy >= 50 ? 1900 + yy : 2000 + yy;
    [month, day, hour, minute, second] = [2, 4, 6, 8, 10].map(i => Number(text.slice(i, i + 2)));
  }
  const ms = Date.UTC(year, month - 1, day, hour, minute, second);
  const date = new Date(ms);
  if (date.getUTCFullYear() !== year || date.getUTCMonth() + 1 !== month ||
      date.getUTCDate() !== day || date.getUTCHours() !== hour ||
      date.getUTCMinutes() !== minute || date.getUTCSeconds() !== second)
    bad('DER_MALFORMED');
  return Math.floor(ms / 1000);
}

export function extensions(value) {
  expect(value, 0x30);
  const result = new Map();
  for (const entry of children(value)) {
    const fields = children(expect(entry, 0x30));
    if (fields.length < 2 || fields.length > 3) bad('DER_MALFORMED');
    const id = oid(fields[0]);
    let index = 1, critical = false;
    if (fields[index].tag === 0x01) {
      const boolean = content(fields[index++]);
      if (boolean.length !== 1 || boolean[0] !== 0xff) bad('DER_MALFORMED');
      critical = true;
    }
    if (index !== fields.length - 1 || result.has(id)) bad('DER_MALFORMED');
    result.set(id, {critical, value: content(expect(fields[index], 0x04))});
  }
  return result;
}

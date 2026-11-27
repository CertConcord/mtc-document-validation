import {types} from 'node:util';
import {DerError} from './der.mjs';

const nativeArray = Object.getPrototypeOf(Uint8Array.prototype);
const getBuffer = Object.getOwnPropertyDescriptor(nativeArray, 'buffer').get;
const getByteOffset = Object.getOwnPropertyDescriptor(nativeArray, 'byteOffset').get;
const getByteLength = Object.getOwnPropertyDescriptor(nativeArray, 'byteLength').get;

// Buffer.from(object) may follow caller-visible conversion hooks. Take a
// private copy of the native byte extent before parsing or checking widths.
export function snapshotMtcBuffer(value, code) {
  if (!Buffer.isBuffer(value) || !types.isUint8Array(value))
    throw new DerError(code);
  try {
    const backing = getBuffer.call(value);
    const offset = getByteOffset.call(value);
    const length = getByteLength.call(value);
    const owned = Buffer.alloc(length);
    Uint8Array.prototype.set.call(owned,
      new Uint8Array(backing, offset, length));
    return owned;
  } catch { throw new DerError(code); }
}

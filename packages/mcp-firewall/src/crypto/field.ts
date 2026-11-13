/**
 * Field elements and integers as the circuit sees them (docs/circuit-spec.md, sections 4 and 5.1-5.2).
 *
 * Every value is a `bigint`. Encoders reject out-of-range values and never reduce them modulo p.
 */

/** The BN254 scalar field modulus. */
export const FIELD_MODULUS = 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001n;

export const U8_MAX = (1n << 8n) - 1n;
export const U32_MAX = (1n << 32n) - 1n;
export const U64_MAX = (1n << 64n) - 1n;
export const U128_MAX = (1n << 128n) - 1n;

/** Thrown when a value cannot be encoded for the circuit. */
export class EncodingError extends Error {
  override readonly name = 'EncodingError';
}

/** Returns `x` if it is a canonical field element, that is, in `[0, p)`. */
export function assertField(x: bigint, name = 'field element'): bigint {
  if (typeof x !== 'bigint') throw new EncodingError(`${name} must be a bigint`);
  if (x < 0n || x >= FIELD_MODULUS) throw new EncodingError(`${name} is not a canonical field element`);
  return x;
}

/** Returns `x` if it fits in an unsigned integer of `bits` bits. */
export function assertUint(x: bigint, bits: 8 | 32 | 64 | 128, name = 'integer'): bigint {
  if (typeof x !== 'bigint') throw new EncodingError(`${name} must be a bigint`);
  if (x < 0n || x >= 1n << BigInt(bits)) throw new EncodingError(`${name} does not fit in u${bits}`);
  return x;
}

const HEX_FIELD = /^0x[0-9a-fA-F]{1,64}$/;
const DECIMAL = /^(0|[1-9][0-9]*)$/;

/**
 * Parses a field element from a `0x` hex string or a bigint. Decimal strings and JavaScript
 * numbers are refused, so that an integer can never be mistaken for a field element by accident.
 */
export function parseField(value: unknown, name = 'field element'): bigint {
  if (typeof value === 'bigint') return assertField(value, name);
  if (typeof value === 'string' && HEX_FIELD.test(value)) return assertField(BigInt(value), name);
  throw new EncodingError(`${name} must be a 0x-prefixed hex string of at most 64 digits`);
}

/**
 * Parses an unsigned integer from a decimal string, a bigint, or a JavaScript number that is a
 * safe integer. Numbers beyond 2^53 are refused: they have already lost precision.
 */
export function parseUint(value: unknown, bits: 8 | 32 | 64 | 128, name = 'integer'): bigint {
  if (typeof value === 'bigint') return assertUint(value, bits, name);
  if (typeof value === 'number') {
    if (!Number.isSafeInteger(value)) throw new EncodingError(`${name} must be a safe integer, or a decimal string`);
    return assertUint(BigInt(value), bits, name);
  }
  if (typeof value === 'string' && DECIMAL.test(value)) return assertUint(BigInt(value), bits, name);
  throw new EncodingError(`${name} must be a decimal string, a bigint or a safe integer`);
}

/** `0x` followed by 64 lowercase hex digits. */
export function fieldToHex(x: bigint): string {
  return '0x' + assertField(x).toString(16).padStart(64, '0');
}

/** 32 bytes, big-endian. */
export function fieldToBytes(x: bigint): Uint8Array {
  return Buffer.from(fieldToHex(x).slice(2), 'hex');
}

/** Reads 32 big-endian bytes and checks the value is canonical. */
export function bytesToField(bytes: Uint8Array, name = 'field element'): bigint {
  if (bytes.length !== 32) throw new EncodingError(`${name} must be 32 bytes`);
  return assertField(BigInt('0x' + Buffer.from(bytes).toString('hex')), name);
}

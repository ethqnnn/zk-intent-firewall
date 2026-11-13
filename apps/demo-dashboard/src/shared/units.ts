/**
 * Decimal token amounts to base units and back, exactly. Floating point never touches an amount.
 */

export class AmountFormatError extends Error {
  override readonly name = 'AmountFormatError';
}

const U128_MAX = (1n << 128n) - 1n;

/** "1,250.5" with 6 decimals is 1250500000n. Commas are accepted as thousands separators. */
export function toBaseUnits(input: string, decimals: number): bigint {
  const s = input.trim().replace(/,/g, '');
  const m = /^(0|[1-9][0-9]*)(?:\.([0-9]+))?$/.exec(s);
  if (!m) throw new AmountFormatError('amount must be a non-negative decimal number');
  const frac = m[2] ?? '';
  if (frac.length > decimals) throw new AmountFormatError(`amount has more than ${decimals} decimal places`);
  const value = BigInt(m[1]!) * 10n ** BigInt(decimals) + BigInt(frac.padEnd(decimals, '0') || '0');
  if (value > U128_MAX) throw new AmountFormatError('amount does not fit in u128');
  return value;
}

/** 1250500000n with 6 decimals is "1,250.50". At least two decimals are shown. */
export function formatUnits(value: bigint | string, decimals: number): string {
  const v = typeof value === 'bigint' ? value : BigInt(value);
  const neg = v < 0n;
  const abs = neg ? -v : v;
  const base = 10n ** BigInt(decimals);
  const whole = (abs / base).toString().replace(/\B(?=(\d{3})+(?!\d))/g, ',');
  let frac = (abs % base).toString().padStart(decimals, '0').replace(/0+$/, '');
  if (frac.length < 2) frac = frac.padEnd(2, '0');
  return `${neg ? '-' : ''}${whole}.${frac}`;
}

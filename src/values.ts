import type { BVValue, BoolValue, FP32Value, TypedValue, ValueType, Width } from './types.js';
import { assert } from './shared.js';
export function sameType(a: ValueType, b: ValueType): boolean {
  return a.kind === b.kind && (a.kind !== 'bv' || (b.kind === 'bv' && a.width === b.width));
}
export function validateTypedValue(value: unknown, type?: ValueType): TypedValue {
  assert(
    !!value && typeof value === 'object' && !Array.isArray(value),
    'INVALID_VALUE',
    'Expected typed value',
  );
  const v = value as Record<string, unknown>;
  const keys = Object.keys(v).sort().join(',');
  if (v.kind === 'bv') {
    assert(
      [8, 16, 32, 64].includes(v.width as number) && keys === 'bits,kind,width',
      'INVALID_VALUE',
      'Invalid BV type or properties',
    );
    assert(
      typeof v.bits === 'string' &&
        new RegExp(`^0x[0-9a-f]{${(v.width as number) / 4}}$`).test(v.bits),
      'INVALID_VALUE',
      'BV bits must be canonical fixed-width lowercase hex',
    );
  } else if (v.kind === 'bool')
    assert(
      keys === 'kind,value' && typeof v.value === 'boolean',
      'INVALID_VALUE',
      'Bool requires a boolean',
    );
  else if (v.kind === 'fp32')
    assert(
      keys === 'bits,kind' && typeof v.bits === 'string' && /^0x[0-9a-f]{8}$/.test(v.bits),
      'INVALID_VALUE',
      'Invalid FP32 bits',
    );
  else assert(false, 'INVALID_VALUE', 'Unknown value kind');
  const result = value as TypedValue;
  assert(
    !type || sameType(result, type),
    'TYPE_MISMATCH',
    'Typed value does not match declared type',
  );
  return result;
}
export function bv(value: bigint, width: Width): BVValue {
  assert(
    typeof value === 'bigint' && [8, 16, 32, 64].includes(width),
    'INVALID_VALUE',
    'BV construction requires BigInt and supported width',
  );
  return {
    kind: 'bv',
    width,
    bits:
      '0x' +
      BigInt.asUintN(width, value)
        .toString(16)
        .padStart(width / 4, '0'),
  };
}
export function bool(value: boolean): BoolValue {
  assert(typeof value === 'boolean', 'INVALID_VALUE', 'Bool construction requires boolean');
  return { kind: 'bool', value };
}
export function fp32Bits(value: number): FP32Value {
  assert(typeof value === 'number', 'INVALID_VALUE', 'Expected number');
  const view = new DataView(new ArrayBuffer(4));
  view.setFloat32(0, value, false);
  return { kind: 'fp32', bits: '0x' + view.getUint32(0, false).toString(16).padStart(8, '0') };
}
export function fp32Number(value: FP32Value): number {
  validateTypedValue(value, { kind: 'fp32' });
  const view = new DataView(new ArrayBuffer(4));
  view.setUint32(0, Number.parseInt(value.bits.slice(2), 16), false);
  return view.getFloat32(0, false);
}
export function valueEquals(a: TypedValue, b: TypedValue): boolean {
  return (
    sameType(a, b) &&
    (a.kind === 'bool'
      ? b.kind === 'bool' && a.value === b.value
      : b.kind !== 'bool' && a.bits === b.bits)
  );
}
export function signed(value: BVValue): bigint {
  return BigInt.asIntN(value.width, BigInt(value.bits));
}

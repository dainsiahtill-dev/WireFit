import { describe, it, expect } from 'vitest';
import { readFile } from 'node:fs/promises';
import { validateBvModel, validateMapping } from '../src/model.js';
import { evaluateBv, evaluateNode } from '../src/bv.js';
import { bv, bool, validateTypedValue } from '../src/values.js';
const load = async (name: string) =>
  validateBvModel(
    JSON.parse(await readFile(new URL(`../examples/model.${name}.json`, import.meta.url), 'utf8')),
  );
describe('exact independent evaluator', () => {
  it('preserves all 64 bits and wraps without Number', async () => {
    const m = await load('increment-u64');
    expect(
      evaluateBv(m, { x: { kind: 'bv', width: 64, bits: '0x0020000000000001' } }).result,
    ).toEqual({ kind: 'bv', width: 64, bits: '0x0020000000000002' });
    expect(evaluateBv(m, { x: bv(-1n, 64) }).result).toEqual(bv(0n, 64));
  });
  it('checks full wide shift count before narrowing', () => {
    const t = { kind: 'bv', width: 8 } as const;
    expect(evaluateNode('bv_shl', t, [bv(1n, 8), bv(256n, 64)], {})).toEqual(bv(0n, 8));
    expect(evaluateNode('bv_ashr', t, [bv(128n, 8), bv(-1n, 64)], {})).toEqual(bv(255n, 8));
  });
  it('rejects malformed values and bool integer coercion', () => {
    for (const bad of [
      { kind: 'bv', width: 64, bits: '0x20000000000001' },
      { kind: 'bv', width: 8, bits: '0xFF' },
      { kind: 'bool', value: 1 },
    ])
      expect(() => validateTypedValue(bad)).toThrow();
  });
  it('evaluates MBA addition exhaustively over BV8 input pairs', async () => {
    const m = await load('mba-u8');
    for (let a = 0; a < 256; a++)
      for (let b = 0; b < 256; b++)
        expect(evaluateBv(m, { a: bv(BigInt(a), 8), b: bv(BigInt(b), 8) }).result).toEqual(
          bv(BigInt((a + b) % 256), 8),
        );
  }, 60000);
  it('rejects cycles, bad operation types, unknown attrs and forged fidelity', async () => {
    const m = await load('mba-u8');
    const bad: any = structuredClone(m);
    bad.nodes[0].args[0] = 'total';
    expect(() => validateBvModel(bad)).toThrow();
    const badType: any = structuredClone(m);
    badType.nodes[0].type = { kind: 'bool' };
    expect(() => validateBvModel(badType)).toThrow();
    const attrs: any = structuredClone(m);
    attrs.nodes[0].attrs = { ignore: true };
    expect(() => validateBvModel(attrs)).toThrow();
    expect(() => validateBvModel({ ...m, binary_fidelity: 'proved' })).toThrow();
  });
  it('rejects input merging and empty output comparison', async () => {
    const m = await load('mba-u8');
    expect(() =>
      validateMapping(m, m, {
        inputs: [
          { left: 'a', right: 'a' },
          { left: 'b', right: 'a' },
        ],
        outputs: [{ left: 'result', right: 'result' }],
      }),
    ).toThrow();
    expect(() =>
      validateMapping(m, m, {
        inputs: [
          { left: 'a', right: 'a' },
          { left: 'b', right: 'b' },
        ],
        outputs: [],
      }),
    ).toThrow();
  });
  it('implements signed comparison, extract, concat, bool and extensions', () => {
    const t = { kind: 'bv', width: 16 } as const;
    expect(evaluateNode('bv_slt', { kind: 'bool' }, [bv(255n, 8), bv(1n, 8)], {})).toEqual(
      bool(true),
    );
    expect(evaluateNode('bv_sext', t, [bv(128n, 8)], {})).toEqual(bv(65408n, 16));
    expect(evaluateNode('bv_concat', t, [bv(0x12n, 8), bv(0x34n, 8)], {})).toEqual(bv(0x1234n, 16));
    expect(
      evaluateNode('bv_extract', { kind: 'bv', width: 8 }, [bv(0x1234n, 16)], { low: 8 }),
    ).toEqual(bv(0x12n, 8));
    expect(evaluateNode('bool_to_bv', t, [bool(true)], {})).toEqual(bv(1n, 16));
  });
});

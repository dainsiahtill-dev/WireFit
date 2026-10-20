import { it, expect } from 'vitest';
import { evaluateNode } from '../src/bv.js';
import { bv, bool } from '../src/values.js';
import type { BvOp, CoreType, TypedValue } from '../src/types.js';
const B = { kind: 'bool' } as const,
  T = { kind: 'bv', width: 8 } as const;
const cases: [BvOp, CoreType, TypedValue[], object, TypedValue][] = [
  ['const', T, [], { value: bv(250n, 8) }, bv(250n, 8)],
  ['copy', T, [bv(250n, 8)], {}, bv(250n, 8)],
  ['bv_add', T, [bv(250n, 8), bv(10n, 8)], {}, bv(4n, 8)],
  ['bv_sub', T, [bv(0n, 8), bv(1n, 8)], {}, bv(255n, 8)],
  ['bv_mul', T, [bv(128n, 8), bv(2n, 8)], {}, bv(0n, 8)],
  ['bv_neg', T, [bv(128n, 8)], {}, bv(128n, 8)],
  ['bv_and', T, [bv(0xf0n, 8), bv(0x3cn, 8)], {}, bv(0x30n, 8)],
  ['bv_or', T, [bv(0xf0n, 8), bv(0x3cn, 8)], {}, bv(0xfcn, 8)],
  ['bv_xor', T, [bv(0xf0n, 8), bv(0x3cn, 8)], {}, bv(0xccn, 8)],
  ['bv_not', T, [bv(0xf0n, 8)], {}, bv(0x0fn, 8)],
  ['bv_eq', B, [bv(7n, 8), bv(7n, 8)], {}, bool(true)],
  ['bv_ne', B, [bv(7n, 8), bv(7n, 8)], {}, bool(false)],
  ['bv_ult', B, [bv(255n, 8), bv(0n, 8)], {}, bool(false)],
  ['bv_ule', B, [bv(255n, 8), bv(255n, 8)], {}, bool(true)],
  ['bv_slt', B, [bv(128n, 8), bv(0n, 8)], {}, bool(true)],
  ['bv_sle', B, [bv(127n, 8), bv(255n, 8)], {}, bool(false)],
  ['bool_and', B, [bool(true), bool(false)], {}, bool(false)],
  ['bool_or', B, [bool(true), bool(false)], {}, bool(true)],
  ['bool_not', B, [bool(false)], {}, bool(true)],
  ['bv_nonzero', B, [bv(2n, 8)], {}, bool(true)],
  ['bool_to_bv', T, [bool(false)], {}, bv(0n, 8)],
  ['select', T, [bool(false), bv(1n, 8), bv(2n, 8)], {}, bv(2n, 8)],
  ['bv_shl', T, [bv(129n, 8), bv(1n, 8)], {}, bv(2n, 8)],
  ['bv_lshr', T, [bv(128n, 8), bv(1n, 8)], {}, bv(64n, 8)],
  ['bv_ashr', T, [bv(128n, 8), bv(1n, 8)], {}, bv(192n, 8)],
  ['bv_zext', { kind: 'bv', width: 16 }, [bv(255n, 8)], {}, bv(255n, 16)],
  ['bv_sext', { kind: 'bv', width: 16 }, [bv(255n, 8)], {}, bv(65535n, 16)],
  ['bv_extract', T, [bv(0xabcdn, 16)], { low: 4 }, bv(0xbcn, 8)],
  ['bv_concat', { kind: 'bv', width: 16 }, [bv(0xabn, 8), bv(0xcdn, 8)], {}, bv(0xabcdn, 16)],
];
it('matches literal boundary expectations for every supported opcode', () => {
  for (const [op, type, args, attrs, want] of cases)
    expect(evaluateNode(op, type, args, attrs), op).toEqual(want);
});
it('rejects forged direct-evaluator types, unknown attrs, and implicit casts', () => {
  expect(() =>
    evaluateNode('bv_add', { kind: 'bv', width: 7 } as any, [bv(1n, 8), bv(2n, 8)], {}),
  ).toThrow();
  expect(() => evaluateNode('copy', T, [bv(1n, 8)], { unexpected: true } as any)).toThrow();
  expect(() => evaluateNode('copy', B, [bv(1n, 8)], {})).toThrow();
});

import { readFile, mkdtemp, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { validateBvModel, defaultMapping } from '../src/model.js';
import { compareBv } from '../src/solver.js';
import { exportModelSource } from '../src/export-model.js';
it('cross-checks every operation encoding with real Z3 and a dependency-free exported module', async () => {
  const base = validateBvModel(
    JSON.parse(await readFile(new URL('../examples/model.add-u8.json', import.meta.url), 'utf8')),
  );
  const nodes: any[] = [];
  let last = 'allTrue';
  nodes.push({ id: last, op: 'const', type: B, args: [], attrs: { value: bool(true) } });
  cases.forEach(([op, type, args, attrs, want], i) => {
    const argIds = args.map((value, j) => {
      const id = `arg${i}_${j}`;
      const { kind } = value;
      nodes.push({
        id,
        op: 'const',
        type: kind === 'bv' ? { kind, width: value.width } : { kind },
        args: [],
        attrs: { value },
      });
      return id;
    });
    const actual = `actual${i}`,
      test = `test${i}`;
    nodes.push({ id: actual, op, type, args: argIds, attrs });
    if (want.kind === 'bv') {
      const id = `want${i}`;
      nodes.push({
        id,
        op: 'const',
        type: { kind: 'bv', width: want.width },
        args: [],
        attrs: { value: want },
      });
      nodes.push({ id: test, op: 'bv_eq', type: B, args: [actual, id], attrs: {} });
    } else
      nodes.push({
        id: test,
        op: want.value ? 'copy' : 'bool_not',
        type: B,
        args: [actual],
        attrs: {},
      });
    const next = `all${i}`;
    nodes.push({ id: next, op: 'bool_and', type: B, args: [last, test], attrs: {} });
    last = next;
  });
  const model = validateBvModel({
    ...base,
    nodes,
    outputs: [{ id: 'result', type: B, ref: last }],
  });
  const reference = validateBvModel({
    ...base,
    nodes: [{ id: 'yes', op: 'const', type: B, args: [], attrs: { value: bool(true) } }],
    outputs: [{ id: 'result', type: B, ref: 'yes' }],
  });
  const budget = {
    wall_time_ms: 60000,
    solver_soft_time_ms: 10000,
    solver_hard_time_ms: 20000,
    max_candidates: 1,
    max_ast_nodes: 1,
    max_oracle_calls: 0,
    max_iterations: 1,
    seed: 1,
  };
  expect(
    (await compareBv(model, reference, base.domain, defaultMapping(model, reference), budget))
      .status,
  ).toBe('proved');
  const dir = await mkdtemp(join(tmpdir(), 'wirefit-allops-'));
  try {
    await writeFile(join(dir, 'model.mjs'), exportModelSource(model), 'utf8');
    await writeFile(
      join(dir, 'check.mjs'),
      `import {evaluate} from './model.mjs';const v={kind:'bv',width:8,bits:'0x00'};console.log(JSON.stringify(evaluate({a:v,b:v})));`,
      'utf8',
    );
    expect(
      JSON.parse((await promisify(execFile)(process.execPath, [join(dir, 'check.mjs')])).stdout),
    ).toEqual({ result: { kind: 'bool', value: true } });
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}, 60000);

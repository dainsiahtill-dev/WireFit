import { it, expect } from 'vitest';
import { readFile } from 'node:fs/promises';
import { validateBvModel, domainContainsPoint } from '../src/model.js';
import { simplifyBv, suggestBvInputs } from '../src/synthesis.js';
import { evaluateBv } from '../src/bv.js';
const load = async (name: string) =>
  validateBvModel(
    JSON.parse(await readFile(new URL(`../examples/model.${name}.json`, import.meta.url), 'utf8')),
  );
const budget = {
  wall_time_ms: 60000,
  solver_soft_time_ms: 10000,
  solver_hard_time_ms: 20000,
  max_candidates: 64,
  max_ast_nodes: 6,
  max_oracle_calls: 0,
  max_iterations: 100,
  seed: 1,
};
it('records a requested narrowed domain on the candidate and checks only that explicit domain', async () => {
  const model = await load('add-u8');
  const domain = {
    constraints: [{ input: 'a', op: 'eq', value: { kind: 'bv', width: 8, bits: '0x00' } as const }],
  };
  const result = await simplifyBv(model, budget, undefined, {
    domain,
    grammar: ['bv_or'],
    constants: [],
  });
  expect(result.candidate.domain).toEqual(domain);
  expect(result.candidate.nodes).toHaveLength(0);
  expect(result.candidate.outputs[0].ref).toBe('b');
  expect(result.check.status).toBe('proved');
  expect(result.search.grammar).toEqual(['bv_or']);
  expect(result.search.constants).toEqual([]);
}, 60000);
it('returns replayed disagreement inputs for same-signature models', async () => {
  const left = await load('add-u8'),
    right = await load('add-u8-wrong');
  const domain = { constraints: [] };
  const result = await suggestBvInputs([left, right], domain, budget, undefined, {
    strategy: 'disagreement',
    max_inputs: 2,
  });
  expect(result.inputs.length).toBeGreaterThan(0);
  for (const point of result.inputs) {
    expect(point.reason).toBe('disagreement');
    expect(evaluateBv(left, point.inputs)).not.toEqual(evaluateBv(right, point.inputs));
  }
}, 60000);
it('returns only in-domain boundaries and refuses signature guessing', async () => {
  const left = await load('add-u8'),
    right = await load('add-u8');
  const domain = {
    constraints: [
      { input: 'a', op: 'uge', value: { kind: 'bv', width: 8, bits: '0x04' } as const },
      { input: 'a', op: 'ule', value: { kind: 'bv', width: 8, bits: '0x07' } as const },
    ],
  };
  const result = await suggestBvInputs([left, right], domain, budget, undefined, {
    strategy: 'boundaries',
    max_inputs: 16,
  });
  expect(result.inputs.length).toBeGreaterThan(0);
  for (const point of result.inputs) expect(domainContainsPoint(domain, point.inputs)).toBe(true);
  expect(result.inputs.some((p) => p.inputs.a.bits === '0x04')).toBe(true);
  expect(result.inputs.some((p) => p.inputs.a.bits === '0x07')).toBe(true);
  const bad = structuredClone(right);
  bad.inputs[0].id = 'renamed';
  await expect(suggestBvInputs([left, bad], domain, budget)).rejects.toThrow();
}, 60000);
it('uses explicitly supplied Bool constants even when every model input is BV', async () => {
  const base = await load('add-u8');
  const model = validateBvModel({
    ...base,
    nodes: [
      {
        id: 'one',
        op: 'const',
        type: { kind: 'bv', width: 8 },
        args: [],
        attrs: { value: { kind: 'bv', width: 8, bits: '0x01' } },
      },
      { id: 'flag', op: 'bv_eq', type: { kind: 'bool' }, args: ['a', 'one'], attrs: {} },
    ],
    outputs: [{ id: 'result', type: { kind: 'bool' }, ref: 'flag' }],
  });
  const domain = {
    constraints: [{ input: 'a', op: 'eq', value: { kind: 'bv', width: 8, bits: '0x01' } as const }],
  };
  const result = await simplifyBv(model, budget, undefined, {
    domain,
    grammar: ['bv_or'],
    constants: [{ kind: 'bool', value: true }],
  });
  expect(result.candidate.nodes).toHaveLength(1);
  expect(result.candidate.nodes[0].op).toBe('const');
  expect(result.check.status).toBe('proved');
}, 60000);

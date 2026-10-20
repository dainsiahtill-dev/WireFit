import { it, expect } from 'vitest';
import { readFile } from 'node:fs/promises';
import { validateBvModel } from '../src/model.js';
import { simplifyBv } from '../src/synthesis.js';
import { evaluateBv } from '../src/bv.js';
import { bv } from '../src/values.js';
const budget = {
  wall_time_ms: 60000,
  solver_soft_time_ms: 10000,
  solver_hard_time_ms: 20000,
  max_candidates: 100,
  max_ast_nodes: 6,
  max_oracle_calls: 0,
  max_iterations: 100,
  seed: 1,
};
it('refines a false observational candidate using a replayed solver counterexample', async () => {
  const source = validateBvModel(
    JSON.parse(await readFile(new URL('../examples/model.add-u8.json', import.meta.url), 'utf8')),
  );
  const result = await simplifyBv(source, budget);
  expect(result.search.refinements).toBeGreaterThan(0);
  for (const inputs of result.search.counterexamples) {
    const out = evaluateBv(source, inputs).result as any;
    expect(out.bits !== (inputs.a as any).bits || out.bits !== (inputs.b as any).bits).toBe(true);
  }
  expect(result.check.status).toBe('proved');
}, 60000);
it('respects candidate budget and never converts exhausted search into a new proof', async () => {
  const source = validateBvModel(
    JSON.parse(await readFile(new URL('../examples/model.add-u8.json', import.meta.url), 'utf8')),
  );
  const result = await simplifyBv(source, { ...budget, max_candidates: 1 });
  expect(result.search.generated).toBeLessThanOrEqual(1);
  expect(result.search.stop_reason).toBe('budget_exhausted');
  expect(evaluateBv(result.candidate, { a: bv(250n, 8), b: bv(10n, 8) }).result).toEqual(bv(4n, 8));
}, 60000);

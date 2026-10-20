import { it, expect } from 'vitest';
import { readFile } from 'node:fs/promises';
import { validateBvModel, defaultMapping } from '../src/model.js';
import { compareBv } from '../src/solver.js';
import { simplifyBv } from '../src/synthesis.js';
import { exportModelSource } from '../src/export-model.js';
import { mkdtemp, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import type { Budget } from '../src/types.js';
const load = async (name: string) =>
  validateBvModel(
    JSON.parse(await readFile(new URL(`../examples/model.${name}.json`, import.meta.url), 'utf8')),
  );
const budget: Budget = {
  wall_time_ms: 60000,
  solver_soft_time_ms: 10000,
  solver_hard_time_ms: 20000,
  max_candidates: 128,
  max_ast_nodes: 8,
  max_oracle_calls: 0,
  max_iterations: 128,
  seed: 42,
};
it('real isolated Z3 proves MBA and independently replays SAT counterexample', async () => {
  const left = await load('mba-u8'),
    right = await load('add-u8'),
    wrong = await load('add-u8-wrong');
  const good = await compareBv(
    left,
    right,
    { constraints: [] },
    defaultMapping(left, right),
    budget,
  );
  expect(good.status).toBe('proved');
  expect(good.queries.map((q) => q.kind)).toEqual([
    'domain_nonempty',
    'domain_containment',
    'equivalence',
  ]);
  expect(good.queries[2].smtlib).toContain('check-sat');
  const bad = await compareBv(
    right,
    wrong,
    { constraints: [] },
    defaultMapping(right, wrong),
    budget,
  );
  expect(bad.status).toBe('disproved');
  expect(bad.counterexample?.left_outputs).not.toEqual(bad.counterexample?.right_outputs);
}, 60000);
it('checks empty domains and containment before proving', async () => {
  const left = await load('add-u8'),
    right = structuredClone(left);
  const value = { kind: 'bv', width: 8, bits: '0x01' } as const;
  await expect(
    compareBv(
      left,
      right,
      {
        constraints: [
          { input: 'a', op: 'eq', value },
          { input: 'a', op: 'ne', value },
        ],
      },
      defaultMapping(left, right),
      budget,
    ),
  ).rejects.toMatchObject({ code: 'DOMAIN_EMPTY' });
  right.domain = { constraints: [{ input: 'a', op: 'eq', value }] };
  await expect(
    compareBv(left, right, { constraints: [] }, defaultMapping(left, right), budget),
  ).rejects.toMatchObject({ code: 'DOMAIN_MISMATCH' });
}, 60000);
it('keeps identically named intermediate nodes independent and preserves wide shift semantics in Z3', async () => {
  const left = await load('wide-shift-u8');
  const right = structuredClone(left);
  right.nodes = right.nodes.map((n) =>
    n.op === 'bv_shl' ? { ...n, op: 'copy', args: [n.args[0]] } : n,
  ) as any;
  expect(
    (await compareBv(left, right, { constraints: [] }, defaultMapping(left, right), budget)).status,
  ).toBe('disproved');
}, 60000);
it('cancellation does not become a proof and terminates the owned worker', async () => {
  const m = await load('mba-u8');
  const ctl = new AbortController();
  ctl.abort();
  expect(await compareBv(m, m, m.domain, defaultMapping(m, m), budget, ctl.signal)).toMatchObject({
    status: 'inconclusive',
    reason: 'cancelled',
  });
});
it('performs a genuine cost-reducing rewrite with exact validation', async () => {
  const m = await load('mba-u8');
  const result = await simplifyBv(m, budget);
  expect(result.candidate.nodes.length).toBeLessThan(m.nodes.length);
  expect(result.check.status).toBe('proved');
}, 60000);
it('exports a standalone module which executes all BV8 pairs in a fresh process', async () => {
  const m = await load('mba-u8');
  const dir = await mkdtemp(join(tmpdir(), 'wirefit-export-'));
  try {
    await writeFile(join(dir, 'model.mjs'), exportModelSource(m), 'utf8');
    await writeFile(
      join(dir, 'check.mjs'),
      `import {evaluate} from './model.mjs';let count=0;for(let a=0;a<256;a++)for(let b=0;b<256;b++){const v=n=>({kind:'bv',width:8,bits:'0x'+n.toString(16).padStart(2,'0')});const out=evaluate({a:v(a),b:v(b)}).result;if(out.bits!==v((a+b)%256).bits)throw Error('mismatch');count++;}console.log(count);`,
      'utf8',
    );
    expect(
      (await promisify(execFile)(process.execPath, [join(dir, 'check.mjs')])).stdout.trim(),
    ).toBe('65536');
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}, 60000);
it('kills an active worker on cancellation and reports confirmed process cleanup', async () => {
  const m = await load('mba-u8'),
    ctl = new AbortController();
  const pending = compareBv(m, m, m.domain, defaultMapping(m, m), budget, ctl.signal);
  setTimeout(() => ctl.abort(), 50);
  const result = await pending;
  expect(result.status).toBe('inconclusive');
  expect(result.reason).toBe('cancelled');
  expect(result.metadata.worker_process).toMatchObject({ cleanup: 'closed' });
}, 15000);
it('reports a hard deadline as inconclusive and preserves submitted SMT-LIB', async () => {
  const m = await load('mba-u8');
  const result = await compareBv(m, m, m.domain, defaultMapping(m, m), {
    ...budget,
    solver_hard_time_ms: 1,
  });
  expect(result.status).toBe('inconclusive');
  expect(result.reason).toBe('timeout');
  expect(result.metadata.submitted_queries).toHaveLength(3);
  expect(result.metadata.worker_process).toMatchObject({ cleanup: 'closed' });
}, 15000);
it('exports strictly checked standalone TypeScript without suppressing compiler diagnostics', async () => {
  const m = await load('mba-u8'),
    dir = await mkdtemp(join(tmpdir(), 'wirefit-ts-'));
  const target = join(dir, 'model.mts');
  try {
    await writeFile(target, exportModelSource(m, 'ts'), 'utf8');
    const tsc = new URL('../node_modules/typescript/bin/tsc', import.meta.url);
    const args = [
      tsc.pathname.replace(/^\/([A-Za-z]:)/, '$1'),
      '--ignoreConfig',
      '--strict',
      '--noEmit',
      '--target',
      'ES2023',
      '--module',
      'NodeNext',
      '--moduleResolution',
      'NodeNext',
      '--skipLibCheck',
      target,
    ];
    await promisify(execFile)(process.execPath, args);
    await writeFile(target, exportModelSource(m, 'ts') + '\nconst invalid: string = 1;\n', 'utf8');
    await expect(promisify(execFile)(process.execPath, args)).rejects.toThrow();
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}, 60000);
import { hashObject } from '../src/shared.js';
it('can persist timeout diagnostics with canonical integer-only semantic serialization', async () => {
  const m = await load('mba-u8');
  const result = await compareBv(m, m, m.domain, defaultMapping(m, m), {
    ...budget,
    solver_hard_time_ms: 1,
  });
  expect(() => hashObject(result)).not.toThrow();
}, 15000);

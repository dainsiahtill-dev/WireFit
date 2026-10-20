/** One task per isolated process. No live Z3 calls while an async check is pending. */
import { init, killThreads } from 'z3-solver';
import { createInterface } from 'node:readline';
import { readFile } from 'node:fs/promises';
import { createRequire } from 'node:module';
import { dirname, join } from 'node:path';
import { createHash } from 'node:crypto';
import type { CoreType, ValueMap } from '../types.js';
const lines = createInterface({ input: process.stdin, crlfDelay: Infinity });
for await (const line of lines) {
  try {
    const task = JSON.parse(line);
    if (task.protocol_version !== 1 || !Array.isArray(task.queries) || task.queries.length !== 3)
      throw new Error('Invalid task');
    const api = await init();
    const ctx = new api.Context('wirefit');
    const records: any[] = [];
    const require = createRequire(import.meta.url);
    const buildDir = dirname(require.resolve('z3-solver'));
    const pkg = JSON.parse(await readFile(join(buildDir, '../package.json'), 'utf8'));
    const wasm = await readFile(join(buildDir, 'z3-built.wasm'));
    const metadata = {
      z3_version: api.getVersionString(),
      z3_solver_package_version: pkg.version,
      wasm_sha256: createHash('sha256').update(wasm).digest('hex'),
      worker_pid: process.pid,
      worker_node: process.version,
    };
    let outcome = 'unknown',
      reason: string | undefined,
      inputs: ValueMap | undefined,
      domainWitness: ValueMap | undefined;
    const extractInputs = (solver: InstanceType<typeof ctx.Solver>): ValueMap => {
      const model = solver.model();
      return Object.fromEntries(
        task.symbols.map((s: { id: string; symbol: string; type: CoreType }) => {
          const value = model.eval(
            s.type.kind === 'bool'
              ? ctx.Bool.const(s.symbol)
              : ctx.BitVec.const(s.symbol, s.type.width),
            true,
          );
          return [
            s.id,
            s.type.kind === 'bool'
              ? { kind: 'bool', value: ctx.isTrue(value as any) }
              : {
                  kind: 'bv',
                  width: s.type.width,
                  bits:
                    '0x' +
                    (value as any)
                      .value()
                      .toString(16)
                      .padStart(s.type.width / 4, '0'),
                },
          ];
        }),
      );
    };
    for (let i = 0; i < task.queries.length; i++) {
      const q = task.queries[i],
        solver = new ctx.Solver();
      solver.set('timeout', task.soft_timeout_ms);
      solver.set('random_seed', task.seed);
      solver.fromString(q.smtlib.replace(/\(check-sat\)\s*$/, ''));
      const start = performance.now();
      const status = await solver.check();
      const record = {
        ...q,
        status,
        duration_ms: Math.round(performance.now() - start),
        ...(status === 'unknown' ? { reason: solver.reasonUnknown() } : {}),
      };
      records.push(record);
      process.stdout.write(
        JSON.stringify({ protocol_version: 1, kind: 'query', query: record }) + '\n',
      );
      if (i === 0 && status === 'sat') domainWitness = extractInputs(solver);
      if (status === 'unknown') {
        reason = record.reason;
        break;
      }
      if (i === 0 && status === 'unsat') {
        outcome = 'empty';
        break;
      }
      if (i === 1 && status === 'sat') {
        outcome = 'mismatch';
        break;
      }
      if (i === 2) {
        if (status === 'unsat') outcome = 'proved';
        else {
          outcome = 'disproved';
          inputs = extractInputs(solver);
        }
      }
    }
    const payload =
      JSON.stringify({
        protocol_version: 1,
        kind: 'result',
        result: {
          outcome,
          reason,
          inputs,
          queries: records,
          metadata: {
            ...metadata,
            domain_witness: domainWitness,
            solver_options: { timeout_ms: task.soft_timeout_ms, random_seed: task.seed },
          },
        },
      }) + '\n';
    killThreads(api.em);
    await new Promise<void>((resolve) => process.stdout.write(payload, () => resolve()));
    process.exit(0);
  } catch (error) {
    process.stderr.write(error instanceof Error ? (error.stack ?? error.message) : String(error));
    process.exit(1);
  }
}

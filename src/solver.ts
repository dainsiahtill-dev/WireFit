import type {
  BvModel,
  BvNode,
  Budget,
  CoreType,
  Domain,
  Mapping,
  TypedValue,
  ValueMap,
} from './types.js';
import { runProcess } from './process.js';
import { existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import {
  assert,
  hashObject,
  semanticHash,
  sourceHash,
  WirefitError,
  validateSchema,
} from './shared.js';
import {
  validateBvModel,
  validateDomain,
  validateMapping,
  domainContainsPoint,
  validateInputs,
} from './model.js';
import { evaluateBv } from './bv.js';
import { valueEquals } from './values.js';
export interface QueryRecord {
  kind: 'domain_nonempty' | 'domain_containment' | 'equivalence';
  status: 'sat' | 'unsat' | 'unknown';
  smtlib: string;
  duration_ms: number;
  reason?: string;
}
export interface ExactCheck {
  status: 'proved' | 'disproved' | 'inconclusive';
  reason?: string;
  counterexample?: { inputs: ValueMap; left_outputs: ValueMap; right_outputs: ValueMap };
  queries: QueryRecord[];
  metadata: Record<string, unknown>;
}
function literal(value: TypedValue): string {
  if (value.kind === 'bool') return String(value.value);
  assert(value.kind === 'bv', 'UNSUPPORTED_VALUE', 'FP32 is outside exact solver');
  return `#x${value.bits.slice(2)}`;
}
function sort(t: CoreType): string {
  return t.kind === 'bool' ? 'Bool' : `(_ BitVec ${t.width})`;
}
function nodeExpr(node: BvNode, args: string[], types: Map<string, CoreType>): string {
  const a = args[0]!,
    b = args[1]!,
    c = args[2]!,
    op = node.op;
  const w = node.type.kind === 'bv' ? node.type.width : 8;
  const unary: Record<string, string> = { bv_neg: 'bvneg', bv_not: 'bvnot', bool_not: 'not' };
  const binary: Record<string, string> = {
    bv_add: 'bvadd',
    bv_sub: 'bvsub',
    bv_mul: 'bvmul',
    bv_and: 'bvand',
    bv_or: 'bvor',
    bv_xor: 'bvxor',
    bv_eq: '=',
    bv_ult: 'bvult',
    bv_ule: 'bvule',
    bv_slt: 'bvslt',
    bv_sle: 'bvsle',
    bool_and: 'and',
    bool_or: 'or',
    bv_concat: 'concat',
  };
  if (op === 'const') return literal(node.attrs.value!);
  if (op === 'copy') return a;
  if (unary[op]) return `(${unary[op]} ${a})`;
  if (binary[op]) return `(${binary[op]} ${a} ${b})`;
  if (op === 'bv_ne') return `(not (= ${a} ${b}))`;
  if (op === 'select') return `(ite ${a} ${b} ${c})`;
  const t = types.get(node.args[0]!)!;
  if (op === 'bv_nonzero') return `(not (= ${a} (_ bv0 ${(t as any).width})))`;
  if (op === 'bool_to_bv') return `(ite ${a} (_ bv1 ${w}) (_ bv0 ${w}))`;
  if (op === 'bv_zext' || op === 'bv_sext')
    return `((_ ${op === 'bv_zext' ? 'zero_extend' : 'sign_extend'} ${w - (t as any).width}) ${a})`;
  if (op === 'bv_extract')
    return `((_ extract ${node.attrs.low! + w - 1} ${node.attrs.low!}) ${a})`;
  if (['bv_shl', 'bv_lshr', 'bv_ashr'].includes(op)) {
    const k = (types.get(node.args[1]!)! as any).width as number;
    const resized =
      k === w ? b : k < w ? `((_ zero_extend ${w - k}) ${b})` : `((_ extract ${w - 1} 0) ${b})`;
    const zero = `(_ bv0 ${w})`,
      full =
        op === 'bv_ashr'
          ? `(ite (bvslt ${a} ${zero}) (_ bv${(1n << BigInt(w)) - 1n} ${w}) ${zero})`
          : zero;
    return `(ite (bvuge ${b} (_ bv${w} ${k})) ${full} (${op === 'bv_shl' ? 'bvshl' : op === 'bv_lshr' ? 'bvlshr' : 'bvashr'} ${a} ${resized}))`;
  }
  throw new WirefitError('UNSUPPORTED_OPERATION', `Cannot encode ${op}`);
}
function compileModel(
  model: BvModel,
  namespace: string,
  vars: Map<string, string>,
): { definitions: string[]; outputs: Map<string, string> } {
  const refs = new Map(vars),
    types = new Map(model.inputs.map((p) => [p.id, p.type]));
  const definitions: string[] = [];
  model.nodes.forEach((n, i) => {
    const symbol = `${namespace}${i}`,
      expr = nodeExpr(
        n,
        n.args.map((id) => refs.get(id)!),
        types,
      );
    definitions.push(`(define-fun ${symbol} () ${sort(n.type)} ${expr})`);
    refs.set(n.id, symbol);
    types.set(n.id, n.type);
  });
  return { definitions, outputs: new Map(model.outputs.map((o) => [o.id, refs.get(o.ref)!])) };
}
function domainExpr(domain: Domain, vars: Map<string, string>): string {
  const ops: Record<string, string> = {
    eq: '=',
    ule: 'bvule',
    uge: 'bvuge',
    sle: 'bvsle',
    sge: 'bvsge',
  };
  const constraints = domain.constraints.map((c) =>
    c.op === 'ne'
      ? `(not (= ${vars.get(c.input)} ${literal(c.value)}))`
      : `(${ops[c.op]} ${vars.get(c.input)} ${literal(c.value)})`,
  );
  return constraints.length ? `(and ${constraints.join(' ')})` : 'true';
}
export function buildExactQueries(
  left: BvModel,
  right: BvModel,
  domain: Domain,
  mapping: Mapping,
): {
  queries: { kind: QueryRecord['kind']; smtlib: string }[];
  symbols: { id: string; symbol: string; type: CoreType }[];
} {
  const symbols = left.inputs.map((p, i) => ({ id: p.id, symbol: `i${i}`, type: p.type }));
  const lv = new Map(symbols.map((p) => [p.id, p.symbol]));
  const rv = new Map(mapping.inputs.map((p) => [p.right, lv.get(p.left)!]));
  const declarations = symbols
    .map((p) => `(declare-fun ${p.symbol} () ${sort(p.type)})`)
    .join('\n');
  const d = domainExpr(domain, lv);
  const contracts = `(and ${domainExpr(left.domain, lv)} ${domainExpr(right.domain, rv)})`;
  const l = compileModel(left, 'L', lv),
    r = compileModel(right, 'R', rv);
  const difference = `(or ${mapping.outputs.map((p) => `(not (= ${l.outputs.get(p.left)} ${r.outputs.get(p.right)}))`).join(' ')})`;
  const query = (kind: QueryRecord['kind'], assertion: string, defs: string[] = []) => ({
    kind,
    smtlib: `(set-logic QF_BV)\n${declarations}\n${defs.join('\n')}\n(assert ${assertion})\n(check-sat)\n`,
  });
  return {
    symbols,
    queries: [
      query('domain_nonempty', d),
      query('domain_containment', `(and ${d} (not ${contracts}))`),
      query('equivalence', `(and ${d} ${difference})`, [...l.definitions, ...r.definitions]),
    ],
  };
}
interface WorkerReply {
  outcome: 'proved' | 'disproved' | 'unknown' | 'empty' | 'mismatch';
  queries: QueryRecord[];
  inputs?: ValueMap;
  metadata: Record<string, unknown>;
  reason?: string;
}
export async function compareBv(
  left: BvModel,
  right: BvModel,
  domain: Domain,
  mapping: Mapping,
  budget: Budget,
  signal?: AbortSignal,
): Promise<ExactCheck> {
  validateBvModel(left);
  validateBvModel(right);
  validateDomain(domain, left.inputs);
  validateMapping(left, right, mapping);
  validateSchema('budget', budget);
  const metadata = {
    adapter: 'wirefit.smtlib.bv.v1',
    left_model_sha256: semanticHash(left),
    right_model_sha256: semanticHash(right),
    left_source_sha256: sourceHash(left),
    right_source_sha256: sourceHash(right),
    domain_sha256: hashObject(domain),
    mapping,
    budget,
    scope: 'declared_model_outputs',
    uncompared_outputs: {
      left: left.outputs
        .filter((o) => !mapping.outputs.some((p) => p.left === o.id))
        .map((o) => o.id),
      right: right.outputs
        .filter((o) => !mapping.outputs.some((p) => p.right === o.id))
        .map((o) => o.id),
    },
  };
  if (signal?.aborted)
    return { status: 'inconclusive', reason: 'cancelled', queries: [], metadata };
  const task = buildExactQueries(left, right, domain, mapping);
  let workerPath = fileURLToPath(new URL('./workers/z3.js', import.meta.url));
  const source = !existsSync(workerPath);
  if (source) workerPath = workerPath.replace(/\.js$/, '.ts');
  const submitted_queries = task.queries;
  let result: WorkerReply;
  const parse = (stdout: string): WorkerReply => {
    let final: WorkerReply | undefined;
    const completed: QueryRecord[] = [];
    for (const line of stdout.trimEnd().split('\n')) {
      if (!line) continue;
      const msg = JSON.parse(line);
      assert(msg.protocol_version === 1, 'WORKER_PROTOCOL_ERROR', 'Unsupported Z3 worker response');
      if (msg.kind === 'query') {
        const query = msg.query,
          index = completed.length,
          submitted = submitted_queries[index];
        assert(
          submitted &&
            query &&
            query.kind === submitted.kind &&
            query.smtlib === submitted.smtlib &&
            ['sat', 'unsat', 'unknown'].includes(query.status) &&
            Number.isSafeInteger(query.duration_ms) &&
            query.duration_ms >= 0,
          'WORKER_PROTOCOL_ERROR',
          'Invalid query record',
        );
        assert(
          index === 0 ||
            (index === 1 && completed[0]?.status === 'sat') ||
            (index === 2 && completed[1]?.status === 'unsat'),
          'WORKER_PROTOCOL_ERROR',
          'Invalid query sequence',
        );
        completed.push(query);
        continue;
      }
      assert(
        msg.kind === 'result' && !final,
        'WORKER_PROTOCOL_ERROR',
        'Duplicate or unknown Z3 worker response',
      );
      final = msg.result;
    }
    assert(
      final &&
        final.metadata &&
        typeof final.metadata === 'object' &&
        Array.isArray(final.queries) &&
        hashObject(final.queries) === hashObject(completed),
      'WORKER_PROTOCOL_ERROR',
      'Z3 worker returned invalid or missing result',
    );
    const expected =
      completed[0]?.status === 'unsat'
        ? 'empty'
        : completed[0]?.status === 'unknown'
          ? 'unknown'
          : completed[1]?.status === 'sat'
            ? 'mismatch'
            : completed[1]?.status === 'unknown'
              ? 'unknown'
              : completed[2]?.status === 'sat'
                ? 'disproved'
                : completed[2]?.status === 'unsat'
                  ? 'proved'
                  : completed[2]?.status === 'unknown'
                    ? 'unknown'
                    : undefined;
    assert(
      expected && final.outcome === expected,
      'WORKER_PROTOCOL_ERROR',
      'Worker verdict contradicts completed solver queries',
    );
    return final;
  };
  try {
    const execution = await runProcess(
      process.execPath,
      [...(source ? ['--import', 'tsx'] : []), workerPath],
      {
        input:
          JSON.stringify({
            protocol_version: 1,
            ...task,
            soft_timeout_ms: budget.solver_soft_time_ms,
            seed: budget.seed,
          }) + '\n',
        timeout_ms: Math.min(budget.wall_time_ms, budget.solver_hard_time_ms),
        max_stdout_bytes: 8_000_000,
        max_stderr_bytes: 8192,
        signal,
      },
    );
    assert(
      execution.code === 0,
      'Z3_WORKER_CRASH',
      `Z3 worker exited ${execution.code}: ${execution.stderr}`,
    );
    result = parse(execution.stdout);
    result.metadata = {
      ...result.metadata,
      worker_process: { pid: execution.pid, code: execution.code, cleanup: 'closed' },
    };
  } catch (error) {
    const detail =
      error instanceof WirefitError && error.details && typeof error.details === 'object'
        ? (error.details as Record<string, unknown>)
        : {};
    const queries: QueryRecord[] = [];
    if (typeof detail.stdout === 'string')
      for (const line of detail.stdout.trimEnd().split('\n')) {
        try {
          const msg = JSON.parse(line);
          if (msg.protocol_version === 1 && msg.kind === 'query') queries.push(msg.query);
        } catch {
          /* Preserve only complete validated protocol records. */
        }
      }
    const reason =
      error instanceof WirefitError && error.code === 'CANCELLED'
        ? 'cancelled'
        : error instanceof WirefitError && error.code === 'TIMEOUT'
          ? 'timeout'
          : error instanceof Error
            ? error.message
            : String(error);
    return {
      status: 'inconclusive',
      reason,
      queries,
      metadata: {
        ...metadata,
        submitted_queries,
        worker_process: {
          ...detail,
          ...(typeof detail.duration_ms === 'number'
            ? { duration_ms: Math.round(detail.duration_ms) }
            : {}),
        },
      },
    };
  }
  const verifyPoint = (value: unknown): ValueMap => {
    try {
      return validateInputs(left.inputs, value);
    } catch (error) {
      throw new WirefitError(
        'INTERNAL_CONSISTENCY_ERROR',
        'Solver returned malformed typed inputs',
        { error: error instanceof Error ? error.message : String(error) },
      );
    }
  };
  const info = { ...metadata, ...result.metadata };
  if (result.metadata.domain_witness) {
    verifyPoint(result.metadata.domain_witness);
    assert(
      domainContainsPoint(domain, result.metadata.domain_witness as ValueMap),
      'INTERNAL_CONSISTENCY_ERROR',
      'Solver domain witness violates requested domain',
    );
  }
  if (result.outcome === 'empty')
    throw new WirefitError('DOMAIN_EMPTY', 'Requested comparison domain is empty', {
      queries: result.queries,
    });
  if (result.outcome === 'mismatch')
    throw new WirefitError(
      'DOMAIN_MISMATCH',
      'Requested domain is not contained in both model contracts',
      { queries: result.queries },
    );
  if (result.outcome === 'unknown')
    return {
      status: 'inconclusive',
      reason: result.reason ?? 'solver_unknown',
      queries: result.queries,
      metadata: info,
    };
  if (result.outcome === 'proved')
    return { status: 'proved', queries: result.queries, metadata: info };
  const inputs = verifyPoint(result.inputs);
  const rightInputs = Object.fromEntries(mapping.inputs.map((p) => [p.right, inputs[p.left]!]));
  assert(
    domainContainsPoint(domain, inputs) &&
      domainContainsPoint(left.domain, inputs) &&
      domainContainsPoint(right.domain, rightInputs),
    'INTERNAL_CONSISTENCY_ERROR',
    'Solver counterexample violates domain',
  );
  const leftOutputs = evaluateBv(left, inputs),
    rightOutputs = evaluateBv(right, rightInputs);
  assert(
    mapping.outputs.some((p) => !valueEquals(leftOutputs[p.left]!, rightOutputs[p.right]!)),
    'INTERNAL_CONSISTENCY_ERROR',
    'Solver counterexample does not reproduce in independent evaluator',
  );
  return {
    status: 'disproved',
    queries: result.queries,
    metadata: info,
    counterexample: { inputs, left_outputs: leftOutputs, right_outputs: rightOutputs },
  };
}

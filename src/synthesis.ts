import type {
  BvModel,
  BvNode,
  BvOp,
  Budget,
  CoreType,
  CoreValue,
  Domain,
  TypedValue,
  ValueMap,
} from './types.js';
import { hashObject, assert } from './shared.js';
import { bv, bool, valueEquals, sameType, validateTypedValue } from './values.js';
import { evaluateBv, evaluateNode } from './bv.js';
import { validateBvModel, defaultMapping, domainContainsPoint, validateDomain } from './model.js';
import { compareBv, type ExactCheck } from './solver.js';
export interface SimplificationResult {
  candidate: BvModel;
  check: ExactCheck;
  search: {
    generated: number;
    sample_rejected: number;
    solver_checked: number;
    refinements: number;
    counterexamples: ValueMap[];
    rules: string[];
    stop_reason: 'space_exhausted' | 'budget_exhausted' | 'cancelled';
    original_cost: number;
    candidate_cost: number;
    grammar: BvOp[];
    constants: CoreValue[];
  };
}
function prune(model: BvModel): BvModel {
  const needed = new Set(model.outputs.map((o) => o.ref));
  if (model.scope.execution_guard.kind === 'model_bool')
    needed.add(model.scope.execution_guard.node_id);
  for (const n of [...model.nodes].reverse())
    if (needed.has(n.id)) n.args.forEach((a) => needed.add(a));
  return { ...model, nodes: model.nodes.filter((n) => needed.has(n.id)) };
}
function rewrite(model: BvModel): { model: BvModel; rules: string[] } {
  const replacements = new Map<string, string>(),
    nodes: BvNode[] = [],
    known = new Map<string, TypedValue>(),
    defs = new Map<string, BvNode>(),
    cse = new Map<string, string>(),
    rules: string[] = [];
  const ref = (id: string) => replacements.get(id) ?? id;
  const equalPair = (a: string[], b: string[]) =>
    a.length === b.length && [...a].sort().join(',') === [...b].sort().join(',');
  for (const original of model.nodes) {
    let n = { ...original, args: original.args.map(ref), attrs: { ...original.attrs } };
    let alias: string | undefined;
    const a = n.args[0]!,
      b = n.args[1]!;
    if (n.op === 'copy') {
      alias = a;
      rules.push('copy');
    }
    if (n.op === 'select' && b === n.args[2]) {
      alias = b;
      rules.push('select_same_branch');
    }
    if (n.op === 'const') known.set(n.id, n.attrs.value!);
    else if (n.args.every((a) => known.has(a))) {
      const v = evaluateNode(
        n.op,
        n.type,
        n.args.map((a) => known.get(a)!),
        n.attrs,
      );
      n = { ...n, op: 'const', args: [], attrs: { value: v } };
      known.set(n.id, v);
      rules.push('constant_fold');
    }
    if (
      ['bv_add', 'bv_or', 'bv_xor', 'bv_sub'].includes(n.op) &&
      known.get(b)?.kind === 'bv' &&
      BigInt((known.get(b) as any).bits) === 0n
    ) {
      alias = a;
      rules.push('right_zero_identity');
    }
    if (
      ['bv_add', 'bv_or', 'bv_xor'].includes(n.op) &&
      known.get(a)?.kind === 'bv' &&
      BigInt((known.get(a) as any).bits) === 0n
    ) {
      alias = b;
      rules.push('left_zero_identity');
    }
    if (['bv_and', 'bv_or'].includes(n.op) && a === b) {
      alias = a;
      rules.push('idempotence');
    }
    if (['bv_xor', 'bv_sub'].includes(n.op) && a === b && n.type.kind === 'bv') {
      n = { ...n, op: 'const', args: [], attrs: { value: bv(0n, n.type.width) } };
      known.set(n.id, n.attrs.value!);
      rules.push('self_cancellation');
    }
    if (n.op === 'bv_add') {
      for (const [x, y] of [
        [a, b],
        [b, a],
      ] as [string, string][]) {
        const xor = defs.get(x),
          mul = defs.get(y);
        if (xor?.op !== 'bv_xor' || mul?.op !== 'bv_mul') continue;
        const andId = mul.args.find((id) => defs.get(id)?.op === 'bv_and');
        const constant = mul.args.find(
          (id) => known.get(id)?.kind === 'bv' && BigInt((known.get(id) as any).bits) === 2n,
        );
        const and = andId ? defs.get(andId) : undefined;
        if (constant && and && equalPair(xor.args, and.args)) {
          n = { ...n, args: [...xor.args] };
          rules.push('xor_plus_twice_and');
          break;
        }
      }
    }
    if (alias) {
      replacements.set(n.id, ref(alias));
      continue;
    }
    const key = hashObject({ op: n.op, type: n.type, args: n.args, attrs: n.attrs });
    const existing = cse.get(key);
    if (existing) {
      replacements.set(n.id, existing);
      rules.push('common_subexpression');
      continue;
    }
    cse.set(key, n.id);
    nodes.push(n);
    defs.set(n.id, n);
  }
  const scope = structuredClone(model.scope);
  if (scope.execution_guard.kind === 'model_bool')
    scope.execution_guard.node_id = ref(scope.execution_guard.node_id);
  return {
    model: prune({
      ...model,
      nodes,
      scope,
      outputs: model.outputs.map((o) => ({ ...o, ref: ref(o.ref) })),
    }),
    rules,
  };
}
interface Expression {
  ref: string;
  type: CoreType;
  nodes: BvNode[];
  depth: number;
}
function* enumerate(
  model: BvModel,
  maxNodes: number,
  maxGenerated: number,
  grammar: BvOp[],
  constants: CoreValue[],
  active: () => boolean,
): Generator<Expression> {
  const pool: Expression[] = model.inputs.map((p) => ({
    ref: p.id,
    type: p.type,
    nodes: [],
    depth: 0,
  }));
  for (const p of pool) yield p;
  let next = 0;
  const fresh = () => {
    let id: string;
    do {
      id = `synth${next++}`;
    } while (model.inputs.some((p) => p.id === id));
    return id;
  };
  const seen = new Set<string>();
  const add = (
    op: BvNode['op'],
    type: CoreType,
    args: Expression[],
    attrs: BvNode['attrs'] = {},
  ): Expression | undefined => {
    const merged = new Map<string, BvNode>();
    args.forEach((a) => a.nodes.forEach((n) => merged.set(n.id, n)));
    if (merged.size + 1 > maxNodes) return;
    const key = hashObject({ op, type, args: args.map((a) => a.ref), attrs });
    if (seen.has(key)) return;
    seen.add(key);
    const node: BvNode = { id: fresh(), op, type, args: args.map((a) => a.ref), attrs };
    return {
      ref: node.id,
      type,
      nodes: [...merged.values(), node],
      depth: 1 + Math.max(0, ...args.map((a) => a.depth)),
    };
  };
  const constantTypes: CoreType[] = constants.map((value) =>
    value.kind === 'bv' ? { kind: 'bv', width: value.width } : { kind: 'bool' },
  );
  const distinctTypes = [
    ...model.inputs.map((p) => p.type),
    ...model.outputs.map((p) => p.type),
    ...constantTypes,
  ].filter((t, i, types) => types.findIndex((other) => sameType(other, t)) === i);
  for (const t of distinctTypes)
    for (const value of constants.filter((value) => sameType(value, t))) {
      const e = add('const', t, [], { value });
      if (e) {
        pool.push(e);
        yield e;
      }
    }
  let generated = pool.length;
  for (let index = 0; index < pool.length && generated < maxGenerated; index++) {
    const a = pool[index]!;
    for (const op of grammar.filter((op) =>
      (a.type.kind === 'bv' ? ['bv_neg', 'bv_not'] : ['bool_not']).includes(op),
    )) {
      const e = add(op, a.type, [a]);
      if (e) {
        pool.push(e);
        generated++;
        yield e;
        if (generated >= maxGenerated) return;
      }
    }
    const available = pool.slice(0, index + 1);
    for (const b of available) {
      for (const op of grammar) {
        if (!active()) return;
        const shift = ['bv_shl', 'bv_lshr', 'bv_ashr'].includes(op),
          comparison = ['bv_ult', 'bv_slt'].includes(op);
        const binary = [
          'bv_add',
          'bv_sub',
          'bv_mul',
          'bv_and',
          'bv_or',
          'bv_xor',
          'bool_and',
          'bool_or',
          ...(shift || comparison ? [op] : []),
        ].includes(op);
        if (
          !binary ||
          (a.type.kind === 'bool' && !['bool_and', 'bool_or'].includes(op)) ||
          (a.type.kind === 'bv' && ['bool_and', 'bool_or'].includes(op))
        )
          continue;
        if (shift ? a.type.kind !== 'bv' || b.type.kind !== 'bv' : !sameType(a.type, b.type))
          continue;
        const output: CoreType = comparison ? { kind: 'bool' } : a.type;
        const directional = ['bv_sub', 'bv_shl', 'bv_lshr', 'bv_ashr', 'bv_ult', 'bv_slt'].includes(
          op,
        );
        for (const pair of directional
          ? [
              [a, b],
              [b, a],
            ]
          : [[a, b]]) {
          if (shift && pair[0]!.type.kind !== 'bv') continue;
          const type = shift ? pair[0]!.type : output;
          const e = add(op, type, pair);
          if (e) {
            pool.push(e);
            generated++;
            yield e;
            if (generated >= maxGenerated) return;
          }
        }
      }
    }
    if (grammar.includes('select')) {
      const booleans = pool.filter((e) => e.type.kind === 'bool');
      for (const condition of booleans)
        for (const b of available) {
          if (!active()) return;
          if (!sameType(a.type, b.type)) continue;
          const e = add('select', a.type, [condition, a, b]);
          if (e) {
            pool.push(e);
            generated++;
            yield e;
            if (generated >= maxGenerated) return;
          }
        }
    }
  }
}
/** Sample filtering only rejects; every selected candidate is checked by the exact solver. */
export interface SimplifyOptions {
  domain?: Domain;
  grammar?: BvOp[];
  constants?: CoreValue[];
}
export async function simplifyBv(
  model: BvModel,
  budget: Budget,
  signal?: AbortSignal,
  options: SimplifyOptions = {},
): Promise<SimplificationResult> {
  validateBvModel(model);
  const domain = validateDomain(options.domain ?? model.domain, model.inputs);
  const grammar = options.grammar ?? [
    'bv_add',
    'bv_sub',
    'bv_mul',
    'bv_and',
    'bv_or',
    'bv_xor',
    'bv_not',
    'bv_neg',
    'bv_shl',
    'bv_lshr',
    'bv_ashr',
    'bv_ult',
    'bv_slt',
    'select',
  ];
  const allowed = [
    'bv_add',
    'bv_sub',
    'bv_mul',
    'bv_and',
    'bv_or',
    'bv_xor',
    'bv_not',
    'bv_neg',
    'bv_shl',
    'bv_lshr',
    'bv_ashr',
    'bv_ult',
    'bv_slt',
    'select',
    'bool_and',
    'bool_or',
    'bool_not',
  ];
  assert(
    Array.isArray(grammar) &&
      grammar.length > 0 &&
      grammar.length <= 32 &&
      new Set(grammar).size === grammar.length &&
      grammar.every((op) => allowed.includes(op)),
    'INVALID_SEARCH',
    'Invalid enumeration grammar',
  );
  const constants =
    options.constants ??
    model.inputs.flatMap<CoreValue>((p) =>
      p.type.kind === 'bv'
        ? [bv(0n, p.type.width), bv(1n, p.type.width), bv(-1n, p.type.width)]
        : [bool(false), bool(true)],
    );
  assert(
    Array.isArray(constants) && constants.length <= 64,
    'INVALID_SEARCH',
    'Invalid constant pool',
  );
  for (const value of constants) {
    const checkedValue = validateTypedValue(value);
    assert(checkedValue.kind !== 'fp32', 'INVALID_SEARCH', 'Exact search accepts core values only');
  }
  const start = Date.now(),
    rewritten = rewrite({ ...model, domain });
  let candidate = rewritten.model,
    check = await compareBv(
      model,
      candidate,
      domain,
      defaultMapping(model, candidate),
      budget,
      signal,
    );
  assert(
    check.status !== 'disproved',
    'INTERNAL_CONSISTENCY_ERROR',
    'Rewrite generated a false identity',
  );
  let generated = 0,
    sample_rejected = 0,
    solver_checked = 1,
    refinements = 0;
  const counterexamples: ValueMap[] = [];
  let stop_reason: SimplificationResult['search']['stop_reason'] = 'space_exhausted';
  // A zero seed deliberately leaves the solver to refine this initial observational class.
  const initial = Object.fromEntries(
    model.inputs.map((p) => [p.id, p.type.kind === 'bv' ? bv(0n, p.type.width) : bool(false)]),
  );
  const samples: ValueMap[] = domainContainsPoint(domain, initial) ? [initial] : [];
  if (
    candidate.nodes.length > 0 &&
    model.outputs.length === 1 &&
    model.scope.execution_guard.kind !== 'model_bool' &&
    check.status === 'proved'
  ) {
    for (const e of enumerate(
      model,
      Math.min(budget.max_ast_nodes, Math.max(0, candidate.nodes.length - 1)),
      budget.max_candidates,
      grammar,
      constants,
      () => !signal?.aborted && Date.now() - start < budget.wall_time_ms,
    )) {
      if (generated % 32 === 0) await new Promise<void>((resolve) => setImmediate(resolve));
      if (signal?.aborted) {
        stop_reason = 'cancelled';
        break;
      }
      if (
        Date.now() - start >= budget.wall_time_ms ||
        generated >= budget.max_candidates ||
        solver_checked >= budget.max_iterations
      ) {
        stop_reason = 'budget_exhausted';
        break;
      }
      generated++;
      if (!sameType(e.type, model.outputs[0]!.type) || e.nodes.length >= candidate.nodes.length)
        continue;
      const trial = validateBvModel({
        ...model,
        domain,
        nodes: e.nodes,
        outputs: [{ ...model.outputs[0]!, ref: e.ref }],
      });
      if (
        samples.some(
          (s) =>
            !valueEquals(
              evaluateBv(model, s)[model.outputs[0]!.id]!,
              evaluateBv(trial, s)[model.outputs[0]!.id]!,
            ),
        )
      ) {
        sample_rejected++;
        continue;
      }
      const remaining = budget.wall_time_ms - (Date.now() - start);
      if (remaining <= 0) {
        stop_reason = 'budget_exhausted';
        break;
      }
      const tested = await compareBv(
        model,
        trial,
        domain,
        defaultMapping(model, trial),
        { ...budget, wall_time_ms: remaining },
        signal,
      );
      solver_checked++;
      if (tested.status === 'proved') {
        candidate = trial;
        check = tested;
      } else if (tested.status === 'disproved') {
        samples.push(tested.counterexample!.inputs);
        counterexamples.push(tested.counterexample!.inputs);
        refinements++;
      } else {
        stop_reason = signal?.aborted ? 'cancelled' : 'budget_exhausted';
        break;
      }
    }
  }
  if (signal?.aborted) stop_reason = 'cancelled';
  else if (Date.now() - start >= budget.wall_time_ms || check.status === 'inconclusive')
    stop_reason = 'budget_exhausted';
  candidate = {
    ...candidate,
    model_id: 'simplified_' + hashObject(candidate).slice(0, 16),
    title: `Simplified: ${model.title}`.slice(0, 256),
  };
  // Model identity/title are outside the semantic digest; the verified executable body is unchanged.
  return {
    candidate,
    check,
    search: {
      generated,
      sample_rejected,
      solver_checked,
      refinements,
      counterexamples,
      rules: rewritten.rules,
      stop_reason,
      original_cost: model.nodes.length,
      candidate_cost: candidate.nodes.length,
      grammar,
      constants,
    },
  };
}

export interface SuggestedPoint {
  inputs: ValueMap;
  reason: 'disagreement' | 'boundary';
  models?: [string, string];
}
export interface SuggestionResult {
  inputs: SuggestedPoint[];
  checks: ExactCheck[];
  domain: Domain;
  status: 'complete' | 'partial';
  stop_reason: 'complete' | 'budget_exhausted' | 'cancelled';
}
export async function suggestBvInputs(
  models: BvModel[],
  domain: Domain,
  budget: Budget,
  signal?: AbortSignal,
  options: { strategy?: 'disagreement' | 'boundaries'; max_inputs?: number } = {},
): Promise<SuggestionResult> {
  assert(
    Array.isArray(models) && models.length >= 2 && models.length <= 16,
    'INVALID_REQUEST',
    'Suggest requires two to sixteen models',
  );
  const first = validateBvModel(models[0]!);
  validateDomain(domain, first.inputs);
  for (const model of models) {
    validateBvModel(model);
    defaultMapping(first, model);
    assert(
      model.outputs.length === first.outputs.length,
      'INVALID_MAPPING',
      'Suggestions require identical signatures',
    );
  }
  const strategy = options.strategy ?? 'disagreement',
    limit = options.max_inputs ?? 16;
  assert(
    (strategy === 'disagreement' || strategy === 'boundaries') &&
      Number.isInteger(limit) &&
      limit >= 1 &&
      limit <= 100000,
    'INVALID_REQUEST',
    'Invalid suggestion options',
  );
  const points: SuggestedPoint[] = [],
    checks: ExactCheck[] = [],
    seen = new Set<string>();
  let status: SuggestionResult['status'] = 'complete',
    stop_reason: SuggestionResult['stop_reason'] = 'complete';
  const start = Date.now();
  const append = (point: SuggestedPoint) => {
    if (points.length >= limit || !domainContainsPoint(domain, point.inputs)) return;
    const hash = hashObject(point.inputs);
    if (!seen.has(hash)) {
      seen.add(hash);
      points.push(point);
    }
  };
  let witness: ValueMap | undefined;
  outer: for (let i = 0; i < (strategy === 'boundaries' ? 1 : models.length); i++)
    for (let j = i + 1; j < models.length; j++) {
      if (signal?.aborted) {
        status = 'partial';
        stop_reason = 'cancelled';
        break outer;
      }
      const remaining = budget.wall_time_ms - (Date.now() - start);
      if (remaining <= 0 || checks.length >= budget.max_iterations) {
        status = 'partial';
        stop_reason = 'budget_exhausted';
        break outer;
      }
      const left = models[i]!,
        right = models[j]!;
      const check = await compareBv(
        left,
        right,
        domain,
        defaultMapping(left, right),
        { ...budget, wall_time_ms: remaining },
        signal,
      );
      checks.push(check);
      witness ??= check.metadata.domain_witness as ValueMap | undefined;
      if (check.status === 'inconclusive') {
        status = 'partial';
        stop_reason = signal?.aborted ? 'cancelled' : 'budget_exhausted';
        break outer;
      }
      if (strategy === 'disagreement' && check.counterexample)
        append({
          inputs: check.counterexample.inputs,
          reason: 'disagreement',
          models: [left.model_id, right.model_id],
        });
      if (strategy === 'disagreement' && points.length >= limit) break outer;
    }
  if (strategy === 'boundaries' && witness && status === 'complete') {
    append({ inputs: witness, reason: 'boundary' });
    for (const input of first.inputs) {
      const type = input.type;
      const endpoints = domain.constraints.filter((c) => c.input === input.id).map((c) => c.value);
      const values: TypedValue[] =
        type.kind === 'bool'
          ? [bool(false), bool(true)]
          : [
              bv(0n, type.width),
              bv(1n, type.width),
              bv(-1n, type.width),
              bv(1n << BigInt(type.width - 1), type.width),
              bv((1n << BigInt(type.width - 1)) - 1n, type.width),
            ];
      values.push(...endpoints);
      for (const endpoint of endpoints)
        if (endpoint.kind === 'bv')
          values.push(
            bv(BigInt(endpoint.bits) - 1n, endpoint.width),
            bv(BigInt(endpoint.bits) + 1n, endpoint.width),
          );
      for (const value of values) {
        if (signal?.aborted) {
          status = 'partial';
          stop_reason = 'cancelled';
          break;
        }
        if (Date.now() - start >= budget.wall_time_ms) {
          status = 'partial';
          stop_reason = 'budget_exhausted';
          break;
        }
        append({ inputs: { ...witness, [input.id]: value }, reason: 'boundary' });
      }
    }
  }
  return { inputs: points, checks, domain, status, stop_reason };
}

import type {
  BvModel,
  BvNode,
  CoreType,
  Domain,
  Mapping,
  Port,
  Signature,
  TypedValue,
  ValueMap,
} from './types.js';
import { assert, validateSchema } from './shared.js';
import { sameType, validateTypedValue, valueEquals, signed, fp32Number } from './values.js';
export function validateDomain(value: unknown, inputs: Port[]): Domain {
  assert(
    !!value && typeof value === 'object' && !Array.isArray(value),
    'INVALID_DOMAIN',
    'Domain must be an object',
  );
  const d = value as Domain;
  assert(
    Object.keys(d).join(',') === 'constraints' &&
      Array.isArray(d.constraints) &&
      d.constraints.length <= 128,
    'INVALID_DOMAIN',
    'Invalid domain properties',
  );
  const types = new Map(inputs.map((p) => [p.id, p.type]));
  for (const c of d.constraints) {
    assert(
      !!c && typeof c === 'object' && Object.keys(c).sort().join(',') === 'input,op,value',
      'INVALID_DOMAIN',
      'Invalid constraint',
    );
    const t = types.get(c.input);
    assert(t, 'INVALID_DOMAIN', 'Constraint references undeclared input');
    validateTypedValue(c.value, t);
    assert(
      (t.kind === 'bool'
        ? ['eq', 'ne']
        : t.kind === 'bv'
          ? ['eq', 'ne', 'ule', 'uge', 'sle', 'sge']
          : ['eq', 'ne', 'le', 'ge']
      ).includes(c.op),
      'INVALID_DOMAIN',
      'Constraint operator is incompatible with type',
    );
    if (c.value.kind === 'fp32')
      assert(
        Number.isFinite(fp32Number(c.value)),
        'INVALID_DOMAIN',
        'Domain endpoint must be finite',
      );
  }
  return d;
}
export function validateInputs(inputs: Port[], values: unknown): ValueMap {
  assert(
    !!values && typeof values === 'object' && !Array.isArray(values),
    'INVALID_INPUT',
    'Inputs must be a typed value map',
  );
  const map = values as ValueMap;
  assert(
    Object.keys(map).length === inputs.length && inputs.every((p) => Object.hasOwn(map, p.id)),
    'INVALID_INPUT',
    'Inputs must exactly match declared signature',
  );
  for (const p of inputs) validateTypedValue(map[p.id], p.type);
  return map;
}
export function domainContainsPoint(domain: Domain, inputs: ValueMap): boolean {
  return domain.constraints.every((c) => {
    const a = inputs[c.input],
      b = c.value;
    if (!a || !sameType(a, b)) return false;
    if (c.op === 'eq' || c.op === 'ne') {
      const eq =
        a.kind === 'fp32' && b.kind === 'fp32'
          ? fp32Number(a) === fp32Number(b)
          : valueEquals(a, b);
      return c.op === 'eq' ? eq : !eq;
    }
    if (a.kind === 'bv' && b.kind === 'bv') {
      const x = c.op.startsWith('s') ? signed(a) : BigInt(a.bits),
        y = c.op.startsWith('s') ? signed(b) : BigInt(b.bits);
      return c.op.endsWith('le') ? x <= y : x >= y;
    }
    if (a.kind === 'fp32' && b.kind === 'fp32') {
      const x = fp32Number(a),
        y = fp32Number(b);
      return Number.isFinite(x) && (c.op === 'le' ? x <= y : x >= y);
    }
    return false;
  });
}
const unary = new Set([
  'copy',
  'bv_neg',
  'bv_not',
  'bool_not',
  'bv_nonzero',
  'bool_to_bv',
  'bv_zext',
  'bv_sext',
  'bv_extract',
]);
const comparisons = new Set(['bv_eq', 'bv_ne', 'bv_ult', 'bv_ule', 'bv_slt', 'bv_sle']);
const arithmetic = new Set(['bv_add', 'bv_sub', 'bv_mul', 'bv_and', 'bv_or', 'bv_xor']);
export function validateNode(node: BvNode, types: Map<string, CoreType>): void {
  assert(
    !!node.type &&
      typeof node.type === 'object' &&
      ((node.type.kind === 'bool' && Object.keys(node.type).join(',') === 'kind') ||
        (node.type.kind === 'bv' &&
          [8, 16, 32, 64].includes(node.type.width) &&
          Object.keys(node.type).sort().join(',') === 'kind,width')),
    'INVALID_TYPE',
    'Invalid core output type',
  );
  assert(
    !!node.attrs && typeof node.attrs === 'object' && !Array.isArray(node.attrs),
    'INVALID_OPERATION',
    'Attributes must be an object',
  );
  const expectedAttrs = node.op === 'const' ? 'value' : node.op === 'bv_extract' ? 'low' : '';
  assert(
    Object.keys(node.attrs).sort().join(',') === expectedAttrs,
    'INVALID_OPERATION',
    'Unexpected operation attributes',
  );
  const ts = node.args.map((id) => {
    const t = types.get(id);
    assert(t, 'INVALID_DAG', `Undefined or forward reference ${id}`);
    return t;
  });
  const out = node.type,
    op = node.op;
  const first = ts[0]!,
    second = ts[1]!,
    third = ts[2]!;
  assert(
    ts.length === (op === 'const' ? 0 : op === 'select' ? 3 : unary.has(op) ? 1 : 2),
    'INVALID_OPERATION',
    'Wrong arity',
  );
  const allBv = () => ts.every((t) => t.kind === 'bv');
  const same = () => ts.every((t) => sameType(t, first));
  const sameOut = () => same() && sameType(out, first);
  let valid = false;
  if (op === 'const') {
    validateTypedValue(node.attrs.value, out);
    valid = true;
  } else if (op === 'copy') valid = sameOut();
  else if (arithmetic.has(op)) valid = allBv() && sameOut();
  else if (op === 'bv_neg' || op === 'bv_not') valid = allBv() && sameOut();
  else if (comparisons.has(op)) valid = allBv() && same() && out.kind === 'bool';
  else if (op === 'bool_and' || op === 'bool_or' || op === 'bool_not')
    valid = ts.every((t) => t.kind === 'bool') && out.kind === 'bool';
  else if (op === 'bv_nonzero') valid = allBv() && out.kind === 'bool';
  else if (op === 'bool_to_bv') valid = first.kind === 'bool' && out.kind === 'bv';
  else if (op === 'select')
    valid = first.kind === 'bool' && sameType(second, third) && sameType(out, second);
  else if (['bv_shl', 'bv_lshr', 'bv_ashr'].includes(op)) valid = allBv() && sameType(out, first);
  else if (op === 'bv_zext' || op === 'bv_sext')
    valid = first.kind === 'bv' && out.kind === 'bv' && out.width > first.width;
  else if (op === 'bv_extract')
    valid =
      first.kind === 'bv' &&
      out.kind === 'bv' &&
      Number.isInteger(node.attrs.low) &&
      node.attrs.low! >= 0 &&
      node.attrs.low! + out.width <= first.width;
  else if (op === 'bv_concat')
    valid =
      first.kind === 'bv' &&
      second.kind === 'bv' &&
      out.kind === 'bv' &&
      out.width === first.width + second.width;
  assert(valid, 'INVALID_OPERATION', `Invalid types for ${node.id}:${op}`);
}
export function validateBvModel(value: unknown): BvModel {
  validateSchema('model', value);
  const model = value as BvModel;
  assert(model.kind === 'bv_dag', 'UNSUPPORTED_MODEL', 'Expected exact BV model');
  const types = new Map<string, CoreType>();
  for (const input of model.inputs) {
    assert(!types.has(input.id), 'DUPLICATE_ID', 'Duplicate input');
    types.set(input.id, input.type);
  }
  for (const node of model.nodes) {
    assert(!types.has(node.id), 'DUPLICATE_ID', `Duplicate node ${node.id}`);
    validateNode(node, types);
    types.set(node.id, node.type);
  }
  const outputs = new Set<string>();
  for (const output of model.outputs) {
    assert(!outputs.has(output.id), 'DUPLICATE_ID', 'Duplicate output');
    outputs.add(output.id);
    const t = types.get(output.ref);
    assert(t && sameType(t, output.type), 'INVALID_OUTPUT', 'Unknown output or wrong output type');
  }
  if (model.scope.execution_guard.kind === 'model_bool')
    assert(
      types.get(model.scope.execution_guard.node_id)?.kind === 'bool',
      'INVALID_GUARD',
      'Execution guard must reference a Bool',
    );
  validateDomain(model.domain, model.inputs);
  return model;
}
export function validateMapping(left: Signature, right: Signature, value: unknown): Mapping {
  assert(
    !!value && typeof value === 'object' && !Array.isArray(value),
    'INVALID_MAPPING',
    'Mapping must be an object',
  );
  const mapping = value as Mapping;
  assert(
    Object.keys(mapping).sort().join(',') === 'inputs,outputs' &&
      Array.isArray(mapping.inputs) &&
      Array.isArray(mapping.outputs),
    'INVALID_MAPPING',
    'Mapping requires input/output lists',
  );
  assert(
    mapping.inputs.length === left.inputs.length &&
      mapping.inputs.length === right.inputs.length &&
      mapping.inputs.length > 0,
    'INVALID_MAPPING',
    'Input mapping must cover both signatures',
  );
  assert(
    mapping.outputs.length > 0 && mapping.outputs.length <= 8,
    'INVALID_MAPPING',
    'Output comparison must be nonempty',
  );
  for (const key of ['inputs', 'outputs'] as const) {
    const usedLeft = new Set<string>(),
      usedRight = new Set<string>();
    for (const pair of mapping[key]) {
      assert(
        !!pair && typeof pair === 'object' && Object.keys(pair).sort().join(',') === 'left,right',
        'INVALID_MAPPING',
        'Invalid mapping pair',
      );
      const l = left[key].find((p) => p.id === pair.left),
        r = right[key].find((p) => p.id === pair.right);
      assert(
        l &&
          r &&
          sameType(l.type, r.type) &&
          !usedLeft.has(pair.left) &&
          !usedRight.has(pair.right),
        'INVALID_MAPPING',
        'Mapping must be type preserving and one-to-one',
      );
      usedLeft.add(pair.left);
      usedRight.add(pair.right);
    }
  }
  return mapping;
}
export function defaultMapping(left: Signature, right: Signature): Mapping {
  return validateMapping(left, right, {
    inputs: left.inputs.map((p) => ({ left: p.id, right: p.id })),
    outputs: left.outputs.map((p) => ({ left: p.id, right: p.id })),
  });
}

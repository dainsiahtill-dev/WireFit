import type { BvModel, BvOp, CoreType, CoreValue, TypedValue, ValueMap, Width } from './types.js';
import { assert } from './shared.js';
import { bv, bool, signed, validateTypedValue } from './values.js';
import { domainContainsPoint, validateBvModel, validateInputs, validateNode } from './model.js';
/** Independent concrete execution: no solver expressions or JavaScript Number for BV bits. */
export function evaluateNode(
  op: BvOp,
  type: CoreType,
  args: TypedValue[],
  attrs: { value?: CoreValue; low?: number },
): CoreValue {
  const types = new Map<string, CoreType>();
  args.forEach((v, i) => {
    validateTypedValue(v);
    assert(v.kind !== 'fp32', 'TYPE_MISMATCH', 'FP32 is not in BV profile');
    types.set(String(i), v);
  });
  validateNode({ id: 'node', op, type, args: args.map((_, i) => String(i)), attrs }, types);
  const a = args[0]!,
    b = args[1]!;
  const av = a?.kind === 'bv' ? BigInt(a.bits) : 0n,
    bv_ = b?.kind === 'bv' ? BigInt(b.bits) : 0n;
  const width = type.kind === 'bv' ? type.width : 8;
  const emit = (x: bigint) => bv(x, width);
  const truth = (v: TypedValue) => v.kind === 'bool' && v.value;
  switch (op) {
    case 'const':
      return attrs.value!;
    case 'copy':
      return a as CoreValue;
    case 'bv_add':
      return emit(av + bv_);
    case 'bv_sub':
      return emit(av - bv_);
    case 'bv_mul':
      return emit(av * bv_);
    case 'bv_neg':
      return emit(-av);
    case 'bv_and':
      return emit(av & bv_);
    case 'bv_or':
      return emit(av | bv_);
    case 'bv_xor':
      return emit(av ^ bv_);
    case 'bv_not':
      return emit(~av);
    case 'bv_eq':
      return bool(av === bv_);
    case 'bv_ne':
      return bool(av !== bv_);
    case 'bv_ult':
      return bool(av < bv_);
    case 'bv_ule':
      return bool(av <= bv_);
    case 'bv_slt':
      return bool(signed(a as any) < signed(b as any));
    case 'bv_sle':
      return bool(signed(a as any) <= signed(b as any));
    case 'bool_and':
      return bool(truth(a) && truth(b));
    case 'bool_or':
      return bool(truth(a) || truth(b));
    case 'bool_not':
      return bool(!truth(a));
    case 'bv_nonzero':
      return bool(av !== 0n);
    case 'bool_to_bv':
      return emit(truth(a) ? 1n : 0n);
    case 'select':
      return args[truth(a) ? 1 : 2] as CoreValue;
    case 'bv_shl':
      return emit(bv_ >= BigInt(width) ? 0n : av << bv_);
    case 'bv_lshr':
      return emit(bv_ >= BigInt(width) ? 0n : av >> bv_);
    case 'bv_ashr': {
      const s = signed(a as any);
      return emit(bv_ >= BigInt(width) ? (s < 0n ? -1n : 0n) : s >> bv_);
    }
    case 'bv_zext':
      return emit(av);
    case 'bv_sext':
      return emit(signed(a as any));
    case 'bv_extract':
      return emit(av >> BigInt(attrs.low!));
    case 'bv_concat':
      return emit((av << BigInt((b as any).width)) | bv_);
    default:
      assert(false, 'UNSUPPORTED_OPERATION', `Unsupported operation ${op}`);
      throw new Error('unreachable');
  }
}
export function evaluateBv(model: BvModel, inputs: ValueMap): ValueMap {
  validateBvModel(model);
  validateInputs(model.inputs, inputs);
  assert(domainContainsPoint(model.domain, inputs), 'OUT_OF_DOMAIN', 'Inputs violate model domain');
  const values = new Map(Object.entries(inputs));
  for (const node of model.nodes)
    values.set(
      node.id,
      evaluateNode(
        node.op,
        node.type,
        node.args.map((id) => values.get(id)!),
        node.attrs,
      ),
    );
  return Object.fromEntries(model.outputs.map((output) => [output.id, values.get(output.ref)!]));
}

import { z } from 'zod';
import { parseEvidence } from '../vendor/rea/src/domain/evidence.js';
import { nativeValueFlowSchema, nativePcodeOperationSchema, nativeVarnodeSchema } from '../vendor/rea/src/domain/native/nativeValueFlow.js';
import type { BvModel, BvNode, BvOp, BVType, CoreType, Width } from './types.js';
import { validateBvModel } from './model.js';
import { assert, hashObject, WirefitError } from './shared.js';
import { reaRecordBundleHash } from './rea.js';

type Operation = z.infer<typeof nativePcodeOperationSchema>;
type Varnode = z.infer<typeof nativeVarnodeSchema>;
export interface PcodeSourceMapEntry {
  model_id: string; role: 'output'|'constant'|'parameter'|'cutpoint'; operation_id: string;
  address: string; input_index?: number; parameter_ordinal?: number; varnode: Varnode;
}
export interface PcodeLift {
  model: BvModel; sourceMap: PcodeSourceMapEntry[]; selectedOperations: string[];
  limitations: string[]; targetReplayEligible: false;
}
const directOperations: Record<string,BvOp> = {
  COPY:'copy',INT_ADD:'bv_add',INT_SUB:'bv_sub',INT_MULT:'bv_mul',INT_2COMP:'bv_neg',INT_NEGATE:'bv_not',
  INT_AND:'bv_and',INT_OR:'bv_or',INT_XOR:'bv_xor',INT_LEFT:'bv_shl',INT_RIGHT:'bv_lshr',INT_SRIGHT:'bv_ashr',
  INT_ZEXT:'bv_zext',INT_SEXT:'bv_sext',PIECE:'bv_concat',
};
const comparisons: Record<string,BvOp> = {INT_EQUAL:'bv_eq',INT_NOTEQUAL:'bv_ne',INT_LESS:'bv_ult',INT_LESSEQUAL:'bv_ule',INT_SLESS:'bv_slt',INT_SLESSEQUAL:'bv_sle'};
const unsupportedEffects = new Set(['LOAD','STORE','CALL','CALLIND','CALLOTHER','INDIRECT','BRANCHIND']);
const binary = new Set(['INT_ADD','INT_SUB','INT_MULT','INT_AND','INT_OR','INT_XOR','INT_LEFT','INT_RIGHT','INT_SRIGHT','PIECE']);

function bvType(varnode: Varnode): BVType {
  assert([1,2,4,8].includes(varnode.size_bytes), 'UNSUPPORTED_PCODE_WIDTH', `Unsupported p-code size ${varnode.size_bytes} bytes`);
  return {kind:'bv',width:(varnode.size_bytes*8) as Width};
}
function literal(varnode: Varnode): string {
  const type = bvType(varnode);
  assert(varnode.kind === 'constant' && varnode.constant_hex !== null, 'INVALID_PCODE_CONSTANT', 'Constant varnode requires constant_hex');
  assert(varnode.constant_hex.length <= type.width/4, 'INVALID_PCODE_CONSTANT', 'Constant exceeds its declared width');
  return '0x'+varnode.constant_hex.padStart(type.width/4,'0');
}
function sameVarnode(left: Varnode, right: Varnode): boolean {
  return left.kind === right.kind && left.size_bytes === right.size_bytes && left.location === right.location && left.constant_hex === right.constant_hex;
}

/**
 * Lift one observed operation output. Definition identity comes from explicit
 * producer def-use edges; textually equal storage locations never establish SSA.
 * Current REA does not expose control/return binding facts, so the result is a
 * local expression with an unknown execution guard, never a target ABI model.
 */
export function liftPcode(input: unknown, outputId: string, cutpoints: readonly string[] = []): PcodeLift {
  const bundleHash = input !== null && typeof input === 'object' ? reaRecordBundleHash(input) : undefined;
  let record: ReturnType<typeof parseEvidence>;
  try { record = parseEvidence(input); }
  catch (error) { throw new WirefitError('INVALID_REA_EVIDENCE','P-code input failed canonical Evidence authentication',error instanceof Error ? error.message:String(error)); }
  assert(record.operation === 'analyze_function', 'UNSUPPORTED_REA_OPERATION', 'P-code lift requires analyze_function Evidence');
  assert(record.provider.id === 'ghidra', 'UNSUPPORTED_REA_PROVIDER', 'P-code mapper is pinned to the Ghidra serialization');
  const dossier = record.normalized_result;
  assert(dossier !== null && typeof dossier === 'object' && !Array.isArray(dossier), 'UNSUPPORTED_PCODE', 'Function dossier must be an object');
  const checkedFlow = nativeValueFlowSchema.safeParse(dossier.native_value_flow);
  assert(checkedFlow.success,'UNSUPPORTED_PCODE_SCHEMA','Native value-flow fields do not match the pinned producer schema');
  const flow = checkedFlow.data;
  assert(flow.available, 'UNSUPPORTED_PCODE', flow.available ? '' : flow.reason);
  assert(!flow.truncated && flow.omitted_operations_lower_bound === 0 && flow.known_omitted_inputs === 0 && flow.known_omitted_edges === 0,
    'INCOMPLETE_EVIDENCE', 'Producer p-code truncation or omitted facts cannot become free inputs');
  assert(flow.operations.length <= 3000 && flow.def_use.length <= 12000 && flow.parameter_uses.length <= 12000,
    'PCODE_BUDGET', 'P-code graph exceeds the supported producer budget');
  const operations = new Map<string,Operation>();
  for (const operation of flow.operations) {
    assert(!operations.has(operation.id),'INVALID_PCODE_SSA','Duplicate p-code operation ID');
    assert(operation.inputs.length <= 64,'PCODE_BUDGET','P-code operation exceeds the input budget');
    operations.set(operation.id,operation);
    assert(operation.opcode !== 'MULTIEQUAL','UNSUPPORTED_PHI_MAPPING','REA does not serialize phi incoming edge slots');
    assert(!unsupportedEffects.has(operation.opcode),'UNSUPPORTED_PCODE_EFFECT',`Unmodeled p-code effect ${operation.opcode} at ${operation.id}`);
  }
  const output = operations.get(outputId);
  assert(output,'UNKNOWN_PCODE_OUTPUT','Selected operation does not exist');
  assert(output.opcode !== 'RETURN','UNSUPPORTED_RETURN_BINDING','Raw RETURN input0 is a destination, not a function return value');
  assert(output.output !== null,'UNKNOWN_PCODE_OUTPUT','Selected operation has no output varnode');
  const inputKey = (use: string,index: number) => JSON.stringify([use,index]);
  const definitions = new Map<string,string>();
  const parameterUses = new Map<string,number>();
  const parameters = new Set<number>();
  for (const parameter of flow.parameters) {
    assert(!parameters.has(parameter.ordinal),'INVALID_PCODE_BINDING','Duplicate parameter ordinal'); parameters.add(parameter.ordinal);
  }
  for (const edge of flow.def_use) {
    const definition = operations.get(edge.definition), use = operations.get(edge.use);
    assert(definition?.output && use && edge.input_index < use.inputs.length,'INCOMPLETE_EVIDENCE','Def-use edge references an absent varnode');
    const operand = use.inputs[edge.input_index]!;
    assert(operand.kind !== 'constant' && sameVarnode(definition.output,operand),'INVALID_PCODE_SSA','Def-use storage/type does not match its exact use');
    const key = inputKey(edge.use,edge.input_index);
    assert(!definitions.has(key),'INVALID_PCODE_SSA','Multiple definitions for one operand slot'); definitions.set(key,edge.definition);
  }
  for (const binding of flow.parameter_uses) {
    const use = operations.get(binding.use);
    assert(parameters.has(binding.ordinal) && use && binding.input_index < use.inputs.length,'INCOMPLETE_EVIDENCE','Parameter binding references missing declaration or input');
    const operand = use.inputs[binding.input_index]!;
    const key = inputKey(binding.use,binding.input_index);
    assert(operand.kind !== 'constant' && !definitions.has(key) && !parameterUses.has(key),'INVALID_PCODE_BINDING','Ambiguous or constant parameter binding');
    parameterUses.set(key,binding.ordinal);
  }
  for (const effect of flow.effects) {
    assert(operations.has(effect.operation),'INCOMPLETE_EVIDENCE','Effect references a missing operation');
    assert(effect.kind === 'conditional_branch','UNSUPPORTED_PCODE_EFFECT',`Unmodeled reported effect ${effect.kind}`);
  }
  // Validate complete definition closure before honoring intentional cutpoints.
  // A cutpoint must not conceal a producer's missing definitions or a cycle.
  const order: Operation[] = [];
  const state = new Map<string,number>();
  const pending: {id:string;exit:boolean}[] = [{id:outputId,exit:false}];
  while (pending.length) {
    const current = pending.pop()!;
    const operation = operations.get(current.id)!;
    if (current.exit) { state.set(current.id,2); order.push(operation); continue; }
    if (state.get(current.id) === 2) continue;
    assert(state.get(current.id) !== 1,'INVALID_PCODE_SSA','P-code definition graph contains a cycle');
    assert(operation.output !== null && operation.block_membership === 'member','INCOMPLETE_EVIDENCE','Selected definition is detached or has no output');
    bvType(operation.output);
    state.set(current.id,1); pending.push({id:current.id,exit:true});
    for (let index=operation.inputs.length-1;index>=0;index--) {
      const operand = operation.inputs[index]!;
      bvType(operand);
      if (operand.kind === 'constant') { literal(operand); continue; }
      assert(operand.constant_hex === null,'INVALID_PCODE_CONSTANT','Nonconstant operand carries a constant value');
      const definition = definitions.get(inputKey(operation.id,index));
      if (definition !== undefined) pending.push({id:definition,exit:false});
      else assert(parameterUses.has(inputKey(operation.id,index)),'INCOMPLETE_EVIDENCE',`No definition or explicit parameter binding for ${operation.id} input ${index}`);
    }
  }
  assert(cutpoints.length <= 16 && new Set(cutpoints).size === cutpoints.length,'INVALID_CUTPOINT','Cutpoints must be unique and within budget');
  const cuts = new Map([...cutpoints].sort().map((id,index) => [id,`cut${index}`]));
  for (const id of cuts.keys()) assert(state.has(id),'INVALID_CUTPOINT','Cutpoint is not an existing varnode in the selected complete definition chain');
  const needed = new Set<string>();
  const stack = [outputId];
  while (stack.length) {
    const id = stack.pop()!;
    if (needed.has(id)) continue;
    needed.add(id);
    if (cuts.has(id)) continue;
    const operation = operations.get(id)!;
    for (let index=0;index<operation.inputs.length;index++) {
      const definition = definitions.get(inputKey(id,index));
      if (definition !== undefined) stack.push(definition);
    }
  }
  const inputs: BvModel['inputs'] = [];
  const nodes: BvNode[] = [];
  const sourceMap: PcodeSourceMapEntry[] = [];
  const refs = new Map<string,string>();
  const portTypes = new Map<string,BVType>();
  let serial = 0;
  const addInput = (id: string,type: BVType): string => {
    const previous = portTypes.get(id);
    assert(previous === undefined || previous.width === type.width,'INVALID_PCODE_BINDING','One parameter ordinal has inconsistent widths');
    if (previous === undefined) { inputs.push({id,type}); portTypes.set(id,type); }
    return id;
  };
  const emit = (opcode: BvOp,type: CoreType,args: string[],attrs: BvNode['attrs'] = {}): string => {
    const id = `n${serial++}`; nodes.push({id,op:opcode,type,args,attrs}); return id;
  };
  for (const operation of order) {
    if (!needed.has(operation.id)) continue;
    const type = bvType(operation.output!);
    const cut = cuts.get(operation.id);
    if (cut !== undefined) {
      refs.set(operation.id,addInput(cut,type));
      sourceMap.push({model_id:cut,role:'cutpoint',operation_id:operation.id,address:operation.address,varnode:operation.output!});
      continue;
    }
    const args: string[] = [];
    for (let index=0;index<operation.inputs.length;index++) {
      if (operation.opcode === 'SUBPIECE' && index === 1) continue;
      const operand = operation.inputs[index]!;
      let ref: string;
      if (operand.kind === 'constant') {
        const valueType = bvType(operand);
        ref = emit('const',valueType,[],{value:{...valueType,bits:literal(operand)}});
        sourceMap.push({model_id:ref,role:'constant',operation_id:operation.id,address:operation.address,input_index:index,varnode:operand});
      } else {
        const definition = definitions.get(inputKey(operation.id,index));
        if (definition !== undefined) {
          const found = refs.get(definition); assert(found,'INVALID_PCODE_SSA','Definition was not emitted before use'); ref = found;
        } else {
          const ordinal = parameterUses.get(inputKey(operation.id,index))!;
          ref = addInput(`p${ordinal}`,bvType(operand));
          sourceMap.push({model_id:ref,role:'parameter',operation_id:operation.id,address:operation.address,input_index:index,parameter_ordinal:ordinal,varnode:operand});
        }
      }
      args.push(ref);
    }
    let ref: string;
    const comparison = comparisons[operation.opcode];
    const direct = directOperations[operation.opcode];
    if (comparison !== undefined) {
      assert(operation.inputs.length === 2 && type.width === 8,'INVALID_PCODE_TYPE','Integer comparison requires two operands and one-byte output');
      ref = emit('bool_to_bv',type,[emit(comparison,{kind:'bool'},args)]);
    } else if (operation.opcode === 'SUBPIECE') {
      assert(operation.inputs.length === 2,'INVALID_PCODE_TYPE','SUBPIECE requires two operands');
      const offset = operation.inputs[1]!;
      assert(offset.kind === 'constant','UNSUPPORTED_SUBPIECE_OFFSET','SUBPIECE offset must be a constant byte count');
      const low = BigInt(literal(offset))*8n;
      assert(low <= 64n,'INVALID_PCODE_TYPE','SUBPIECE offset exceeds the maximum supported source width');
      ref = emit('bv_extract',type,args,{low:Number(low)});
    } else {
      assert(direct !== undefined,'UNSUPPORTED_PCODE_OPCODE',`Unsupported opcode ${operation.opcode}`);
      assert(operation.inputs.length === (binary.has(operation.opcode) ? 2 : 1),'INVALID_PCODE_TYPE','P-code arity is invalid');
      ref = emit(direct,type,args);
    }
    refs.set(operation.id,ref);
    sourceMap.push({model_id:ref,role:'output',operation_id:operation.id,address:operation.address,varnode:operation.output!});
  }
  assert(inputs.length > 0,'CONSTANT_ONLY_UNSUPPORTED','V1 model contract requires at least one genuine declared input');
  const limitations = [...record.limitations,...flow.limitations,
    'REA high-p-code does not encode the execution guard or an independently verified function-return/ABI binding.',
    'This expression models decompiler dataflow only; original-target fidelity remains unvalidated.'];
  if (cuts.size) limitations.push('Explicit cutpoints preserve source SSA identity; cutpoint inputs are not original ABI parameters.');
  const model: BvModel = {
    schema_version:1,model_id:`wirefit_lift_${hashObject({evidence_id:record.evidence_id,outputId,cutpoints:[...cuts.keys()]}).slice(0,32)}`,
    title:`P-code local output ${outputId}`.slice(0,256),kind:'bv_dag',semantics_profile:'wirefix.bv.total.v1',
    scope:{kind:'expression',observation:'declared_outputs',source_completeness:'complete',execution_guard:{kind:'unknown'},observation_point:{kind:'local_value',source_location:output.address}},
    provenance:{source_kind:'rea_portable',source_ref:bundleHash === undefined ? null : {bundle_sha256:bundleHash,evidence_id:record.evidence_id,
      provider_id:record.provider.id,analysis_profile_digest:record.analysis_profile?.digest ?? null,target_sha256:record.subject?.digest.sha256 ?? null,location:output.address},
      source_artifacts:[],notes:`Evidence ${record.evidence_id}. ${limitations.join(' ')}`.slice(0,4096)},
    domain:{constraints:[]},inputs,nodes,outputs:[{id:'y',type:bvType(output.output),ref:refs.get(outputId)!}],
  };
  validateBvModel(model);
  return {model,sourceMap,selectedOperations:order.filter(operation=>needed.has(operation.id)).map(operation=>operation.id),limitations,targetReplayEligible:false};
}

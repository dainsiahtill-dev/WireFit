import { describe, expect, it } from 'vitest';
import { createEvidence } from '../vendor/rea/src/domain/evidence.js';
import { liftPcode } from '../src/pcode.js';
import { evaluateBv } from '../src/bv.js';

// These are synthetic wire-boundary fixtures, not native-provider integration evidence.
const variable = (size = 8) => ({kind:'register',size_bytes:size,location:'register:0x0',constant_hex:null});
const constant = (hex: string, size = 8) => ({kind:'constant',size_bytes:size,location:null,constant_hex:hex});
const op = (id: string, opcode: string, inputs: any[], output: any = variable()) => ({id,address:'0x401000',sequence:0,opcode,is_dead:false,block_membership:'member',inputs,output});
function record(operations: any[], overrides: any = {}) {
  return createEvidence({path:'/synthetic/test',sha256:'b'.repeat(64),format:'elf',architecture:'x86_64'}, {id:'ghidra',name:'Ghidra',version:'12.1.4'}, {
    operation:'analyze_function',parameters:{},result:{native_value_flow:{available:true,provenance:'ghidra-high-pcode',operations,
      def_use:[],parameters:[{ordinal:0,name:'x',data_type:'uint64_t'}],parameter_uses:[{ordinal:0,use:'a',input_index:0}],effects:[],truncated:false,
      omitted_operations_lower_bound:0,known_omitted_inputs:0,known_omitted_edges:0,limitations:['Synthetic fixture only.'],...overrides}},
  });
}
function codeOf(action:()=>unknown) { try { action(); } catch(error) { return (error as any).code; } return null; }

describe('bounded p-code lift (synthetic actual-schema fixtures)', () => {
  it('keeps a 64-bit literal exact and a local observation guarded unknown', () => {
    const lifted = liftPcode(record([op('a','INT_ADD',[variable(),constant('20000000000001')])]),'a');
    expect(lifted.model.nodes.find(node=>node.op==='const')?.attrs.value).toEqual({kind:'bv',width:64,bits:'0x0020000000000001'});
    expect(lifted.model.scope.execution_guard).toEqual({kind:'unknown'});
    expect(lifted.model.scope.observation_point.kind).toBe('local_value');
    expect(lifted.targetReplayEligible).toBe(false);
  });
  it('keeps same-storage SSA definitions distinct through explicit def-use edges', () => {
    const evidence = record([op('a','INT_ADD',[variable(),constant('1')]),op('b','INT_ADD',[variable(),constant('2')])],{
      def_use:[{definition:'a',use:'b',input_index:0}],
    });
    const lifted = liftPcode(evidence,'b');
    expect(lifted.sourceMap.filter(entry=>entry.role==='output').map(entry=>entry.operation_id)).toEqual(['a','b']);
    expect(evaluateBv(lifted.model,{p0:{kind:'bv',width:64,bits:'0x0000000000000007'}}).y).toEqual({kind:'bv',width:64,bits:'0x000000000000000a'});
  });
  it('distinguishes a deliberate cutpoint from missing producer definitions', () => {
    const evidence = record([op('a','INT_ADD',[variable(),constant('1')]),op('b','INT_ADD',[variable(),constant('2')])],{def_use:[{definition:'a',use:'b',input_index:0}]});
    expect(liftPcode(evidence,'b',['a']).model.inputs.map(input=>input.id)).toEqual(['cut0']);
    const missing = record([op('a','INT_ADD',[variable(),constant('1')])],{parameter_uses:[]});
    expect(codeOf(()=>liftPcode(missing,'a'))).toBe('INCOMPLETE_EVIDENCE');
    expect(codeOf(()=>liftPcode(record([op('a','INT_ADD',[variable(),constant('1')])],{truncated:true}),'a',['a']))).toBe('INCOMPLETE_EVIDENCE');
  });
  it('maps comparison via an explicit Bool to byte bridge', () => {
    const lifted = liftPcode(record([op('a','INT_SLESS',[variable(),constant('0')],variable(1))]),'a');
    expect(lifted.model.nodes.map(node=>node.op)).toEqual(['const','bv_slt','bool_to_bv']);
    expect(evaluateBv(lifted.model,{p0:{kind:'bv',width:64,bits:'0xffffffffffffffff'}}).y).toEqual({kind:'bv',width:8,bits:'0x01'});
  });
  it('refuses phi without incoming slots, unknown effects and raw RETURN destination selection', () => {
    expect(codeOf(()=>liftPcode(record([op('a','MULTIEQUAL',[variable(),variable()])]),'a'))).toBe('UNSUPPORTED_PHI_MAPPING');
    expect(codeOf(()=>liftPcode(record([op('a','INT_ADD',[variable(),constant('1')]),op('dead','STORE',[constant('0'),variable(),variable()],null)]),'a'))).toBe('UNSUPPORTED_PCODE_EFFECT');
    expect(codeOf(()=>liftPcode(record([op('a','RETURN',[constant('deadbeef')],null)]),'a'))).toBe('UNSUPPORTED_RETURN_BINDING');
  });
  it('rejects unauthenticated records and malformed producer schemas with typed diagnostics',()=>{
    const evidence=record([op('a','INT_ADD',[variable(),constant('1')])]);
    const changed=structuredClone(evidence);
    changed.normalized_result={native_value_flow:{available:true}};
    expect(codeOf(()=>liftPcode(changed,'a'))).toBe('INVALID_REA_EVIDENCE');
    expect(codeOf(()=>liftPcode(record([op('a','INT_ADD',[variable(),constant('1')])],{parameters:null}),'a'))).toBe('UNSUPPORTED_PCODE_SCHEMA');
  });
  it('checks SUBPIECE byte offsets and preserves PIECE high input order', () => {
    const evidence = record([op('a','SUBPIECE',[variable(),constant('1')],variable(4))]);
    const lifted = liftPcode(evidence,'a');
    expect(lifted.model.nodes.at(-1)?.attrs.low).toBe(8);
    expect(evaluateBv(lifted.model,{p0:{kind:'bv',width:64,bits:'0x0123456789abcdef'}}).y).toEqual({kind:'bv',width:32,bits:'0x6789abcd'});
    const piece = liftPcode(record([op('a','PIECE',[variable(4),constant('89abcdef',4)])]),'a');
    expect(evaluateBv(piece.model,{p0:{kind:'bv',width:32,bits:'0x01234567'}}).y).toEqual({kind:'bv',width:64,bits:'0x0123456789abcdef'});
  });
});

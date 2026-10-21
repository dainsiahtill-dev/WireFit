import {assert} from '../../shared.js';
import type {DevelopContext,EvaluateContext,FrozenCandidate,ResearchDirectionSpec} from '../types.js';

/**
 * D06 and D07: the control flow scope and the private execution page.
 *
 * This file owns its own parsers and its own decoder; it imports no other
 * direction file.
 */

// ---------------------------------------------------------------- D06 -----

/** One audited function scope as recorded by the lane scope audits. */
export interface ScopeAuditEntry{
 entry_va:string;
 status:string;
 body_bytes:number;
 instructions:number;
 outside_body_count:number;
 outside_guard_count:number;
 raw_pcode_pcs_in_listing:boolean;
 accepted_c:string|null;
 rejected_c:string|null;
}

export interface ScopeAuditDocument{
 functions:ScopeAuditEntry[];
}

/** The three scope audits of D06, in declaration order. */
export const SCOPE_AUDIT_ROLES:readonly string[]=['business_audit','algorithm_audit','grid_audit'];

/** The declared acceptance rule: a function is accepted iff its audited status is `observed`. */
export const ACCEPTED_SCOPE_STATUS='observed';

/** The partition of the audited functions into accepted and rejected scopes. */
export interface ScopePartition{
 accepted:Map<string,ScopeAuditEntry>;
 rejected:Map<string,ScopeAuditEntry>;
}

/** Loads one scope audit and validates the shape of its entries. */
export async function loadScopeAudit(ctx:DevelopContext|EvaluateContext,role:string):Promise<ScopeAuditEntry[]>{
 const document=await ctx.corpus.json<ScopeAuditDocument>(role);
 const functions=document.functions;
 assert(Array.isArray(functions),'CORPUS_INVALID','Scope audit '+role+' carries no functions array.');
 for(const entry of functions)
  assert(typeof entry.entry_va==='string'&&entry.entry_va.length>0&&typeof entry.status==='string'&&
   Number.isInteger(entry.outside_body_count)&&Number.isInteger(entry.outside_guard_count)&&
   typeof entry.raw_pcode_pcs_in_listing==='boolean',
   'CORPUS_INVALID','Scope audit entries are malformed in role '+role+'.');
 return functions;
}

/** Merges the three scope audits into one deduplicated partition. */
export async function partitionScopedFunctions(ctx:DevelopContext|EvaluateContext):Promise<ScopePartition>{
 const accepted=new Map<string,ScopeAuditEntry>();
 const rejected=new Map<string,ScopeAuditEntry>();
 for(const role of SCOPE_AUDIT_ROLES){
  for(const entry of await loadScopeAudit(ctx,role)){
   const target=entry.status===ACCEPTED_SCOPE_STATUS?accepted:rejected;
   const existing=target.get(entry.entry_va);
   assert(existing===undefined||existing.status===entry.status,
    'CORPUS_INVALID','Function '+entry.entry_va+' carries two different audited statuses.');
   if(existing===undefined)target.set(entry.entry_va,entry);
  }
 }
 for(const entry_va of accepted.keys())
  assert(!rejected.has(entry_va),'CORPUS_INVALID','Function '+entry_va+' is both accepted and rejected.');
 return {accepted,rejected};
}

/** The scope facts of one function, in the shape the catalog checks read. */
export function scopeRecord(entry:ScopeAuditEntry):{
 entry_va:string;status:string;outside_body_count:number;outside_guard_count:number;raw_pcode_pcs_in_listing:boolean;}{
 return {
  entry_va:entry.entry_va,
  status:entry.status,
  outside_body_count:entry.outside_body_count,
  outside_guard_count:entry.outside_guard_count,
  raw_pcode_pcs_in_listing:entry.raw_pcode_pcs_in_listing,
 };
}

export const D06={
 direction_id:'D06' as const,
 async develop(ctx:DevelopContext):Promise<{candidate:unknown;notes:string[]}>{
  const partition=await partitionScopedFunctions(ctx);
  const visible=new Set<string>([...ctx.split.train,...ctx.split.validation]);
  const developEntries=[...partition.accepted.values()].filter((entry)=>visible.has(entry.entry_va));
  const rejected=[...partition.rejected.values()].map((entry)=>({
   entry_va:entry.entry_va,
   status:entry.status,
   outside_body_count:entry.outside_body_count,
   outside_guard_count:entry.outside_guard_count,
   reason:'the audited status is not `'+ACCEPTED_SCOPE_STATUS+'`',
  }));
  assert(developEntries.length>0,'SPLIT_EMPTY','D06 has no develop rows.');
  const escaping=developEntries.filter((entry)=>entry.outside_body_count!==0||entry.outside_guard_count!==0||!entry.raw_pcode_pcs_in_listing);
  assert(escaping.length===0,'SCOPE_RULE_VIOLATED',
   'An accepted develop function escapes its scope: '+escaping.map((entry)=>entry.entry_va).join(', '));
  const candidate={
   acceptance_rule:'status == "'+ACCEPTED_SCOPE_STATUS+'"',
   accepted_function_count:partition.accepted.size,
   rejected_function_count:rejected.length,
   rejected_entry_va:rejected[0]?.entry_va??'',
  };
  const artifact={
   accepted_function_count:partition.accepted.size,
   develop_function_count:developEntries.length,
   develop_row_count:visible.size,
   acceptance_rule:candidate.acceptance_rule,
   accepted:developEntries.map((entry)=>scopeRecord(entry)),
   rejected,
  };
  ctx.corpus.registerDocument('develop/d06_scope',artifact);
  await ctx.putArtifact(artifact);
  return {candidate,notes:[
   'The three scope audits were merged into '+String(partition.accepted.size)+' accepted and '+String(rejected.length)+' rejected function scopes.',
   'On the '+String(developEntries.length)+' develop rows every accepted function keeps outside_body_count, outside_guard_count and raw_pcode_pcs_in_listing inside its own scope.',
  ]};
 },
 async evaluate(ctx:EvaluateContext,_spec:ResearchDirectionSpec,frozen:FrozenCandidate):Promise<{notes:string[]}>{
  const partition=await partitionScopedFunctions(ctx);
  const candidate=frozen.candidate as {
   acceptance_rule:string;accepted_function_count:number;rejected_function_count:number;rejected_entry_va:string;};
  assert(candidate.accepted_function_count===partition.accepted.size,'CANDIDATE_MISMATCH',
   'The frozen accepted function count disagrees with the audits: '+String(candidate.accepted_function_count)+' vs '+String(partition.accepted.size)+'.');
  assert(candidate.rejected_function_count===partition.rejected.size,'CANDIDATE_MISMATCH',
   'The frozen rejected function count disagrees with the audits: '+String(candidate.rejected_function_count)+' vs '+String(partition.rejected.size)+'.');
  const functions=ctx.holdout.map((entry_va)=>{
   const entry=partition.accepted.get(entry_va);
   assert(entry!==undefined,'SPLIT_ROW_UNKNOWN','The holdout row is not an accepted function: '+entry_va);
   return scopeRecord(entry);
  });
  const functionsArtifact={functions};
  ctx.corpus.registerDocument('evaluate/d06_functions',functionsArtifact);
  await ctx.putArtifact(functionsArtifact);
  const negative=[...partition.rejected.values()].map((entry)=>scopeRecord(entry));
  const negativeArtifact={functions:negative};
  ctx.corpus.registerDocument('evaluate/d06_negative_control',negativeArtifact);
  await ctx.putArtifact(negativeArtifact);
  return {notes:[
   'The frozen acceptance rule was applied to '+String(functions.length)+' holdout functions.',
   'The negative control carries the '+String(negative.length)+' rejected scope(s) of the audits.',
  ]};
 },
};

// ---------------------------------------------------------------- D07 -----

/** The immediate kind of one instruction. */
export type ImmediateKind='none'|'imm8'|'imm16or32'|'rel8'|'rel32'|'moffs32';

/** One entry of the independent opcode table. */
export interface OpcodeEntry{
 mnemonic:string;
 group:'group1'|'group5'|null;
 modrm:boolean;
 immediate:ImmediateKind;
 conditional:boolean;
}

/**
 * The independent opcode table of the D07 decoder.
 *
 * `one_byte` and `two_byte` are keyed by the lowercase hex opcode byte;
 * `groups` maps a ModRM `reg` digit to the mnemonic of the group member.
 */
export interface OpcodeTable{
 one_byte:Record<string,OpcodeEntry>;
 two_byte:Record<string,OpcodeEntry>;
 groups:Record<string,Record<string,string>>;
}

/** The conditional branch mnemonics, indexed by the condition code. */
export const JCC_NAMES:readonly string[]=[
 'jo','jno','jb','jnb','je','jne','jbe','ja','js','jns','jp','jnp','jl','jge','jle','jg',
];

/** The two byte opcode of the multi byte NOP form. */
export const NOP_TWO_BYTE_OPCODE='1f';

function opcodeEntry(
 mnemonic:string,
 immediate:ImmediateKind='none',
 modrm=false,
 conditional=false,
 group:'group1'|'group5'|null=null,
):OpcodeEntry{
 return {mnemonic,group,modrm,immediate,conditional};
}

/**
 * The independent x86 length/opcode table used by D07.
 *
 * It is written from the instruction encoding rules, not from the recorded
 * listing: the decoder must be able to produce a mnemonic and a length from a
 * byte string alone. The table covers the operand forms that occur in the
 * private execution page plus the neighbouring forms of the same families.
 */
export function buildOpcodeTable():OpcodeTable{
 const one_byte:Record<string,OpcodeEntry>={};
 const two_byte:Record<string,OpcodeEntry>={};
 const hex=(value:number):string=>value.toString(16).padStart(2,'0');
 for(let reg=0;reg<8;reg++){
  one_byte[hex(0x50+reg)]=opcodeEntry('push');
  one_byte[hex(0x58+reg)]=opcodeEntry('pop');
 }
 one_byte['60']=opcodeEntry('pushal');
 one_byte['61']=opcodeEntry('popal');
 one_byte['68']=opcodeEntry('push','imm16or32');
 one_byte['6a']=opcodeEntry('push','imm8');
 for(let condition=0;condition<16;condition++)
  one_byte[hex(0x70+condition)]=opcodeEntry(JCC_NAMES[condition]!,'rel8',false,true);
 one_byte['80']=opcodeEntry('add','imm8',true,false,'group1');
 one_byte['81']=opcodeEntry('add','imm16or32',true,false,'group1');
 one_byte['83']=opcodeEntry('add','imm8',true,false,'group1');
 one_byte['85']=opcodeEntry('test','none',true);
 one_byte['89']=opcodeEntry('mov','none',true);
 one_byte['8a']=opcodeEntry('mov','none',true);
 one_byte['8b']=opcodeEntry('mov','none',true);
 one_byte['8d']=opcodeEntry('lea','none',true);
 for(let reg=0;reg<8;reg++)one_byte[hex(0x90+reg)]=opcodeEntry('xchg');
 one_byte['98']=opcodeEntry('cwde');
 one_byte['99']=opcodeEntry('cdq');
 one_byte['9c']=opcodeEntry('pushfd');
 one_byte['9d']=opcodeEntry('popfd');
 one_byte['a1']=opcodeEntry('mov','moffs32');
 one_byte['a3']=opcodeEntry('mov','moffs32');
 for(let reg=0;reg<8;reg++)one_byte[hex(0xb0+reg)]=opcodeEntry('mov','imm8');
 for(let reg=0;reg<8;reg++)one_byte[hex(0xb8+reg)]=opcodeEntry('mov','imm16or32');
 one_byte['e8']=opcodeEntry('call','rel32');
 one_byte['e9']=opcodeEntry('jmp','rel32');
 one_byte['eb']=opcodeEntry('jmp','rel8');
 one_byte['ff']=opcodeEntry('inc','none',true,false,'group5');
 two_byte[NOP_TWO_BYTE_OPCODE]=opcodeEntry('nop','none',true);
 two_byte['31']=opcodeEntry('rdtsc');
 for(let condition=0;condition<16;condition++)
  two_byte[hex(0x80+condition)]=opcodeEntry(JCC_NAMES[condition]!,'rel32',false,true);
 two_byte['b6']=opcodeEntry('movzx','none',true);
 two_byte['b7']=opcodeEntry('movzx','none',true);
 two_byte['be']=opcodeEntry('movsx','none',true);
 two_byte['bf']=opcodeEntry('movsx','none',true);
 return {
  one_byte,
  two_byte,
  groups:{
   group1:{'0':'add','1':'or','2':'adc','3':'sbb','4':'and','5':'sub','6':'xor','7':'cmp'},
   group5:{'0':'inc','1':'dec','2':'call','3':'callf','4':'jmp','5':'jmpf','6':'push'},
  },
 };
}

/** One decoded instruction of the independent decoder. */
export interface DecodedInstruction{
 mnemonic:string;
 length:number;
 conditional:boolean;
}

/** The length of a ModRM byte together with its SIB byte and displacement. */
export function modrmLength(bytes:Uint8Array,offset:number):number|null{
 const modrm=bytes[offset];
 if(modrm===undefined)return null;
 const mod=modrm>>6,rm=modrm&7;
 if(mod===3)return 1;
 let length=1;
 if(rm===4){
  const sib=bytes[offset+1];
  if(sib===undefined)return null;
  length+=1;
  if(mod===0&&(sib&7)===5)length+=4;
 }
 if(mod===0&&rm===5)length+=4;
 else if(mod===1)length+=1;
 else if(mod===2)length+=4;
 return length;
}

/** The byte length of the immediate of one opcode form. */
export function immediateLength(kind:ImmediateKind,operandSize16:boolean):number{
 switch(kind){
  case 'none':return 0;
  case 'imm8':return 1;
  case 'imm16or32':return operandSize16?2:4;
  case 'rel8':return 1;
  case 'rel32':return 4;
  case 'moffs32':return 4;
 }
}

/** Parses a lowercase or uppercase hex byte string into bytes. */
export function hexToBytes(hex:string):Uint8Array|null{
 if(hex.length%2!==0||!/^[0-9a-fA-F]*$/.test(hex))return null;
 const bytes=new Uint8Array(hex.length/2);
 for(let index=0;index<bytes.length;index++)bytes[index]=Number.parseInt(hex.slice(index*2,index*2+2),16);
 return bytes;
}

/**
 * The independent decoder: it derives a mnemonic and a length from the bytes
 * alone, using the given opcode table. It never reads a recorded mnemonic or
 * a recorded length.
 */
export function decodeInstruction(bytes:Uint8Array,table:OpcodeTable):DecodedInstruction|null{
 if(bytes.length===0)return null;
 let offset=0;
 let operandSize16=false;
 for(;;){
  const byte=bytes[offset];
  if(byte===undefined)return null;
  if(byte===0x66){operandSize16=true;offset++;continue;}
  if(byte===0x67||byte===0xf0||byte===0xf2||byte===0xf3||
   byte===0x2e||byte===0x36||byte===0x3e||byte===0x26||byte===0x64||byte===0x65){offset++;continue;}
  break;
 }
 const opcode=bytes[offset]!;
 offset++;
 let spec:OpcodeEntry|undefined;
 if(opcode===0x0f){
  const second=bytes[offset];
  if(second===undefined)return null;
  spec=table.two_byte[second.toString(16).padStart(2,'0')];
  offset++;
 }else
  spec=table.one_byte[opcode.toString(16).padStart(2,'0')];
 if(spec===undefined)return null;
 let mnemonic=spec.mnemonic;
 if(spec.group!==null){
  const group=table.groups[spec.group];
  if(group===undefined)return null;
  const modrm=bytes[offset];
  if(modrm===undefined)return null;
  const name=group[String((modrm>>3)&7)];
  if(name===undefined)return null;
  mnemonic=name;
 }
 if(spec.modrm){
  const size=modrmLength(bytes,offset);
  if(size===null)return null;
  offset+=size;
 }
 offset+=immediateLength(spec.immediate,operandSize16);
 if(offset>bytes.length)return null;
 return {mnemonic,length:offset,conditional:spec.conditional};
}

/** The mnemonic recorded by the lane, normalised to the decoder's spelling. */
export function recordedMnemonic(text:string):string{
 const token=text.trim().split(/\s+/)[0];
 return token===undefined?'':token.toLowerCase();
}

/** Every mnemonic the opcode table can produce, in ascending order. */
export function tableMnemonics(table:OpcodeTable):string[]{
 const names=new Set<string>();
 for(const entry of Object.values(table.one_byte))names.add(entry.mnemonic);
 for(const entry of Object.values(table.two_byte))names.add(entry.mnemonic);
 for(const group of Object.values(table.groups))
  for(const name of Object.values(group))names.add(name);
 return [...names].sort();
}

/** One listed instruction of the private execution page. */
export interface CallpopListingEntry{
 pc:string;
 bytes:string;
 text:string;
 size_bytes:number;
}

/** One recorded memory operand of the private execution page. */
export interface CallpopMemoryOperand{
 pc:string;
 expression:string;
 captured_value_hex?:string|null;
 unknown_reason?:string|null;
}

export interface CallpopDocument{
 listing:CallpopListingEntry[];
 memory_operands:CallpopMemoryOperand[];
}

/** One guard of the private execution page. */
export interface StaticSliceGuard{
 load_pc:string;
 test_pc:string;
 branch_pc:string;
 relation:string;
 unknown:string;
}

export interface StaticSlicesDocument{
 guards:StaticSliceGuard[];
}

/** Loads the listing of the private execution page. */
export async function loadCallpopListing(ctx:DevelopContext|EvaluateContext):Promise<CallpopListingEntry[]>{
 const document=await ctx.corpus.json<CallpopDocument>('private_closure_callpop');
 const listing=document.listing;
 assert(Array.isArray(listing)&&listing.length>0,'CORPUS_INVALID','The callpop evidence carries no listing.');
 for(const entry of listing)
  assert(typeof entry.pc==='string'&&typeof entry.bytes==='string'&&typeof entry.text==='string'&&
   Number.isInteger(entry.size_bytes),'CORPUS_INVALID','The callpop listing entries are malformed.');
 return listing;
}

/** Decodes one listing entry with the given table. */
export function decodeListingEntry(entry:CallpopListingEntry,table:OpcodeTable):DecodedInstruction|null{
 const bytes=hexToBytes(entry.bytes);
 if(bytes===null)return null;
 return decodeInstruction(bytes,table);
}

/**
 * Whether the independent decoder reproduced the recorded decode of one
 * listing entry: the same mnemonic and the same instruction length.
 */
export function reproducesRecordedDecode(entry:CallpopListingEntry,table:OpcodeTable):boolean{
 const decoded=decodeListingEntry(entry,table);
 if(decoded===null)return false;
 return decoded.mnemonic===recordedMnemonic(entry.text)&&decoded.length===entry.size_bytes;
}

export const D07={
 direction_id:'D07' as const,
 async develop(ctx:DevelopContext):Promise<{candidate:unknown;notes:string[]}>{
  const table=buildOpcodeTable();
  const listing=await loadCallpopListing(ctx);
  const visible=new Set<string>([...ctx.split.train,...ctx.split.validation]);
  const developEntries=listing.filter((entry)=>visible.has(entry.pc));
  assert(developEntries.length>0,'SPLIT_EMPTY','D07 has no develop rows.');
  const rows=developEntries.map((entry)=>{
   const decoded=decodeListingEntry(entry,table);
   return {
    pc:entry.pc,
    decoded:decoded!==null,
    mnemonic:decoded===null?'':decoded.mnemonic,
    bytes_reproduced:decoded!==null&&decoded.mnemonic===recordedMnemonic(entry.text)&&decoded.length===entry.size_bytes,
   };
  });
  const unsupported=rows.filter((row)=>!row.decoded).length;
  const mismatched=rows.filter((row)=>row.decoded&&!row.bytes_reproduced).length;
  const mnemonics=[...new Set(rows.filter((row)=>row.decoded).map((row)=>row.mnemonic))].sort();
  const candidate={opcodes:table,decoder:'independent_x86_length_opcode'};
  const artifact={
   decoded_instructions:rows.filter((row)=>row.decoded).length,
   develop_row_count:rows.length,
   supported_mnemonics:mnemonics,
   table_mnemonics:tableMnemonics(table),
   unsupported,
   mismatched,
   parser:'independent_opcode_table',
  };
  ctx.corpus.registerDocument('develop/d07_decoder',artifact);
  await ctx.putArtifact(artifact);
  return {candidate,notes:[
   'The independent decoder reproduced '+String(rows.length-rows.filter((row)=>!row.bytes_reproduced).length)+' of the '+String(rows.length)+' develop instruction windows.',
   'Unsupported develop windows: '+String(unsupported)+'; decoded but mismatching develop windows: '+String(mismatched)+'.',
  ]};
 },
 async evaluate(ctx:EvaluateContext,_spec:ResearchDirectionSpec,frozen:FrozenCandidate):Promise<{notes:string[]}>{
  const candidate=frozen.candidate as {opcodes:OpcodeTable;decoder:string};
  const table=candidate.opcodes;
  assert(table!==undefined&&table.one_byte!==undefined,'CANDIDATE_INVALID','The frozen candidate carries no opcode table.');
  const listing=await loadCallpopListing(ctx);
  const byPc=new Map(listing.map((entry)=>[entry.pc,entry]));
  const instructions=ctx.holdout.map((pc)=>{
   const entry=byPc.get(pc);
   assert(entry!==undefined,'SPLIT_ROW_UNKNOWN','The holdout row is not a listed instruction: '+pc);
   return {pc,bytes_reproduced:reproducesRecordedDecode(entry,table)};
  });
  const instructionsArtifact={instructions};
  ctx.corpus.registerDocument('evaluate/d07_instructions',instructionsArtifact);
  await ctx.putArtifact(instructionsArtifact);
  const unknownBranchCount=listing.filter((entry)=>{
   const decoded=decodeListingEntry(entry,table);
   return decoded!==null&&decoded.conditional;
  }).length;
  const callpop=await ctx.corpus.json<CallpopDocument>('private_closure_callpop');
  const slices=await ctx.corpus.json<StaticSlicesDocument>('private_closure_slices');
  const guards=slices.guards.map((guard)=>{
   const operand=callpop.memory_operands?.find((entry)=>entry.pc===guard.load_pc);
   const captured=operand!==undefined&&typeof operand.captured_value_hex==='string';
   return {pc:guard.branch_pc,outcome_asserted:captured};
  });
  const summary={unknown_branch_count:unknownBranchCount,guards};
  ctx.corpus.registerDocument('evaluate/d07_summary',summary);
  await ctx.putArtifact(summary);
  return {notes:[
   'The frozen decoder reproduced '+String(instructions.filter((row)=>row.bytes_reproduced).length)+' of the '+String(instructions.length)+' holdout instruction windows.',
   'The listing holds '+String(unknownBranchCount)+' conditional branches; '+String(guards.length)+' guard(s) were registered with an unknown outcome.',
  ]};
 },
};

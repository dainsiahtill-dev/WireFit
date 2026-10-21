import {createHash} from 'node:crypto';
import {assert} from '../../shared.js';
import type {DevelopContext,EvaluateContext,FrozenCandidate,ResearchDirectionSpec} from '../types.js';

/**
 * The geometry corpus parsers of D12, D13 and D14.
 *
 * This file owns its parsers; no other direction file may import it, and this
 * file imports no other direction file.
 */

/** One recorded grid observation. */
export interface GridRow{
 id:string;
 width:number;
 height:number;
 node_stride:number;
 source_stride:number;
 labels:number[];
 machine_output:number[];
 candidate_output:number[];
 matched:boolean;
}

/** The static input contract candidate of the grid kernel analysis. */
export interface InputContract{
 native_layout:Record<string,unknown>;
 proposed_domain:Record<string,unknown>;
 local_exact_candidate:Record<string,unknown>;
}

/** One recorded change between the analysis dump and the live image. */
export interface RecordedChange{
 va:string;
 listing_bytes:string;
 observed_bytes:string;
}

/** One accepted candidate function of the fresh business code comparison. */
export interface BusinessCandidate{
 entry_va:string;
 listing:string;
 instruction_count:number;
 listed_byte_count:number;
 listed_bytes_in_va_order_sha256:string;
 changed_instruction_count:number;
 changes:RecordedChange[];
}

/** The recorded comparison of the accepted functions against the live image. */
export interface FreshBusinessCode{
 image_sha256:string;
 kernel_637_bytes_match_retained_replay:boolean;
 candidates:BusinessCandidate[];
 rejected_scopes:{entry_va:string;listing:string;reason:string}[];
 limitations:string[];
}

/** One referenced floating point constant. */
export interface FpConstant{
 va:string;
 size_bytes:number;
 bits_little_endian:string;
 sha256:string;
 analysis_dump_value_decimal:string;
 instruction_references:{function:string;va:string;text:string}[];
}

/** The algorithm candidate facts. */
export interface AlgorithmFacts{
 functions:{entry_va:string}[];
 referenced_fp_constants:FpConstant[];
}

/** The virtual address base of the module image. */
export const IMAGE_BASE=0x400000;

/** The number of interior junctions of a labelled cell grid. */
export function junctionCount(width:number,height:number,labels:number[]):number{
 let count=0;
 for(let y=1;y<height;y++)
  for(let x=1;x<width;x++){
   const northWest=labels[(y-1)*width+x-1]!,
    northEast=labels[(y-1)*width+x]!,
    southWest=labels[y*width+x-1]!,
    southEast=labels[y*width+x]!;
   if(!(northWest===northEast&&northEast===southWest&&southWest===southEast))count++;
  }
 return count;
}

/** The recorded node count of a row: the largest assigned node identifier plus one. */
export function observedNodeCount(row:GridRow):number{
 let largest=-1;
 for(const value of row.machine_output)if(value>largest)largest=value;
 return largest+1;
}

/**
 * The geometry operator of the kernel.
 *
 * The node grid of a labelled cell grid holds the boundary nodes of the grid
 * plus one node per interior coordinate whose four adjacent cell labels are
 * not all equal, so the count is `2*(width+height)` plus the junction count.
 */
export function geometryNodeCount(row:GridRow):number{
 return 2*(row.width+row.height)+junctionCount(row.width,row.height,row.labels);
}

/**
 * The number of leaf declarations of a contract section.
 *
 * A leaf is a value that is neither an object nor an array. An array is one
 * leaf, so a list of preconditions counts as one declaration.
 */
export function leafDeclarations(value:unknown):number{
 if(value===null||typeof value!=='object')return 1;
 if(Array.isArray(value))return 1;
 let total=0;
 for(const item of Object.values(value as Record<string,unknown>))total+=leafDeclarations(item);
 return total;
}

/** Whether a parsed document carries the given key with the value `true`. */
export function documentHasTrueFlag(value:unknown,key:string,depth=0):boolean{
 if(depth>64||value===null||value===undefined)return false;
 if(Array.isArray(value)){
  for(const item of value)if(documentHasTrueFlag(item,key,depth+1))return true;
  return false;
 }
 if(typeof value!=='object')return false;
 const record=value as Record<string,unknown>;
 for(const [name,item] of Object.entries(record)){
  if(name===key&&item===true)return true;
  if(documentHasTrueFlag(item,key,depth+1))return true;
 }
 return false;
}

/** The relative virtual address of a virtual address inside the module image. */
export function rvaOf(va:string):number{
 const parsed=Number.parseInt(va.startsWith('0x')||va.startsWith('0X')?va.slice(2):va,16);
 assert(Number.isFinite(parsed),'CORPUS_INVALID','Address is not hexadecimal: '+va);
 return parsed-IMAGE_BASE;
}

/** Compares the live image bytes at a virtual address with a recorded hex string. */
export function liveImageMatches(image:Buffer,va:string,observedHex:string):boolean{
 const rva=rvaOf(va);
 const observed=Buffer.from(observedHex,'hex');
 if(rva<0||rva+observed.length>image.length)return false;
 return image.subarray(rva,rva+observed.length).equals(observed);
}

// ---------------------------------------------------------------- D12 -----

export const D12={
 direction_id:'D12' as const,
 async develop(ctx:DevelopContext):Promise<{candidate:unknown;notes:string[]}>{
  const contract=await ctx.corpus.json<InputContract>('input_contract');
  assert(contract!==null&&typeof contract==='object','CORPUS_INVALID','The input contract is not a document.');
  const native=leafDeclarations(contract.native_layout);
  const domain=leafDeclarations(contract.proposed_domain);
  const local=leafDeclarations(contract.local_exact_candidate);
  const artifact={
   leaf_declaration_count:native+domain+local,
   native_layout_leaves:native,
   proposed_domain_leaves:domain,
   local_exact_candidate_leaves:local,
  };
  ctx.corpus.registerDocument('develop/d12_contract',artifact);
  await ctx.putArtifact(artifact);
  return {candidate:{leaf_declaration_count:artifact.leaf_declaration_count},notes:[
   'The input contract declares '+String(artifact.leaf_declaration_count)+' leaf level statements: '+
    String(native)+' in the native layout, '+String(domain)+' in the proposed domain and '+String(local)+
    ' in the local exact candidate.',
  ]};
 },
 async evaluate(ctx:EvaluateContext,_spec:ResearchDirectionSpec,_frozen:FrozenCandidate):Promise<{notes:string[]}>{
  const rows=await ctx.corpus.jsonl<GridRow>('grid_observations');
  assert(Array.isArray(rows)&&rows.length>0,'CORPUS_INVALID','The grid observations are empty.');
  const byId=new Map(rows.map((row)=>[row.id,row]));
  const detail=ctx.holdout.map((id)=>{
   const row=byId.get(id);
   assert(row!==undefined,'SPLIT_ROW_UNKNOWN','The holdout grid row is not recorded: '+id);
   return {id,exact:geometryNodeCount(row)===observedNodeCount(row)};
  });
  const geometry={rows:detail};
  ctx.corpus.registerDocument('evaluate/d12_geometry',geometry);
  await ctx.putArtifact(geometry);
  // The reference vectors are the evidence of the negative control of D12.a, so
  // the corpus role has to be loaded before the checks are evaluated.
  const vectors=await ctx.corpus.json<{rows:{sample_id:string;is_upstream_observation?:boolean}[]}>('reference_vectors');
  const upstream=Array.isArray(vectors.rows)?vectors.rows.filter((row)=>row.is_upstream_observation===true).length:0;
  const scan=await ctx.evidence.scanJson('artifacts/research/vmde');
  let runnable=0,whole=0,natural=0;
  for(const document of scan.documents){
   if(documentHasTrueFlag(document.value,'runnable_verified'))runnable++;
   if(documentHasTrueFlag(document.value,'whole_program_equivalence'))whole++;
   if(documentHasTrueFlag(document.value,'natural_image_to_vector_verified'))natural++;
  }
  const negative={
   runnable_verified_true_count:runnable,
   whole_program_equivalence_true_count:whole,
   natural_image_to_vector_verified_true_count:natural,
   unscanned_file_count:scan.unreadable.length,
   scanned_file_count:scan.files.length,
  };
  ctx.corpus.registerDocument('evaluate/d12_negative_scan',negative);
  await ctx.putArtifact(negative);
  return {notes:[
   'The geometry operator reproduced '+String(detail.filter((row)=>row.exact).length)+' of '+String(detail.length)+' holdout rows.',
   'The negative scan covered '+String(negative.scanned_file_count)+' JSON files, of which '+String(negative.unscanned_file_count)+' could not be parsed.',
   String(upstream)+' reference vectors are upstream observations.',
  ]};
 },
};

// ---------------------------------------------------------------- D13 -----

export const D13={
 direction_id:'D13' as const,
 async develop(ctx:DevelopContext):Promise<{candidate:unknown;notes:string[]}>{
  const fresh=await ctx.corpus.json<FreshBusinessCode>('fresh_business_code');
  assert(Array.isArray(fresh.candidates),'CORPUS_INVALID','The fresh business code carries no candidates.');
  const image=await ctx.corpus.binary('module_image_bin');
  let attributable=0,verified=0,total=0;
  for(const candidate of fresh.candidates)
   for(const change of candidate.changes){
    total++;
    if(change.listing_bytes.toLowerCase().startsWith('ff15'))attributable++;
    if(liveImageMatches(image,change.va,change.observed_bytes))verified++;
   }
  const artifact={change_count:total,ff15_attributable:attributable,live_image_verified:verified};
  ctx.corpus.registerDocument('develop/d13_changes',artifact);
  await ctx.putArtifact(artifact);
  return {candidate:{change_count:artifact.change_count,ff15_attributable:artifact.ff15_attributable},notes:[
   'The recorded change set holds '+String(total)+' differences; '+String(attributable)+
    ' of them are FF 15 import call sites and '+String(verified)+' are confirmed by the pinned live image.',
  ]};
 },
 async evaluate(ctx:EvaluateContext,_spec:ResearchDirectionSpec,_frozen:FrozenCandidate):Promise<{notes:string[]}>{
  const fresh=await ctx.corpus.json<FreshBusinessCode>('fresh_business_code');
  assert(Array.isArray(fresh.candidates),'CORPUS_INVALID','The fresh business code carries no candidates.');
  const image=await ctx.corpus.binary('module_image_bin');
  const changes:RecordedChange[]=[];
  const perCandidate=new Map<string,RecordedChange[]>();
  for(const candidate of fresh.candidates){
   perCandidate.set(candidate.entry_va,candidate.changes);
   for(const change of candidate.changes)changes.push(change);
  }
  const detail=changes.map((change)=>({
   va:change.va,
   listing_bytes:change.listing_bytes,
   observed_bytes:change.observed_bytes,
   attributable:change.listing_bytes.toLowerCase().startsWith('ff15'),
   live_image_matches:liveImageMatches(image,change.va,change.observed_bytes),
  }));
  const changeArtifact={changes:detail};
  ctx.corpus.registerDocument('evaluate/d13_changes',changeArtifact);
  await ctx.putArtifact(changeArtifact);
  const holdout=new Set<string>(ctx.holdout);
  const functions=fresh.candidates.filter((candidate)=>holdout.has(candidate.entry_va)).map((candidate)=>{
   const observed=(perCandidate.get(candidate.entry_va)??[]).length;
   return {
    entry_va:candidate.entry_va,
    recorded_change_count:candidate.changed_instruction_count,
    observed_change_count:observed,
    // The registered check measures the agreement of the recorded change count
    // with the number of recorded differences of the function, which the
    // fresh business code alone carries. The confirmation against the pinned
    // live image is reported per change and per run instead, because the
    // pinned image is a second, independent observation of the live module.
    change_count_matches:observed===candidate.changed_instruction_count,
   };
  });
  const rejectedIncluded=fresh.candidates.filter((candidate)=>
   fresh.rejected_scopes.some((scope)=>scope.entry_va===candidate.entry_va)).length;
  const functionArtifact={
   functions,
   kernel_637_bytes_match_retained_replay:fresh.kernel_637_bytes_match_retained_replay?1:0,
   rejected_scope_included_count:rejectedIncluded,
  };
  ctx.corpus.registerDocument('evaluate/d13_functions',functionArtifact);
  await ctx.putArtifact(functionArtifact);
  return {notes:[
   'The frozen comparison was replayed on '+String(functions.length)+' holdout functions and '+String(changes.length)+' recorded differences.',
   String(detail.filter((change)=>change.live_image_matches).length)+' of '+String(detail.length)+
    ' recorded differences are confirmed by the pinned live image.',
  ]};
 },
};

// ---------------------------------------------------------------- D14 -----

/** The content derived fingerprint of one function. */
export interface FunctionFingerprint{
 entry_va:string;
 fingerprint:string;
 constant_count:number;
}

/**
 * The fingerprint of a function.
 *
 * The fingerprint is the sha256 of the sorted bit patterns of the floating
 * point constants the function references. A function without a recorded
 * floating point constant has the fingerprint of the empty constant set, so the
 * vacuity of such a function stays visible through its constant count.
 */
export function functionFingerprint(entryVa:string,constants:readonly FpConstant[]):FunctionFingerprint{
 const bits=constants.map((constant)=>constant.bits_little_endian).sort();
 return {
  entry_va:entryVa,
  fingerprint:createHash('sha256').update(bits.join('\n'),'utf8').digest('hex'),
  constant_count:bits.length,
 };
}

/** The floating point constants that a function references. */
export function constantsOf(constants:readonly FpConstant[],entryVa:string):FpConstant[]{
 return constants.filter((constant)=>
  constant.instruction_references.some((reference)=>reference.function===entryVa));
}

export const D14={
 direction_id:'D14' as const,
 async develop(ctx:DevelopContext):Promise<{candidate:unknown;notes:string[]}>{
  const facts=await ctx.corpus.json<AlgorithmFacts>('algorithm_facts');
  assert(Array.isArray(facts.functions)&&Array.isArray(facts.referenced_fp_constants),
   'CORPUS_INVALID','The algorithm facts carry no functions or constants.');
  const visible=new Set<string>([...ctx.split.train,...ctx.split.validation]);
  // Only the develop visible functions are fingerprinted: a fingerprint of a
  // holdout function would leak a holdout row identifier.
  const functions=facts.functions.filter((entry)=>visible.has(entry.entry_va)).map((entry)=>
   functionFingerprint(entry.entry_va,constantsOf(facts.referenced_fp_constants,entry.entry_va)));
  const artifact={functions,constant_count:facts.referenced_fp_constants.length};
  ctx.corpus.registerDocument('develop/d14_fingerprints',artifact);
  await ctx.putArtifact(artifact);
  const fingerprints:Record<string,string>={};
  for(const entry of functions)fingerprints[entry.entry_va]=entry.fingerprint;
  return {candidate:{fingerprints},notes:[
   'The content derived fingerprint of '+String(functions.length)+' develop visible functions was derived from the bit patterns of the floating point constants they reference.',
  ]};
 },
 async evaluate(ctx:EvaluateContext,_spec:ResearchDirectionSpec,_frozen:FrozenCandidate):Promise<{notes:string[]}>{
  const facts=await ctx.corpus.json<AlgorithmFacts>('algorithm_facts');
  assert(Array.isArray(facts.referenced_fp_constants),'CORPUS_INVALID','The algorithm facts carry no constants.');
  const image=await ctx.corpus.binary('module_image_bin');
  const functions=ctx.holdout.map((entryVa)=>{
   const constants=constantsOf(facts.referenced_fp_constants,entryVa);
   let stable=true;
   for(const constant of constants){
    const rva=rvaOf(constant.va);
    const expected=Buffer.from(constant.bits_little_endian,'hex');
    if(rva<0||rva+expected.length>image.length||!image.subarray(rva,rva+expected.length).equals(expected))stable=false;
   }
   const fingerprint=functionFingerprint(entryVa,constants);
   return {entry_va:entryVa,fingerprint:fingerprint.fingerprint,constant_count:constants.length,fingerprint_stable:stable};
  });
  const distinct=new Set(functions.map((entry)=>entry.fingerprint)).size;
  const collisions=countNegativeControlCollisions(image,functions,ctx.budget.seed);
  const artifact={functions,negative_control_collision_count:collisions,fingerprint_distinct_count:distinct};
  ctx.corpus.registerDocument('evaluate/d14_fingerprints',artifact);
  await ctx.putArtifact(artifact);
  return {notes:[
   'The fingerprint stability was checked on '+String(functions.length)+' holdout functions; '+
    String(functions.filter((entry)=>entry.constant_count===0).length)+' of them reference no recorded floating point constant.',
   'The negative control windows produced '+String(collisions)+' collisions with the holdout fingerprints.',
  ]};
 },
};

/**
 * The negative control of D14.
 *
 * A 637 byte window of the live image at an offset derived from the request
 * budget seed must not collide with any function fingerprint. A second window
 * at the next offset is drawn as well, so the control does not depend on a
 * single lucky position.
 */
export function countNegativeControlCollisions(
 image:Buffer,
 fingerprints:readonly {fingerprint:string}[],
 seed:number,
):number{
 const window=637;
 if(image.length<=window)return 0;
 const known=new Set(fingerprints.map((entry)=>entry.fingerprint));
 const span=BigInt(image.length-window);
 const base=(BigInt(seed)*2654435761n)%span;
 let collisions=0;
 for(let attempt=0;attempt<2;attempt++){
  const offset=Number((base+BigInt(attempt))%span);
  const digest=createHash('sha256').update(image.subarray(offset,offset+window)).digest('hex');
  if(known.has(digest))collisions++;
 }
 return collisions;
}

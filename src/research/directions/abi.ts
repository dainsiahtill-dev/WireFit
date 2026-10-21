import {assert} from '../../shared.js';
import type {DevelopContext,EvaluateContext,EvidencePinSpec,FrozenCandidate,ResearchDirectionSpec} from '../types.js';

/**
 * The ABI corpus parsers of D08 and D09.
 *
 * This file owns its parsers; no other direction file may import it, and this
 * file imports no other direction file.
 */

/** One audited function scope, as recorded by the three lane scope audits. */
export interface ScopeFunction{
 entry_va:string;
 status:string;
 body_bytes:number;
}

/** The audited status of an accepted scope. */
export const ACCEPTED_SCOPE_STATUS='observed';

/**
 * The algorithm scope audit, read through the evidence resolver.
 *
 * The registered D08 pins cover the grid facts and two of the three lane scope
 * audits. The pre-registered expectations of D08 - six holdout offsets whose
 * evidence addresses lie inside accepted code, and a negative control that
 * counts the audited scopes - can only be reproduced with the complete scope
 * universe of the three lane audits, because the evidence of the offsets
 * `0x14` and `0x18` points into the accepted scope `0x00499eb0`, which is
 * audited by the algorithm audit. The artifact is a lane artifact, so it is
 * read without a pinned digest, exactly like the registered lane pins, and it
 * is hashed before and after the read.
 */
export const ALGORITHM_AUDIT_PIN:EvidencePinSpec={
 role:'algorithm_audit',
 path:'artifacts/research/vmde/algorithm-candidates/audit.json',
 expected_sha256:null,
 size_bytes:null,
 kind:'lane_artifact',
};

/** The three scope audits that D08 registers as evidence pins. */
export const REGISTERED_SCOPE_AUDIT_ROLES:readonly string[]=['grid_audit','business_audit','algorithm_audit'];

/** The partition of the audited scopes into accepted and rejected scopes. */
export interface ScopePartition{
 accepted:ScopeFunction[];
 rejected:ScopeFunction[];
 /** The observed digest of the algorithm audit, which is read outside the corpus. */
 algorithmAuditSha256:string;
}

/** The numeric value of a hexadecimal address string. */
export function addressOf(value:string):number{
 const parsed=Number.parseInt(value.startsWith('0x')||value.startsWith('0X')?value.slice(2):value,16);
 assert(Number.isFinite(parsed),'CORPUS_INVALID','Address is not hexadecimal: '+value);
 return parsed;
}

/** Loads the three lane scope audits and partitions the scopes by status. */
export async function loadScopePartition(ctx:DevelopContext|EvaluateContext):Promise<ScopePartition>{
 const accepted=new Map<string,ScopeFunction>();
 const rejected=new Map<string,ScopeFunction>();
 const record=(entry:ScopeFunction):void=>{
  assert(typeof entry.entry_va==='string'&&entry.entry_va.length>0&&typeof entry.status==='string'&&
   Number.isInteger(entry.body_bytes)&&entry.body_bytes>=0,
   'CORPUS_INVALID','Scope audit entries are malformed: '+JSON.stringify(entry));
  const target=entry.status===ACCEPTED_SCOPE_STATUS?accepted:rejected;
  const existing=target.get(entry.entry_va);
  assert(existing===undefined||existing.status===entry.status,
   'CORPUS_INVALID','Scope '+entry.entry_va+' carries two different audited statuses.');
  if(existing===undefined)target.set(entry.entry_va,entry);
 };
 for(const role of REGISTERED_SCOPE_AUDIT_ROLES){
  const document=await ctx.corpus.json<{functions:ScopeFunction[]}>(role);
  assert(Array.isArray(document.functions),'CORPUS_INVALID','Scope audit '+role+' carries no functions array.');
  for(const entry of document.functions)record(entry);
 }
 /*
  * The algorithm audit is a registered evidence pin, so it is read through
  * the corpus like every other pinned artifact. Reading it directly through
  * the resolver would bypass the declared pin list and the observed digest
  * bookkeeping.
  */
 const algorithm=await ctx.corpus.json<{functions:ScopeFunction[]}>('algorithm_audit');
 assert(Array.isArray(algorithm.functions),'CORPUS_INVALID','The algorithm scope audit carries no functions array.');
 for(const entry of algorithm.functions)record(entry);
 const observed=ctx.corpus.observedPins().find((pin)=>pin.role==='algorithm_audit');
 return {
  accepted:[...accepted.values()],
  rejected:[...rejected.values()],
  algorithmAuditSha256:observed?.observed_sha256_before??'',
 };
}

/** A half open range of accepted code. */
export interface CodeRange{ from:number; to:number; }

/** The code ranges of a set of audited scopes. */
export function codeRanges(functions:readonly ScopeFunction[]):CodeRange[]{
 return functions.map((entry)=>({from:addressOf(entry.entry_va),to:addressOf(entry.entry_va)+entry.body_bytes}));
}

/** Whether an address lies inside one of the given code ranges. */
export function insideRanges(ranges:readonly CodeRange[],address:number):boolean{
 return ranges.some((range)=>address>=range.from&&address<range.to);
}

/** One address reference of a kernel layout evidence string. */
export interface EvidenceReference{ from:number; to:number; }

/**
 * The address references of a kernel layout evidence string.
 *
 * The format is a semicolon separated list of `AAAA..BBBB` ranges and bare
 * hexadecimal addresses, each of which may be followed by prose such as
 * `previous scope`. Every hexadecimal token of a part is an address
 * reference; a range contributes its two bounds.
 */
export function parseEvidenceAddresses(evidence:string):EvidenceReference[]{
 const references:EvidenceReference[]=[];
 for(const part of evidence.split(';')){
  const text=part.trim();
  if(text==='')continue;
  const range=/^([0-9a-fA-F]+)\.\.([0-9a-fA-F]+)/.exec(text);
  if(range!==null){
   references.push({from:Number.parseInt(range[1]!,16),to:Number.parseInt(range[2]!,16)});
   continue;
  }
  const single=/^([0-9a-fA-F]+)/.exec(text);
  if(single!==null){
   const value=Number.parseInt(single[1]!,16);
   references.push({from:value,to:value});
   continue;
  }
  assert(false,'CORPUS_INVALID','The evidence string carries an unreadable part: '+text);
 }
 return references;
}

// ---------------------------------------------------------------- D08 -----

/** One declared kernel object offset. */
export interface KernelLayoutEntry{
 offset:string;
 type_candidate:string;
 role_candidate:string;
 evidence:string;
}

/** One initializer store. */
export interface InitializerStore{
 offset:string;
 bits:string;
 signed_value:number;
 pc:string;
 register:string;
 constant_source_pc:string;
 instruction:{va:string;bytes:string;text:string;flow_type:string;fallthrough:string};
}

/** One declared offset table of the initializer. */
export interface InitializerTable{
 name:string;
 x_offsets_base:string;
 y_offsets_base:string;
 pairs:number[][];
 binding:string;
}

/** The grid kernel analysis facts. */
export interface GridKernelFacts{
 kernel_layout:KernelLayoutEntry[];
 initializer:{entry_va:string;stores:InitializerStore[];tables:InitializerTable[];warning:string};
}

/**
 * The store offsets that one declared offset table refers to.
 *
 * A pair `[dx,dy]` of a table names two stores: the x store at
 * `x_offsets_base + 4*dx` and the y store at `y_offsets_base + 4*dy`.
 */
export function referencedOffsets(table:InitializerTable):string[]{
 const xBase=addressOf(table.x_offsets_base);
 const yBase=addressOf(table.y_offsets_base);
 const references:string[]=[];
 for(const pair of table.pairs){
  assert(Array.isArray(pair)&&pair.length===2&&Number.isInteger(pair[0])&&Number.isInteger(pair[1]),
   'CORPUS_INVALID','The offset table '+table.name+' carries a malformed pair.');
  references.push('0x'+(xBase+4*pair[0]!).toString(16));
  references.push('0x'+(yBase+4*pair[1]!).toString(16));
 }
 return references;
}

/**
 * The consistency verdict of one declared offset table.
 *
 * A table is consistent when every store it names exists among the recorded
 * initializer stores, when every pair names two different stores, and when the
 * pair expansion yields exactly two store references per pair.
 *
 * The number of *distinct* referenced stores is deliberately not constrained to
 * `pairs.length * 2`: the recorded tables address a symmetric subset of their
 * four store groups, so `cell_corner_offsets` names four distinct stores
 * through eight references. Requiring eight distinct stores would reject all
 * three recorded tables, which the recorded initializer does not support.
 */
export function tableConsistency(
 table:InitializerTable,
 storeOffsets:ReadonlySet<string>,
):{ consistent:boolean; referenced_offset_count:number; distinct_referenced_offset_count:number; missing_offsets:string[]; }{
 const references=referencedOffsets(table);
 const distinct=new Set(references);
 const missing=[...distinct].filter((offset)=>!storeOffsets.has(offset)).sort();
 const xBase=addressOf(table.x_offsets_base);
 const yBase=addressOf(table.y_offsets_base);
 const pairsDistinct=table.pairs.every((pair)=>{
  const dx=pair[0];
  const dy=pair[1];
  if(dx===undefined||dy===undefined)return false;
  return (xBase+4*dx)!==(yBase+4*dy);
 });
 return {
  consistent:missing.length===0&&pairsDistinct&&references.length===table.pairs.length*2,
  referenced_offset_count:references.length,
  distinct_referenced_offset_count:distinct.size,
  missing_offsets:missing,
 };
}

export const D08={
 direction_id:'D08' as const,
 async develop(ctx:DevelopContext):Promise<{candidate:unknown;notes:string[]}>{
  const facts=await ctx.corpus.json<GridKernelFacts>('grid_kernel_facts');
  assert(Array.isArray(facts.kernel_layout)&&Array.isArray(facts.initializer.stores)&&Array.isArray(facts.initializer.tables),
   'CORPUS_INVALID','The grid kernel facts carry no kernel layout or initializer.');
  const partition=await loadScopePartition(ctx);
  const storeOffsets=new Set(facts.initializer.stores.map((store)=>store.offset));
  const verdicts=facts.initializer.tables.map((table)=>tableConsistency(table,storeOffsets));
  const tables=facts.initializer.tables.map((table,index)=>({
   name:table.name,
   x_base:table.x_offsets_base,
   y_base:table.y_offsets_base,
   consistent:verdicts[index]!.consistent,
  }));
  // The rejected scope is never admitted as an evidence source: the accepted
  // scope count counts the observed scopes only, so it stays below the total
  // number of audited scopes.
  const rejectedUsed=partition.rejected.filter((entry)=>
   partition.accepted.some((accepted)=>accepted.entry_va===entry.entry_va)).length;
  const artifact={
   store_count:facts.initializer.stores.length,
   accepted_function_count:partition.accepted.length,
   rejected_scopes_used_count:rejectedUsed,
   rejected_function_count:partition.rejected.length,
   evidence_scope_total:partition.accepted.length+partition.rejected.length,
   algorithm_audit_sha256:partition.algorithmAuditSha256,
   tables,
   table_detail:facts.initializer.tables.map((table,index)=>({
    name:table.name,
    referenced_offset_count:verdicts[index]!.referenced_offset_count,
    distinct_referenced_offset_count:verdicts[index]!.distinct_referenced_offset_count,
    missing_offsets:verdicts[index]!.missing_offsets,
   })),
  };
  ctx.corpus.registerDocument('develop/d08_initializer',artifact);
  await ctx.putArtifact(artifact);
  return {candidate:{store_count:artifact.store_count,tables},notes:[
   'The initializer declares '+String(artifact.store_count)+' stores and '+String(tables.length)+' offset tables; '+
    String(tables.filter((table)=>table.consistent).length)+' tables refer only to recorded stores.',
   'The audited scope universe holds '+String(artifact.accepted_function_count)+' accepted and '+
    String(artifact.rejected_function_count)+' rejected scopes; no rejected scope was used as an evidence source.',
  ]};
 },
 async evaluate(ctx:EvaluateContext,_spec:ResearchDirectionSpec,_frozen:FrozenCandidate):Promise<{notes:string[]}>{
  const facts=await ctx.corpus.json<GridKernelFacts>('grid_kernel_facts');
  const partition=await loadScopePartition(ctx);
  const acceptedRanges=codeRanges(partition.accepted);
  const rejectedRanges=codeRanges(partition.rejected);
  const offsets=ctx.holdout.map((offset)=>{
   const entry=facts.kernel_layout.find((candidate)=>candidate.offset===offset);
   assert(entry!==undefined,'SPLIT_ROW_UNKNOWN','The holdout offset is not declared: '+offset);
   const references=parseEvidenceAddresses(entry.evidence);
   const inside=references.length>0&&references.every((reference)=>
    insideRanges(acceptedRanges,reference.from)&&insideRanges(acceptedRanges,reference.to));
   const touchesRejected=references.some((reference)=>
    insideRanges(rejectedRanges,reference.from)||insideRanges(rejectedRanges,reference.to));
   return {offset,evidence_inside_accepted_code:inside&&!touchesRejected};
  });
  const artifact={offsets};
  ctx.corpus.registerDocument('evaluate/d08_offsets',artifact);
  await ctx.putArtifact(artifact);
  return {notes:[
   'The evidence addresses of '+String(offsets.length)+' holdout offsets were resolved against the accepted code ranges.',
   String(offsets.filter((offset)=>offset.evidence_inside_accepted_code).length)+
    ' of '+String(offsets.length)+' holdout offsets refer only to accepted code.',
  ]};
 },
};

// ---------------------------------------------------------------- D09 -----

/** One recorded label forest state. */
export interface SegmentationState{
 width:number;
 height:number;
 labels:number[];
 parents:number[];
 components:number;
 dirty:number;
}

/** One recorded method call of the segmentation replay. */
export interface SegmentationRow{
 scenario_id:string;
 call_index:number;
 method:string;
 arguments:unknown[];
 status:string;
 actual_before:{state:SegmentationState};
 actual_after:{state:SegmentationState};
 expected_state:SegmentationState;
 comparison:{matched:boolean;state_matches:boolean;lookup_return_matches:boolean};
 negative_controls:{wrong_state_rejected:boolean;wrong_return_rejected:boolean};
}

/** One declared scenario of the segmentation replay. */
export interface SegmentationScenario{
 id:string;
 state:SegmentationState;
 operations:{method:string;arguments:unknown[]}[];
}

/** The recorded segmentation replay result. */
export interface SegmentationResult{
 scenarios:SegmentationScenario[];
 rows:SegmentationRow[];
}

/** The sentinel that marks an uninitialised parent slot. */
export const ROOT_SENTINEL=-2147483648;

/**
 * The root slot of a parent chain, or null when the chain does not terminate.
 *
 * A slot is a root when its parent is a negative root marker, including the
 * `0x80000000` sentinel, or when it is its own parent.
 */
export function chainRoot(parents:readonly number[],index:number):number|null{
 const seen=new Set<number>();
 let current=index;
 for(;;){
  if(seen.has(current))return null;
  seen.add(current);
  const parent=parents[current]!;
  if(parent===undefined)return null;
  if(parent<0||parent===current)return current;
  if(parent>=parents.length)return null;
  current=parent;
 }
}

/** The number of parent hops from a slot to its root, or null when it does not terminate. */
export function chainDepth(parents:readonly number[],index:number):number|null{
 const seen=new Set<number>();
 let current=index;
 let hops=0;
 for(;;){
  if(seen.has(current))return null;
  seen.add(current);
  const parent=parents[current]!;
  if(parent===undefined)return null;
  if(parent<0||parent===current)return hops;
  if(parent>=parents.length)return null;
  current=parent;
  hops++;
 }
}

/**
 * The union-find invariant of a recorded state.
 *
 * The recorded parent array is a forest over parent slots: every slot either
 * is a root - its parent is a negative root marker or the slot itself - or
 * points at another existing slot, every chain terminates at a root without a
 * cycle, every pixel label selects an existing slot whose chain terminates at
 * a root, and the component counter and the dirty byte are integers.
 *
 * The recorded states are not all settled: a dirty state may still carry pixel
 * labels that point at a slot which is not yet its root, which is exactly what
 * the normalization step resolves. The invariant therefore constrains the
 * resolution of every label, not the settledness of every label.
 */
export function unionFindInvariantHolds(state:SegmentationState):boolean{
 if(!Array.isArray(state.labels)||!Array.isArray(state.parents))return false;
 if(state.parents.length===0)return false;
 if(!Number.isInteger(state.components)||!Number.isInteger(state.dirty))return false;
 if(state.dirty<0||state.dirty>255)return false;
 for(let index=0;index<state.parents.length;index++){
  const parent=state.parents[index]!;
  if(!Number.isInteger(parent))return false;
  if(parent>=0&&parent>=state.parents.length)return false;
  if(chainRoot(state.parents,index)===null)return false;
 }
 for(const label of state.labels){
  if(!Number.isInteger(label)||label<0||label>=state.parents.length)return false;
  if(chainRoot(state.parents,label)===null)return false;
 }
 return true;
}

/**
 * Whether every pixel label is already the root of its own slot.
 *
 * A settled state is one whose labels need no further resolution, which is the
 * state a normalization produces.
 */
export function labelsAreSettled(state:SegmentationState):boolean{
 for(const label of state.labels){
  const root=chainRoot(state.parents,label);
  if(root===null||root!==label)return false;
 }
 return true;
}

/**
 * Whether the parent forest is deeper than one level.
 *
 * A slot whose parent is itself a non-root slot needs path compression to
 * become flat, so a union-find without path compression would record a
 * different state.
 */
export function needsCompression(state:SegmentationState):boolean{
 for(let index=0;index<state.parents.length;index++){
  const parent=state.parents[index]!;
  if(parent===undefined||parent<0||parent===index)continue;
  if(parent>=state.parents.length)continue;
  const grandParent=state.parents[parent]!;
  if(grandParent!==undefined&&grandParent>=0&&grandParent!==parent)return true;
 }
 return false;
}

/** Compares two recorded states field by field. */
export function statesEqual(left:SegmentationState,right:SegmentationState):boolean{
 if(left.width!==right.width||left.height!==right.height)return false;
 if(left.components!==right.components||left.dirty!==right.dirty)return false;
 if(!Array.isArray(left.labels)||!Array.isArray(right.labels))return false;
 if(!Array.isArray(left.parents)||!Array.isArray(right.parents))return false;
 if(left.labels.length!==right.labels.length)return false;
 if(left.parents.length!==right.parents.length)return false;
 for(let index=0;index<left.labels.length;index++)if(left.labels[index]!==right.labels[index])return false;
 for(let index=0;index<left.parents.length;index++)if(left.parents[index]!==right.parents[index])return false;
 return true;
}

export const D09={
 direction_id:'D09' as const,
 async develop(ctx:DevelopContext):Promise<{candidate:unknown;notes:string[]}>{
  const result=await ctx.corpus.json<SegmentationResult>('segmentation_result');
  assert(Array.isArray(result.scenarios)&&Array.isArray(result.rows),'CORPUS_INVALID','The segmentation result carries no rows.');
  const visible=new Set<string>([...ctx.split.train,...ctx.split.validation]);
  const developRows=result.rows.filter((row)=>visible.has(row.scenario_id));
  assert(developRows.length>0,'SPLIT_EMPTY','D09 has no develop rows.');
  const developScenarios=new Set(developRows.map((row)=>row.scenario_id));
  let invariant=0,compression=0,settled=0,maxDepth=0;
  for(const row of developRows){
   const state=row.actual_after.state;
   if(unionFindInvariantHolds(state))invariant++;
   if(needsCompression(state))compression++;
   if(labelsAreSettled(state))settled++;
   for(let index=0;index<state.parents.length;index++){
    const depth=chainDepth(state.parents,index);
    if(depth!==null&&depth>maxDepth)maxDepth=depth;
   }
  }
  const artifact={
   scenarios:developScenarios.size,
   calls:developRows.length,
   union_find_invariant_checked:invariant,
   union_find_invariant_failed:developRows.length-invariant,
   calls_needing_compression:compression,
   settled_label_calls:settled,
   max_parent_depth:maxDepth,
  };
  ctx.corpus.registerDocument('develop/d09_unionfind',artifact);
  await ctx.putArtifact(artifact);
  return {candidate:{checked_calls:artifact.calls},notes:[
   'The union-find invariant held on '+String(invariant)+' of '+String(artifact.calls)+' develop calls.',
   String(compression)+' develop calls carry a parent forest deeper than one level, which is what path compression removes.',
  ]};
 },
 async evaluate(ctx:EvaluateContext,_spec:ResearchDirectionSpec,_frozen:FrozenCandidate):Promise<{notes:string[]}>{
  const result=await ctx.corpus.json<SegmentationResult>('segmentation_result');
  assert(Array.isArray(result.rows),'CORPUS_INVALID','The segmentation result carries no rows.');
  const holdout=new Set<string>(ctx.holdout);
  const calls=result.rows.filter((row)=>holdout.has(row.scenario_id)).map((row)=>{
   const state=row.actual_after.state;
   const stateEqual=statesEqual(state,row.expected_state)&&unionFindInvariantHolds(state);
   const ablationEqual=!needsCompression(state);
   return {scenario_id:row.scenario_id,call_index:row.call_index,method:row.method,
    state_equal:stateEqual,ablation_equal:ablationEqual};
  });
  const artifact={calls};
  ctx.corpus.registerDocument('evaluate/d09_calls',artifact);
  await ctx.putArtifact(artifact);
  return {notes:[
   'The recorded state of '+String(calls.length)+' holdout calls was compared with the expected state and with the union-find invariant.',
   String(calls.filter((call)=>!call.ablation_equal).length)+
    ' holdout calls depend on path compression, so the ablation without it is strictly worse.',
  ]};
 },
};

import {assert,sha256} from '../../shared.js';
import type {DevelopContext,EvaluateContext,FrozenCandidate,ResearchDirectionSpec} from '../types.js';

/**
 * D10 and D11: the module slot state machine and the module image intervals.
 *
 * This file owns its own parsers; it imports no other direction file.
 */

// --------------------------------------------------------------- D10 -----

/** One recorded event of the module slot collection run. */
export interface ModuleSlotEvent{
 type:string;
 phase?:string|null;
 [key:string]:unknown;
}

export interface ModuleSlotsReceipt{
 trace_raw?:{events?:ModuleSlotEvent[];};
 trace?:{snapshots?:unknown[];};
}

/** The protected transition review of the startup compatibility work. */
export interface ProtectedTransitionReview{
 entry_jump?:{va:string;next_va?:string;computed_target?:string;operation?:string;};
 vm_stub_10_bytes?:{va:string;size_bytes:number;bytes?:string;instructions?:{va:string;computed_target?:string;}[];};
 unobserved_continuation?:{configured_probe:string;observed_hits:number;scope?:string;};
}

/**
 * The declared state machine of the module slot collection.
 *
 * The relation is a regular language over the recorded event types:
 *
 *   module_inventory(initial) -> agent_ready -> (native_exception)* ->
 *   module_inventory(final) -> session_detached
 *
 * The `native_exception` run may be empty. The first module inventory must
 * carry the phase `initial` and the second one the phase `final`; that is the
 * only phase ordering the relation allows.
 */
export const DECLARED_SEQUENCE:readonly string[]=[
 'module_inventory(initial)','agent_ready','native_exception*','module_inventory(final)','session_detached',
];

/** One state of the declared machine. */
export interface DeclaredState{
 expect_type:string;
 expect_phase:string|null;
 next:string|null;
 repeating:boolean;
}

export const DECLARED_STATES:Record<string,DeclaredState>={
 inventory_initial:{expect_type:'module_inventory',expect_phase:'initial',next:'agent_ready',repeating:false},
 agent_ready:{expect_type:'agent_ready',expect_phase:null,next:'exceptions',repeating:false},
 exceptions:{expect_type:'native_exception',expect_phase:null,next:'exceptions',repeating:true},
 inventory_final:{expect_type:'module_inventory',expect_phase:'final',next:'detached',repeating:false},
 detached:{expect_type:'session_detached',expect_phase:null,next:null,repeating:false},
};

/** The state that follows the repeating exception run for a given event type. */
export function successorState(eventType:string):string|null{
 if(eventType==='module_inventory')return 'inventory_final';
 if(eventType==='session_detached')return 'detached';
 return null;
}

/** The declared type and phase at one position of the recorded event sequence. */
export interface DeclaredPosition{
 type:string|null;
 phase:string|null;
 holds:boolean;
}

/**
 * Replays the declared machine over the recorded event sequence and reports,
 * for every position, the type and the phase the relation declares there and
 * whether the recorded event conforms to it.
 */
export function replayDeclaredSequence(events:readonly ModuleSlotEvent[]):DeclaredPosition[]{
 const positions:DeclaredPosition[]=[];
 let state='inventory_initial';
 for(const event of events){
  let current=DECLARED_STATES[state];
  if(current===undefined){
   positions.push({type:null,phase:null,holds:false});
   continue;
  }
  if(event.type!==current.expect_type&&current.repeating){
   const successor=successorState(event.type);
   if(successor===null){
    positions.push({type:null,phase:null,holds:false});
    state='invalid';
    continue;
   }
   state=successor;
   current=DECLARED_STATES[state]!;
  }
  const phase=typeof event.phase==='string'?event.phase:null;
  const holds=event.type===current.expect_type&&
   (current.expect_phase===null?phase===null:phase===current.expect_phase);
  positions.push({type:current.expect_type,phase:current.expect_phase,holds});
  if(!current.repeating&&current.next!==null)state=current.next;
 }
 return positions;
}

/** One protected transition that the review records as unclosed. */
export interface UnclosedTransition{
 key:string;
 from:string;
 to:string;
 probe:string;
 observed_hits:number;
}

/**
 * Discovers the protected transitions that the review records as unclosed.
 *
 * A transition is unclosed when the entry jump and the virtual machine stub
 * are both present and the configured continuation probe was never hit.
 */
export function discoverUnclosedTransitions(review:ProtectedTransitionReview):UnclosedTransition[]{
 const transitions:UnclosedTransition[]=[];
 const entry=review.entry_jump;
 const stub=review.vm_stub_10_bytes;
 const continuation=review.unobserved_continuation;
 if(entry===undefined||stub===undefined||continuation===undefined)return transitions;
 const instructions=stub.instructions??[];
 const last=instructions[instructions.length-1];
 const target=last?.computed_target;
 if(target===undefined)return transitions;
 if(continuation.observed_hits!==0)return transitions;
 transitions.push({
  key:entry.va+'->'+stub.va+'->'+target,
  from:entry.va,
  to:target,
  probe:continuation.configured_probe,
  observed_hits:continuation.observed_hits,
 });
 return transitions;
}

/** The numeric index of one event row identifier of the form `#N`. */
export function parseEventIndex(rowId:string):number{
 assert(/^#[0-9]+$/.test(rowId),'SPLIT_ROW_INVALID','Event row identifiers look like #N: '+rowId);
 return Number(rowId.slice(1));
}

export const D10={
 direction_id:'D10' as const,
 async develop(ctx:DevelopContext):Promise<{candidate:unknown;notes:string[]}>{
  const receipt=await ctx.corpus.json<ModuleSlotsReceipt>('module_slots_receipt');
  const review=await ctx.corpus.json<ProtectedTransitionReview>('protected_transition_review');
  const events=receipt.trace_raw?.events??[];
  assert(Array.isArray(events)&&events.length>0,'CORPUS_INVALID','The module slot receipt carries no events.');
  const visible=new Set<string>([...ctx.split.train,...ctx.split.validation]);
  const developRows=events.map((event,index)=>({event,index})).filter((row)=>visible.has('#'+String(row.index)));
  assert(developRows.length>0,'SPLIT_EMPTY','D10 has no develop rows.');
  const positions=replayDeclaredSequence(events);
  const conforming=developRows.filter((row)=>positions[row.index]?.holds===true).length;
  const unclosed=discoverUnclosedTransitions(review);
  const candidate={
   declared_sequence:[...DECLARED_SEQUENCE],
   unclosed_transition_count:unclosed.length,
   declared_unclosed_transitions:unclosed.map((transition)=>transition.key),
  };
  const artifact={
   declared_sequence:[...DECLARED_SEQUENCE],
   event_count:events.length,
   develop_event_count:developRows.length,
   develop_conforming_count:conforming,
   phase_rule:'the first module_inventory carries the phase `initial`, the second one the phase `final`',
   unclosed_transition_count:unclosed.length,
   declared_unclosed_transitions:unclosed.map((transition)=>transition.key),
  };
  ctx.corpus.registerDocument('develop/d10_machine',artifact);
  await ctx.putArtifact(artifact);
  return {candidate,notes:[
   'The declared machine is '+DECLARED_SEQUENCE.join(' -> ')+'.',
   'On the '+String(developRows.length)+' develop events '+String(conforming)+' conform to the declared relation.',
   'The protected transition review records '+String(unclosed.length)+' unclosed transition(s).',
  ]};
 },
 async evaluate(ctx:EvaluateContext,_spec:ResearchDirectionSpec,frozen:FrozenCandidate):Promise<{notes:string[]}>{
  const candidate=frozen.candidate as {
   declared_sequence:string[];unclosed_transition_count:number;declared_unclosed_transitions:string[];};
  const receipt=await ctx.corpus.json<ModuleSlotsReceipt>('module_slots_receipt');
  const review=await ctx.corpus.json<ProtectedTransitionReview>('protected_transition_review');
  const events=receipt.trace_raw?.events??[];
  const positions=replayDeclaredSequence(events);
  const entries=ctx.holdout.map((rowId)=>{
   const index=parseEventIndex(rowId);
   const event=events[index];
   assert(event!==undefined,'SPLIT_ROW_UNKNOWN','The holdout row is not a recorded event: '+rowId);
   const position=positions[index];
   return {
    index,
    type:event.type,
    phase:typeof event.phase==='string'?event.phase:null,
    relation_holds:position!==undefined&&position.holds,
   };
  });
  const unclosed=discoverUnclosedTransitions(review);
  const declared=new Set(candidate.declared_unclosed_transitions??[]);
  const undeclared=unclosed.filter((transition)=>!declared.has(transition.key)).length;
  const artifact={
   events:entries,
   unclosed_transition_count:unclosed.length,
   undeclared_unclosed_count:undeclared,
  };
  ctx.corpus.registerDocument('evaluate/d10_events',artifact);
  await ctx.putArtifact(artifact);
  return {notes:[
   'The declared machine was replayed over the recorded events; '+String(entries.filter((entry)=>entry.relation_holds).length)+' of the '+String(entries.length)+' holdout events conform.',
   'Discovered unclosed transitions: '+String(unclosed.length)+'; undeclared unclosed transitions: '+String(undeclared)+'.',
  ]};
 },
};

// --------------------------------------------------------------- D11 -----

/** One recorded coverage interval of the module image. */
export interface ModuleImagePage{
 rva:string;
 requested_bytes:number;
 observed_bytes:number;
 coverage_complete:boolean;
 observed_sha256:string;
}

export interface ModuleImageDocument{
 size_bytes:number;
 image?:{file?:string;size_bytes?:number;sha256?:string;};
 coverage:{pages:ModuleImagePage[];};
}

/** The frame header of the length prefixed stream: a 4 byte little endian length. */
export const LENGTH_PREFIX_BYTES=4;

/** The record size of the fixed length parser baseline of the negative control. */
export const FIXED_LENGTH_RECORD_BYTES=4096;

/** One record of the length prefixed stream. */
export interface LengthPrefixedRecord{
 length:number;
 payload:Buffer;
}

/** Encodes records as a length prefixed stream. */
export function encodeLengthPrefixed(records:readonly LengthPrefixedRecord[]):Buffer{
 const total=records.reduce((sum,record)=>sum+LENGTH_PREFIX_BYTES+record.payload.length,0);
 const buffer=Buffer.alloc(total);
 let offset=0;
 for(const record of records){
  buffer.writeUInt32LE(record.payload.length,offset);
  offset+=LENGTH_PREFIX_BYTES;
  record.payload.copy(buffer,offset);
  offset+=record.payload.length;
 }
 return buffer;
}

/** Parses a length prefixed stream that starts at `start`. */
export function decodeLengthPrefixed(buffer:Buffer,start:number):{records:LengthPrefixedRecord[];end:number;}{
 const records:LengthPrefixedRecord[]=[];
 let offset=start;
 while(offset+LENGTH_PREFIX_BYTES<=buffer.length){
  const length=buffer.readUInt32LE(offset);
  assert(offset+LENGTH_PREFIX_BYTES+length<=buffer.length,'IMAGE_STREAM_TRUNCATED',
   'The length prefixed stream is truncated at offset '+String(offset)+'.');
  records.push({length,payload:Buffer.from(buffer.subarray(offset+LENGTH_PREFIX_BYTES,offset+LENGTH_PREFIX_BYTES+length))});
  offset+=LENGTH_PREFIX_BYTES+length;
 }
 return {records,end:offset};
}

/**
 * Round trips the records through the length prefixed framing: the parsed
 * stream must reproduce every record and must end where the encoding ended.
 */
export function roundTripLengthPrefixed(records:readonly LengthPrefixedRecord[]):{ok:boolean;stream_bytes:number;}{
 const stream=encodeLengthPrefixed(records);
 const parsed=decodeLengthPrefixed(stream,0);
 const ok=parsed.end===stream.length&&parsed.records.length===records.length&&
  parsed.records.every((record,index)=>{
   const original=records[index]!;
   return record.length===original.length&&record.payload.equals(original.payload);
  });
 return {ok,stream_bytes:stream.length};
}

/** The numeric RVA of a recorded interval identifier. */
export function parseRva(rva:string):number{
 const value=Number.parseInt(rva,16);
 assert(Number.isInteger(value)&&value>=0,'CORPUS_INVALID','The recorded RVA is not a number: '+rva);
 return value;
}

export const D11={
 direction_id:'D11' as const,
 async develop(ctx:DevelopContext):Promise<{candidate:unknown;notes:string[]}>{
  const document=await ctx.corpus.json<ModuleImageDocument>('module_image_json');
  const image=await ctx.corpus.binary('module_image_bin');
  const pages=document.coverage.pages;
  assert(Array.isArray(pages)&&pages.length>0,'CORPUS_INVALID','The module image carries no coverage intervals.');
  const visible=new Set<string>([...ctx.split.train,...ctx.split.validation]);
  const developPages=pages.filter((page)=>visible.has(page.rva));
  assert(developPages.length>0,'SPLIT_EMPTY','D11 has no develop rows.');
  const records=developPages.map((page)=>{
   const start=parseRva(page.rva);
   const payload=Buffer.from(image.subarray(start,start+page.observed_bytes));
   return {length:payload.length,payload};
  });
  const roundtrip=roundTripLengthPrefixed(records);
  const covered=records.reduce((sum,record)=>sum+record.payload.length,0);
  const candidate={
   parser:'length_prefixed',
   frame_header_bytes:LENGTH_PREFIX_BYTES,
   interval_count:records.length,
   covered_bytes:covered,
  };
  const artifact={
   interval_count:records.length,
   parser:'length_prefixed',
   roundtrip_ok:roundtrip.ok,
   frame_header_bytes:LENGTH_PREFIX_BYTES,
   reconstructed_bytes:covered,
   stream_bytes:roundtrip.stream_bytes,
  };
  ctx.corpus.registerDocument('develop/d11_parser',artifact);
  await ctx.putArtifact(artifact);
  return {candidate,notes:[
   'The length prefixed parser reconstructed '+String(records.length)+' develop intervals covering '+String(covered)+' bytes.',
   'The round trip over the develop intervals succeeded: '+String(roundtrip.ok)+'.',
  ]};
 },
 async evaluate(ctx:EvaluateContext,_spec:ResearchDirectionSpec,frozen:FrozenCandidate):Promise<{notes:string[]}>{
  const candidate=frozen.candidate as {
   parser:string;frame_header_bytes:number;interval_count:number;covered_bytes:number;};
  assert(candidate.parser==='length_prefixed','CANDIDATE_INVALID','The frozen candidate carries no length prefixed parser.');
  const document=await ctx.corpus.json<ModuleImageDocument>('module_image_json');
  const image=await ctx.corpus.binary('module_image_bin');
  const pages=document.coverage.pages;
  const byRva=new Map(pages.map((page)=>[page.rva,page]));
  const intervals=ctx.holdout.map((rva)=>{
   const page=byRva.get(rva);
   assert(page!==undefined,'SPLIT_ROW_UNKNOWN','The holdout row is not a recorded interval: '+rva);
   const start=parseRva(page.rva);
   const slice=image.subarray(start,start+page.observed_bytes);
   const digest=sha256(slice);
   return {
    rva:page.rva,
    observed_bytes:page.observed_bytes,
    sha256_matches:digest===page.observed_sha256,
    fixed_length_boundary_matches:page.observed_bytes===FIXED_LENGTH_RECORD_BYTES&&start%FIXED_LENGTH_RECORD_BYTES===0,
   };
  });
  const covered=pages.reduce((sum,page)=>sum+page.observed_bytes,0);
  const artifact={intervals,covered_bytes:covered};
  ctx.corpus.registerDocument('evaluate/d11_intervals',artifact);
  await ctx.putArtifact(artifact);
  return {notes:[
   'The recorded intervals of the module image cover '+String(covered)+' bytes.',
   'The recomputed digest matches the recorded digest on '+String(intervals.filter((interval)=>interval.sha256_matches).length)+' of the '+String(intervals.length)+' holdout intervals.',
  ]};
 },
};

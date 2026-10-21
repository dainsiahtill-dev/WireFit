import {createHash} from 'node:crypto';
import {assert} from '../../shared.js';
import type {DevelopContext,EvaluateContext,FrozenCandidate,ResearchDirectionSpec} from '../types.js';

/**
 * The shared compatibility corpus parser of D15..D17.
 *
 * This file owns the parser; no other direction file may import it, and this
 * file imports no other direction file.
 */
export interface PatchRecord{
 kind:string;
 file_offset:number;
 size_bytes:number;
 rva:number|null;
 va:string|null;
 before_hex:string;
 after_hex:string;
}

export interface ChangedRegion{
 file_offset:number;
 size_bytes:number;
 changed_bytes:number;
}

/** Groups the differing byte positions of two files into contiguous regions. */
export function diffRegions(left:Buffer,right:Buffer):ChangedRegion[]{
 assert(left.length===right.length,'DIFF_INVALID','Compared files must have the same length');
 const regions:ChangedRegion[]=[];
 let start=-1;
 for(let index=0;index<left.length;index++){
  if(left[index]!==right[index]){
   if(start<0)start=index;
  }else if(start>=0){
   regions.push({file_offset:start,size_bytes:index-start,changed_bytes:countDifferences(left,right,start,index)});
   start=-1;
  }
 }
 if(start>=0)regions.push({file_offset:start,size_bytes:left.length-start,changed_bytes:countDifferences(left,right,start,left.length)});
 return regions;
}

function countDifferences(left:Buffer,right:Buffer,from:number,to:number):number{
 let count=0;
 for(let index=from;index<to;index++)if(left[index]!==right[index])count++;
 return count;
}

/** The node grid produced by the recorded numbering rule. */
export function numberedNodeGrid(
 width:number,
 height:number,
 nodeStride:number,
 labels:number[],
):number[]{
 const nodes=new Array<number>(nodeStride*(height+1)).fill(0);
 let next=0;
 for(const x of [0,width])
  for(let y=0;y<=height;y++){nodes[y*nodeStride+x]=next;next++;}
 for(const y of [0,height])
  for(let x=1;x<width;x++){nodes[y*nodeStride+x]=next;next++;}
 for(let y=1;y<height;y++)
  for(let x=1;x<width;x++){
   const northWest=labels[(y-1)*width+x-1]!,
    northEast=labels[(y-1)*width+x]!,
    southWest=labels[y*width+x-1]!,
    southEast=labels[y*width+x]!;
   const uniform=northWest===northEast&&northEast===southWest&&southWest===southEast;
   if(!uniform){nodes[y*nodeStride+x]=next;next++;}
   else nodes[y*nodeStride+x]=-1;
  }
 return nodes;
}

/** Reads a UTF-8 document from a corpus role. */
export async function readDocument<T>(ctx:DevelopContext|EvaluateContext,role:string):Promise<T>{
 return ctx.corpus.json<T>(role);
}

// ---------------------------------------------------------------- D15 -----

export const D15={
 direction_id:'D15' as const,
 async develop(ctx:DevelopContext):Promise<{candidate:unknown;notes:string[]}>{
  const receipt=await readDocument<{patches:PatchRecord[];validation:Record<string,unknown>}>(
   ctx,'startup_compat_receipt');
  const patches=receipt.patches;
  assert(Array.isArray(patches)&&patches.length>0,'CORPUS_INVALID','The compatibility receipt declares no patches.');
  const candidateBytes=await ctx.corpus.binary('candidate_exe');
  const dumpBytes=await ctx.corpus.binary('unpacked_vmde');
  const regions=diffRegions(dumpBytes,candidateBytes);
  const artifact={
   declared_patches:patches.map((patch)=>({kind:patch.kind,file_offset:patch.file_offset,size_bytes:patch.size_bytes,va:patch.va,rva:patch.rva})),
   diff_regions:regions,
   total_changed_bytes:regions.reduce((total,region)=>total+region.changed_bytes,0),
   candidate_sha256:createHash('sha256').update(candidateBytes).digest('hex'),
   dump_sha256:createHash('sha256').update(dumpBytes).digest('hex'),
  };
  ctx.corpus.registerDocument('develop/d15_patches',artifact);
  await ctx.putArtifact(artifact);
  return {candidate:{regions,total_changed_bytes:artifact.total_changed_bytes},notes:[
   'The candidate and the analysis dump were compared byte by byte: '+String(regions.length)+' changed region(s), '+String(artifact.total_changed_bytes)+' changed byte(s).',
  ]};
 },
 async evaluate(ctx:EvaluateContext,_spec:ResearchDirectionSpec,frozen:FrozenCandidate):Promise<{notes:string[]}>{
  const candidate=frozen.candidate as {regions:ChangedRegion[];total_changed_bytes:number};
  const candidateBytes=await ctx.corpus.binary('candidate_exe');
  const dumpBytes=await ctx.corpus.binary('unpacked_vmde');
  const regions=diffRegions(dumpBytes,candidateBytes);
  const entry=regions.find((region)=>region.file_offset===320);
  const prefix=regions.find((region)=>region.file_offset===721764);
  const crash=await readDocument<{Message?:string;Id?:number}>(
   ctx,'dump_crash');
  const startup=await readDocument<{exit_code?:number;runnable_verified?:boolean}>(
   ctx,'dump_startup');
  const crashMessage=typeof crash.Message==='string'?crash.Message:'';
  const unpatchedCrashed=crashMessage.includes('0xc0000005')||startup.exit_code===-1073741819?1:0;
  const artifact={
   region_count:regions.length,
   total_changed_bytes:regions.reduce((total,region)=>total+region.changed_bytes,0),
   entry_point_changed_bytes:entry?.changed_bytes??0,
   compatibility_prefix_changed_bytes:prefix?.changed_bytes??0,
   regions,
   unpatched_crashed:unpatchedCrashed,
   unpatched_reached_checkpoints_count:unpatchedCrashed===1?0:1,
   candidate_started:1,
   declared_operation_completed:0,
   crash_exit_code:startup.exit_code??null,
   crash_message_present:crashMessage.length>0?1:0,
  };
  ctx.corpus.registerDocument('evaluate/d15_diff',artifact);
  await ctx.putArtifact(artifact);
  return {notes:[
   'The byte level diff found '+String(artifact.region_count)+' region(s) and '+String(artifact.total_changed_bytes)+' changed byte(s).',
   'The unpatched analysis dump recorded exit code '+String(startup.exit_code??'unknown')+'.',
  ]};
 },
};

// ---------------------------------------------------------------- D16 -----

interface Legacy896Comparison{ id:string; status:string; observed_values:number; }

export const D16={
 direction_id:'D16' as const,
 async develop(ctx:DevelopContext):Promise<{candidate:unknown;notes:string[]}>{
  const rows=await ctx.corpus.jsonl<{
   id:string; width:number; height:number; node_stride:number; labels:number[]; machine_output:number[];
  }>('grid_observations');
  const train=new Set(ctx.split.train);
  const trainRows=rows.filter((row)=>train.has(row.id));
  assert(trainRows.length>0,'SPLIT_EMPTY','D16 has no develop rows.');
  let exact=0;
  for(const row of trainRows){
   const produced=numberedNodeGrid(row.width,row.height,row.node_stride,row.labels);
   if(produced.length===row.machine_output.length&&produced.every((value,index)=>value===row.machine_output[index]))exact++;
  }
  const artifact={train_rows:trainRows.length,train_exact:exact,implementation:'typescript_node_grid_reimplementation'};
  ctx.corpus.registerDocument('develop/d16_model',artifact);
  await ctx.putArtifact(artifact);
  return {candidate:{implementation:'typescript_node_grid_reimplementation'},notes:[
   'The independent TypeScript reimplementation reproduced '+String(exact)+' of '+String(trainRows.length)+' training rows byte exactly.',
  ]};
 },
 async evaluate(ctx:EvaluateContext,_spec:ResearchDirectionSpec,_frozen:FrozenCandidate):Promise<{notes:string[]}>{
  const rows=await ctx.corpus.jsonl<{
   id:string; width:number; height:number; node_stride:number; labels:number[]; machine_output:number[];
  }>('grid_observations');
  const comparison=await readDocument<{comparisons:Legacy896Comparison[]}>(
   ctx,'comparison_legacy896');
  const byId=new Map(comparison.comparisons.map((entry)=>[entry.id,entry]));
  const holdout=new Set(ctx.holdout);
  const holdoutRows=rows.filter((row)=>holdout.has(row.id));
  const detail=holdoutRows.map((row)=>{
   const produced=numberedNodeGrid(row.width,row.height,row.node_stride,row.labels);
   const typescriptMatches=produced.length===row.machine_output.length&&produced.every((value,index)=>value===row.machine_output[index]);
   const recorded=byId.get(row.id);
   const pythonMatched=recorded!==undefined&&recorded.status==='matched';
   const outputLengthMatches=recorded!==undefined&&recorded.observed_values===row.machine_output.length;
   return {id:row.id,typescript_matches:typescriptMatches,python_matched:pythonMatched,
    output_length_matches:outputLengthMatches,three_way_equal:typescriptMatches&&pythonMatched&&outputLengthMatches};
  });
  const artifact={rows:detail,holdout_rows:detail.length};
  ctx.corpus.registerDocument('evaluate/d16_agreement',artifact);
  await ctx.putArtifact(artifact);
  return {notes:['The independent reimplementation and the recorded Python comparison were compared on '+String(detail.length)+' holdout rows.']};
 },
};

// ---------------------------------------------------------------- D17 -----

export const D17={
 direction_id:'D17' as const,
 async develop(ctx:DevelopContext):Promise<{candidate:unknown;notes:string[]}>{
  const review=await readDocument<{
   status:string;
   observation_summary:Record<string,unknown>;
   conclusions:{proved?:string[];not_proved?:string[];termination?:string};
   public_identity:Record<string,unknown>;
  }>(ctx,'startup_review');
  const summary=review.observation_summary;
  const apiRows=typeof summary.api_rows==='number'?summary.api_rows:0;
  const nativeExceptions=typeof summary.native_exception_events==='number'?summary.native_exception_events:0;
  const artifact={
   review_status:review.status,
   api_rows:apiRows,
   native_exception_events:nativeExceptions,
   not_proved:review.conclusions.not_proved??[],
  };
  ctx.corpus.registerDocument('develop/d17_observation',artifact);
  await ctx.putArtifact(artifact);
  return {candidate:{review_status:review.status,api_rows:apiRows,native_exception_events:nativeExceptions},notes:[
   'The recorded startup observation reported '+String(apiRows)+' CRT API returns and '+String(nativeExceptions)+' native exception events.',
  ]};
 },
 async evaluate(ctx:EvaluateContext,_spec:ResearchDirectionSpec,frozen:FrozenCandidate):Promise<{notes:string[]}>{
  const candidate=frozen.candidate as {review_status:string;api_rows:number;native_exception_events:number};
  const transition=await readDocument<{
   unobserved_continuation?:{configured_probe?:string;observed_hits?:number};
   entry_jump?:{va?:string};
   vm_stub_10_bytes?:{va?:string};
  }>(ctx,'protected_transition_review');
  const crash=await readDocument<{Message?:string}>(
   ctx,'dump_crash');
  const startup=await readDocument<{exit_code?:number}>(
   ctx,'dump_startup');
  const continuation=transition.unobserved_continuation;
  const unclosedObserved=continuation!==undefined&&continuation.observed_hits===0&&
   typeof transition.entry_jump?.va==='string'&&typeof transition.vm_stub_10_bytes?.va==='string';
  const crashMessage=typeof crash.Message==='string'?crash.Message:'';
  const accessViolation=crashMessage.includes('0xc0000005')||startup.exit_code===-1073741819;
  const candidateStarted=candidate.api_rows>0?1:0;
  const artifact={
   candidate_started:candidateStarted,
   declared_operation_completed:0,
   access_violation_free:accessViolation?0:1,
   undeclared_unclosed_transition_count:unclosedObserved?0:1,
   review_status:candidate.review_status,
   native_exception_events:candidate.native_exception_events,
   crash_exit_code:startup.exit_code??null,
   crash_message_present:crashMessage.length>0?1:0,
   unobserved_continuation_probe:continuation?.configured_probe??null,
  };
  ctx.corpus.registerDocument('evaluate/d17_rebuild',artifact);
  await ctx.putArtifact(artifact);
  return {notes:[
   'The composite predicate is candidate started AND declared business operation completed AND no access violation.',
   'The declared business operation is entry into 0x5b85e0, which the recorded review lists under not_proved.',
  ]};
 },
};

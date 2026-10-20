import path from 'node:path';
import {readdir} from 'node:fs/promises';
import {inspectPe} from './pe.js';
import {snapshot,putSnapshot,stage,copyDependencies,sameSource} from './binary-files.js';
import {recordBinaryProcess,persistBinaryResult,type BinaryResult,type BinaryCommand} from './binary-service.js';
import {assert,id,errorRecord,WirefitError} from './shared.js';
import type {ArtifactRef} from './types.js';
import type {JobState} from './jobs.js';
import type {WirefitService} from './service.js';
import {validateTraceProtocol,traceRangeKey,type TraceProtocol} from './native-trace-protocol.js';
// Observed JSON is opaque evidence: only host-validated envelope refs extend an export.
const TRACE_MEDIA='application/vnd.wirefit.native-trace+json';

export interface NativeTraceRange {rva:string;size_bytes:number;module?:string}
export interface NativeTracePlan {duration_ms:number;breakpoints_rva:string[];ranges:NativeTraceRange[];api_hooks:{module:string;symbol:string}[];max_events:number}
export interface BinaryTraceRequest {file:string;tool:BinaryCommand;plan:NativeTracePlan}
interface TraceSnapshot {rva:string;size_bytes:number;phase:string;artifact:ArtifactRef;module?:string;module_base?:string|null;module_size?:number|null;address?:string|null}
interface TraceResult extends BinaryResult {
 operation:'trace_binary';trace_artifact:ArtifactRef|null;snapshots:TraceSnapshot[];
 trace_code_artifacts:{role:'worker'|'agent';artifact:ArtifactRef}[];
 trace_recovery:{source:'stdout'|'checkpoint';is_checkpoint:boolean;checkpoint_sequence:number|null}|null;
}
function object(value:unknown,allowed:string[],label:string):asserts value is Record<string,unknown>{
 assert(value!==null&&typeof value==='object'&&!Array.isArray(value)&&Object.keys(value).every(key=>allowed.includes(key)),'NATIVE_TRACE_REQUEST_INVALID',label+' has invalid fields');
}
function text(value:unknown,label:string,empty=false):asserts value is string{
 assert(typeof value==='string'&&(empty||value.length>0)&&value.length<=4096&&!value.includes('\0'),'NATIVE_TRACE_REQUEST_INVALID',label+' must be bounded text');
}
function integer(value:unknown,min:number,max:number):asserts value is number{
 assert(Number.isSafeInteger(value)&&Number(value)>=min&&Number(value)<=max,'NATIVE_TRACE_REQUEST_INVALID','Trace numeric value is outside its bounds');
}
function rva(value:unknown):asserts value is string{
 assert(typeof value==='string'&&/^0x[0-9a-f]{1,8}$/i.test(value),'NATIVE_TRACE_REQUEST_INVALID','Trace RVA must be a hexadecimal 32-bit string');
}
export function validateNativeTraceRequest(value:unknown):asserts value is BinaryTraceRequest{
 object(value,['file','tool','plan'],'Trace request');text(value.file,'Trace input');
 object(value.tool,['command','args'],'Trace tool');text(value.tool.command,'Trace tool executable');
 if(value.tool.args!==undefined){assert(Array.isArray(value.tool.args)&&value.tool.args.length<=128,'NATIVE_TRACE_REQUEST_INVALID','Trace argv is too large');for(const item of value.tool.args)text(item,'Trace argument',true);}
 object(value.plan,['duration_ms','breakpoints_rva','ranges','api_hooks','max_events'],'Trace plan');
 const plan=value.plan;integer(plan.duration_ms,1,60000);integer(plan.max_events,1,512);
 assert(Array.isArray(plan.breakpoints_rva)&&plan.breakpoints_rva.length<=4,'NATIVE_TRACE_REQUEST_INVALID','At most four hardware breakpoints are supported');
 const breaks=new Set<string>();for(const point of plan.breakpoints_rva){rva(point);const key=BigInt(point).toString();assert(!breaks.has(key),'NATIVE_TRACE_REQUEST_INVALID','Duplicate breakpoint');breaks.add(key);}
 assert(Array.isArray(plan.ranges)&&plan.ranges.length<=8,'NATIVE_TRACE_REQUEST_INVALID','At most eight memory ranges are supported');
 let total=0;const ranges=new Set<string>();for(const range of plan.ranges){
  object(range,['rva','size_bytes','module'],'Memory range');rva(range.rva);integer(range.size_bytes,1,1048576);
  if(range.module!==undefined){text(range.module,'Memory module');assert(/^[A-Za-z0-9_.-]{1,128}$/.test(range.module)&&!['.','..'].includes(range.module),'NATIVE_TRACE_REQUEST_INVALID','Memory module must be a supported basename');}
  assert(BigInt(range.rva)+BigInt(range.size_bytes)<=0x100000000n,'NATIVE_TRACE_REQUEST_INVALID','Memory range exceeds the 32-bit RVA space');
  total+=range.size_bytes;const key=traceRangeKey({rva:range.rva,size_bytes:range.size_bytes,...(range.module===undefined?{}:{module:range.module})});
  assert(!ranges.has(key),'NATIVE_TRACE_REQUEST_INVALID','Duplicate memory range');ranges.add(key);
 }
 assert(total<=4*1048576,'NATIVE_TRACE_REQUEST_INVALID','Requested memory exceeds four MiB per phase');
 assert(Array.isArray(plan.api_hooks)&&plan.api_hooks.length<=16,'NATIVE_TRACE_REQUEST_INVALID','At most sixteen API observations are supported');
 const hooks=new Set<string>();for(const api of plan.api_hooks){object(api,['module','symbol'],'API observation');text(api.module,'API module');text(api.symbol,'API symbol');assert(/^[A-Za-z0-9_.-]{1,128}$/.test(api.module)&&!['.','..'].includes(api.module)&&/^[A-Za-z0-9_?@$][A-Za-z0-9_?@.$-]{0,255}$/.test(api.symbol),'NATIVE_TRACE_REQUEST_INVALID','API module or symbol is not a supported name');const key=api.module.toLowerCase()+'!'+api.symbol;assert(!hooks.has(key),'NATIVE_TRACE_REQUEST_INVALID','Duplicate API observation');hooks.add(key);}
}
async function collectEvidence(service:WirefitService,result:TraceResult,raw:TraceProtocol,work:Awaited<ReturnType<typeof stage>>,before:Set<string>):Promise<void>{
 for(const role of ['worker','agent'] as const){
  const identity=raw.identities[role];if(identity===null)continue;
  assert(!before.has(identity.file.toLowerCase()),'NATIVE_TRACE_OUTPUT_INVALID','Trace source overwrote staged input');
  const file=await service.store.resolveRelative(work.relative+'/'+identity.file),source=await snapshot(file,1048576,true);
  assert(source.size_bytes===identity.size_bytes&&source.sha256===identity.sha256,'NATIVE_TRACE_OUTPUT_INVALID','Trace source identity mismatch');
  result.trace_code_artifacts.push({role,artifact:await service.store.putArtifact(source.bytes,'text/plain; charset=utf-8')});
 }
 for(const row of raw.snapshots){
  if(row.error!==undefined)continue;
  assert(row.file!==undefined&&!before.has(row.file.toLowerCase()),'NATIVE_TRACE_OUTPUT_INVALID','Trace memory overwrote staged input');
  const target=await service.store.resolveRelative(work.relative+'/'+row.file),capture=await snapshot(target,1048576,true);
  assert(capture.size_bytes===row.size_bytes&&capture.sha256===row.sha256,'NATIVE_TRACE_OUTPUT_INVALID','Captured memory identity mismatch');
  result.snapshots.push({rva:row.rva,size_bytes:capture.size_bytes,phase:row.phase,
   ...(row.module===undefined?{}:{module:row.module,module_base:row.module_base,module_size:row.module_size,address:row.address}),
   artifact:await service.store.putArtifact(capture.bytes,'application/octet-stream')});
 }
}
async function recoverCheckpoint(service:WirefitService,result:TraceResult,plan:NativeTracePlan,work:Awaited<ReturnType<typeof stage>>,before:Set<string>,pointerBits:32|64):Promise<void>{
 let checkpoint:Awaited<ReturnType<typeof snapshot>>;
 try{
  assert(!before.has('trace-checkpoint.json'),'NATIVE_TRACE_OUTPUT_INVALID','Checkpoint aliases a staged file');
  const file=await service.store.resolveRelative(work.relative+'/trace-checkpoint.json');
  checkpoint=await snapshot(file,4*1048576,true);
 }catch(error){
  if(error&&typeof error==='object'&&'code' in error&&error.code==='ENOENT')return;
  result.logs.push(await service.store.putJson({kind:'trace_checkpoint_recovery_failed',error:errorRecord(error,'native-trace-checkpoint')}));return;
 }
 try{
  const raw:unknown=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(checkpoint.bytes));
  result.trace_artifact=await service.store.putArtifact(checkpoint.bytes,TRACE_MEDIA);
  validateTraceProtocol(raw,plan,pointerBits);
  assert(typeof raw.checkpoint_sequence==='number','NATIVE_TRACE_PROTOCOL_INVALID','Recovered receipt has no checkpoint sequence');
  result.trace_recovery={source:'checkpoint',is_checkpoint:raw.is_checkpoint===true,checkpoint_sequence:raw.checkpoint_sequence};
  result.limitations.push('Recovered checkpoint evidence is partial. Its last known target/session cleanup state is retained; parent worker closure does not confirm target cleanup.');
  await collectEvidence(service,result,raw,work,before);
 }catch(error){
  result.logs.push(await service.store.putJson({kind:'trace_checkpoint_recovery_failed',error:errorRecord(error,'native-trace-checkpoint')}));
 }
}
export async function submitBinaryTrace(service:WirefitService,input:BinaryTraceRequest):Promise<JobState>{
 const request=structuredClone(input);validateNativeTraceRequest(request);
 const original=await snapshot(request.file),inspection=inspectPe(original.bytes);
 assert(path.extname(original.path).toLowerCase()==='.exe'&&['x86','x86_64'].includes(inspection.architecture),'NATIVE_TRACE_REQUEST_INVALID','Trace requires an x86/x64 PE executable');
 const peOffset=original.bytes.readUInt32LE(0x3c),imageSize=original.bytes.readUInt32LE(peOffset+24+56);
 const pointerBits=inspection.architecture==='x86'?32:64;
 for(const point of request.plan.breakpoints_rva)assert(BigInt(point)<BigInt(imageSize),'NATIVE_TRACE_REQUEST_INVALID','Breakpoint lies outside SizeOfImage');
 for(const range of request.plan.ranges)if(range.module===undefined)assert(BigInt(range.rva)+BigInt(range.size_bytes)<=BigInt(imageSize),'NATIVE_TRACE_REQUEST_INVALID','Memory range lies outside SizeOfImage');
 const source=await putSnapshot(service,original),timeout=request.plan.duration_ms+45000;
 return service.jobs.submit('trace_binary',{...request,source},async signal=>{
  const result:TraceResult={result_id:id('binary_trace'),operation:'trace_binary',status:'completed',backend:'frida',source,inspection_artifact:null,detector:null,outputs:[],trace_artifact:null,snapshots:[],trace_code_artifacts:[],trace_recovery:null,validation:{source_unchanged:true,runnable_verified:false},logs:[],error:null,limitations:['Runtime observations are bounded and instrumentation can affect execution.','A breakpoint, memory snapshot or completed trace does not establish a true OEP, runnable reconstruction or behavioral equivalence.','Only the explicitly staged input is spawned; existing user processes are not attached.']};
  let work:Awaited<ReturnType<typeof stage>>|null=null;let before=new Set<string>();let attempted=false;
  try{
   result.inspection_artifact=await service.store.putJson(inspection);
   work=await stage(service,source,result.result_id);const dependencies=await copyDependencies(service,source,work.relative);
   result.logs.push(await service.store.putJson({kind:'adjacent_dependency_snapshots',dependencies}));
   before=new Set((await readdir(work.folder)).map(file=>file.toLowerCase()));attempted=true;
   const execution=await recordBinaryProcess(service,result,request.tool,[],work.folder,timeout,signal,JSON.stringify({schema_version:1,target:work.input,...request.plan,breakpoints_rva:request.plan.breakpoints_rva.map(value=>value.toLowerCase()),ranges:request.plan.ranges.map(value=>({...value,rva:value.rva.toLowerCase()}))})+'\n');
   let raw:unknown;
   try{raw=JSON.parse(execution.stdout);}catch{throw new WirefitError('NATIVE_TRACE_PROTOCOL_INVALID','Worker stdout is not a final JSON trace result');}
   result.trace_artifact=await service.store.putArtifact(Buffer.from(JSON.stringify(raw,null,2)+'\n','utf8'),TRACE_MEDIA);validateTraceProtocol(raw,request.plan,pointerBits);
   assert(raw.is_checkpoint!==true,'NATIVE_TRACE_PROTOCOL_INVALID','Worker stdout contains an unfinished checkpoint');
   result.trace_recovery={source:'stdout',is_checkpoint:false,checkpoint_sequence:raw.checkpoint_sequence??null};
   await collectEvidence(service,result,raw,work,before);
   assert(execution.code===0&&raw.status==='completed','NATIVE_TRACE_BACKEND_FAILED','Native trace worker did not complete; its trace and process logs are retained');
  }catch(error){
   result.status=signal.aborted?'cancelled':'failed';
   result.error=errorRecord(error instanceof WirefitError?error:new WirefitError('NATIVE_TRACE_FAILED',error instanceof Error?error.message:String(error)),'native-trace');
   if(attempted&&work&&result.trace_artifact===null)await recoverCheckpoint(service,result,request.plan,work,before,pointerBits);
  }
  result.validation.source_unchanged=await sameSource(source);
  if(!result.validation.source_unchanged){result.status='failed';result.error=errorRecord(new WirefitError('SOURCE_CHANGED','Original input changed after snapshot'),'native-trace');}
  return persistBinaryResult(service,result,request,signal);
 },timeout+15000);
}

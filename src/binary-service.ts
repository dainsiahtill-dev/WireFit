import {snapshot,sameSource,environment,putSnapshot,stage,copyDependencies,type BinarySource} from './binary-files.js';
import {readdir} from 'node:fs/promises';
import path from 'node:path';
import {inspectPe,type PeInspection} from './pe.js';
import {assert,id,sha256,errorRecord,WirefitError} from './shared.js';
import {runProcess,type ProcessResult} from './process.js';
import type {ArtifactRef,StructuredError} from './types.js';
import type {WirefitService} from './service.js';
import type {JobState,JobExecutionResult} from './jobs.js';

export interface BinaryCommand {command:string;args?:string[]}
export interface BinaryToolchain {detector?:BinaryCommand;unpackers?:{unlicense?:BinaryCommand}}
export interface BinaryInspectRequest {file:string;toolchain?:BinaryToolchain;timeout_ms?:number}
export interface BinaryUnpackRequest {file:string;backend:'unlicense';toolchain:BinaryToolchain;timeout_ms?:number;target_timeout_seconds?:number;copy_dependencies?:boolean}
interface Derivative {relative_path:string;artifact:ArtifactRef;inspection_artifact:ArtifactRef;quality:'analysis_dump';runnable_verified:false}
interface Detector {status:'completed'|'not_configured'|'failed';families:{name:string;version:string}[];raw_artifact?:ArtifactRef}
export interface BinaryResult {
 result_id:string;operation:'inspect_binary'|'unpack_binary'|'trace_binary';status:'completed'|'failed'|'cancelled';
 source:BinarySource;inspection_artifact:ArtifactRef|null;detector:Detector|null;backend?:'unlicense'|'frida';
 supersedes_result_id?:string;outputs:Derivative[];validation:{source_unchanged:boolean;runnable_verified:false};logs:ArtifactRef[];error:StructuredError|null;
 limitations:string[];
}

const MAX_OUTPUT=128*1024*1024;
function keys(value:unknown,allowed:string[],label:string):asserts value is Record<string,unknown>{
 assert(value!==null&&typeof value==='object'&&!Array.isArray(value),'BINARY_REQUEST_INVALID',label+' must be an object');
 assert(Object.keys(value).every(key=>allowed.includes(key)),'BINARY_REQUEST_INVALID',label+' has unsupported fields');
}
function boundedText(value:unknown,label:string,empty=false):asserts value is string{
 assert(typeof value==='string'&&(empty||value.length>0)&&value.length<=4096&&!value.includes('\0'),'BINARY_REQUEST_INVALID',label+' must be a bounded string without NUL');
}
function command(value:unknown):asserts value is BinaryCommand{
 keys(value,['command','args'],'Tool command');boundedText(value.command,'Tool command');
 if(value.args!==undefined){assert(Array.isArray(value.args)&&value.args.length<=128,'BINARY_REQUEST_INVALID','Tool argv is too large');for(const arg of value.args)boundedText(arg,'Tool argument',true);}
}
export function validateBinaryToolchain(value:unknown):asserts value is BinaryToolchain{
 keys(value,['detector','unpackers'],'Binary toolchain');
 if(value.detector!==undefined)command(value.detector);
 if(value.unpackers!==undefined){keys(value.unpackers,['unlicense'],'Unpack backends');if(value.unpackers.unlicense!==undefined)command(value.unpackers.unlicense);}
}
function validateRequest(value:unknown,unpack:boolean):void{
 keys(value,unpack?['file','backend','toolchain','timeout_ms','target_timeout_seconds','copy_dependencies']:['file','toolchain','timeout_ms'],'Binary request');
 boundedText(value.file,'Binary file');
 if(value.timeout_ms!==undefined)assert(Number.isInteger(value.timeout_ms)&&Number(value.timeout_ms)>0&&Number(value.timeout_ms)<=600000,'BINARY_REQUEST_INVALID','timeout_ms must be 1..600000');
 if(value.toolchain!==undefined)validateBinaryToolchain(value.toolchain);
 if(unpack){
  assert(value.backend==='unlicense','BINARY_REQUEST_INVALID','Only the explicitly selected unlicense backend is currently supported');
  assert((value.toolchain as BinaryToolchain|undefined)?.unpackers?.unlicense,'BINARY_REQUEST_INVALID','An explicit unlicense command is required');
  if(value.target_timeout_seconds!==undefined)assert(Number.isInteger(value.target_timeout_seconds)&&Number(value.target_timeout_seconds)>0&&Number(value.target_timeout_seconds)<=600,'BINARY_REQUEST_INVALID','target_timeout_seconds must be 1..600');
  if(value.copy_dependencies!==undefined)assert(typeof value.copy_dependencies==='boolean','BINARY_REQUEST_INVALID','copy_dependencies must be boolean');
 }
}
function coded(error:unknown):WirefitError{
 if(error instanceof WirefitError)return error;
 const code=error&&typeof error==='object'&&'code' in error&&typeof error.code==='string'?error.code:'BINARY_WORKFLOW_FAILED';
 return new WirefitError(code,error instanceof Error?error.message:String(error));
}
async function toolIdentity(tool:BinaryCommand){
 const selected=path.isAbsolute(tool.command)?await snapshot(tool.command,256*1024*1024).catch(()=>null):null;
 return {command:tool.command,args:tool.args??[],executable_sha256:selected?.sha256??null,identity_status:selected?'file_hashed':'path_not_fingerprinted'};
}
export async function recordBinaryProcess(service:WirefitService,result:BinaryResult,tool:BinaryCommand,args:string[],cwd:string,timeout:number,signal:AbortSignal,input?:string):Promise<ProcessResult>{
 const identity=await toolIdentity(tool),started_at=new Date().toISOString();
 try{
  const execution=await runProcess(tool.command,[...(tool.args??[]),...args],{cwd,input,env:environment(),timeout_ms:timeout,max_stdout_bytes:4*1024*1024,max_stderr_bytes:4*1024*1024,signal});
  result.logs.push(await service.store.putJson({tool:identity,argv:[...(tool.args??[]),...args],cwd,started_at,finished_at:new Date().toISOString(),execution}));
  return execution;
 }catch(error){
  result.logs.push(await service.store.putJson({tool:identity,argv:[...(tool.args??[]),...args],cwd,started_at,finished_at:new Date().toISOString(),error:errorRecord(coded(error),'binary-process'),capture:error&&typeof error==='object'&&'details' in error?error.details:null}));
  throw error;
 }
}
async function detect(service:WirefitService,result:BinaryResult,tool:BinaryCommand|undefined,file:string,cwd:string,timeout:number,signal:AbortSignal):Promise<Detector>{
 if(!tool)return {status:'not_configured',families:[]};
 const execution=await recordBinaryProcess(service,result,tool,['-j',file],cwd,timeout,signal);
 assert(execution.code===0,'DETECTOR_FAILED','Detector exited with code '+execution.code);
 let raw:unknown;try{raw=JSON.parse(execution.stdout);}catch{throw new WirefitError('DETECTOR_PROTOCOL_ERROR','Detector did not return JSON');}
 const raw_artifact=await service.store.putJson(raw),families:Detector['families']=[];
 if(raw&&typeof raw==='object'&&'detects' in raw&&Array.isArray(raw.detects)){
  for(const item of raw.detects.slice(0,64)){
   if(item&&typeof item==='object'&&Array.isArray(item.values))for(const value of item.values.slice(0,128)){
    if(value&&typeof value==='object'&&['protector','packer'].includes(value.type)&&typeof value.name==='string'){
     families.push({name:value.name.slice(0,256),version:typeof value.version==='string'?value.version.slice(0,128):''});if(families.length===16)break;
    }
   }
   if(families.length>=16)break;
  }
 }
 return {status:'completed',families,raw_artifact};
}
export async function persistBinaryResult(service:WirefitService,result:BinaryResult,request:unknown,signal:AbortSignal):Promise<JobExecutionResult>{
 const markCancelled=()=>{result.status='cancelled';result.error=errorRecord(new WirefitError('CANCELLED','Binary workflow cancelled; completed artifacts are retained'),'binary-workflow');};
 const publish=()=>service.store.putObject('runs',result.result_id,{result,request,model_ids:[],candidate_model_id:null,dataset_id:null,observations_artifact:null,comparison_artifact:null,test_inputs_artifact:null});
 if(signal.aborted&&result.status==='completed')markCancelled();
 await publish();
 if(signal.aborted&&result.status==='completed'){
  // A cancellation arriving while immutable publication was in flight gets its
  // own terminal receipt. The already-written historical receipt is preserved.
  result.supersedes_result_id=result.result_id;result.result_id=id('binary_cancelled');markCancelled();await publish();
 }
 return {result_id:result.result_id,status:result.status,...(result.error?{error:result.error}:{})};
}
async function collectDerivatives(service:WirefitService,result:BinaryResult,folder:string,relative:string,before:Set<string>){
 let found=0;
 for(const entry of await readdir(folder,{withFileTypes:true})){
  if(before.has(entry.name)||!/\.(exe|dll)$/i.test(entry.name))continue;
  assert(entry.isFile()&&!entry.isSymbolicLink(),'UNPACK_OUTPUT_ALIAS','Generated PE outputs must be regular files');
  assert(++found<=32,'RESOURCE_LIMIT','Unpacker generated more than 32 candidate PE files');
  const target=await service.store.resolveRelative(relative+'/'+entry.name);
  const output=await snapshot(target,MAX_OUTPUT,true);
  assert(output.sha256!==result.source.sha256,'UNPACK_OUTPUT_UNCHANGED','Generated output is identical to its protected source');
  let inspection:PeInspection;try{inspection=inspectPe(output.bytes);}catch(error){throw new WirefitError('UNPACK_OUTPUT_INVALID','Generated output is not an inspectable PE: '+coded(error).message);}
  result.outputs.push({relative_path:relative+'/'+entry.name,artifact:await service.store.putArtifact(output.bytes,'application/vnd.microsoft.portable-executable'),inspection_artifact:await service.store.putJson(inspection),quality:'analysis_dump',runnable_verified:false});
 }
}
function initial(source:BinarySource,operation:BinaryResult['operation']):BinaryResult{
 return {result_id:id(operation==='inspect_binary'?'binary_inspection':'binary_unpack'),operation,status:'completed',source,inspection_artifact:null,detector:null,outputs:[],validation:{source_unchanged:true,runnable_verified:false},logs:[],error:null,limitations:['PE metadata and a generated dump do not establish runnable output, devirtualized functions or behavioral equivalence.','External unpacking is a separately selected tool capability; Handwired is not an unpacker.']};
}
export async function submitBinaryInspection(service:WirefitService,input:BinaryInspectRequest):Promise<JobState>{
 const request=structuredClone(input);validateRequest(request,false);
 const selected=await snapshot(request.file),inspection=inspectPe(selected.bytes),source=await putSnapshot(service,selected),timeout=request.timeout_ms??120000;
 return service.jobs.submit('inspect_binary',{...request,source},async signal=>{
  const result=initial(source,'inspect_binary');
  try{
   result.inspection_artifact=await service.store.putJson(inspection);
   if(request.toolchain?.detector){
    const work=await stage(service,source,result.result_id);
    result.detector=await detect(service,result,request.toolchain.detector,work.input,work.folder,timeout,signal);
   }else result.detector={status:'not_configured',families:[]};
  }catch(error){result.status=signal.aborted?'cancelled':'failed';result.error=errorRecord(coded(error),'binary-inspection');result.detector??={status:'failed',families:[]};}
  result.validation.source_unchanged=await sameSource(source);
  if(!result.validation.source_unchanged){result.status='failed';result.error=errorRecord(new WirefitError('SOURCE_CHANGED','Original target changed after its snapshot'),'binary-inspection');}
  return persistBinaryResult(service,result,request,signal);
 },Math.min(86400000,timeout+5000));
}
export async function submitBinaryUnpack(service:WirefitService,input:BinaryUnpackRequest):Promise<JobState>{
 const request=structuredClone(input);validateRequest(request,true);
 const selected=await snapshot(request.file),inspection=inspectPe(selected.bytes),source=await putSnapshot(service,selected),timeout=request.timeout_ms??240000;
 return service.jobs.submit('unpack_binary',{...request,source},async signal=>{
  const result=initial(source,'unpack_binary');result.backend='unlicense';
  let work:Awaited<ReturnType<typeof stage>>|null=null,before=new Set<string>(),backendAttempted=false;
  try{
   result.inspection_artifact=await service.store.putJson(inspection);
   work=await stage(service,source,result.result_id);
   if(request.copy_dependencies!==false){
    const dependencies=await copyDependencies(service,source,work.relative);
    result.logs.push(await service.store.putJson({kind:'adjacent_dependency_snapshots',dependencies}));
   }
   result.detector=await detect(service,result,request.toolchain.detector,work.input,work.folder,Math.min(timeout,120000),signal);
   if(result.detector.families.length>0)assert(result.detector.families.some(f=>/themida|winlicense/i.test(f.name)),'UNPACK_BACKEND_MISMATCH','The configured unlicense backend does not match the detected protector');
   if(signal.aborted)throw new WirefitError('CANCELLED','Unpacking cancelled before backend execution');
   const tool=request.toolchain.unpackers!.unlicense!;
   before=new Set(await readdir(work.folder));
   backendAttempted=true;
   const execution=await recordBinaryProcess(service,result,tool,[work.input,'--timeout='+String(request.target_timeout_seconds??60)],work.folder,timeout,signal);
   assert(execution.code===0,'UNPACK_BACKEND_FAILED','Unpack backend exited with code '+execution.code);
  }catch(error){result.status=signal.aborted?'cancelled':'failed';result.error=errorRecord(coded(error),'binary-unpack');}
  finally{
   if(work&&backendAttempted){
    try{await collectDerivatives(service,result,work.folder,work.relative,before);}
    catch(error){result.status=signal.aborted?'cancelled':'failed';result.error??=errorRecord(coded(error),'binary-output');}
   }
   if(result.status==='completed'&&result.outputs.length===0){result.status='failed';result.error=errorRecord(new WirefitError('UNPACK_OUTPUT_MISSING','Backend returned without a new inspectable PE derivative'),'binary-output');}
   result.validation.source_unchanged=await sameSource(source);
   if(!result.validation.source_unchanged){result.status='failed';result.error=errorRecord(new WirefitError('SOURCE_CHANGED','Original target changed after its snapshot'),'binary-unpack');}
  }
  return persistBinaryResult(service,result,request,signal);
 },Math.min(86400000,timeout+(request.toolchain.detector?120000:0)+15000));
}

import {readFile,realpath,stat,access} from 'node:fs/promises';
import {constants} from 'node:fs';
import path from 'node:path';
import {assert,WirefitError,validateSchema,readJson,sha256,hashObject,errorRecord,id} from './shared.js';
import {validateDomain,validateInputs,domainContainsPoint} from './model.js';
import {fp32Number} from './values.js';
import {runProcess,type ProcessResult} from './process.js';
import type {Signature,Domain,Observation,ValueMap} from './types.js';

export interface OracleManifest {
 schema_version:1;oracle_id:string;kind:'process_jsonl';source_kind:'original_target'|'reference_fixture';
 argv:string[];cwd:string;signature:Signature;domain:Domain;target_files:{path:string;sha256:string;role:'target'|'wrapper'|'runtime_helper'}[];
 protocol_version:1;reset_strategy:'fresh_process'|'batch_resettable';request_timeout_ms:number;batch_timeout_ms:number;max_stdout_line_bytes:number;max_stderr_bytes:number;allowed_env_keys:string[];notes:string;
}
export interface OracleBinding {
 oracle_id:string;manifest:OracleManifest;manifest_path:string;executable:string;executable_sha256:string;resolved_cwd:string;
 path_bindings?:{requested_path:string;resolved_path:string}[];
 files:{path:string;sha256:string;role:string}[];environment:Record<string,string>;identity_sha256:string;registered_at:string;
 runtime:{platform:string;arch:string;executable_version:string|null};
}
export interface InputSample {sample_id:string;split:'train'|'validation'|'holdout';inputs:ValueMap}
export interface OracleCall {observation:Observation;actual_calls:number;execution:ProcessResult|null}
async function fileHash(file:string):Promise<string>{return sha256(await readFile(file));}
export async function resolveExecutable(command:string,cwd:string):Promise<string>{
 if(command.includes('/')||command.includes('\\')||path.isAbsolute(command)){
  const result=await realpath(path.resolve(cwd,command));
  assert(!/\.(cmd|bat)$/i.test(result),'ORACLE_EXECUTABLE_INVALID','Shell scripts are not executable Oracle runtimes');return result;
 }
 const suffixes=process.platform==='win32'?['',...(process.env.PATHEXT??'.EXE;.COM').split(';').filter(s=>!/cmd|bat/i.test(s))]:[''];
 for(const directory of (process.env.PATH??'').split(path.delimiter)){
  if(!directory)continue;
  for(const suffix of suffixes){
   const candidate=path.join(directory,command+suffix);
   try{await access(candidate,process.platform==='win32'?constants.F_OK:constants.X_OK);if((await stat(candidate)).isFile())return realpath(candidate);}catch{}
  }
 }
 throw new WirefitError('ORACLE_NOT_BUILT','Oracle executable not found: '+command);
}
function validateSignature(signature:Signature):void{
 for(const ports of [signature.inputs,signature.outputs]){
  assert(ports.length>0&&new Set(ports.map(p=>p.id)).size===ports.length,'SIGNATURE_INVALID','Oracle ports must have unique IDs');
 }
}
export async function bindOracle(manifestPath:string):Promise<OracleBinding>{
 const manifest=validateSchema<OracleManifest>('oracle',await readJson(manifestPath));
 validateSignature(manifest.signature);validateDomain(manifest.domain,manifest.signature.inputs);
 assert(manifest.reset_strategy==='fresh_process','UNSUPPORTED_RESET','batch_resettable requires independent reset evidence and is not enabled');
 const manifestFile=await realpath(path.resolve(manifestPath));
 const base=path.dirname(manifestFile);
 const cwd=await realpath(path.resolve(base,manifest.cwd));
 assert((await stat(cwd)).isDirectory(),'ORACLE_NOT_BUILT','Oracle cwd must be a directory');
 const executable=await resolveExecutable(manifest.argv[0]!,cwd);
 const files:OracleBinding['files']=[],path_bindings:NonNullable<OracleBinding['path_bindings']>=[];
 for(const file of manifest.target_files){
  const requested_path=path.resolve(base,file.path);
  const absolute=await realpath(requested_path).catch(error=>{throw new WirefitError('ORACLE_NOT_BUILT','Declared Oracle target/helper is missing: '+file.path,error);});
  assert(await fileHash(absolute)===file.sha256,'TARGET_CHANGED','Declared target hash mismatch: '+absolute);
  assert(!files.some(f=>f.path===absolute),'ORACLE_INVALID','Duplicate target file alias');
  path_bindings.push({requested_path,resolved_path:absolute});
  files.push({path:absolute,sha256:file.sha256,role:file.role});
 }
 for(const arg of manifest.argv.slice(1)){
  if(arg.startsWith('-'))continue;
  try{
   const candidate=await realpath(path.resolve(cwd,arg));
   if((await stat(candidate)).isFile()){assert(files.some(file=>file.path===candidate),'ORACLE_CLOSURE_INCOMPLETE','Oracle argv file is not declared in target_files: '+arg);path_bindings.push({requested_path:path.resolve(cwd,arg),resolved_path:candidate});}
  }catch(error){if(error instanceof WirefitError)throw error;}
 }
 const environment:Record<string,string>={};
 for(const key of manifest.allowed_env_keys)if(process.env[key]!==undefined)environment[key]=process.env[key]!;
 const executable_sha256=await fileHash(executable);
 const identity={manifest,executable,executable_sha256,resolved_cwd:cwd,files,path_bindings,environment,platform:process.platform,arch:process.arch};
 return {oracle_id:manifest.oracle_id,manifest,manifest_path:manifestFile,executable,executable_sha256,resolved_cwd:cwd,files,path_bindings,environment,identity_sha256:hashObject(identity),registered_at:new Date().toISOString(),runtime:{platform:process.platform,arch:process.arch,executable_version:executable===await realpath(process.execPath)?process.version:null}};
}
export async function checkOracleIdentity(binding:OracleBinding):Promise<void>{
 assert(binding.runtime.platform===process.platform&&binding.runtime.arch===process.arch,'ORACLE_BINDING_INVALID','Oracle runtime platform/architecture changed; rebind explicitly');
 const identity={manifest:binding.manifest,executable:binding.executable,executable_sha256:binding.executable_sha256,resolved_cwd:binding.resolved_cwd,files:binding.files,path_bindings:binding.path_bindings??[],environment:binding.environment,platform:binding.runtime.platform,arch:binding.runtime.arch};
 assert(hashObject(identity)===binding.identity_sha256,'ORACLE_BINDING_INVALID','Oracle binding was modified or needs explicit rebinding');
 try {
  assert(await realpath(binding.resolved_cwd)===binding.resolved_cwd,'TARGET_CHANGED','Oracle cwd resolution changed');
  for(const alias of binding.path_bindings??[])assert(await realpath(alias.requested_path)===alias.resolved_path,'TARGET_CHANGED','Oracle declared/argument path resolution changed: '+alias.requested_path);
  assert(await fileHash(binding.executable)===binding.executable_sha256,'TARGET_CHANGED','Oracle executable identity changed');
  for(const file of binding.files)assert(await fileHash(file.path)===file.sha256,'TARGET_CHANGED','Oracle target/helper identity changed: '+file.path);
 } catch(error) {if(error instanceof WirefitError)throw error;throw new WirefitError('TARGET_CHANGED','Oracle target/runtime path is unavailable or changed',error);}
}
export async function callOracle(binding:OracleBinding,sample:InputSample,options:{signal?:AbortSignal;timeout_ms?:number}={}):Promise<OracleCall>{
 // Freeze the call envelope before the first asynchronous identity/file operation.
 sample=structuredClone(sample);binding=structuredClone(binding);
 const callSignal=options.signal,callTimeout=options.timeout_ms;
 validateSchema('input-sample',sample);
 validateInputs(binding.manifest.signature.inputs,sample.inputs);
 const started=Date.now();
 const observation:Observation={schema_version:1,observation_id:id('observation'),sample_id:sample.sample_id,request_id:id('q'),record_kind:'observed',source_kind:binding.manifest.source_kind,source_id:binding.oracle_id,source_identity_sha256:binding.identity_sha256,split:sample.split,inputs:structuredClone(sample.inputs),observed_at:new Date(started).toISOString(),duration_ms:0,raw_artifacts:[],status:'ok',outputs:{},error:null};
 let calls=0;let execution:ProcessResult|null=null;
 try{
  for(const value of Object.values(sample.inputs))if(value.kind==='fp32')assert(Number.isFinite(fp32Number(value)),'NONFINITE_INPUT','Oracle profile accepts only finite FP32');
  assert(domainContainsPoint(binding.manifest.domain,sample.inputs),'OUT_OF_DOMAIN','Oracle input is outside declared domain');
  await checkOracleIdentity(binding);
  if(callSignal?.aborted)throw new WirefitError('CANCELLED','Oracle call cancelled');
  const request={protocol_version:1,request_id:observation.request_id,inputs:sample.inputs};
  validateSchema('oracle-request',request);
  calls=1;
  execution=await runProcess(binding.executable,binding.manifest.argv.slice(1),{cwd:binding.resolved_cwd,env:binding.environment,input:JSON.stringify(request)+'\n',timeout_ms:Math.min(callTimeout??binding.manifest.request_timeout_ms,binding.manifest.request_timeout_ms),max_stdout_bytes:binding.manifest.max_stdout_line_bytes+2,max_stderr_bytes:binding.manifest.max_stderr_bytes,signal:callSignal});
  await checkOracleIdentity(binding);
  assert(execution.code===0,'ORACLE_CRASH','Oracle process exited with code '+execution.code);
  const lines=execution.stdout.replace(/\r\n/g,'\n').split('\n');
  if(lines.at(-1)==='')lines.pop();
  assert(lines.length===1&&lines[0]!==''&&Buffer.byteLength(lines[0]!,'utf8')<=binding.manifest.max_stdout_line_bytes,'PROTOCOL_ERROR','Oracle must emit exactly one JSONL response');
  let response:unknown;try{response=JSON.parse(lines[0]!);}catch{throw new WirefitError('PROTOCOL_ERROR','Oracle emitted malformed JSON');}
  const typed=validateSchema<{protocol_version:1;request_id:string;status:string;outputs:ValueMap;error:Observation['error']}>('oracle-response',response);
  assert(typed.request_id===request.request_id,'PROTOCOL_ERROR','Oracle response request_id mismatch');
  if(typed.status!=='ok')throw new WirefitError('TARGET_ERROR',typed.error?.message??'Oracle returned a target error');
  validateInputs(binding.manifest.signature.outputs,typed.outputs);
  for(const value of Object.values(typed.outputs))if(value.kind==='fp32')assert(Number.isFinite(fp32Number(value)),'NONFINITE_OUTPUT','Oracle returned non-finite output');
  observation.outputs=typed.outputs;
 }catch(error){
  const code=error instanceof WirefitError?error.code:'ORACLE_ERROR';
  if(!execution&&error instanceof WirefitError&&error.details&&typeof error.details==='object'){
   const raw=error.details as Partial<ProcessResult>;
   if(typeof raw.stdout==='string'&&typeof raw.stderr==='string'&&typeof raw.duration_ms==='number'&&Number.isFinite(raw.duration_ms)&&typeof raw.pid==='number'&&Number.isInteger(raw.pid))execution={stdout:raw.stdout,stderr:raw.stderr,code:typeof raw.code==='number'?raw.code:null,signal:typeof raw.signal==='string'?raw.signal:null,duration_ms:raw.duration_ms,stderr_truncated:raw.stderr_truncated===true,pid:raw.pid};
  }
  if(code==='PROCESS_START_FAILED'||code==='CANCELLED'&&!execution)calls=0;
  observation.status=code==='TIMEOUT'?'timeout':code==='CANCELLED'?'cancelled':code==='OUT_OF_DOMAIN'?'out_of_domain':code.startsWith('NONFINITE')?'nonfinite':code==='ORACLE_CRASH'||code==='PROCESS_START_FAILED'?'crash':code==='TARGET_ERROR'?'target_error':'protocol_error';
  observation.outputs={};observation.error=errorRecord(error,'oracle');
 }finally{observation.duration_ms=Math.max(0,Date.now()-started);}
 validateSchema('observation',observation);
 return {observation,actual_calls:calls,execution};
}




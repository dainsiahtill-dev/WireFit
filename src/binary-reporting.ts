import {mkdir,lstat,realpath,readdir,writeFile,unlink} from 'node:fs/promises';
import path from 'node:path';
import {CaseStore} from './store.js';
import {assert,sha256} from './shared.js';
import type {ArtifactRef} from './types.js';
import type {ExportManifest} from './reporting.js';
import {runProcess} from './process.js';
import {binaryVerifyHelper} from './binary-verify.js';

type BinaryOperation='inspect_binary'|'unpack_binary'|'trace_binary';
type BinaryStatus='completed'|'failed'|'cancelled';
interface BinaryRecord {
 result_id:string;operation:BinaryOperation;status:BinaryStatus;
 source:{path:string;sha256:string;size_bytes:number;artifact:ArtifactRef};
 inspection_artifact:ArtifactRef|null;
 outputs:{relative_path:string;artifact:ArtifactRef;inspection_artifact:ArtifactRef;quality:'analysis_dump';runnable_verified:false}[];
 validation:{source_unchanged:boolean;runnable_verified:false};logs:ArtifactRef[];limitations:string[];
}
interface BinaryRun {result:BinaryRecord;request:unknown}
interface BinaryFile {relative_path:string;role:'source'|'derivative'|'dependency';sha256:string;size_bytes:number}
export interface BinaryExportManifest extends ExportManifest {
 report_kind:'binary';operation:BinaryOperation;original_status:BinaryStatus;binaries:BinaryFile[];
 verification:{scope:'file_identity_only';target_execution:'not_run';runnable_verified:false;behavioral_equivalence:'not_established'};
}
const MAX_BYTES=512*1024*1024,MAX_REFERENCES=8192,MAX_GRAPH_NODES=100000,MAX_JSON=16*1024*1024;
const digestPattern=/^[0-9a-f]{64}$/;
function record(value:unknown,label:string):Record<string,unknown>{
 assert(value!==null&&typeof value==='object'&&!Array.isArray(value),'EXPORT_BINARY_INVALID',label+' must be an object');
 return value as Record<string,unknown>;
}
function artifact(value:unknown):asserts value is ArtifactRef{
 const item=record(value,'Artifact reference');
 assert(Object.keys(item).sort().join(',')==='media_type,relative_path,sha256,size_bytes'&&typeof item.sha256==='string'&&digestPattern.test(item.sha256)&&item.relative_path==='artifacts/'+item.sha256&&typeof item.media_type==='string'&&item.media_type.length>0&&item.media_type.length<=256&&Number.isSafeInteger(item.size_bytes)&&Number(item.size_bytes)>=0&&Number(item.size_bytes)<=128*1024*1024,'EXPORT_REFERENCE_INVALID','Artifact reference is malformed or not content-addressed');
}
function safeFilename(value:unknown):asserts value is string{
 assert(typeof value==='string'&&value.length>0&&value.length<=255&&value!=='.'&&value!=='..'&&!/[<>:"/\\|?*\x00-\x1f]/.test(value)&&!/[. ]$/.test(value)&&!/^(con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\.|$)/i.test(value),'EXPORT_PATH_INVALID','Binary filename is not portable');
}
function parseRun(value:unknown,runId:string):BinaryRun{
 const run=record(value,'Binary run'),result=record(run.result,'Binary result');
 assert(result.result_id===runId&&['inspect_binary','unpack_binary','trace_binary'].includes(String(result.operation))&&['completed','failed','cancelled'].includes(String(result.status)),'EXPORT_BINARY_INVALID','Binary result identity or status is invalid');
 record(run.request,'Binary request');
 const source=record(result.source,'Binary source');artifact(source.artifact);
 assert(typeof source.path==='string'&&source.path.length>0&&source.path.length<=4096&&source.sha256===source.artifact.sha256&&source.size_bytes===source.artifact.size_bytes,'EXPORT_BINARY_INVALID','Binary source identity mismatch');
 if(result.inspection_artifact!==null)artifact(result.inspection_artifact);
 const validation=record(result.validation,'Binary validation');
 assert(typeof validation.source_unchanged==='boolean'&&validation.runnable_verified===false,'EXPORT_BINARY_INVALID','Binary export cannot promote a runnable verdict');
 assert(Array.isArray(result.outputs)&&result.outputs.length<=32&&Array.isArray(result.logs)&&result.logs.length<=256&&Array.isArray(result.limitations)&&result.limitations.length<=128&&result.limitations.every(item=>typeof item==='string'&&item.length<=4096),'EXPORT_BINARY_INVALID','Binary result arrays are invalid');
 for(const output of result.outputs){
  const item=record(output,'Binary derivative');
  assert(item.quality==='analysis_dump'&&item.runnable_verified===false,'EXPORT_BINARY_INVALID','Binary derivative has an unsupported quality claim');
  artifact(item.artifact);artifact(item.inspection_artifact);
  assert(typeof item.relative_path==='string','EXPORT_PATH_INVALID','Derivative path is missing');
  const parts=item.relative_path.split('/');
  assert(parts.length===3&&parts[0]==='.binary-work'&&/^[A-Za-z][A-Za-z0-9_.:-]{0,127}$/.test(parts[1]??''),'EXPORT_PATH_INVALID','Derivative does not identify a staged output');
  safeFilename(parts[2]);
 }
 for(const log of result.logs)artifact(log);
 return value as BinaryRun;
}
function references(value:unknown):ArtifactRef[]{
 const pending=[value],output:ArtifactRef[]=[];let examined=0;
 while(pending.length){
  assert(++examined<=MAX_GRAPH_NODES,'EXPORT_BUDGET','Binary reference graph exceeds node budget');
  const item=pending.pop();
  if(item===null||typeof item!=='object')continue;
  if(!Array.isArray(item)&&'relative_path' in item&&'media_type' in item){artifact(item);output.push(item);continue;}
  const children=Array.isArray(item)?item:Object.values(item);
  assert(pending.length+children.length+examined<=MAX_GRAPH_NODES,'EXPORT_BUDGET','Binary reference graph exceeds pending node budget');
  for(const child of children)pending.push(child);
 }
 return output;
}
async function ensureNoLinks(absolute:string):Promise<void>{
 const parsed=path.parse(absolute);let current=parsed.root;
 for(const part of absolute.slice(parsed.root.length).split(path.sep).filter(Boolean)){
  current=path.join(current,part);
  try{assert(!(await lstat(current)).isSymbolicLink(),'EXPORT_PATH_INVALID','Export path contains a symlink or junction');}
  catch(error){if((error as NodeJS.ErrnoException).code!=='ENOENT')throw error;}
 }
}
const structuredMedia=new Set(['application/json','application/x-ndjson','application/jsonl']);
function parseJson(bytes:Buffer,media:string):unknown{
 assert(bytes.length<=MAX_JSON,'EXPORT_BUDGET','Binary structured artifact exceeds 16 MiB');
 try{
  const text=new TextDecoder('utf-8',{fatal:true}).decode(bytes);
  if(media==='application/json')return JSON.parse(text);
  const rows:unknown[]=[];let start=0,lines=0;
  while(start<text.length){
   assert(++lines<=MAX_GRAPH_NODES,'EXPORT_BUDGET','Binary JSONL line count exceeds budget');
   const newline=text.indexOf('\n',start),end=newline<0?text.length:newline;
   const line=text.slice(start,end).trim();
   if(line.length>0)rows.push(JSON.parse(line));
   start=end+1;
  }
  return rows;
 }catch(error){
  if(error&&typeof error==='object'&&'code' in error&&error.code==='EXPORT_BUDGET')throw error;
  assert(false,'EXPORT_REFERENCE_INVALID','Binary structured artifact is not valid UTF-8 JSON/JSONL');
 }
}
// Export case snapshots; verification never runs a native target or upgrades its quality.
export async function exportBinaryReport(store:CaseStore,runId:string,outDir:string):Promise<BinaryExportManifest>{
 const run=parseRun(await store.getObject('runs',runId),runId),result=run.result;
 assert(typeof outDir==='string'&&outDir.length>0&&!outDir.includes('\0'),'EXPORT_PATH_INVALID','Export destination must be nonempty');
 const destination=path.resolve(outDir);await ensureNoLinks(destination);
 try{assert((await readdir(destination)).length===0,'EXPORT_DIRECTORY_NOT_EMPTY','Export destination must be absent or empty');}
 catch(error){if((error as NodeJS.ErrnoException).code!=='ENOENT')throw error;}
 await mkdir(destination,{recursive:true});await ensureNoLinks(destination);
 const resolved=await realpath(destination);
 assert((process.platform==='win32'?resolved.toLowerCase():resolved)===(process.platform==='win32'?destination.toLowerCase():destination),'EXPORT_PATH_INVALID','Export destination resolves through an alias');
 const reservation=path.join(destination,'.wirefit-export.lock');
 await writeFile(reservation,runId+'\n',{encoding:'utf8',flag:'wx'});
 const files:BinaryExportManifest['files']=[],paths=new Set<string>();let bytesWritten=0;
 const write=async(relative:string,value:string|Uint8Array,media:string)=>{
  assert(relative.split('/').every(part=>{safeFilename(part);return true;}),'EXPORT_PATH_INVALID','Export relative path is invalid');
  assert(!paths.has(relative.toLowerCase()),'EXPORT_BINARY_NAME_CONFLICT','Export paths collide case-insensitively');
  const target=path.resolve(destination,...relative.split('/'));
  assert(target.startsWith(destination+path.sep),'EXPORT_PATH_INVALID','Export file escapes destination');
  const bytes=typeof value==='string'?Buffer.from(value,'utf8'):Buffer.from(value);
  bytesWritten+=bytes.length;assert(bytesWritten<=MAX_BYTES&&files.length<10000,'EXPORT_BUDGET','Binary export exceeds byte or file budget');
  await ensureNoLinks(path.dirname(target));await mkdir(path.dirname(target),{recursive:true});await ensureNoLinks(path.dirname(target));
  await writeFile(target,bytes,{flag:'wx'});paths.add(relative.toLowerCase());
  files.push({relative_path:relative,sha256:sha256(bytes),size_bytes:bytes.length,media_type:media});
 };
 const json=async(relative:string,value:unknown)=>write(relative,JSON.stringify(value,null,2)+'\n','application/json');
 try{
  const queue=references(run),cache=new Map<string,{ref:ArtifactRef;bytes:Buffer;json:unknown;parsed:Set<string>}>();
  let totalRead=0;
  for(let index=0;index<queue.length;index++){
   assert(queue.length<=MAX_REFERENCES,'EXPORT_BUDGET','Binary artifact closure exceeds reference budget');
   const ref=queue[index]!,previous=cache.get(ref.relative_path);
   if(previous){
    assert(previous.ref.sha256===ref.sha256&&previous.ref.size_bytes===ref.size_bytes,'EXPORT_REFERENCE_CONFLICT','Artifact path has conflicting identities');
    if(structuredMedia.has(ref.media_type)&&!previous.parsed.has(ref.media_type)){
     const value=parseJson(previous.bytes,ref.media_type);previous.parsed.add(ref.media_type);
     if(ref.media_type==='application/json')previous.json=value;
     queue.push(...references(value));
    }
    continue;
   }
   const bytes=await store.readArtifact(ref);totalRead+=bytes.length;
   assert(totalRead<=MAX_BYTES,'EXPORT_BUDGET','Binary artifact closure exceeds 512 MiB');
   const value=structuredMedia.has(ref.media_type)?parseJson(bytes,ref.media_type):undefined;
   cache.set(ref.relative_path,{ref,bytes,json:value,parsed:new Set(value===undefined?[]:[ref.media_type])});
   await write(ref.relative_path,bytes,ref.media_type);
   if(value!==undefined)queue.push(...references(value));
  }
  const item=(ref:ArtifactRef)=>{
   const value=cache.get(ref.relative_path);assert(value,'EXPORT_REFERENCE_INVALID','Required binary artifact is absent from closure');return value;
  };
  const source=item(result.source.artifact);
  if(result.inspection_artifact!==null){
   const metadata=record(item(result.inspection_artifact).json,'Source PE metadata');
   assert(metadata.sha256===result.source.sha256&&metadata.size_bytes===result.source.size_bytes,'EXPORT_BINARY_INVALID','Source inspection identity mismatch');
  }
  const binaries:BinaryFile[]=[],binaryNames=new Set<string>();
  const binary=async(name:string,ref:ArtifactRef,role:BinaryFile['role'])=>{
   safeFilename(name);const relative=role==='source'?'source/'+name:'binaries/'+name;
   assert(!binaryNames.has(relative.toLowerCase()),'EXPORT_BINARY_NAME_CONFLICT','Binary/dependency names collide case-insensitively');
   binaryNames.add(relative.toLowerCase());await write(relative,item(ref).bytes,ref.media_type);
   binaries.push({relative_path:relative,role,sha256:ref.sha256,size_bytes:ref.size_bytes});
  };
  await binary('input.pe',source.ref,'source');
  for(const output of result.outputs){
   const metadata=record(item(output.inspection_artifact).json,'Output PE metadata');
   assert(metadata.sha256===output.artifact.sha256&&metadata.size_bytes===output.artifact.size_bytes,'EXPORT_BINARY_INVALID','Derivative inspection identity mismatch');
   await binary(output.relative_path.split('/').at(-1)!,output.artifact,'derivative');
  }
  for(const ref of result.logs){
   const log=item(ref).json;
   if(!log||typeof log!=='object'||Array.isArray(log)||!('kind' in log)||log.kind!=='adjacent_dependency_snapshots')continue;
   const list='dependencies' in log?log.dependencies:null;
   assert(Array.isArray(list)&&list.length<=64,'EXPORT_BINARY_INVALID','Dependency snapshot list is invalid');
   for(const dependencyRef of list){
    artifact(dependencyRef);const dependency=record(item(dependencyRef).json,'Dependency snapshot');
    safeFilename(dependency.file);assert(/\.dll$/i.test(dependency.file),'EXPORT_PATH_INVALID','Adjacent dependency is not a DLL filename');artifact(dependency.artifact);
    assert(dependency.sha256===dependency.artifact.sha256&&dependency.size_bytes===dependency.artifact.size_bytes,'EXPORT_BINARY_INVALID','Dependency identity mismatch');
    await binary(dependency.file,dependency.artifact,'dependency');
   }
  }
  await json('result.json',result);await json('request.json',run.request);await json('run.json',run);
  await write('verify.mjs',binaryVerifyHelper,'text/javascript');
  const report='# Wirefit binary report\n\nRun: '+runId+'\n\nOperation: '+result.operation+'. Recorded status: **'+result.status+'**.\n\nSource SHA256: `'+result.source.sha256+'`.\n\nGenerated PE files are analysis dumps. Runnable verification: **false**. Behavioral equivalence: **not established**.\n\nRun `node verify.mjs` with Node 24 to verify the manifest and included file identities. This helper never executes the PE, invokes Ghidra, reruns an unpacker or makes fresh original-target observations. Matching file identities do not change the recorded operation status.\n\nThe source snapshot is in source/input.pe, derivatives and adjacent dependency snapshots are in binaries/, and the complete referenced artifact closure is retained under artifacts/. A well-formed import table does not establish correct startup or TLS state.\n';
  await write('report.md',report,'text/markdown');
  const payload:Omit<BinaryExportManifest,'manifest_sha256'|'output_directory'>={
   schema_version:1,product:'Wirefit',report_kind:'binary',run_id:runId,operation:result.operation,original_status:result.status,
   files,models:[],candidate_module:null,binaries,
   external_dependencies:[{kind:'native_analysis_tools',identity:{recorded_in:'run.json and artifact logs'},reason:'New native analysis requires separately configured tools. This package only verifies recorded file snapshots.'}],
   fresh_target_replay:{status:'unavailable',reason:'No native target is executed by binary export verification.'},
   verification:{scope:'file_identity_only',target_execution:'not_run',runnable_verified:false,behavioral_equivalence:'not_established'}
  };
  const manifestBytes=Buffer.from(JSON.stringify(payload,null,2)+'\n','utf8'),manifest_sha256=sha256(manifestBytes);
  await writeFile(path.join(destination,'manifest.json'),manifestBytes,{flag:'wx'});
  await writeFile(path.join(destination,'manifest.sha256'),manifest_sha256+'  manifest.json\n',{encoding:'utf8',flag:'wx'});
  const execution=await runProcess(process.execPath,[path.join(destination,'verify.mjs')],{cwd:destination,timeout_ms:30000,max_stdout_bytes:1024*1024});
  assert(execution.code===0,'EXPORT_REPLAY_FAILED','Standalone binary file verification failed: '+execution.stderr);
  const verification=JSON.parse(execution.stdout) as {file_integrity?:{status?:string};target_execution?:string;runnable_verified?:boolean};
  assert(verification.file_integrity?.status==='matched'&&verification.target_execution==='not_run'&&verification.runnable_verified===false,'EXPORT_REPLAY_FAILED','Binary verifier returned an invalid scope or result');
  // The observed receipt is outside its manifest. The helper computes fresh checks.
  await writeFile(path.join(destination,'verification-receipt.json'),JSON.stringify({record_kind:'observed',kind:'fresh_process_binary_file_verification',executed_at:new Date().toISOString(),runtime:process.version,manifest_sha256,execution,verification},null,2)+'\n',{encoding:'utf8',flag:'wx'});
  return {...payload,manifest_sha256,output_directory:destination};
 }finally{await unlink(reservation).catch(()=>undefined);}
}

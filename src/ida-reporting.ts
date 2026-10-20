import path from 'node:path';
import {mkdir,readdir,lstat,realpath,writeFile,unlink} from 'node:fs/promises';
import type {CaseStore} from './store.js';
import type {ArtifactRef} from './types.js';
import type {ExportManifest} from './reporting.js';
import {assert,sha256} from './shared.js';
import {runProcess} from './process.js';

const MAX_BYTES=512*1024*1024;
async function noLinks(target:string):Promise<void>{
  const absolute=path.resolve(target),base=path.parse(absolute).root;let current=base;
  for(const part of absolute.slice(base.length).split(path.sep).filter(Boolean)){
    current=path.join(current,part);
    try{assert(!(await lstat(current)).isSymbolicLink(),'EXPORT_PATH_INVALID','Export paths must not contain links');}
    catch(error){if((error as NodeJS.ErrnoException).code!=='ENOENT')throw error;}
  }
}
function registered(value:unknown):asserts value is ArtifactRef{
  const ref=value as Partial<ArtifactRef>|null;
  assert(ref&&typeof ref.sha256==='string'&&/^[a-f0-9]{64}$/.test(ref.sha256)&&ref.relative_path==='artifacts/'+ref.sha256&&typeof ref.media_type==='string'&&Number.isSafeInteger(ref.size_bytes)&&Number(ref.size_bytes)>=0,'EXPORT_REFERENCE_INVALID','Invalid host-registered IDA artifact');
}
/** Standalone verifier checks file identities; it never invokes IDA or the input. */
const verifySource=String.raw`import {readFile,lstat,realpath} from 'node:fs/promises';
import {createHash} from 'node:crypto';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
const root=path.dirname(fileURLToPath(import.meta.url));
const fail=message=>{throw new Error('EXPORT_INTEGRITY_ERROR '+message);};
const hash=bytes=>createHash('sha256').update(bytes).digest('hex');
async function owned(relative,limit=128*1024*1024){
 if(typeof relative!=='string'||relative.length>4096||!relative.split('/').every(p=>/^[A-Za-z0-9_.-]+$/.test(p)&&p!=='.'&&p!=='..'))fail('invalid path');
 let current=root;for(const part of relative.split('/')){current=path.join(current,part);if((await lstat(current)).isSymbolicLink())fail('linked file');}
 const info=await lstat(current);if(!info.isFile()||info.size>limit)fail('file budget');
 const bytes=await readFile(current);if(bytes.length!==info.size)fail('file changed');return bytes;
}
if((await realpath(root)).toLowerCase()!==root.toLowerCase())fail('aliased package directory');
const bytes=await owned('manifest.json',4*1024*1024),detached=(new TextDecoder('utf-8',{fatal:true}).decode(await owned('manifest.sha256',256))).trim();
if(detached!==hash(bytes)+'  manifest.json')fail('manifest digest');
const manifest=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(bytes));
if(manifest.schema_version!==1||manifest.report_kind!=='ida'||manifest.operation!=='analyze_ida'||!Array.isArray(manifest.files)||manifest.files.length>1024)fail('manifest format');
if(manifest.verification?.target_execution!=='not_run'||manifest.verification?.runnable_verified!==false||manifest.verification?.whole_program_equivalence!==false)fail('scope');
let total=0;const names=new Set();
for(const entry of manifest.files){
 if(!entry||typeof entry.relative_path!=='string'||!/^[a-f0-9]{64}$/.test(entry.sha256)||!Number.isSafeInteger(entry.size_bytes)||entry.size_bytes<0)fail('file entry');
 const key=entry.relative_path.toLowerCase();if(names.has(key))fail('duplicate file');names.add(key);
 total+=entry.size_bytes;if(total>512*1024*1024)fail('total budget');
 const file=await owned(entry.relative_path);if(file.length!==entry.size_bytes||hash(file)!==entry.sha256)fail('changed '+entry.relative_path);
}
for(const required of ['run.json','result.json','source/input.bin','verify.mjs'])if(!names.has(required))fail('missing '+required);
const result=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(await owned('result.json')));
if(result.operation!=='analyze_ida'||result.result_id!==manifest.run_id||result.status!==manifest.original_status||!['completed','partial','failed','cancelled'].includes(result.status)||result.validation?.runnable_verified!==false||result.validation?.whole_program_equivalence!==false)fail('result identity');
if(hash(await owned('source/input.bin'))!==result.source?.sha256)fail('source snapshot identity');
process.stdout.write(JSON.stringify({file_integrity:{status:'matched',checked:manifest.files.length},original_operation:result.operation,original_status:result.status,target_execution:'not_run',runnable_verified:false,behavioral_equivalence:'not_established'})+'\n','utf8');
`;

export async function exportIdaReport(store:CaseStore,runId:string,outDir:string):Promise<ExportManifest>{
  const run=await store.getObject<{result:Record<string,any>;request:unknown}>('runs',runId),result=run.result;
  assert(result?.operation==='analyze_ida'&&result.result_id===runId&&['completed','partial','failed','cancelled'].includes(result.status)&&result.provider?.id==='ida','EXPORT_IDA_INVALID','Invalid IDA report identity');
  assert(result.validation?.runnable_verified===false&&result.validation?.whole_program_equivalence===false,'EXPORT_IDA_INVALID','Invalid IDA verification scope');
  assert(typeof outDir==='string'&&outDir.length>0&&!outDir.includes('\0'),'EXPORT_PATH_INVALID','Export destination is required');
  const destination=path.resolve(outDir);await noLinks(destination);
  try{assert((await readdir(destination)).length===0,'EXPORT_DIRECTORY_NOT_EMPTY','Export directory must be absent or empty');}
  catch(error){if((error as NodeJS.ErrnoException).code!=='ENOENT')throw error;}
  await mkdir(destination,{recursive:true});await noLinks(destination);
  const resolved=await realpath(destination);assert((process.platform==='win32'?resolved.toLowerCase():resolved)===(process.platform==='win32'?destination.toLowerCase():destination),'EXPORT_PATH_INVALID','Export directory is aliased');
  const lock=path.join(destination,'.wirefit-export.lock');await writeFile(lock,runId+'\n',{encoding:'utf8',flag:'wx'});
  const files:ExportManifest['files']=[];let total=0;
  async function write(relative:string,value:string|Uint8Array,media_type:string){
    assert(relative.split('/').every(part=>/^[A-Za-z0-9_.-]+$/.test(part)&&part!=='.'&&part!=='..'),'EXPORT_PATH_INVALID','Invalid generated filename');
    const target=path.join(destination,...relative.split('/'));await noLinks(target);await mkdir(path.dirname(target),{recursive:true});await noLinks(target);
    const bytes=typeof value==='string'?Buffer.from(value,'utf8'):Buffer.from(value);total+=bytes.length;
    assert(total<=MAX_BYTES&&files.length<1024,'EXPORT_BUDGET','IDA export exceeds budget');
    await writeFile(target,bytes,{flag:'wx'});files.push({relative_path:relative,sha256:sha256(bytes),size_bytes:bytes.length,media_type});
  }
  try{
    // Follow only envelopes registered by the host adapter, never references inside raw MCP JSON.
    registered(result.source?.artifact);assert(result.source.sha256===result.source.artifact.sha256&&result.source.size_bytes===result.source.artifact.size_bytes,'EXPORT_IDA_INVALID','Source identity differs from its artifact');
    assert(Array.isArray(result.artifacts)&&result.artifacts.length<=256,'EXPORT_BUDGET','IDA artifact list exceeds budget');
    const refs=new Map<string,ArtifactRef>();
    for(const candidate of [result.source.artifact,...result.artifacts]){
      registered(candidate);const previous=refs.get(candidate.sha256);
      assert(!previous||previous.size_bytes===candidate.size_bytes&&previous.media_type===candidate.media_type,'EXPORT_REFERENCE_CONFLICT','Conflicting artifact identity');refs.set(candidate.sha256,candidate);
    }
    const source=await store.readArtifact(result.source.artifact);await write('source/input.bin',source,'application/octet-stream');
    for(const ref of refs.values())await write('artifacts/'+ref.sha256,await store.readArtifact(ref),ref.media_type);
    await write('run.json',JSON.stringify(run,null,2)+'\n','application/json');
    await write('result.json',JSON.stringify(result,null,2)+'\n','application/json');
    const scope=typeof result.source_scope?.description==='string'?result.source_scope.description.slice(0,8192):'Only the supplied input snapshot is analyzed; no original-target fidelity is inferred.';
    await write('report.md','# WireFit IDA evidence report\n\nRun: '+runId+'\n\nRecorded status: **'+result.status+'**.\n\nSource SHA-256: `'+result.source.sha256+'`.\n\nInput scope: '+scope+'\n\nThis package retains read-only static analysis and original query failures. Target execution: **not_run**. Runnable verification: **false**. Behavioral equivalence: **not established**.\n\nRun `node verify.mjs` to verify included file identities. It does not invoke IDA, run the input or promote the saved result. Original MCP replies and their catalog remain in artifacts/.\n','text/markdown; charset=utf-8');
    await write('verify.mjs',verifySource,'text/javascript');
    const payload={schema_version:1 as const,product:'Wirefit' as const,run_id:runId,report_kind:'ida',operation:'analyze_ida',original_status:result.status,files,models:[],candidate_module:null,external_dependencies:[{kind:'ida',identity:result.provider,reason:'IDA analysis is retained as evidence; it is not rerun by this verifier.'}],fresh_target_replay:{status:'unavailable' as const,reason:'Static IDA export does not execute the original target.'},verification:{target_execution:'not_run',runnable_verified:false,whole_program_equivalence:false}};
    const manifest=JSON.stringify(payload,null,2)+'\n',digest=sha256(Buffer.from(manifest,'utf8'));
    await writeFile(path.join(destination,'manifest.json'),manifest,{encoding:'utf8',flag:'wx'});
    await writeFile(path.join(destination,'manifest.sha256'),digest+'  manifest.json\n',{encoding:'utf8',flag:'wx'});
    const verification=await runProcess(process.execPath,[path.join(destination,'verify.mjs')],{timeout_ms:15000,max_stdout_bytes:65536,max_stderr_bytes:65536});
    assert(verification.code===0,'EXPORT_INTEGRITY_ERROR','Standalone IDA verification failed: '+verification.stderr);
    return {...payload,manifest_sha256:digest,output_directory:destination};
  }finally{await unlink(lock);}
}

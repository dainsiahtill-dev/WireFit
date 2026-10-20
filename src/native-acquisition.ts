import {mkdir,readdir,writeFile} from 'node:fs/promises';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {performance} from 'node:perf_hooks';
import {isDeepStrictEqual} from 'node:util';
import type {Snapshot} from './binary-files.js';
import type {AcquisitionOptions} from './native-acquisition-options.js';
import {prepareAcquisition} from './native-acquisition-prepare.js';
import {assertAcquisitionPath,assertNewAcquisitionOutput,readAcquisitionFile,decodeAcquisitionJson,writeAcquisitionJson,writeAcquisitionText} from './native-acquisition-files.js';
import {validateOwnedCheckpoint,validateAcquisitionRequest,validateProcessIdentity,validateWindowCapture,validateMainCapture,validatePrivateCapture,isoFiletime,type OwnedCheckpoint,type MainCaptureExpected} from './native-acquisition-evidence.js';
import {runProcess,type ProcessResult} from './process.js';
import {CaseStore} from './store.js';
import type {JobState} from './jobs.js';
import {validateTraceProtocol,type TraceProtocol} from './native-trace-protocol.js';
import {WirefitError,assert,errorRecord,rootDir} from './shared.js';
import type {StructuredError} from './types.js';

type Row=Record<string,unknown>;
type Status='pending'|'not_requested'|'completed'|'partial'|'failed'|'dependency_failed';
interface FileIdentity {path:string;size_bytes:number;sha256:string;role?:string;frozen_copy?:string}
interface CommandRecord {requested:boolean;status:Status;command?:string;args?:string[];started_at?:string;finished_at?:string;execution?:Omit<ProcessResult,'stdout'|'stderr'>;result?:unknown;error?:StructuredError;logs?:{stdout:string;stderr:string}}
interface Owned extends OwnedCheckpoint {work:string;executable:string;job_id:string;creation_filetime:string;identity:unknown}
export interface AcquisitionPorts {run?:typeof runProcess;signal?:AbortSignal;onEvent?:(event:Record<string,unknown>)=>void}
export interface AcquisitionReceipt extends Row {
 schema_version:1;status:'partial_or_failed'|'cancelled'|'observations_collected';source:FileIdentity&{unchanged?:boolean};code:FileIdentity[];
 collectors:Record<string,CommandRecord>;cli_trace:CommandRecord;finalization_errors:StructuredError[];
 job?:JobState;trace?:Row;trace_raw?:TraceProtocol;owned?:Owned;
}
const record=(value:unknown):value is Row=>value!==null&&typeof value==='object'&&!Array.isArray(value);
const identify=(snapshot:Snapshot,role?:string):FileIdentity=>({path:snapshot.path,size_bytes:snapshot.size_bytes,sha256:snapshot.sha256,...(role===undefined?{}:{role})});
const utc=()=>new Date().toISOString();
const equalPath=(a:string,b:string)=>process.platform==='win32'?a.toLowerCase()===b.toLowerCase():a===b;
const identityProbe="import json,sys;from pathlib import Path;ns={'__name__':'identity_probe','__file__':sys.argv[1]};exec(compile(Path(sys.argv[1]).read_text(encoding='utf-8'),sys.argv[1],'exec'),ns)\nwith ns['WindowsMemoryReader'](int(sys.argv[2])) as reader:print(json.dumps(reader.identity()))";
function fatalIdentity(value:unknown):boolean{
 const pending:unknown[]=[value];let nodes=0;
 while(pending.length&&nodes++<100000){const next=pending.pop();if(Array.isArray(next)){pending.push(...next);continue;}if(!record(next))continue;
  if(typeof next.code==='string'&&/^(?:PROCESS_IDENTITY[^ ]*|SOURCE_IDENTITY[^ ]*|SOURCE_CHANGED|SUPPORT_IDENTITY_MISMATCH|CLOSED_HANDLE|HANDLE_CLOSED|PROCESS_EXITED|INPUT_CHANGED)$/.test(next.code))return true;
  for(const [key,item] of Object.entries(next))if(['error','additional_errors','start_error','end_error'].includes(key))pending.push(item);
 }
 return false;
}
function checkedJob(value:JobState):JobState{
 assert(value&&value.operation==='trace_binary'&&/^job_[a-f0-9]{32}$/.test(value.job_id),'ACQUISITION_OWNERSHIP_INVALID','New case contains an unexpected job');
 isoFiletime(value.created_at);if(value.started_at!==null)assert(isoFiletime(value.started_at)>=isoFiletime(value.created_at),'ACQUISITION_OWNERSHIP_INVALID','Job start predates creation');return value;
}
function pause(milliseconds:number,signal?:AbortSignal):Promise<void>{
 if(signal?.aborted)return Promise.reject(new WirefitError('CANCELLED','Acquisition cancelled'));
 return new Promise((resolve,reject)=>{const aborted=()=>{clearTimeout(timer);reject(new WirefitError('CANCELLED','Acquisition cancelled'));};const timer=setTimeout(()=>{signal?.removeEventListener('abort',aborted);resolve();},Math.max(1,milliseconds));signal?.addEventListener('abort',aborted,{once:true});});
}

/** Owns a new CLI lifecycle; observers never accept an external PID. */
export async function acquireNativeEvidence(input:AcquisitionOptions,ports:AcquisitionPorts={}):Promise<AcquisitionReceipt>{
 const prepared=await prepareAcquisition(input),{options,source,tool,plan,image_size}=prepared,run=ports.run??runProcess;
 if(ports.signal?.aborted)throw new WirefitError('CANCELLED','Acquisition cancelled before output creation');
 const cli=path.join(rootDir,'dist/src/cli.js'),bridge=path.join(rootDir,'dist/src/native-acquisition-cli.js');
 const ownFile=fileURLToPath(import.meta.url),extension=path.extname(ownFile),moduleDir=path.dirname(ownFile);
 const paths:Record<string,string>={cli,bridge,worker:path.join(rootDir,'tools/native-trace/worker.py'),agent:path.join(rootDir,'tools/native-trace/agent.js'),
  memory:path.join(rootDir,'tools/native-trace/memory-image.py'),private:path.join(rootDir,'tools/native-trace/private-regions.py'),windows:path.join(rootDir,'tools/native-trace/window-inventory.ps1'),orchestrator:ownFile};
 for(const name of ['files','options','prepare','evidence'])paths[name]=path.join(moduleDir,'native-acquisition-'+name+extension);
 paths.process=path.join(moduleDir,'process'+extension);
 const code:FileIdentity[]=[],copies=new Map<string,Snapshot>();
 for(const [role,file] of Object.entries(paths)){const data=await readAcquisitionFile(file,1048576,true);code.push(identify(data,role));copies.set(role,data);}
 for(const [role,file] of [['node',process.execPath],['python',options.python],...(options.powershell?[['powershell',options.powershell]]:[])] as [string,string][]){code.push(identify(await readAcquisitionFile(file,134217728),role));}
 await assertNewAcquisitionOutput(options.out);await mkdir(options.out);const out=await assertAcquisitionPath(options.out),casePath=path.join(out,'case'),inputs=path.join(out,'inputs');
 const receipt:AcquisitionReceipt={schema_version:1,kind:'owned_public_cli_native_acquisition',status:'partial_or_failed',started_at:utc(),out,case:casePath,
  source:identify(source),plan,tool,options,code,code_unchanged:false,collectors:{main:{requested:true,status:'pending'},private:{requested:options.callers.length>0,status:options.callers.length?'pending':'not_requested'},windows:{requested:options.powershell!==undefined,status:options.powershell?'pending':'not_requested'}},
  cli_trace:{requested:true,status:'pending'},finalization_errors:[],runnable_verified:false,whole_program_equivalence:false,
  limitations:['Separate observer HANDLEs and sampling phases are non-atomic.','A trace, byte capture, code hash or file verification does not establish executed paths, an OEP, ABI, complete dependency closure or runnable reconstruction.','Observer executables and trace runtime dependencies are separately installed; their recorded hashes do not attest a publisher or all loaded code.']};
 const controller=new AbortController(),cancel=()=>controller.abort();ports.signal?.addEventListener('abort',cancel,{once:true});
 let reader:CaseStore|undefined,traceTask:Promise<void>|undefined,traceLive=false,traceExecution:ProcessResult|undefined,traceFailure:unknown,owned:Owned|undefined,job:JobState|undefined;
 let mainSummary:{complete:boolean}|undefined,privateComplete=false,windowComplete=false;
 const roleFiles:Record<string,string>={};
 const emit=(event:Row)=>ports.onEvent?.(event);
 const finalError=(error:unknown,scope:string)=>receipt.finalization_errors.push(errorRecord(error,scope));
 async function persistExecution(role:string,item:CommandRecord,execution:ProcessResult):Promise<void>{
  const {stdout,stderr,...metadata}=execution;item.execution=metadata;item.logs={stdout:role+'-stdout.txt',stderr:role+'-stderr.txt'};
  await writeAcquisitionText(path.join(out,item.logs.stdout),stdout);await writeAcquisitionText(path.join(out,item.logs.stderr),stderr);
  try{item.result=decodeAcquisitionJson(Buffer.from(stdout,'utf8'));}catch(error){item.error=errorRecord(error,'acquisition-'+role);item.status='failed';}
 }
 async function command(role:string,executable:string,args:string[],timeout:number):Promise<CommandRecord>{
  const item:CommandRecord={requested:true,status:'pending',command:executable,args,started_at:utc()};receipt.collectors[role]=item;
  try{const execution=await run(executable,args,{cwd:rootDir,timeout_ms:timeout,max_stdout_bytes:16777216,max_stderr_bytes:1048576,signal:controller.signal});
   await persistExecution(role,item,execution);const status=record(item.result)?item.result.status:undefined;
   item.status=item.error||execution.code!==0?'failed':status==='partial'?'partial':status===undefined||status==='completed'?'completed':'failed';
  }catch(error){item.error=errorRecord(error,'acquisition-'+role);item.status='failed';
   if(error instanceof WirefitError&&record(error.details)&&typeof error.details.stdout==='string'&&typeof error.details.stderr==='string'){
    try{await persistExecution(role,item,error.details as unknown as ProcessResult);}catch(logError){finalError(logError,'acquisition-'+role+'-logs');}
   }
  }finally{item.finished_at=utc();}
  try{
   if(fatalIdentity(item.result))throw new WirefitError('ACQUISITION_OWNERSHIP_INVALID','Observer reported a process, source or tool identity failure');
   assertObserverBindings(role,item.result);
  }catch(error){item.status='failed';item.error=errorRecord(error,'acquisition-'+role+'-ownership');throw error;}
  return item;
 }
 async function jobNow(requireRunning=false):Promise<JobState|undefined>{
  assert(reader,'ACQUISITION_OWNERSHIP_INVALID','Case reader is unavailable');const jobs=await reader.listObjects<JobState>('jobs');
  assert(jobs.length<=1,'ACQUISITION_OWNERSHIP_INVALID','New case contains concurrent jobs');const current=jobs[0]?.value;if(current)checkedJob(current);
  if(requireRunning)assert(traceLive&&current?.status==='running'&&!controller.signal.aborted,'ACQUISITION_NOT_LIVE','Owned trace is no longer live');return current;
 }
 async function stableInputs():Promise<void>{
  for(const role of ['memory','private','windows','worker','agent']){const expected=copies.get(role)!;const file=roleFiles[role]??expected.path;assert((await readAcquisitionFile(file,1048576,true)).sha256===expected.sha256,'ACQUISITION_CODE_CHANGED','Frozen observer or trace source changed');}
  assert((await readAcquisitionFile(roleFiles.config!,65536,true)).sha256===prepared.config_file.sha256&&(await readAcquisitionFile(roleFiles.plan!,65536,true)).sha256===prepared.plan_file.sha256,'ACQUISITION_CODE_CHANGED','Frozen trace inputs changed');
 }
 async function probe(role:string,expectedToken?:string):Promise<string>{
  assert(owned&&job?.started_at,'ACQUISITION_OWNERSHIP_INVALID','Owned identity is absent');await jobNow(true);await stableInputs();
  const value=await command(role,options.python,['-X','utf8','-I','-S','-c',identityProbe,roleFiles.memory!,String(owned.pid)],5000);
  assert(value.status==='completed','ACQUISITION_OWNERSHIP_INVALID','Owned process identity probe failed');
  const token=validateProcessIdentity(value.result,{pid:owned.pid,executable:owned.executable,...(expectedToken===undefined?{}:{creation_filetime:expectedToken}),started_at:job.started_at,observed_before:new Date(Date.now()+1).toISOString()});
  if(expectedToken===undefined)owned.identity=value.result;return token;
 }
 function context(finished_at:string):MainCaptureExpected{
  assert(owned&&job?.started_at,'ACQUISITION_OWNERSHIP_INVALID','Owned process context is absent');return {pid:owned.pid,executable:owned.executable,creation_filetime:owned.creation_filetime,started_at:job.started_at,finished_at,source_sha256:source.sha256,image_base:owned.image_base,image_size};
 }
 /** Ownership contradictions stop the lifecycle; unrelated metadata defects only fail that observer. */
 function assertObserverBindings(role:string,value:unknown):void {
  if(!owned||!record(value)||!['main','private','windows'].includes(role))return;
  const match=(row:Row,key:string,expected:unknown,isPath=false)=>{
   if(!Object.hasOwn(row,key))return;
   const actual=row[key];
   assert(isPath?typeof actual==='string'&&equalPath(path.normalize(actual),path.normalize(String(expected))):actual===expected,
    'ACQUISITION_OWNERSHIP_INVALID',`Observer ${role} ${key} differs from the owned process or frozen input`);
  };
  const processFields=(row:Row)=>{
   match(row,'pid',owned!.pid);match(row,'executable',owned!.executable,true);match(row,'creation_filetime',owned!.creation_filetime);
   if(Object.hasOwn(row,'alive'))assert(row.alive===true,'ACQUISITION_OWNERSHIP_INVALID','Observer reports that the owned process is no longer live');
   if(Object.hasOwn(row,'exit_filetime'))match(row,'exit_filetime','0');
   if(Object.hasOwn(row,'exit_code'))match(row,'exit_code',259);
  };
  match(value,'pid',owned.pid);
  const identity=record(value.identity)?value.identity:undefined;
  if(identity){
   match(identity,'pid',owned.pid);match(identity,'expected_executable',owned.executable,true);match(identity,'expected_creation_filetime',owned.creation_filetime);
   for(const endpoint of [identity.start,identity.end])if(record(endpoint))processFields(endpoint);
  }
  if(role==='windows'){
   match(value,'executable',owned.executable,true);
   if(Object.hasOwn(value,'process_started_at')){
    let token:bigint;try{token=isoFiletime(value.process_started_at);}catch(error){throw new WirefitError('ACQUISITION_OWNERSHIP_INVALID','Window observer reports an invalid creation identity',errorRecord(error,'window-identity'));}
    assert(token===BigInt(owned.creation_filetime),'ACQUISITION_OWNERSHIP_INVALID','Window observer creation identity differs');
   }
  }
  const inputs=record(value.inputs)?value.inputs:undefined;
  const observedSource=role==='private'?inputs?.source:value.source;
  if(record(observedSource)){match(observedSource,'path',owned.executable,true);match(observedSource,'sha256',source.sha256);match(observedSource,'size_bytes',source.size_bytes);}
  const observedTool=record(value.tool)?value.tool:undefined;
  const toolMatch=(row:unknown,name:string)=>{if(record(row)){match(row,'sha256',copies.get(name)!.sha256);match(row,'size_bytes',copies.get(name)!.size_bytes);}};
  if(role==='main')toolMatch(observedTool,'memory');
  if(role==='private'&&observedTool){toolMatch(observedTool.helper,'private');toolMatch(observedTool.memory_image_support,'memory');}
 }
 async function validateObserver(role:'main'|'private'|'windows',validate:()=>Promise<void>):Promise<void>{
  const item=receipt.collectors[role]!;assertObserverBindings(role,item.result);
  try{await validate();}catch(error){
   item.status='failed';item.error=errorRecord(error,'acquisition-'+role+'-validation');
   if(role==='main')mainSummary=undefined;
   if(role==='private')privateComplete=false;
   if(role==='windows')windowComplete=false;
   if(error instanceof WirefitError&&['ACQUISITION_OWNERSHIP_INVALID','ACQUISITION_CODE_CHANGED','ACQUISITION_PATH_INVALID'].includes(error.code))throw error;
  }
 }
 async function validateMain(finished_at:string):Promise<void>{
  const item=receipt.collectors.main!;if(!record(item.result)||!['completed','partial'].includes(String(item.result.status)))return;
  const image=await readAcquisitionFile(path.join(out,'main.bin'),67108864,true),document=await readAcquisitionFile(path.join(out,'main.json'),16777216,true);
  assert(isDeepStrictEqual(decodeAcquisitionJson(document.bytes),item.result),'ACQUISITION_EVIDENCE_INVALID','Main stdout differs from its stored receipt');
  const identity=record(item.result.identity)?item.result.identity:undefined;
  if(identity?.start)validateProcessIdentity(identity.start,{pid:owned!.pid,executable:owned!.executable,creation_filetime:owned!.creation_filetime,started_at:job!.started_at!,observed_before:finished_at});
  mainSummary=validateMainCapture(item.result,image.bytes,context(finished_at));
  const toolIdentity=record(item.result.tool)?item.result.tool:undefined;assert(toolIdentity?.sha256===copies.get('memory')!.sha256,'ACQUISITION_CODE_CHANGED','Main observer source hash differs');
 }
 async function validatePrivate(finished_at:string):Promise<void>{
  const item=receipt.collectors.private!;if(!record(item.result)||!['completed','partial'].includes(String(item.result.status)))return;
  const document=await readAcquisitionFile(path.join(out,'private.json'),16777216,true),mainDocument=await readAcquisitionFile(path.join(out,'main.json'),16777216,true),main=await readAcquisitionFile(path.join(out,'main.bin'),67108864,true);
  assert(isDeepStrictEqual(decodeAcquisitionJson(document.bytes),item.result),'ACQUISITION_EVIDENCE_INVALID','Private stdout differs from its stored receipt');
  assert(Array.isArray(item.result.captures)&&item.result.captures.length<=128,'ACQUISITION_EVIDENCE_INVALID','Private capture list is invalid');const files=new Map<string,Buffer>();let total=0;
  for(const raw of item.result.captures){assert(record(raw)&&typeof raw.file==='string'&&/^private-[0-9]{3}\.bin$/.test(raw.file)&&!files.has(raw.file),'ACQUISITION_EVIDENCE_INVALID','Private capture filename is invalid');const data=await readAcquisitionFile(path.join(out,raw.file),16777216,true);total+=data.size_bytes;assert(total<=16777216,'RESOURCE_LIMIT','Private observations exceed sixteen MiB');files.set(raw.file,data.bytes);}
  privateComplete=validatePrivateCapture(item.result,files,main.bytes,{...context(finished_at),callers:options.callers,main_receipt_sha256:mainDocument.sha256,main_image_sha256:main.sha256,helper_sha256:copies.get('private')!.sha256,support_sha256:copies.get('memory')!.sha256}).complete;
 }
 try{
  await mkdir(inputs);await mkdir(path.join(inputs,'code'));
  for(const [role,data] of copies){const helper=['memory','private','windows'].includes(role);const destination=path.join(inputs,helper?path.basename(data.path):'code/'+role+path.extname(data.path));await writeFile(destination,data.bytes,{flag:'wx'});roleFiles[role]=destination;const id=code.find(row=>row.role===role)!;id.frozen_copy=destination;}
  roleFiles.config=path.join(inputs,'trace-config.json');roleFiles.plan=path.join(inputs,'trace-plan.json');await writeFile(roleFiles.config,prepared.config_file.bytes,{flag:'wx'});await writeFile(roleFiles.plan,prepared.plan_file.bytes,{flag:'wx'});
  receipt.input_files=[{...identify(prepared.config_file),frozen_copy:roleFiles.config},{...identify(prepared.plan_file),frozen_copy:roleFiles.plan}];
  await writeAcquisitionJson(path.join(out,'request.json'),receipt);
  const created=await command('case-create',process.execPath,[cli,'case','create','--dir',casePath],15000);assert(created.status==='completed','ACQUISITION_CASE_FAILED','Public case-create command failed');
  reader=await CaseStore.open(casePath,false);const traceArgs=[bridge,'binary','trace','--case',casePath,'--file',source.path,'--config',roleFiles.config,'--plan',roleFiles.plan];
  receipt.cli_trace={requested:true,status:'pending',command:process.execPath,args:traceArgs,started_at:utc()};const originMono=performance.now(),originWall=Date.now();traceLive=true;
  traceTask=run(process.execPath,traceArgs,{cwd:rootDir,timeout_ms:plan.duration_ms+70000,max_stdout_bytes:16777216,max_stderr_bytes:1048576,signal:controller.signal,cancel_ipc:{message:{type:'wirefit_cancel'},grace_ms:10000}})
   .then(value=>{traceExecution=value;},error=>{traceFailure=error;}).finally(()=>{traceLive=false;});
  const readiness=performance.now()+20000;let ready:OwnedCheckpoint|undefined,work:string|undefined;
  while(performance.now()<readiness){
   assert(traceLive&&!controller.signal.aborted,'ACQUISITION_NOT_LIVE','Owned CLI closed before readiness');job=await jobNow();
   if(job){assert(['queued','running'].includes(job.status),'ACQUISITION_NOT_LIVE','Job ended before readiness');assert(job.request_artifact,'ACQUISITION_OWNERSHIP_INVALID','Job request artifact is missing');validateAcquisitionRequest(decodeAcquisitionJson(await reader.readArtifact(job.request_artifact)),{file:source.path,tool,plan,source_sha256:source.sha256,source_size_bytes:source.size_bytes});}
   try{
    const directory=await reader.resolveRelative('.binary-work');const entries=await readdir(directory,{withFileTypes:true});assert(entries.length<=1&&entries.every(row=>row.isDirectory()&&!row.isSymbolicLink()),'ACQUISITION_OWNERSHIP_INVALID','Unexpected staging entries');
    if(entries.length===1){assert(/^binary_trace_[a-f0-9]{32}$/.test(entries[0]!.name),'ACQUISITION_OWNERSHIP_INVALID','Unexpected staged result ID');work=await assertAcquisitionPath(path.join(directory,entries[0]!.name));
     const checkpoint=decodeAcquisitionJson((await readAcquisitionFile(path.join(work,'trace-checkpoint.json'),4194304,true)).bytes);validateTraceProtocol(checkpoint,plan,32);
     if(checkpoint.events.some(event=>event.type==='agent_ready')&&job?.started_at){ready=validateOwnedCheckpoint(checkpoint,plan,{image_size});break;}
    }
   }catch(error){if((error as NodeJS.ErrnoException).code!=='ENOENT'&&(error as WirefitError).code!=='ACQUISITION_FILE_CHANGED')throw error;}
   await pause(100,controller.signal);
  }
  assert(ready&&work&&job?.started_at,'ACQUISITION_READINESS_TIMEOUT','No validated live owned checkpoint became available');
  const executable=path.join(work,path.basename(source.path));assert((await readAcquisitionFile(executable,67108864,true)).sha256===source.sha256,'ACQUISITION_OWNERSHIP_INVALID','Staged source differs from the fixed input');
  for(const role of ['worker','agent'] as const){const got=ready.checkpoint.identities[role];assert(got?.sha256===copies.get(role)!.sha256&&got.size_bytes===copies.get(role)!.size_bytes,'ACQUISITION_CODE_CHANGED','Worker or agent differs from this invocation');}
  owned={...ready,work,executable,job_id:job.job_id,creation_filetime:'',identity:null};receipt.owned=owned;
  owned.creation_filetime=await probe('identity');await writeAcquisitionJson(path.join(out,'owned-ready.json'),{owned,job});emit({event:'owned_cli_ready',out,job_id:job.job_id,pid:owned.pid});
  const scheduled=Date.parse(job.started_at)+options.capture_at_ms,deadline=originMono+(scheduled-originWall),end=deadline+plan.duration_ms-options.capture_at_ms;
  while(performance.now()<deadline){await jobNow(true);await pause(Math.min(100,deadline-performance.now()),controller.signal);}
  const late=Math.max(0,performance.now()-deadline);assert(late<=5000&&performance.now()<end,'ACQUISITION_CAPTURE_WINDOW_MISSED','Readiness missed the bounded capture window');
  receipt.timing={anchor:'job.started_at',requested_capture_at_ms:options.capture_at_ms,scheduled_utc:new Date(scheduled).toISOString(),actual_started_at:utc(),late_by_ms:late,monotonic_elapsed_from_cli_start_ms:performance.now()-originMono};
  await jobNow(true);await stableInputs();const main=await command('main',options.python,['-X','utf8','-I','-S',roleFiles.memory!,'--pid',String(owned.pid),'--expected-exe',executable,'--expected-start-filetime',owned.creation_filetime,'--base',owned.image_base,'--size',String(image_size),'--out',path.join(out,'main'),'--timeout-ms','10000'],14000);
  if(['completed','partial'].includes(main.status))await validateObserver('main',()=>validateMain(new Date(Date.now()+1).toISOString()));
  if(options.callers.length){if(mainSummary){await jobNow(true);await stableInputs();const item=await command('private',options.python,['-X','utf8','-I','-S',roleFiles.private!,'--receipt',path.join(out,'main.json'),'--image',path.join(out,'main.bin'),...options.callers.flatMap(value=>['--caller-rva',value]),'--out',path.join(out,'private'),'--timeout-ms','10000'],14000);if(['completed','partial'].includes(item.status))await validateObserver('private',()=>validatePrivate(new Date(Date.now()+1).toISOString()));}
   else receipt.collectors.private={requested:true,status:'dependency_failed',error:errorRecord(new WirefitError('ACQUISITION_DEPENDENCY_FAILED','Private capture requires a validated main image'),'acquisition-private')};}
  if(options.powershell){await probe('identity-windows',owned.creation_filetime);await jobNow(true);const item=await command('windows',options.powershell,['-NoProfile','-NonInteractive','-File',roleFiles.windows!,'-TargetPid',String(owned.pid),'-ExpectedExecutable',executable,'-OutputFile',path.join(out,'windows.json')],10000);
   if(item.status==='completed')await validateObserver('windows',async()=>{validateWindowCapture(item.result,context(new Date(Date.now()+1).toISOString()));const document=await readAcquisitionFile(path.join(out,'windows.json'),16777216,true);assert(isDeepStrictEqual(decodeAcquisitionJson(document.bytes),item.result),'ACQUISITION_EVIDENCE_INVALID','Window stdout differs from its stored receipt');windowComplete=true;});}
  await traceTask;
 }catch(error){receipt.error=errorRecord(error,'acquisition');controller.abort();}
 finally{
  if(traceTask)await traceTask;ports.signal?.removeEventListener('abort',cancel);
  try{const execution=traceExecution??(traceFailure instanceof WirefitError&&record(traceFailure.details)?traceFailure.details as unknown as ProcessResult:undefined);
   if(execution){await persistExecution('cli-trace',receipt.cli_trace,execution);receipt.cli_trace.status=execution.code===0&&!traceFailure&&!receipt.cli_trace.error?'completed':'failed';}
   if(traceFailure)receipt.cli_trace.error=errorRecord(traceFailure,'acquisition-cli');receipt.cli_trace.finished_at=utc();
  }catch(error){finalError(error,'acquisition-cli-logs');}
  try{if(reader){const jobs=await reader.listObjects<JobState>('jobs');assert(jobs.length===1,'ACQUISITION_OWNERSHIP_INVALID','Expected one owned trace job');receipt.job=checkedJob(jobs[0]!.value);job=receipt.job;
    if(job.result_id){assert(!owned||job.result_id===path.basename(owned.work),'ACQUISITION_OWNERSHIP_INVALID','Terminal result differs from the owned stage');const stored=await reader.getObject<{request:unknown;result:Row}>('runs',job.result_id);receipt.trace=stored.result;
     assert(record(stored.request),'ACQUISITION_EVIDENCE_INVALID','Stored run request is invalid');validateAcquisitionRequest({...stored.request,source:stored.result.source},{file:source.path,tool,plan,source_sha256:source.sha256,source_size_bytes:source.size_bytes});
     assert(record(stored.result.trace_artifact),'ACQUISITION_EVIDENCE_INVALID','Raw trace artifact is missing');const raw=decodeAcquisitionJson(await reader.readArtifact(stored.result.trace_artifact as never));validateTraceProtocol(raw,plan,32);receipt.trace_raw=raw;
     for(const role of ['worker','agent'] as const){assert(raw.identities[role]?.sha256===copies.get(role)!.sha256,'ACQUISITION_CODE_CHANGED','Final worker or agent identity changed');}
     if(owned)assert(raw.pid===owned.pid,'ACQUISITION_OWNERSHIP_INVALID','Terminal target PID differs');
    }
   }}catch(error){finalError(error,'acquisition-trace-evidence');}
  if(reader)try{await reader.close();}catch(error){finalError(error,'acquisition-reader-close');}
  try{receipt.source.unchanged=(await readAcquisitionFile(source.path)).sha256===source.sha256;}catch(error){receipt.source.unchanged=false;finalError(error,'acquisition-source');}
  receipt.code_unchanged=true;
  for(const row of code)try{if((await readAcquisitionFile(row.path,row.role==='node'||row.role==='python'||row.role==='powershell'?134217728:1048576)).sha256!==row.sha256||row.frozen_copy&&(await readAcquisitionFile(row.frozen_copy,1048576,true)).sha256!==row.sha256)receipt.code_unchanged=false;}catch(error){receipt.code_unchanged=false;finalError(error,'acquisition-code');}
  try{await stableInputs();}catch(error){finalError(error,'acquisition-frozen-inputs');}
  if(job?.finished_at&&owned){try{await validateMain(job.finished_at);if(options.callers.length)await validatePrivate(job.finished_at);if(options.powershell&&receipt.collectors.windows?.status==='completed')validateWindowCapture(receipt.collectors.windows.result,context(job.finished_at));}catch(error){finalError(error,'acquisition-terminal-observers');}}
  const raw=receipt.trace_raw,cleanup=raw?.cleanup as (TraceProtocol['cleanup']&{errors?:unknown})|undefined;
  const cleaned=cleanup&&['owned_pid_terminated','session_detached','windows_job_assigned','windows_job_closed'].every(key=>cleanup[key as keyof typeof cleanup]===true)&&Array.isArray(cleanup.errors)&&cleanup.errors.length===0;
  const snapshots=raw?.snapshots,fullSnapshots=snapshots?.length===plan.ranges.length*2&&snapshots.every(row=>row.error===undefined);
  const requested=[receipt.collectors.main!,...(options.callers.length?[receipt.collectors.private!]:[]),...(options.powershell?[receipt.collectors.windows!]:[])];
  receipt.status=ports.signal?.aborted?'cancelled':!receipt.error&&!receipt.cli_trace.error&&receipt.cli_trace.status==='completed'&&job?.status==='completed'&&receipt.trace?.status==='completed'&&record(receipt.trace.validation)&&receipt.trace.validation.source_unchanged===true&&raw?.status==='completed'&&cleaned&&fullSnapshots&&receipt.source.unchanged&&receipt.code_unchanged&&mainSummary?.complete&&(!options.callers.length||privateComplete)&&(!options.powershell||windowComplete)&&requested.every(item=>item.status==='completed'&&!item.error)&&receipt.finalization_errors.length===0?'observations_collected':'partial_or_failed';
  receipt.finished_at=utc();await writeAcquisitionJson(path.join(out,'receipt.json'),receipt);emit({event:'finished',out,status:receipt.status,job:job?.status,source_unchanged:receipt.source.unchanged});
 }
 return receipt;
}

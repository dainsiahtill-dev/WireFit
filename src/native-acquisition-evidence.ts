/** Pure validation of owned-process evidence; no filesystem or process access. */
import path from 'node:path';
import {WirefitError,hashObject,sha256} from './shared.js';
import {validateNativeTraceRequest,type NativeTracePlan} from './native-trace.js';
import {validateTraceProtocol,type TraceProtocol} from './native-trace-protocol.js';
import type {BinaryCommand} from './binary-service.js';

const CODE='ACQUISITION_EVIDENCE_INVALID',MAX_IMAGE=64*1024*1024,UINT64=1n<<64n;
const DIGEST=/^[a-f0-9]{64}$/,COUNTING='union_of_observed_prefix_bytes_per_disjoint_rva_extent';
type Row=Record<string,unknown>;
export interface OwnedCheckpointExpected {image_size:number}
export interface OwnedCheckpoint {pid:number;image_base:string;image_size:number;checkpoint:TraceProtocol}
export interface AcquisitionRequestExpected {file:string;tool:BinaryCommand;plan:NativeTracePlan;source_sha256:string;source_size_bytes:number}
export interface ProcessIdentityExpected {pid:number;executable:string;creation_filetime?:string;started_at:string;observed_before:string}
export interface WindowCaptureExpected {pid:number;executable:string;creation_filetime:string;started_at:string;finished_at:string}
export interface MainCaptureExpected extends WindowCaptureExpected {source_sha256:string;image_base:string;image_size:number}
export interface MainCaptureSummary {complete:boolean;observed_bytes:number;unobserved_bytes:number}
function need(value:unknown,message:string):asserts value {if(!value)throw new WirefitError(CODE,message);}
function boundary<T>(run:()=>T):T {
 try{return run();}catch(error){if(error instanceof WirefitError&&error.code===CODE)throw error;
  throw new WirefitError(CODE,'Acquisition evidence validation failed',{reason:error instanceof WirefitError?error.code:'INVALID_VALUE',message:error instanceof Error?error.message:'Invalid value'});
 }
}
function record(value:unknown,label:string,allowed?:readonly string[]):Row {
 need(value!==null&&typeof value==='object'&&!Array.isArray(value),label+' must be an object');
 need(Object.getPrototypeOf(value)===Object.prototype||Object.getPrototypeOf(value)===null,label+' must be a plain record');
 if(allowed)need(Object.keys(value).every(key=>allowed.includes(key)),label+' contains unexpected fields');
 return value as Row;
}
function text(value:unknown,label:string,max=4096,empty=false):string {
 need(typeof value==='string'&&(empty||value.length>0)&&value.length<=max&&!value.includes('\0'),label+' must be bounded text');return value;
}
function integer(value:unknown,min:number,max:number,label:string):number {
 need(Number.isSafeInteger(value)&&Number(value)>=min&&Number(value)<=max,label+' is outside its integer bound');return value as number;
}
function digest(value:unknown,label:string):string {need(typeof value==='string'&&DIGEST.test(value),label+' must be a lowercase SHA-256');return value;}
function decimal(value:unknown,label:string,zero=false):bigint {
 need(typeof value==='string'&&(zero?/^(?:0|[1-9][0-9]{0,19})$/:/^[1-9][0-9]{0,19}$/).test(value),label+' must be a canonical decimal uint64');
 const result=BigInt(value);need(result<UINT64,label+' exceeds uint64');return result;
}
function hex(value:unknown,label:string):bigint {
 need(typeof value==='string'&&/^0x[0-9a-f]{1,8}$/i.test(value),label+' must be a bounded PE32 address');return BigInt(value);
}
function executablePath(value:unknown):string {
 const name=text(value,'Executable path',32767);const windows=/^[A-Za-z]:[\\/]/.test(name);
 need(windows||path.posix.isAbsolute(name),'Executable path must be absolute');
 const rest=windows?name.slice(3):name.slice(1);const parts=rest.split(windows?/[\\/]/:/\//);
 need(parts.every(part=>part.length>0&&part!=='.'&&part!=='..'&&!/[. ]$/.test(part)&&!/[<>:"|?*\x00-\x1f]/.test(part)&&!/^(?:con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\.|$)/i.test(part)),
  'Executable path contains an alias or unsupported component');
 return windows?path.win32.normalize(name).toLowerCase():name;
}
function samePath(actual:unknown,expected:unknown):void {need(executablePath(actual)===executablePath(expected),'Executable path does not match the owned process');}
function errorRow(value:unknown,label:string):Row {
 const row=record(value,label,['code','message']);text(row.code,label+' code',256);text(row.message,label+' message',4096);return row;
}

/** Convert at 100ns precision; fractional digits never pass through Number. */
export function isoFiletime(value:unknown):bigint {return boundary(()=>{
 const timestamp=text(value,'UTC timestamp',64);const match=/^(\d{4}-\d{2}-\d{2})T(\d{2}:\d{2}:\d{2})(?:\.(\d{1,7}))?(?:Z|\+00:00)$/.exec(timestamp);
 need(match,'Timestamp must be UTC ISO with at most seven fractional digits');
 const whole=match[1]+'T'+match[2],milliseconds=Date.parse(whole+'Z');
 need(Number.isSafeInteger(milliseconds)&&new Date(milliseconds).toISOString().slice(0,19)===whole,'Invalid UTC calendar timestamp');
 const result=(BigInt(milliseconds)+11644473600000n)*10000n+BigInt((match[3]??'').padEnd(7,'0'));
 need(result>0n&&result<UINT64,'Timestamp is outside positive FILETIME bounds');return result;
});}
function validatePlan(plan:NativeTracePlan):void {validateNativeTraceRequest({file:'evidence.exe',tool:{command:'not-executed'},plan});}
export function validateOwnedCheckpoint(value:unknown,plan:NativeTracePlan,expected:OwnedCheckpointExpected):OwnedCheckpoint {return boundary(()=>{
 validatePlan(plan);need(plan.breakpoints_rva.length===0&&plan.api_hooks.length===0&&plan.max_events>=2,'Owned acquisition must be passive');
 integer(expected.image_size,1,MAX_IMAGE,'Expected image size');validateTraceProtocol(value,plan,32);
 need(value.is_checkpoint===true,'Owned PID requires a live checkpoint');integer(value.pid,1,0xffffffff,'Owned PID');
 need(value.identities.worker!==null&&value.identities.agent!==null&&value.identities.frida!==null&&value.frida_version===value.identities.frida.version,'Live checkpoint lacks collector or runtime origins');
 const ready=value.events.filter(row=>row.type==='agent_ready');need(ready.length===1,'Checkpoint must contain exactly one agent_ready');const event=ready[0]!;
 need(event.arch==='ia32'&&event.pointer_size===4&&event.hardware_breakpoints===0&&event.installed_api_hooks===0,'Ready architecture or passive state disagrees');
 const base=hex(event.image_base,'Ready image base'),size=integer(event.image_size,1,MAX_IMAGE,'Ready image size');
 need(base>0n&&base+BigInt(size)<=0x100000000n,'Ready image interval exceeds PE32 bounds');need(size===expected.image_size,'Ready image size differs from the source PE');
 need(value.cleanup.windows_job_assigned===true&&value.cleanup.windows_job_closed!==true&&value.cleanup.owned_pid_terminated===false&&value.cleanup.session_detached===false,'Checkpoint does not represent a live owned Windows Job');
 return {pid:value.pid as number,image_base:'0x'+base.toString(16),image_size:size,checkpoint:structuredClone(value)};
});}
export function validateAcquisitionRequest(value:unknown,expected:AcquisitionRequestExpected):void {boundary(()=>{
 const row=record(value,'Job request',['file','tool','plan','source']);
 validateNativeTraceRequest({file:row.file,tool:row.tool,plan:row.plan});validateNativeTraceRequest({file:expected.file,tool:expected.tool,plan:expected.plan});
 samePath(row.file,expected.file);need(hashObject(row.tool)===hashObject(expected.tool)&&hashObject(row.plan)===hashObject(expected.plan),'Job backend or plan differs from the frozen request');
 const source=record(row.source,'Job source',['path','sha256','size_bytes','artifact']);samePath(source.path,expected.file);
 digest(expected.source_sha256,'Expected source hash');integer(expected.source_size_bytes,1,MAX_IMAGE,'Expected source size');
 need(source.sha256===expected.source_sha256&&source.size_bytes===expected.source_size_bytes,'Job source hash or size differs');
 const artifact=record(source.artifact,'Source artifact',['sha256','relative_path','media_type','size_bytes']);
 need(artifact.sha256===expected.source_sha256&&artifact.relative_path==='artifacts/'+expected.source_sha256&&artifact.size_bytes===expected.source_size_bytes&&artifact.media_type==='application/vnd.microsoft.portable-executable','Job source ArtifactRef differs from the frozen PE');
});}
interface CheckedIdentity {creation:bigint;observed:bigint;alive:boolean;token:string}
function processIdentity(value:unknown,expected:ProcessIdentityExpected,requireAlive:boolean):CheckedIdentity {
 const row=record(value,'Process identity',['pid','executable','creation_filetime','exit_filetime','exit_code','alive','observed_utc']);
 integer(expected.pid,1,0xffffffff,'Expected PID');need(row.pid===expected.pid,'Process identity PID differs');samePath(row.executable,expected.executable);
 const creation=decimal(row.creation_filetime,'Creation FILETIME'),observed=isoFiletime(row.observed_utc),start=isoFiletime(expected.started_at),end=isoFiletime(expected.observed_before);
 need(start<=creation&&creation<=observed&&observed<=end,'Process creation or observation is outside the owning lifetime');
 if(expected.creation_filetime!==undefined)need(creation===decimal(expected.creation_filetime,'Expected creation FILETIME'),'Process creation FILETIME differs');
 need(typeof row.alive==='boolean','Process liveness is absent');const exited=decimal(row.exit_filetime,'Exit FILETIME',true);integer(row.exit_code,0,0xffffffff,'Process exit code');
 if(row.alive)need(exited===0n&&row.exit_code===259,'Live process exit fields disagree');
 else need(!requireAlive&&exited>=creation&&exited<=observed&&row.exit_code!==259,'Process is not live or its exit fields disagree');
 return {creation,observed,alive:row.alive,token:row.creation_filetime as string};
}
export function validateProcessIdentity(value:unknown,expected:ProcessIdentityExpected):string {return boundary(()=>processIdentity(value,expected,true).token);}
export function validateWindowCapture(value:unknown,expected:WindowCaptureExpected):void {boundary(()=>{
 integer(expected.pid,1,0xffffffff,'Expected PID');
 const row=record(value,'Window capture',['schema_version','kind','pid','executable','process_started_at','observed_at','scope','inventory']);
 need(row.schema_version===1&&row.kind==='path_bound_window_inventory'&&row.pid===expected.pid,'Window capture kind or PID differs');samePath(row.executable,expected.executable);
 const creation=decimal(expected.creation_filetime,'Expected creation FILETIME'),start=isoFiletime(expected.started_at),end=isoFiletime(expected.finished_at),observed=isoFiletime(row.observed_at);
 need(isoFiletime(row.process_started_at)===creation,'Window process creation differs at 100ns precision');
 need(start<=creation&&creation<=observed&&observed<=end,'Window observation is outside the job lifetime');
 text(row.scope,'Window scope',256);const inventory=record(row.inventory,'Window inventory',['windows','truncated']);
 need(Array.isArray(inventory.windows)&&inventory.windows.length<=256&&typeof inventory.truncated==='boolean','Window inventory is not bounded');
 const handles=new Set<string>();for(const value of inventory.windows){
  const window=record(value,'Window row',['handle','parent_handle','thread_id','process_id','class_name','text','visible','text_query_timed_out','text_query_status','text_query_error_code','text_at_buffer_limit']);
  need(window.process_id===expected.pid,'Window row belongs to another PID');integer(window.thread_id,1,0xffffffff,'Window thread ID');
  const handle=text(window.handle,'Window handle',18);need(/^0x[0-9a-f]{1,16}$/i.test(handle)&&BigInt(handle)>0n&&!handles.has(BigInt(handle).toString()),'Invalid or duplicate window handle');handles.add(BigInt(handle).toString());
  if(window.parent_handle!==null){const parent=text(window.parent_handle,'Parent window handle',18);need(/^0x[0-9a-f]{1,16}$/i.test(parent)&&BigInt(parent)>0n,'Invalid parent window handle');}
  text(window.text,'Window text',512,true);text(window.class_name,'Window class',128,true);
  need(typeof window.visible==='boolean'&&typeof window.text_query_timed_out==='boolean'&&typeof window.text_at_buffer_limit==='boolean','Window flags are invalid');
  need(['caption','wm_gettext','failed'].includes(String(window.text_query_status)),'Window text-query status is invalid');
  if(window.text_query_status==='failed'){integer(window.text_query_error_code,0,0xffffffff,'Window text-query error');need(window.text_query_timed_out===(window.text_query_error_code===1460),'Window timeout evidence disagrees');}
  else need(window.text_query_error_code===null&&window.text_query_timed_out===false,'Successful window text query has an error');
 }
});}
function coverage(value:unknown,image:Buffer,status:unknown):MainCaptureSummary {
 const row=record(value,'Image coverage',['pages','observed_bytes','unobserved_bytes','unverified_output_bytes','coverage_complete','counting','stopped_reason']);
 need(Array.isArray(row.pages)&&row.pages.length>0&&row.pages.length<=Math.ceil(image.length/4096)+1,'Coverage extent count exceeds its bound');
 let offset=0,observed=0,unverified=0;
 for(const value of row.pages){
  const page=record(value,'Coverage extent',['rva','requested_bytes','observed_bytes','coverage_complete','observed_prefix_bytes','observed_sha256','attempts','unobserved_reason','output_bytes_unverified','output_write_error','retry_error']);
  need(hex(page.rva,'Extent RVA')===BigInt(offset),'Coverage extents must be ordered, contiguous and disjoint');const size=integer(page.requested_bytes,1,65536,'Extent length');need(offset+size<=image.length,'Coverage extent exceeds image size');
  const count=integer(page.observed_prefix_bytes,0,size,'Observed prefix');need(page.observed_bytes===count&&page.coverage_complete===(count===size),'Extent counters disagree');
  need(page.output_bytes_unverified===undefined||page.output_bytes_unverified===true,'Unverified extent flag is invalid');
  if(page.output_bytes_unverified){need(count===0,'Unverified bytes cannot be observed');unverified+=size;}
  if(count)need(digest(page.observed_sha256,'Observed prefix hash')===sha256(image.subarray(offset,offset+count)),'Observed prefix bytes do not match their hash');
  else need(page.observed_sha256===null,'Empty observed prefix must have a null digest');
  if(!page.output_bytes_unverified)need(image.subarray(offset+count,offset+size).every(byte=>byte===0),'Unread bytes must remain explicit zero placeholders');
  need(Array.isArray(page.attempts)&&page.attempts.length<=2,'Read attempt count exceeds its bound');let availablePrefix=0,unknownPersistence=false;
  for(const value of page.attempts){
   const attempt=record(value,'Read attempt',['rva','requested_bytes','transferred_bytes','success','winerror','source','transferred_sha256','output_write']);
   const address=hex(attempt.rva,'Attempt RVA'),requested=integer(attempt.requested_bytes,1,65536,'Attempt length'),transferred=integer(attempt.transferred_bytes,0,requested,'Transferred bytes');
   need(address+BigInt(requested)<=BigInt(image.length)&&typeof attempt.success==='boolean'&&['initial_chunk','page_retry'].includes(String(attempt.source)),'Read attempt is outside the image');integer(attempt.winerror,0,0xffffffff,'Read error');
   if(attempt.success)need(attempt.winerror===0&&transferred===requested,'Successful read attempt has incomplete transfer or error');
   if(transferred)digest(attempt.transferred_sha256,'Transferred bytes hash');else need(attempt.transferred_sha256===null,'Empty transfer must have a null hash');
   if(attempt.source==='page_retry')need(address===BigInt(offset)&&requested===size,'Page retry differs from the extent');
   // RPM bytes become observations only after a known persisted prefix. The
   // initial write is chunk-relative; a retry writes the current page prefix.
   let persisted:number|null=transferred===0?0:null;
   if(attempt.output_write!==undefined){const write=record(attempt.output_write,'Output write',['success','written_prefix_bytes']);need(typeof write.success==='boolean','Output write status is invalid');
    persisted=write.written_prefix_bytes===null?null:integer(write.written_prefix_bytes,0,transferred,'Written prefix');
    if(write.success)need(persisted===transferred,'Successful write is incomplete');
    else need(status!=='completed','Completed coverage contains an output write failure');
   }
   const affected=address<BigInt(offset+size)&&address+BigInt(transferred)>BigInt(offset);
   if(persisted===null&&affected){unknownPersistence=true;availablePrefix=0;}
   else if(persisted!==null&&!unknownPersistence&&address<=BigInt(offset))availablePrefix=Math.max(availablePrefix,Math.max(0,Math.min(size,Number(address)+persisted-offset)));
  }
  need(!unknownPersistence||page.output_bytes_unverified===true,'Unknown output writes require an explicitly unverified extent');
  need(page.output_bytes_unverified?count===0:count===availablePrefix,'Observed extent differs from its persisted-prefix union');
  if(page.unobserved_reason!==undefined)text(page.unobserved_reason,'Unread reason',256);
  if(page.output_write_error!==undefined)errorRow(page.output_write_error,'Output write error');if(page.retry_error!==undefined)errorRow(page.retry_error,'Retry error');
  offset+=size;observed+=count;
 }
 need(offset===image.length&&row.observed_bytes===observed&&row.unobserved_bytes===image.length-observed&&row.unverified_output_bytes===unverified,'Coverage totals or complete extent span disagree');
 need(row.counting===COUNTING&&row.coverage_complete===(observed===image.length),'Coverage counting semantics disagree');
 need(status==='completed'?observed===image.length:status==='partial'&&observed<image.length,'Capture status contradicts coverage');
 if(row.stopped_reason!==undefined)text(row.stopped_reason,'Capture stop reason',256);
 return {complete:observed===image.length,observed_bytes:observed,unobserved_bytes:image.length-observed};
}
export function validateMainCapture(value:unknown,image:Buffer,expected:MainCaptureExpected):MainCaptureSummary {return boundary(()=>{
 const row=record(value,'Main capture',['schema_version','status','pid','base','size_bytes','atomic','runnable_pe','layout','observation','unobserved_fill','unobserved_fill_note','zero_fill_is_observed','started_utc','ended_utc','limits','identity','tool','coverage','image','error','additional_errors','live_header','mutable_header_differences','cleanup','source','elapsed_ms']);
 need(row.schema_version===1&&['completed','partial'].includes(String(row.status))&&row.pid===expected.pid,'Main capture status or PID differs');
 need(row.atomic===false&&row.runnable_pe===false&&row.layout==='flat_rva_memory'&&row.observation==='cooperative_non_atomic_external_read'&&row.zero_fill_is_observed===false,'Main capture scope is invalid');
 const size=integer(expected.image_size,1,MAX_IMAGE,'Expected image size'),base=hex(expected.image_base,'Expected image base');
 need(base>0n&&base+BigInt(size)<=0x100000000n&&hex(row.base,'Capture base')===base&&row.size_bytes===size,'Main capture image interval differs');
 need(Buffer.isBuffer(image)&&image.length===size,'Main capture bytes differ in size');
 const source=record(row.source,'Capture source',['path','sha256','size_bytes','header','write_delete_sharing_denied','verified_stable']);samePath(source.path,expected.executable);
 need(source.sha256===digest(expected.source_sha256,'Expected source hash')&&source.write_delete_sharing_denied===true&&source.verified_stable===true,'Main capture source hash or stability differs');integer(source.size_bytes,1,MAX_IMAGE,'Capture source size');
 const artifact=record(row.image,'Main image',['file','size_bytes','sha256','hash_includes_unobserved_zero_fill']);
 const name=text(artifact.file,'Main image basename',255);need(/^[A-Za-z0-9][A-Za-z0-9_.-]*\.bin$/.test(name)&&!name.includes('..')&&!/^(?:con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\.|$)/i.test(name),'Main image basename is invalid');
 need(artifact.size_bytes===size&&digest(artifact.sha256,'Main image hash')===sha256(image)&&artifact.hash_includes_unobserved_zero_fill===true,'Main image digest or placeholder semantics differ');
 const cleanup=record(row.cleanup,'Capture cleanup',['process_handle_closed','source_handle_closed']);need(cleanup.process_handle_closed===true&&cleanup.source_handle_closed===true,'Capture did not confirm both HANDLEs closed');
 const tool=record(row.tool,'Main reader source',['file','size_bytes','sha256']);need(tool.file==='memory-image.py','Unexpected main reader filename');integer(tool.size_bytes,1,1048576,'Reader source size');digest(tool.sha256,'Reader source hash');
 const limits=record(row.limits,'Capture limits',['image_bytes','chunk_bytes','retry_page_bytes','timeout_ms']);need(limits.image_bytes===MAX_IMAGE&&limits.chunk_bytes===65536&&limits.retry_page_bytes===4096,'Capture read limits differ');integer(limits.timeout_ms,1,60000,'Capture timeout');
 const start=isoFiletime(row.started_utc),end=isoFiletime(row.ended_utc),jobStart=isoFiletime(expected.started_at),jobEnd=isoFiletime(expected.finished_at),creation=decimal(expected.creation_filetime,'Expected creation FILETIME');
 need(jobStart<=creation&&creation<=start&&start<=end&&end<=jobEnd,'Main capture interval is outside the owning job');
 const identities=record(row.identity,'Capture identities',['expected_executable','expected_creation_filetime','start','end']);samePath(identities.expected_executable,expected.executable);need(identities.expected_creation_filetime===expected.creation_filetime,'Capture expected creation token differs');
 const identityExpected={...expected,observed_before:row.ended_utc as string};const first=processIdentity(identities.start,identityExpected,true),last=processIdentity(identities.end,identityExpected,row.status==='completed');
 need(start<=first.observed&&first.observed<=last.observed&&last.observed<=end,'HANDLE identity observations are outside capture interval');
 const result=coverage(row.coverage,image,row.status);const unverified=(row.coverage as Row).unverified_output_bytes as number;
 need(row.unobserved_fill===(unverified?'zero_except_unverified_output_write_ranges':'zero'),'Unobserved fill semantics differ');
 if(row.unobserved_fill_note!==undefined)text(row.unobserved_fill_note,'Unobserved fill note');
 if(row.error!==null){const error=errorRow(row.error,'Capture error');need(row.status==='partial','Completed capture contains an error');need(!/^(?:PROCESS_IDENTITY|CLOSED_HANDLE)/.test(String(error.code)),'Capture encountered an ownership identity failure');}
 if(row.additional_errors!==undefined){need(Array.isArray(row.additional_errors)&&row.additional_errors.length<=16,'Capture errors exceed bound');for(const value of row.additional_errors){const error=errorRow(value,'Additional capture error');need(!/^(?:PROCESS_IDENTITY|CLOSED_HANDLE)/.test(String(error.code)),'Capture encountered an ownership identity failure');}need(row.status!=='completed'||row.additional_errors.length===0,'Completed capture contains additional errors');}
 if(row.elapsed_ms!==undefined)need(typeof row.elapsed_ms==='number'&&Number.isFinite(row.elapsed_ms)&&row.elapsed_ms>=0&&row.elapsed_ms<=3600000,'Capture elapsed time is invalid');
 if(row.live_header!==null&&row.live_header!==undefined)record(row.live_header,'Live header');if(source.header!==undefined)record(source.header,'Source header');
 need(Array.isArray(row.mutable_header_differences)&&row.mutable_header_differences.length<=32,'Mutable header differences exceed bound');
 return result;
});}
export interface PrivateCaptureExpected extends MainCaptureExpected {
 callers:string[];main_receipt_sha256:string;main_image_sha256:string;helper_sha256:string;support_sha256:string;
}
function privateError(value:unknown,label:string):void {
 const row=record(value,label,['code','message','winerror']);text(row.code,label+' code',256);text(row.message,label+' message');
 if(row.winerror!==undefined)integer(row.winerror,0,0xffffffff,label+' Winerror');
 need(!/^(?:PROCESS_IDENTITY|CLOSED_HANDLE)/.test(String(row.code)),'Private capture encountered an ownership identity failure');
}
const REGION_KEYS=['base','allocation_base','size_bytes','allocation_protect','state','protect','type','returned_size','allocation_fields_defined','capture_reason','capture_file','byte_capture_status'] as const;
function privateRegion(value:unknown,label:string,accepted=false):Row {
 const row=record(value,label,REGION_KEYS),base=hex(row.base,label+' base'),allocation=hex(row.allocation_base,label+' allocation');
 const size=integer(row.size_bytes,1,0x100000000,label+' size');need(base+BigInt(size)<=0x100000000n,'Private metadata interval exceeds PE32');
 const state=hex(row.state,label+' state'),protect=hex(row.protect,label+' protection');hex(row.type,label+' type');hex(row.allocation_protect,label+' allocation protection');
 need([0x1000n,0x2000n,0x10000n].includes(state)&&row.allocation_fields_defined===(state!==0x10000n),'Private metadata state is invalid');
 need(state===0x10000n||allocation>0n&&allocation<=base,'Private metadata allocation is invalid');
 need(row.returned_size===28||row.returned_size===48,'Private metadata ABI structure size is invalid');
 if(row.capture_reason!==null)text(row.capture_reason,label+' rejection',256);
 if(accepted)need(base>0n&&state===0x1000n&&hex(row.type,label+' type')===0x20000n&&(protect&0x100n)===0n&&[0x20n,0x40n,0x80n].includes(protect&0xffn)&&row.capture_reason===null,'Captured region is not committed readable executable private memory');
 return row;
}
function samePrivateRegion(left:Row,right:Row):boolean {
 const hexFields=['base','allocation_base','allocation_protect','state','protect','type'];
 return hexFields.every(key=>hex(left[key],'Region '+key)===hex(right[key],'Region '+key))&&
  ['size_bytes','returned_size','allocation_fields_defined'].every(key=>left[key]===right[key]);
}
function executablePrivateRegion(region:Row):boolean {
 const protect=hex(region.protect,'Region protection');
 return hex(region.state,'Region state')===0x1000n&&hex(region.type,'Region type')===0x20000n&&(protect&0x100n)===0n&&[0x20n,0x40n,0x80n].includes(protect&0xffn);
}
function callerIndices(value:unknown,count:number,label:string):number[] {
 need(Array.isArray(value)&&value.length<=count,label+' exceeds caller bound');const result=value.map(item=>integer(item,0,count-1,label));need(new Set(result).size===result.length,label+' contains duplicates');return result;
}
/** Completed means the declared bounded observer scope, never dependency closure. */
export function validatePrivateCapture(value:unknown,captures:ReadonlyMap<string,Buffer>,main:Buffer,expected:PrivateCaptureExpected):MainCaptureSummary {return boundary(()=>{
 const row=record(value,'Private capture',['schema_version','kind','status','atomic','runnable_verified','scope','started_utc','ended_utc','inputs','tool','identity','callers','allocations','captures','queries','limits','cleanup','error','additional_errors','elapsed_ms','totals']);
 need(row.schema_version===1&&row.kind==='bound_private_executable_regions'&&['completed','partial'].includes(String(row.status))&&row.atomic===false&&row.runnable_verified===false&&row.scope==='readable_executable_private_regions_of_captured_rel32_targets','Private capture scope is invalid');
 const imageSize=integer(expected.image_size,1,MAX_IMAGE,'Expected main image size'),base=hex(expected.image_base,'Main image base');need(base>0n&&base+BigInt(imageSize)<=0x100000000n&&Buffer.isBuffer(main)&&main.length===imageSize,'Main bytes or interval differ');
 need(sha256(main)===digest(expected.main_image_sha256,'Expected main image hash'),'Private capture main image bytes differ');
 need(Array.isArray(expected.callers)&&expected.callers.length>=1&&expected.callers.length<=16,'Private callers exceed their bound');
 const requested=expected.callers.map(value=>hex(value,'Requested caller RVA'));need(new Set(requested.map(String)).size===requested.length,'Duplicate requested caller');
 const inputs=record(row.inputs,'Private inputs',['main_receipt','main_image','source']);
 const receipt=record(inputs.main_receipt,'Main receipt input',['path','sha256','size_bytes']);executablePath(receipt.path);integer(receipt.size_bytes,1,16*1024*1024,'Main receipt size');need(receipt.sha256===digest(expected.main_receipt_sha256,'Expected main receipt hash'),'Private main receipt hash differs');
 const inputImage=record(inputs.main_image,'Main image input',['path','sha256','size_bytes']);executablePath(inputImage.path);need(inputImage.sha256===expected.main_image_sha256&&inputImage.size_bytes===imageSize,'Private main image identity differs');
 const source=record(inputs.source,'Private source',['path','sha256','size_bytes','verified_stable']);samePath(source.path,expected.executable);integer(source.size_bytes,1,MAX_IMAGE,'Private source size');need(source.sha256===digest(expected.source_sha256,'Expected source hash')&&source.verified_stable===true,'Private source identity or stability differs');
 const tools=record(row.tool,'Private tool identities',['helper','memory_image_support']);
 for(const [role,file,expectedHash] of [['helper','private-regions.py',expected.helper_sha256],['memory_image_support','memory-image.py',expected.support_sha256]] as const){
  const tool=record(tools[role],role,['file','sha256','size_bytes']);need(tool.file===file&&tool.sha256===digest(expectedHash,role+' expected hash'),'Private collector source identity differs');integer(tool.size_bytes,1,1048576,role+' size');
 }
 const start=isoFiletime(row.started_utc),end=isoFiletime(row.ended_utc),creation=decimal(expected.creation_filetime,'Expected creation FILETIME');
 need(isoFiletime(expected.started_at)<=creation&&creation<=start&&start<=end&&end<=isoFiletime(expected.finished_at),'Private capture interval is outside the job');
 const identity=record(row.identity,'Private identity',['start','end','pid','expected_executable','expected_creation_filetime']);need(identity.pid===expected.pid&&identity.expected_creation_filetime===expected.creation_filetime,'Private expected PID or creation token differs');samePath(identity.expected_executable,expected.executable);
 const identityExpected={...expected,observed_before:row.ended_utc as string},first=processIdentity(identity.start,identityExpected,true),last=processIdentity(identity.end,identityExpected,row.status==='completed');
 need(start<=first.observed&&first.observed<=last.observed&&last.observed<=end,'Private identity observations exceed the capture interval');
 const cleanup=record(row.cleanup,'Private HANDLE cleanup',['process_handle_closed','source_handle_closed','image_handle_closed']);need(cleanup.process_handle_closed===true&&cleanup.source_handle_closed===true&&cleanup.image_handle_closed===true,'Private capture did not confirm all three HANDLEs closed');
 const limits=record(row.limits,'Private limits',['total_capture_bytes','allocation_scan_span_bytes','query_count','callers','capture_regions','timeout_ms']);
 need(limits.total_capture_bytes===16777216&&limits.allocation_scan_span_bytes===16777216&&limits.query_count===4096&&limits.callers===16&&limits.capture_regions===128,'Private policy limits differ');integer(limits.timeout_ms,1,60000,'Private capture timeout');
 need(Array.isArray(row.callers)&&row.callers.length===requested.length,'Private caller count differs');const callers:Row[]=[];
 for(const [index,value] of row.callers.entries()){
  const caller=record(value,'Private caller',['caller_rva','caller_va','expected_bytes','target_va','status','unknown_reason','target_region_captured','live_read','target_initial_region','allocation_base','capture_file','allocation_metadata_scan_complete']);
  const offset=hex(caller.caller_rva,'Caller RVA');need(offset===requested[index]&&offset+6n<=BigInt(main.length),'Private caller RVA differs or exceeds main image');const bytes=main.subarray(Number(offset),Number(offset)+6);
  need(bytes[0]===0xe8&&caller.expected_bytes===bytes.toString('hex')&&hex(caller.caller_va,'Caller VA')===base+offset,'Private caller bytes differ from current main image');
  const target=base+offset+5n+BigInt(bytes.readInt32LE(1));need(target>0n&&target<0x100000000n&&hex(caller.target_va,'Caller target')===target,'Private target does not match the current signed rel32');
  need(['captured','unknown'].includes(String(caller.status))&&typeof caller.target_region_captured==='boolean','Private caller status is invalid');
  if(caller.live_read!==undefined){const live=record(caller.live_read,'Same-HANDLE caller bytes',['hex','transferred_bytes','success','winerror']);const count=integer(live.transferred_bytes,0,6,'Live caller byte count');need(typeof live.hex==='string'&&/^(?:[0-9a-f]{2}){0,6}$/.test(live.hex)&&live.hex.length===count*2&&typeof live.success==='boolean','Live caller byte record is invalid');integer(live.winerror,0,0xffffffff,'Live caller Winerror');}
  if(caller.status==='captured'){
   const live=record(caller.live_read,'Captured caller live reread');need(live.success===true&&live.winerror===0&&live.transferred_bytes===6&&live.hex===bytes.toString('hex')&&caller.target_region_captured===true&&caller.unknown_reason===null,'Captured caller lacks the matching live six bytes');
   need(typeof caller.allocation_metadata_scan_complete==='boolean','Captured caller lacks metadata scan status');const initial=privateRegion(caller.target_initial_region,'Caller initial target region',true),initialBase=hex(initial.base,'Initial target region base');need(initialBase<=target&&target<initialBase+BigInt(initial.size_bytes as number)&&hex(initial.allocation_base,'Initial target allocation')===hex(caller.allocation_base,'Caller allocation'),'Initial target metadata differs from the caller');
  }else{need(caller.target_region_captured===false,'Unknown caller cannot claim a complete target');privateError(caller.unknown_reason,'Unknown caller reason');if(caller.target_initial_region!==undefined)privateRegion(caller.target_initial_region,'Unknown caller target region');}
  callers.push(caller);
 }
 need(Array.isArray(row.captures)&&row.captures.length<=128&&captures instanceof Map&&captures.size===row.captures.length,'Private capture file map differs or exceeds bound');
 const files=new Map<string,{row:Row;base:bigint;size:number;summary:MainCaptureSummary}>();let totalBytes=0,observed=0,unobserved=0,allComplete=true;
 for(const value of row.captures){
  const capture=record(value,'Private region capture',['file','base','allocation_base','size_bytes','status','sha256','coverage','region_at_plan','target_caller_indices','unobserved_fill','zero_fill_is_observed','error','additional_errors']);
  const file=text(capture.file,'Private capture basename',32);need(/^private-(?:00[1-9]|0[1-9][0-9]|1[01][0-9]|12[0-8])\.bin$/.test(file)&&!files.has(file),'Invalid or duplicate private capture basename');
  const bytes=captures.get(file),size=integer(capture.size_bytes,1,16777216,'Private region size'),address=hex(capture.base,'Private region base');
  need(address>0n&&address+BigInt(size)<=0x100000000n&&Buffer.isBuffer(bytes)&&bytes.length===size&&digest(capture.sha256,'Private image hash')===sha256(bytes),'Private region bytes or interval differ');
  const allocation=hex(capture.allocation_base,'Private allocation base');need(allocation>0n&&allocation<=address,'Private allocation base differs');
  const metadata=privateRegion(capture.region_at_plan,'Captured region metadata',true);need(hex(metadata.base,'Planned base')===address&&metadata.size_bytes===size&&hex(metadata.allocation_base,'Planned allocation')===allocation,'Captured bytes differ from their planned region');
  for(const prior of files.values())need(address+BigInt(size)<=prior.base||prior.base+BigInt(prior.size)<=address,'Private byte captures overlap');
  need(capture.zero_fill_is_observed===false,'Private zero fill cannot be observed');const summary=coverage(capture.coverage,bytes,capture.status),unknown=(capture.coverage as Row).unverified_output_bytes;
  need(capture.unobserved_fill===(unknown?'zero_except_unverified_output_write_ranges':'zero'),'Private placeholder semantics disagree');
  if(capture.error!==null){privateError(capture.error,'Private region error');need(capture.status!=='completed','Completed private region contains an error');}
  if(capture.additional_errors!==undefined){need(Array.isArray(capture.additional_errors)&&capture.additional_errors.length<=16,'Private region errors exceed bound');for(const error of capture.additional_errors)privateError(error,'Private region error');need(capture.status!=='completed'||capture.additional_errors.length===0,'Completed private region contains errors');}
  const linked=callerIndices(capture.target_caller_indices,callers.length,'Region caller indices');
  for(const index of linked){const caller=callers[index]!,target=hex(caller.target_va,'Linked target');need(caller.capture_file===file&&address<=target&&target<address+BigInt(size),'Caller target is outside its linked capture');}
  totalBytes+=size;observed+=summary.observed_bytes;unobserved+=summary.unobserved_bytes;allComplete&&=summary.complete;files.set(file,{row:capture,base:address,size,summary});
 }
 need(totalBytes<=16777216,'Private byte capture total exceeds policy');for(const name of captures.keys())need(files.has(name),'Unregistered private capture bytes');
 for(const [index,caller] of callers.entries()){
  if(caller.capture_file!==undefined){const file=text(caller.capture_file,'Caller capture file',32),capture=files.get(file);need(capture,'Caller capture file is absent');const target=hex(caller.target_va,'Caller target');need(capture.base<=target&&target<capture.base+BigInt(capture.size)&&(capture.row.target_caller_indices as number[]).includes(index),'Caller/capture association differs');
   need(hex(caller.allocation_base,'Caller allocation')===hex(capture.row.allocation_base,'Capture allocation'),'Caller allocation differs from the captured region');
   if(caller.status==='captured')need(capture.summary.complete,'Captured caller points to a partial region');
  }else need(caller.status!=='captured','Captured caller has no byte capture');
 }
 need(Array.isArray(row.queries)&&row.queries.length<=4096,'Private queries exceed bound');const queries:Row[]=[];for(const value of row.queries){
  const query=record(value,'Private query',['address','purpose','observed_utc','region','error']);const address=hex(query.address,'Query address');text(query.purpose,'Query purpose',64);const time=isoFiletime(query.observed_utc);need(start<=time&&time<=end,'Private query is outside the capture interval');
  need((query.region!==undefined)!==(query.error!==undefined),'Query must have either metadata or an error');if(query.region!==undefined){const region=privateRegion(query.region,'Query region'),base=hex(region.base,'Query region base');need(base<=address&&address<base+BigInt(region.size_bytes as number),'Query address is outside returned metadata');}else privateError(query.error,'Private query error');queries.push(query);
 }
 need(Array.isArray(row.allocations)&&row.allocations.length<=16,'Private allocation count exceeds bound');const allocations=new Map<string,Row>();let allScanned=true;
 const representedCaptures=new Set<string>(),usedScans=new Set<number>();let scanIndex=-1;
 const matchScan=(address:bigint,region:Row)=>{
  const index=queries.findIndex((query,index)=>index>scanIndex&&query.purpose==='allocation_scan'&&hex(query.address,'Scan query address')===address&&query.region!==undefined&&samePrivateRegion(query.region as Row,region));
  need(index>=0,'Allocation inventory lacks its ordered scan query');usedScans.add(index);scanIndex=index;
 };

 for(const value of row.allocations){
  const allocation=record(value,'Private allocation',['allocation_base','caller_indices','metadata_scan_complete','regions','byte_scope','all_allocation_bytes_captured','boundary_region','scan_error']);
  const address=hex(allocation.allocation_base,'Allocation base'),key=address.toString();need(address>0n&&!allocations.has(key),'Invalid or duplicate allocation');
  need(typeof allocation.metadata_scan_complete==='boolean'&&allocation.byte_scope==='readable_executable_private_regions_only'&&allocation.all_allocation_bytes_captured===false,'Private allocation scope differs');
  const linked=callerIndices(allocation.caller_indices,callers.length,'Allocation caller indices');for(const index of linked)need(hex(callers[index]!.allocation_base,'Caller allocation')===address,'Allocation caller link differs');
  need(Array.isArray(allocation.regions)&&allocation.regions.length<=4096,'Allocation metadata exceeds bound');let cursor=address;
  for(const value of allocation.regions){const region=privateRegion(value,'Allocation region');need(hex(region.allocation_base,'Region allocation')===address&&hex(region.base,'Region base')===cursor,'Allocation inventory must advance contiguously from its base');
   matchScan(cursor,region);cursor+=BigInt(region.size_bytes as number);
   if(region.capture_file!==undefined){
    privateRegion(region,'Captured allocation region',true);const file=text(region.capture_file,'Metadata capture file',32),capture=files.get(file);
    need(capture&&!representedCaptures.has(file)&&hex(capture.row.allocation_base,'Capture allocation')===address&&samePrivateRegion(region,capture.row.region_at_plan as Row)&&region.byte_capture_status===capture.row.status,'Allocation region attributes differ from its unique byte capture');representedCaptures.add(file);
   }else if(executablePrivateRegion(region))allComplete=false;
  }
  if(allocation.metadata_scan_complete){
   need(cursor-address<=16777216n,'Completed allocation scan exceeds its bounded span');
   const boundary=privateRegion(allocation.boundary_region,'Allocation boundary'),boundaryBase=hex(boundary.base,'Boundary base');
   need(boundaryBase<=cursor&&cursor<boundaryBase+BigInt(boundary.size_bytes as number)&&(hex(boundary.state,'Boundary state')===0x10000n||hex(boundary.allocation_base,'Boundary allocation')!==address),'Completed scan lacks a containing free or different-allocation boundary');matchScan(cursor,boundary);
  }else if(allocation.boundary_region!==undefined)privateRegion(allocation.boundary_region,'Incomplete allocation boundary');
  if(allocation.scan_error!==undefined)privateError(allocation.scan_error,'Allocation scan error');
  allScanned&&=allocation.metadata_scan_complete&&allocation.scan_error===undefined;allocations.set(key,allocation);
 }
 need(representedCaptures.size===files.size,'Byte capture is absent from the allocation region inventory');
 if(row.status==='completed')need(queries.every((query,index)=>query.purpose!=='allocation_scan'||usedScans.has(index)),'Completed scan omits recorded allocation queries');
 for(const [index,caller] of callers.entries())if(caller.capture_file!==undefined){const allocation=allocations.get(hex(caller.allocation_base,'Caller allocation').toString());need(allocation&&(allocation.caller_indices as number[]).includes(index),'Captured caller allocation link is absent');need(caller.allocation_metadata_scan_complete===allocation.metadata_scan_complete,'Caller metadata scan status differs from its allocation');}
 const totals=record(row.totals,'Private totals',['capture_file_bytes','observed_bytes','unobserved_bytes','query_count']);need(totals.capture_file_bytes===totalBytes&&totals.observed_bytes===observed&&totals.unobserved_bytes===unobserved&&totals.query_count===row.queries.length,'Private aggregate totals disagree');
 if(row.error!==null)privateError(row.error,'Private capture error');if(row.additional_errors!==undefined){need(Array.isArray(row.additional_errors)&&row.additional_errors.length<=16,'Private errors exceed bound');for(const error of row.additional_errors)privateError(error,'Private capture error');}
 const complete=callers.every(caller=>caller.status==='captured')&&files.size>0&&observed>0&&allComplete&&allScanned&&row.error===null&&(row.additional_errors===undefined||(row.additional_errors as unknown[]).length===0);
 need(row.status==='completed'?complete:!complete,'Private status contradicts its bounded evidence');
 if(row.elapsed_ms!==undefined)need(typeof row.elapsed_ms==='number'&&Number.isFinite(row.elapsed_ms)&&row.elapsed_ms>=0&&row.elapsed_ms<=3600000,'Private elapsed time is invalid');
 return {complete,observed_bytes:observed,unobserved_bytes:unobserved};
});}
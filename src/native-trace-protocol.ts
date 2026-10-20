import {assert} from './shared.js';
import type {NativeTracePlan,NativeTraceRange} from './native-trace.js';

export interface TraceCodeIdentity {file:string;sha256:string;size_bytes:number}
export interface TraceMemoryObservation {rva:string;size_bytes:number;phase:string;file?:string;sha256?:string;error?:string;module?:string;module_base?:string|null;module_size?:number|null;address?:string|null}
export interface TraceProtocol {
 schema_version:1;status:'completed'|'failed';pid:number|null;frida_version:string|null;
 events:Record<string,unknown>[];snapshots:TraceMemoryObservation[];
 identities:{worker:TraceCodeIdentity|null;agent:TraceCodeIdentity|null;frida:{version:string;module_path:string}|null};
 cleanup:{owned_pid_terminated:boolean;session_detached:boolean;windows_job_assigned?:boolean;windows_job_closed?:boolean};
 error:{code:string;message:string}|null;is_checkpoint?:boolean;checkpoint_sequence?:number;
}
const PROTOCOL='NATIVE_TRACE_PROTOCOL_INVALID',OUTPUT='NATIVE_TRACE_OUTPUT_INVALID';
function record(value:unknown):value is Record<string,unknown>{return value!==null&&typeof value==='object'&&!Array.isArray(value);}
function bounded(value:unknown,max=4096):value is string{return typeof value==='string'&&value.length>0&&value.length<=max&&!value.includes('\0');}
function uint(value:unknown):value is number{return Number.isSafeInteger(value)&&Number(value)>=0;}
const canonical=(value:string)=>BigInt(value).toString(16);
export function traceRangeKey(range:NativeTraceRange):string{
 return (range.module===undefined?'main:':'module:'+range.module.toLowerCase()+':')+canonical(range.rva)+':'+range.size_bytes;
}
function moduleLocation(value:Record<string,unknown>,pointerBits:32|64):void{
 if(value.module===undefined){
  assert(!('module_base' in value)&&!('module_size' in value)&&!('address' in value),OUTPUT,'Main-image observation contains unrequested module metadata');return;
 }
 assert(typeof value.module==='string'&&/^[A-Za-z0-9_.-]{1,128}$/.test(value.module)&&!['.','..'].includes(value.module),OUTPUT,'Snapshot module is not a supported basename');
 if(value.module_base===null){
  assert(value.module_size===null&&value.address===null&&value.error!==undefined,OUTPUT,'An unavailable module must have explicit null location and a capture error');return;
 }
 assert(typeof value.module_base==='string'&&/^0x[0-9a-f]{1,16}$/i.test(value.module_base)&&BigInt(value.module_base)>0n&&
  uint(value.module_size)&&value.module_size>0&&value.module_size<=0xffffffff,OUTPUT,'Snapshot module identity is invalid');
 const base=BigInt(value.module_base),size=BigInt(value.module_size),pointerLimit=1n<<BigInt(pointerBits);
 assert(base+size<=pointerLimit,OUTPUT,'Snapshot module interval overflows the pointer width');
 if(value.address===null){assert(value.error!==undefined,OUTPUT,'Successful module snapshot has no runtime address');return;}
 assert(typeof value.address==='string'&&/^0x[0-9a-f]{1,16}$/i.test(value.address),OUTPUT,'Snapshot address is invalid');
 const offset=BigInt(value.rva as string),length=BigInt(value.size_bytes as number),address=BigInt(value.address);
 assert(address===base+offset&&offset+length<=size&&address+length<=pointerLimit,OUTPUT,'Snapshot read is outside its recorded runtime module');
}

function identities(value:unknown,required:boolean):void{
 assert(record(value),PROTOCOL,'Worker source identities are absent');
 for(const role of ['worker','agent'] as const){
  const item=value[role];
  if(item===null&&!required)continue;
  assert(record(item)&&item.file===(role==='worker'?'trace-worker.py':'trace-agent.js')&&
   typeof item.sha256==='string'&&/^[a-f0-9]{64}$/.test(item.sha256)&&uint(item.size_bytes)&&item.size_bytes>0&&item.size_bytes<=1048576,
  PROTOCOL,'Worker source identity is invalid');
 }
 const frida=value.frida;
 assert(frida===null&&!required||record(frida)&&bounded(frida.version,256)&&bounded(frida.module_path),PROTOCOL,'Frida origin is invalid');
}
function hooks(value:unknown,complete:unknown,plan:NativeTracePlan,successful:boolean):void{
 assert(record(value)&&typeof complete==='boolean',PROTOCOL,'API hook state evidence is absent');
 for(const phase of ['initial','current','final']){
  const states=value[phase];assert(Array.isArray(states)&&states.length<=plan.api_hooks.length,PROTOCOL,'API hook states are invalid');
  if(successful&&(phase!=='final'||complete))assert(states.length===plan.api_hooks.length,PROTOCOL,'A requested API hook has no recorded state');
  const seen=new Set<string>();
  for(const state of states){
   assert(record(state)&&typeof state.module==='string'&&typeof state.symbol==='string'&&
    plan.api_hooks.some(api=>api.module.toLowerCase()===String(state.module).toLowerCase()&&api.symbol===state.symbol),PROTOCOL,'API hook state was not requested');
   const key=state.module.toLowerCase()+'!'+state.symbol;
   assert(!seen.has(key),PROTOCOL,'Duplicate API hook state');seen.add(key);
   assert(['pending_module','installed','error','unobserved'].includes(String(state.status))&&uint(state.observations)&&
    (state.address===null||typeof state.address==='string'&&/^0x[0-9a-f]{1,16}$/i.test(state.address))&&
    (state.error===null||bounded(state.error)),PROTOCOL,'API hook state fields are invalid');
   if(state.status==='installed')assert(typeof state.address==='string',PROTOCOL,'Installed API hook has no address');
   if(state.status==='error')assert(bounded(state.error),PROTOCOL,'Failed API hook has no diagnostic');
   if(successful&&phase==='final'&&complete)assert(['installed','unobserved'].includes(String(state.status)),PROTOCOL,'Successful trace contains an unresolved API hook error');
  }
 }
}
function observations(rows:unknown[],plan:NativeTracePlan,complete:boolean,pointerBits:32|64):void{
 const phases=new Set(['initial','final',...plan.breakpoints_rva.map(point=>'breakpoint-'+canonical(point))]);
 const seen=new Set<string>(),files=new Set<string>();
 const plannedBytes=plan.ranges.reduce((sum,range)=>sum+range.size_bytes,0),phaseBytes=new Map<string,number>();
 for(const value of rows){
  assert(record(value)&&typeof value.rva==='string'&&/^0x[0-9a-f]{1,8}$/i.test(value.rva)&&uint(value.size_bytes)&&
   plan.ranges.some(range=>canonical(range.rva)===canonical(String(value.rva))&&range.size_bytes===value.size_bytes&&
    (range.module===undefined?value.module===undefined:typeof value.module==='string'&&range.module.toLowerCase()===value.module.toLowerCase()))&&
   typeof value.phase==='string'&&phases.has(value.phase),OUTPUT,'Snapshot does not correspond to a requested phase/range');
  moduleLocation(value,pointerBits);
  const rangeKey=traceRangeKey({rva:value.rva,size_bytes:value.size_bytes,...(value.module===undefined?{}:{module:value.module as string})});
  const key=value.phase+':'+rangeKey;
  assert(!seen.has(key),OUTPUT,'Worker duplicated a phase/range observation');seen.add(key);
  const bytes=(phaseBytes.get(value.phase)??0)+value.size_bytes;
  assert(bytes<=plannedBytes,OUTPUT,'Worker exceeded planned memory per phase');phaseBytes.set(value.phase,bytes);
  if(value.error!==undefined){
   assert(bounded(value.error)&&!('file' in value)&&!('sha256' in value),OUTPUT,'Failed snapshot must not provide invented bytes');continue;
  }
  assert(typeof value.file==='string'&&/^[A-Za-z][A-Za-z0-9_.-]{0,127}\.bin$/.test(value.file)&&
   typeof value.sha256==='string'&&/^[a-f0-9]{64}$/.test(value.sha256),OUTPUT,'Snapshot filename or digest is invalid');
  const filename=value.file.toLowerCase();assert(!files.has(filename),OUTPUT,'Memory observations must have distinct files');files.add(filename);
 }
 if(complete)for(const phase of ['initial','final'])for(const range of plan.ranges)
  assert(seen.has(phase+':'+traceRangeKey(range)),OUTPUT,'A mandatory memory observation is absent; report bytes or a capture error');
}
export function validateTraceProtocol(value:unknown,plan:NativeTracePlan,pointerBits:32|64=64):asserts value is TraceProtocol{
 assert(pointerBits===32||pointerBits===64,PROTOCOL,'Target pointer width is invalid');
 assert(record(value),PROTOCOL,'Worker returned no protocol object');
 assert(value.schema_version===1&&['completed','failed'].includes(String(value.status))&&
  Array.isArray(value.events)&&value.events.length<=plan.max_events&&value.events.every(record)&&
  Array.isArray(value.snapshots)&&value.snapshots.length<=plan.ranges.length*(2+plan.breakpoints_rva.length),PROTOCOL,'Worker protocol arrays or version are invalid');
 const completed=value.status==='completed';
 assert((value.pid===null||uint(value.pid)&&value.pid>0)&&(value.frida_version===null||bounded(value.frida_version,256)),PROTOCOL,'Worker identity fields are invalid');
 assert(completed?value.error===null:record(value.error)&&bounded(value.error.code,256)&&bounded(value.error.message),PROTOCOL,'Worker status and error disagree');
 assert(value.is_checkpoint===undefined||typeof value.is_checkpoint==='boolean',PROTOCOL,'Checkpoint marker is invalid');
 if(value.is_checkpoint===true)assert(!completed&&uint(value.checkpoint_sequence)&&value.checkpoint_sequence>0,PROTOCOL,'Intermediate checkpoint cannot report success');
 assert(uint(value.omitted_events)&&typeof value.omitted_events_complete==='boolean',PROTOCOL,'Worker omission evidence is invalid');
 identities(value.identities,completed);
 if(completed)assert(value.pid!==null&&value.frida_version===(value.identities as {frida:{version:string}}).frida.version,PROTOCOL,'Runtime identity is inconsistent');
 hooks(value.hook_states,value.hook_states_complete,plan,completed);
 observations(value.snapshots,plan,completed,pointerBits);
 const cleanup=value.cleanup;
 assert(record(cleanup)&&typeof cleanup.owned_pid_terminated==='boolean'&&typeof cleanup.session_detached==='boolean'&&
  (cleanup.windows_job_assigned===undefined||typeof cleanup.windows_job_assigned==='boolean')&&
  (cleanup.windows_job_closed===undefined||typeof cleanup.windows_job_closed==='boolean'),PROTOCOL,'Worker cleanup evidence is invalid');
 if(completed)assert(cleanup.owned_pid_terminated===true&&cleanup.session_detached===true&&cleanup.windows_job_assigned===true&&cleanup.windows_job_closed===true,
  'NATIVE_TRACE_CLEANUP_INCOMPLETE','Owned target/session/Windows Job closure was not confirmed');
}

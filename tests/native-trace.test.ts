import {exportReport} from '../src/reporting.js';
import {afterEach,describe,it,expect} from 'vitest';
import {mkdtemp,writeFile,readFile,realpath,lstat,rm} from 'node:fs/promises';
import {existsSync} from 'node:fs';
import path from 'node:path';
import {tmpdir} from 'node:os';
import {WirefitService} from '../src/service.js';
import {submitBinaryTrace,validateNativeTraceRequest} from '../src/native-trace.js';
import {validateTraceProtocol} from '../src/native-trace-protocol.js';
import {runProcess} from '../src/process.js';
const roots:string[]=[];
afterEach(async()=>{for(const root of roots.splice(0)){const safe=await realpath(root);expect(safe.toLowerCase().startsWith((path.resolve(tmpdir())+path.sep+'wirefit-trace-host-').toLowerCase())).toBe(true);expect((await lstat(root)).isSymbolicLink()).toBe(false);await rm(safe,{recursive:true,force:true});}});
const plan=()=>({duration_ms:10,breakpoints_rva:['0x1000'],ranges:[{rva:'0x1000',size_bytes:16}],api_hooks:[],max_events:8});
const syntheticProtocol = `
const identities={};
for(const [role,file] of [['worker','trace-worker.py'],['agent','trace-agent.js']]){
 const bytes=Buffer.from('synthetic '+role+' source (no target execution)','utf8');
 await writeFile(file,bytes,{flag:'wx'});
 identities[role]={file,size_bytes:bytes.length,sha256:createHash('sha256').update(bytes).digest('hex')};
}
identities.frida={version:'synthetic-no-frida',module_path:process.execPath};
const initial={rva:'0x1000',size_bytes:16,phase:'initial',error:'synthetic initial memory unavailable'};
const final={rva:'0x1000',size_bytes:16,phase:'final',error:'synthetic final memory unavailable'};
const base={schema_version:1,status:'completed',frida_version:'synthetic-no-frida',pid:process.pid,
 identities,events:[],snapshots:[initial,final],omitted_events:0,omitted_events_complete:true,
 hook_states:{initial:[],current:[],final:[]},hook_states_complete:true,
 cleanup:{owned_pid_terminated:true,session_detached:true,windows_job_assigned:true,windows_job_closed:true},error:null};
const reply=value=>console.log(JSON.stringify({...base,...value}));
`;
async function fixture(body=''){
 const root=await mkdtemp(path.join(tmpdir(),'wirefit-trace-host-'));roots.push(root);
 const service=await WirefitService.create(path.join(root,'case'));
 const bytes=Buffer.alloc(1024);bytes.write('MZ');bytes.writeUInt32LE(128,60);bytes.write('PE\0\0',128);bytes.writeUInt16LE(0x14c,132);bytes.writeUInt16LE(1,134);bytes.writeUInt16LE(224,148);
 const o=152;bytes.writeUInt16LE(0x10b,o);bytes.writeUInt32LE(4096,o+16);bytes.writeUInt32LE(0x400000,o+28);bytes.writeUInt32LE(4096,o+32);bytes.writeUInt32LE(512,o+36);bytes.writeUInt32LE(8192,o+56);bytes.writeUInt32LE(512,o+60);bytes.writeUInt32LE(16,o+92);
 const s=o+224;bytes.write('.text',s);bytes.writeUInt32LE(512,s+8);bytes.writeUInt32LE(4096,s+12);bytes.writeUInt32LE(512,s+16);bytes.writeUInt32LE(512,s+20);bytes.writeUInt32LE(0x60000020,s+36);bytes[512]=0xc3;
 const file=path.join(root,'original.exe');await writeFile(file,bytes);await writeFile(path.join(root,'support.dll'),bytes);
 const script=path.join(root,'worker.mjs');
 const prefix="import{readFileSync}from'node:fs';import{readFile,writeFile}from'node:fs/promises';import{createHash}from'node:crypto';const request=JSON.parse(readFileSync(0,'utf8'));";
 const normal="const b=Buffer.alloc(16,66);await writeFile('capture-0000.bin',b,{flag:'wx'});reply({events:[{type:'test-only',target:request.target,dependency_present:(await readFile('support.dll')).length===1024}],snapshots:[initial,{file:'capture-0000.bin',rva:'0x1000',size_bytes:16,sha256:createHash('sha256').update(b).digest('hex'),phase:'final'}]});";
 await writeFile(script,prefix+syntheticProtocol+(body||normal),'utf8');
 return {root,service,bytes,file,tool:{command:process.execPath,args:[script]},plan:plan()};
}
describe('owned native trace host',()=>{
 it('validates strict plan bounds and rejects field injection',()=>{
  const good={file:'sample.exe',tool:{command:'python'},plan:plan()};expect(()=>validateNativeTraceRequest(good)).not.toThrow();
  for(const bad of [{...good,pid:1},{...good,plan:{...plan(),verdict:'restored'}},{...good,tool:{command:'python',shell:true}},{...good,plan:{...plan(),duration_ms:0}},{...good,plan:{...plan(),breakpoints_rva:Array(5).fill('0x1000')}},{...good,plan:{...plan(),ranges:[{rva:'0x0',size_bytes:1048577}]}},{...good,plan:{...plan(),max_events:513}},{...good,plan:{...plan(),api_hooks:[{module:'..',symbol:'entry'}]}},{...good,plan:{...plan(),api_hooks:[{module:'kernel32.dll',symbol:'bad symbol'}]}}]){
   expect(()=>validateNativeTraceRequest(bad)).toThrow();
  }
 });
 it('stages immutable input and DLLs and retains bounded memory observations without a PE claim',async()=>{
  const f=await fixture();
  try{
   const job=await f.service.jobs.wait((await submitBinaryTrace(f.service,{file:f.file,tool:f.tool,plan:f.plan})).job_id);
   expect(job.status).toBe('completed');const result:any=await f.service.getResult(job.result_id!);
   expect(result.operation).toBe('trace_binary');expect(result.outputs).toEqual([]);expect(result.validation).toEqual({source_unchanged:true,runnable_verified:false});
   const trace=JSON.parse((await f.service.store.readArtifact(result.trace_artifact)).toString('utf8'));
   expect(trace.events[0].target).not.toBe(f.file);expect(trace.events[0].dependency_present).toBe(true);
   expect(result.snapshots).toHaveLength(1);expect(await f.service.store.readArtifact(result.snapshots[0].artifact)).toEqual(Buffer.alloc(16,66));
   expect(await readFile(f.file)).toEqual(f.bytes);
   const exported=await exportReport(f.service.store,job.result_id!,path.join(f.root,'portable-trace'));expect(exported.candidate_module).toBe(null);
  }finally{await f.service.close();}
 });
 it('rejects out-of-image breakpoints/ranges before scheduling execution',async()=>{
  const f=await fixture();
  try{
   await expect(submitBinaryTrace(f.service,{file:f.file,tool:f.tool,plan:{...f.plan,breakpoints_rva:['0x2000']}})).rejects.toMatchObject({code:'NATIVE_TRACE_REQUEST_INVALID'});
   await expect(submitBinaryTrace(f.service,{file:f.file,tool:f.tool,plan:{...f.plan,ranges:[{rva:'0x1fff',size_bytes:16}]}})).rejects.toMatchObject({code:'NATIVE_TRACE_REQUEST_INVALID'});
   expect(await f.service.store.listObjects('jobs')).toEqual([]);
  }finally{await f.service.close();}
 });
 it('retains failure and process diagnostics when the worker does not produce protocol JSON',async()=>{
  const f=await fixture("console.log('invalid worker response');console.error('test-only failure');process.exitCode=7;");
  try{
   const job=await f.service.jobs.wait((await submitBinaryTrace(f.service,{file:f.file,tool:f.tool,plan:f.plan})).job_id);
   expect(job.status).toBe('failed');expect(job.result_id).toBeTruthy();const result:any=await f.service.getResult(job.result_id!);
   const logs=await Promise.all(result.logs.map(async(ref:any)=>(await f.service.store.readArtifact(ref)).toString('utf8')));
   expect(logs.join('\n')).toContain('test-only failure');expect(result.validation.runnable_verified).toBe(false);
  }finally{await f.service.close();}
 });
 it.each(['../outside.bin','capture-0000.exe'])('rejects unsupported snapshot filename %s',async name=>{
  const body="reply({snapshots:[initial,{file:"+JSON.stringify(name)+",rva:'0x1000',size_bytes:16,sha256:'a'.repeat(64),phase:'final'}]});";
  const f=await fixture(body);
  try{
   const job=await f.service.jobs.wait((await submitBinaryTrace(f.service,{file:f.file,tool:f.tool,plan:f.plan})).job_id);
   expect(job.status).toBe('failed');const result:any=await f.service.getResult(job.result_id!);expect(result.error.code).toBe('NATIVE_TRACE_OUTPUT_INVALID');
  }finally{await f.service.close();}
 });
 it('keeps inaccessible requested snapshots explicit instead of inventing bytes',async()=>{
  const f=await fixture("reply({snapshots:[initial,{...final,error:'memory not readable'}]});");
  try{
   const job=await f.service.jobs.wait((await submitBinaryTrace(f.service,{file:f.file,tool:f.tool,plan:f.plan})).job_id);
   expect(job.status).toBe('completed');const result:any=await f.service.getResult(job.result_id!);
   expect(result.snapshots).toEqual([]);const raw=JSON.parse((await f.service.store.readArtifact(result.trace_artifact)).toString('utf8'));expect(raw.snapshots[1].error).toBe('memory not readable');
  }finally{await f.service.close();}
 });
 it('fails worker-reported incomplete cleanup instead of declaring a completed trace',async()=>{
  const f=await fixture("reply({cleanup:{...base.cleanup,owned_pid_terminated:false}});");
  try{
   const job=await f.service.jobs.wait((await submitBinaryTrace(f.service,{file:f.file,tool:f.tool,plan:f.plan})).job_id);
   expect(job.status).toBe('failed');const result:any=await f.service.getResult(job.result_id!);expect(result.error.code).toBe('NATIVE_TRACE_CLEANUP_INCOMPLETE');
  }finally{await f.service.close();}
 });
 it.each([
  ['unassigned Job',"reply({cleanup:{...base.cleanup,windows_job_assigned:false}});",'NATIVE_TRACE_CLEANUP_INCOMPLETE'],
  ['unclosed Job',"reply({cleanup:{...base.cleanup,windows_job_closed:false}});",'NATIVE_TRACE_CLEANUP_INCOMPLETE'],
  ['contradictory success',"reply({error:{code:'HOOK_FAILED',message:'fixture'}});",'NATIVE_TRACE_PROTOCOL_INVALID'],
  ['missing source identities',"reply({identities:null});",'NATIVE_TRACE_PROTOCOL_INVALID'],
  ['unknown phase',"reply({snapshots:[initial,{...final,phase:'recovered-and-verified'}]});",'NATIVE_TRACE_OUTPUT_INVALID'],
  ['duplicate observation',"reply({snapshots:[initial,final,final]});",'NATIVE_TRACE_OUTPUT_INVALID'],
  ['missing initial observation',"reply({snapshots:[final]});",'NATIVE_TRACE_OUTPUT_INVALID'],
  ['unplanned breakpoint phase',"reply({snapshots:[initial,final,{...final,phase:'breakpoint-1001'}]});",'NATIVE_TRACE_OUTPUT_INVALID'],
  ['changed agent source',"await writeFile('trace-agent.js','changed after reported hash','utf8');reply({});",'NATIVE_TRACE_OUTPUT_INVALID'],
 ])('rejects %s without promoting the trace',async(_label,body,code)=>{
  const f=await fixture(body);
  try{
   const job=await f.service.jobs.wait((await submitBinaryTrace(f.service,{file:f.file,tool:f.tool,plan:f.plan})).job_id);
   expect(job.status).toBe('failed');const result:any=await f.service.getResult(job.result_id!);
   expect(result.error.code).toBe(code);expect(result.trace_artifact).toBeTruthy();expect(result.outputs).toEqual([]);
  }finally{await f.service.close();}
 });
 it.each([false,true])('retains interrupted checkpoint evidence and diagnoses missing files (%s)',async missingCapture=>{
  const f=await fixture("const b=Buffer.alloc(16,67);await writeFile('capture-0001.bin',b,{flag:'wx'});await writeFile('trace-checkpoint.json',JSON.stringify({...base,status:'failed',error:{code:'INTERRUPTED',message:'collection in progress'},is_checkpoint:true,checkpoint_sequence:7,omitted_events_complete:false,hook_states_complete:false,snapshots:[{rva:'0x1000',size_bytes:16,phase:'initial',file:'capture-0001.bin',sha256:createHash('sha256').update(b).digest('hex')}],cleanup:{owned_pid_terminated:false,session_detached:false,windows_job_assigned:true,windows_job_closed:false}}),'utf8');await writeFile(process.argv[2],'ready','utf8');setInterval(()=>{},1000);");
  const ready=path.join(f.root,'checkpoint-ready.txt');f.tool.args.push(ready);
  try{
   const submitted=await submitBinaryTrace(f.service,{file:f.file,tool:f.tool,plan:{...f.plan,duration_ms:60000}});
   const deadline=Date.now()+10000;while(!existsSync(ready)&&Date.now()<deadline)await new Promise(resolve=>setTimeout(resolve,20));
   expect(existsSync(ready)).toBe(true);
   if(missingCapture){
    const pending=await f.service.jobs.get(submitted.job_id);expect(pending.status).toBe('running');
    const work=await f.service.store.resolveRelative('.binary-work');
    const {readdir}=await import('node:fs/promises');
    const [directory]=await readdir(work);expect(directory).toBeTruthy();
    await rm(path.join(work,directory!,'capture-0001.bin'));
   }
   await f.service.jobs.cancel(submitted.job_id);
   const job=await f.service.jobs.wait(submitted.job_id);expect(job.status).toBe('cancelled');
   const result:any=await f.service.getResult(job.result_id!);expect(result.error.code).toBe('CANCELLED');
   expect(result.trace_recovery).toMatchObject({source:'checkpoint',is_checkpoint:true,checkpoint_sequence:7});
   if(missingCapture){
    expect(result.snapshots).toHaveLength(0);
    const logs=await Promise.all(result.logs.map(async(ref:any)=>(await f.service.store.readArtifact(ref)).toString('utf8')));
    expect(logs.join('\n')).toContain('trace_checkpoint_recovery_failed');
   }else{
    expect(result.snapshots).toHaveLength(1);expect(await f.service.store.readArtifact(result.snapshots[0].artifact)).toEqual(Buffer.alloc(16,67));
   }
   expect(result.trace_code_artifacts).toHaveLength(2);
   const exported=await exportReport(f.service.store,job.result_id!,path.join(f.root,'cancelled-trace'));
   expect(exported.candidate_module).toBe(null);expect(result.status).toBe('cancelled');
  }finally{await f.service.close();}
 },20000);
 it('exports observed JSON as evidence without following worker-injected case artifact references',async()=>{
  const payload='{"unrelated":"case-private observation"}';
  const body="const payload="+JSON.stringify(payload)+";const sha=createHash('sha256').update(payload,'utf8').digest('hex');reply({events:[{type:'untrusted-observation',payload:{relative_path:'artifacts/'+sha,sha256:sha,size_bytes:Buffer.byteLength(payload,'utf8'),media_type:'application/json'}}]});";
  const f=await fixture(body);
  try{
   const unrelated=await f.service.store.putArtifact(Buffer.from(payload,'utf8'),'application/json');
   const job=await f.service.jobs.wait((await submitBinaryTrace(f.service,{file:f.file,tool:f.tool,plan:f.plan})).job_id);expect(job.status).toBe('completed');
   const exported=await exportReport(f.service.store,job.result_id!,path.join(f.root,'isolated-observations'));
   expect(exported.files.some(file=>file.relative_path===unrelated.relative_path)).toBe(false);
  }finally{await f.service.close();}
 });
});

const scopedPlan=()=>({duration_ms:10,breakpoints_rva:[],ranges:[{module:'KERNEL32.dll',rva:'0x1000',size_bytes:4}],api_hooks:[],max_events:8});
const scopedLocation=()=>({module:'kernel32.DLL',rva:'0x1000',size_bytes:4,module_base:'0x70000000',module_size:0xf0000,address:'0x70001000'});
function scopedProtocol(rows?:unknown[]){return {schema_version:1,status:'completed',frida_version:'fixture',pid:1,events:[],
 identities:{worker:{file:'trace-worker.py',sha256:'a'.repeat(64),size_bytes:1},agent:{file:'trace-agent.js',sha256:'b'.repeat(64),size_bytes:1},frida:{version:'fixture',module_path:'explicit-fixture'}},
 snapshots:rows??[{...scopedLocation(),phase:'initial',error:'read failed'},{...scopedLocation(),phase:'final',file:'module-final.bin',sha256:'c'.repeat(64)}],
 omitted_events:0,omitted_events_complete:true,hook_states:{initial:[],current:[],final:[]},hook_states_complete:true,
 cleanup:{owned_pid_terminated:true,session_detached:true,windows_job_assigned:true,windows_job_closed:true},error:null};}

describe('module-relative native trace memory',()=>{
 it('accepts separate scopes at the same RVA and rejects unsafe or duplicate module requests',()=>{
  const valid={file:'sample.exe',tool:{command:'python'},plan:{...scopedPlan(),ranges:[...scopedPlan().ranges,{rva:'0x1000',size_bytes:4},{module:'USER32.dll',rva:'0x1000',size_bytes:4}]}};
  expect(()=>validateNativeTraceRequest(valid)).not.toThrow();
  for(const module of ['', '.', '..', '../kernel32.dll','C:\\kernel32.dll','x'.repeat(129),null,7])
   expect(()=>validateNativeTraceRequest({...valid,plan:{...scopedPlan(),ranges:[{module,rva:'0x1000',size_bytes:4}]}})).toThrow();
  expect(()=>validateNativeTraceRequest({...valid,plan:{...scopedPlan(),ranges:[...scopedPlan().ranges,{module:'kernel32.DLL',rva:'0x00001000',size_bytes:4}]}})).toThrow();
  expect(()=>validateNativeTraceRequest({...valid,plan:{...scopedPlan(),ranges:[{module:'KERNEL32.dll',rva:'0xffffffff',size_bytes:2}]}})).toThrow();
  expect(()=>validateNativeTraceRequest({...valid,plan:{...scopedPlan(),ranges:Array.from({length:5},(_,i)=>({module:'KERNEL32.dll',rva:'0x'+(i*1048576).toString(16),size_bytes:1048576}))}})).toThrow();
 });
 it('validates case-insensitive scoped observations and keeps same-RVA scopes distinct',()=>{
  const plan={...scopedPlan(),ranges:[...scopedPlan().ranges,{rva:'0x1000',size_bytes:4}]};
  const raw=scopedProtocol();raw.snapshots.push({rva:'0x1000',size_bytes:4,phase:'initial',error:'main unavailable'},{rva:'0x1000',size_bytes:4,phase:'final',error:'main unavailable'});
  expect(()=>validateTraceProtocol(raw,plan)).not.toThrow();
 });
 it.each([
  ['unrequested module',{module:'USER32.dll'}],['missing base',{module_base:undefined}],['zero base',{module_base:'0x0'}],
  ['negative base',{module_base:'-1'}],['numeric base',{module_base:1879048192}],['zero module size',{module_size:0}],
  ['too-large module size',{module_size:0x100000000}],['fractional module size',{module_size:4096.5}],
  ['mismatched address',{address:'0x70001001'}],['null success address',{address:null}],['missing success address',{address:undefined}],
  ['read outside module',{module_size:0x1003}],['overflowing module interval',{module_base:'0xfffffffffffffff0',address:'0xfffffffffffffff0'}],
  ['unscoped metadata injection',{module:undefined}],
 ])('rejects %s instead of retaining unbound module bytes',(_label,changes)=>{
  const raw=scopedProtocol();raw.snapshots[1]={...scopedLocation(),phase:'final',file:'module-final.bin',sha256:'c'.repeat(64),...changes};
  expect(()=>validateTraceProtocol(raw,scopedPlan())).toThrow();
 });
 it('requires explicit nulls when the requested module is unavailable and accepts loaded-range errors',()=>{
  const absent={module:'KERNEL32.dll',rva:'0x1000',size_bytes:4,module_base:null,module_size:null,address:null,phase:'initial',error:'module not loaded'};
  expect(()=>validateTraceProtocol(scopedProtocol([absent,{...scopedLocation(),phase:'final',error:'volatile read failed'}]),scopedPlan())).not.toThrow();
  expect(()=>validateTraceProtocol(scopedProtocol([{...absent,module_size:8192},{...scopedLocation(),phase:'final',error:'failed'}]),scopedPlan())).toThrow();
  expect(()=>validateTraceProtocol(scopedProtocol([{...scopedLocation(),module_size:4096,address:null,phase:'initial',error:'out of module'},{...scopedLocation(),phase:'final',error:'failed'}]),scopedPlan())).not.toThrow();
 });
 it('rejects module metadata on an unscoped main-image observation',()=>{
  const plan={...scopedPlan(),ranges:[{rva:'0x1000',size_bytes:4}]};
  const raw=scopedProtocol([{rva:'0x1000',size_bytes:4,phase:'initial',module_base:'0x70000000',error:'injected provenance'},{rva:'0x1000',size_bytes:4,phase:'final',error:'unavailable'}]);
  expect(()=>validateTraceProtocol(raw,plan)).toThrow();
 });
 it('uses the inspected target pointer width instead of accepting a 64-bit location for an x86 target',()=>{
  const row={...scopedLocation(),module_base:'0x100000000',address:'0x100001000',phase:'final',file:'module-final.bin',sha256:'c'.repeat(64)};
  const raw=scopedProtocol([{...row,phase:'initial',error:'read failed',file:undefined,sha256:undefined},row]);
  delete (raw.snapshots[0] as any).file;delete (raw.snapshots[0] as any).sha256;
  expect(()=>validateTraceProtocol(raw,scopedPlan(),32)).toThrow();
  expect(()=>validateTraceProtocol(raw,scopedPlan(),64)).not.toThrow();
 });
 it('uses phase-local loaded bases outside the main image and preserves them in portable export',async()=>{
  const f=await fixture("const snapshots=[];for(const [phase,module_base]of[['initial','0x70000000'],['final','0x71000000']]){const b=Buffer.from([1,2,3,4]),file='module-'+phase+'.bin';await writeFile(file,b,{flag:'wx'});snapshots.push({module:'kernel32.DLL',rva:'0x817fc',size_bytes:4,phase,module_base,module_size:0xf0000,address:'0x'+(BigInt(module_base)+0x817fcn).toString(16),file,sha256:createHash('sha256').update(b).digest('hex')});}reply({snapshots});");
  try{
   const job=await f.service.jobs.wait((await submitBinaryTrace(f.service,{file:f.file,tool:f.tool,plan:{...scopedPlan(),ranges:[{module:'KERNEL32.dll',rva:'0x817fc',size_bytes:4}]}})).job_id);
   expect(job.status).toBe('completed');const result:any=await f.service.getResult(job.result_id!);
   expect(result.snapshots.map((row:any)=>({module:row.module,base:row.module_base,size:row.module_size,address:row.address}))).toEqual([
    {module:'kernel32.DLL',base:'0x70000000',size:0xf0000,address:'0x700817fc'},
    {module:'kernel32.DLL',base:'0x71000000',size:0xf0000,address:'0x710817fc'}]);
   expect(result.outputs).toEqual([]);expect(result.validation.runnable_verified).toBe(false);
   const out=path.join(f.root,'portable-modules');await exportReport(f.service.store,job.result_id!,out);
   const saved=JSON.parse(await readFile(path.join(out,'result.json'),'utf8'));expect(saved.snapshots).toEqual(result.snapshots);
   const checked=await runProcess(process.execPath,[path.join(out,'verify.mjs')],{timeout_ms:10000});expect(checked.code).toBe(0);expect(JSON.parse(checked.stdout).target_execution).toBe('not_run');
  }finally{await f.service.close();}
 });
 it('binds module protocol locations to the actual inspected x86 target',async()=>{
  const f=await fixture("const b=Buffer.from([1,2,3,4]);await writeFile('module-invalid-width.bin',b,{flag:'wx'});const row={module:'KERNEL32.dll',rva:'0x1000',size_bytes:4,module_base:'0x100000000',module_size:0xf0000,address:'0x100001000'};reply({snapshots:[{...row,phase:'initial',error:'read unavailable'},{...row,phase:'final',file:'module-invalid-width.bin',sha256:createHash('sha256').update(b).digest('hex')}]});");
  try{
   const job=await f.service.jobs.wait((await submitBinaryTrace(f.service,{file:f.file,tool:f.tool,plan:scopedPlan()})).job_id);
   expect(job.status).toBe('failed');const result:any=await f.service.getResult(job.result_id!);
   expect(result.error.code).toBe('NATIVE_TRACE_OUTPUT_INVALID');expect(result.snapshots).toEqual([]);expect(result.trace_artifact).toBeTruthy();expect(result.validation.runnable_verified).toBe(false);
  }finally{await f.service.close();}
 });
 it('retains scoped checkpoint bytes and location after cancellation',async()=>{
  const f=await fixture("const b=Buffer.from([5,6,7,8]);await writeFile('module-checkpoint.bin',b,{flag:'wx'});await writeFile('trace-checkpoint.json',JSON.stringify({...base,status:'failed',error:{code:'INTERRUPTED',message:'collection in progress'},is_checkpoint:true,checkpoint_sequence:7,omitted_events_complete:false,hook_states_complete:false,snapshots:[{module:'KERNEL32.dll',module_base:'0x70000000',module_size:0xf0000,address:'0x700817fc',rva:'0x817fc',size_bytes:4,phase:'initial',file:'module-checkpoint.bin',sha256:createHash('sha256').update(b).digest('hex')}],cleanup:{owned_pid_terminated:false,session_detached:false,windows_job_assigned:true,windows_job_closed:false}}),'utf8');await writeFile(process.argv[2],'ready','utf8');setInterval(()=>{},1000);");
  const ready=path.join(f.root,'module-ready.txt');f.tool.args.push(ready);
  try{
   const submitted=await submitBinaryTrace(f.service,{file:f.file,tool:f.tool,plan:{...scopedPlan(),duration_ms:60000,ranges:[{module:'KERNEL32.dll',rva:'0x817fc',size_bytes:4}]}});
   const deadline=Date.now()+10000;while(!existsSync(ready)&&Date.now()<deadline)await new Promise(resolve=>setTimeout(resolve,20));expect(existsSync(ready)).toBe(true);
   await f.service.jobs.cancel(submitted.job_id);const job=await f.service.jobs.wait(submitted.job_id);expect(job.status).toBe('cancelled');
   const result:any=await f.service.getResult(job.result_id!);expect(result.trace_recovery.source).toBe('checkpoint');
   expect(result.snapshots[0]).toMatchObject({module:'KERNEL32.dll',module_base:'0x70000000',module_size:0xf0000,address:'0x700817fc'});
   expect(await f.service.store.readArtifact(result.snapshots[0].artifact)).toEqual(Buffer.from([5,6,7,8]));expect(result.validation.runnable_verified).toBe(false);
  }finally{await f.service.close();}
 },20000);
});

import {afterEach,describe,expect,it} from 'vitest';
import {mkdtemp,mkdir,readFile,readdir,realpath,rm,writeFile} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {runInNewContext} from 'node:vm';
import {createHash} from 'node:crypto';
import {runProcess} from '../src/process.js';

const worker=fileURLToPath(new URL('../tools/native-trace/worker.py',import.meta.url));
const owned:string[]=[];
afterEach(async()=>{
 for(const directory of owned.splice(0)){
  const resolved=await realpath(directory);const temporaryRoot=await realpath(tmpdir());
  if(path.dirname(resolved)!==temporaryRoot||!path.basename(resolved).startsWith('wirefit-trace-worker-'))throw new Error('Refusing cleanup outside owned temporary directory');
  await rm(resolved,{recursive:true,force:true});
 }
});
async function fixture(){
 const directory=await mkdtemp(path.join(tmpdir(),'wirefit-trace-worker-'));owned.push(directory);
 const modules=path.join(directory,'empty-modules');await mkdir(modules);
 const target=path.join(directory,'测试-stage.exe');await writeFile(target,'fixture; never executed','utf8');
 const input={schema_version:1,target,duration_ms:1,breakpoints_rva:[],ranges:[],api_hooks:[],max_events:4};
 const invoke=async(value:unknown=input,raw?:string)=>{
  const execution=await runProcess(process.env['WIREFIT_PYTHON']??'python',['-X','utf8','-I','-S',worker,'--module-path',modules],{cwd:directory,input:raw??JSON.stringify(value),timeout_ms:10000});
  expect(execution.stdout.trim(),'worker must emit a structured failure even before Frida is available').not.toBe('');
  expect(execution.stdout.trim().split('\n')).toHaveLength(1);
  const result=JSON.parse(execution.stdout);
  expect(execution.code).not.toBe(0);expect(result.status).toBe('failed');
  expect(result.cleanup.owned_pid_terminated).toBe(false);expect(result.cleanup.session_detached).toBe(false);
  expect(result.pid).toBeNull();expect(result.events).toEqual([]);expect(result.snapshots).toEqual([]);
  expect(await readFile(target,'utf8')).toBe('fixture; never executed');
  const expected=['empty-modules','测试-stage.exe'];
  if(result.identities?.worker)expected.push('trace-worker.py','trace-agent.js','trace-checkpoint.json');
  expect((await readdir(directory)).sort()).toEqual(expected.sort());
  return result;
 };
 return {input,invoke,target,directory};
}
async function pythonCollector(directory:string,body:string,value:unknown={}){
 const code="import json,sys;from pathlib import Path;ns={'__name__':'worker_test'};exec(compile(Path(sys.argv[1]).read_text(encoding='utf-8'),sys.argv[1],'exec'),ns);value=json.loads(sys.stdin.read());"+body;
 const execution=await runProcess(process.env['WIREFIT_PYTHON']??'python',['-X','utf8','-I','-S','-c',code,worker],{cwd:directory,input:JSON.stringify(value),timeout_ms:10000});
 expect(execution.code,execution.stderr).toBe(0);return JSON.parse(execution.stdout);
}

describe('native trace Python worker boundary without target execution',()=>{
 it.each(['{','null','[]','{"schema_version":1,"schema_version":1}','{"schema_version":1,"target":"\\ud800"}','{"schema_version":1,"target":1e999}'])('rejects malformed or non-object protocol input (%#)',async raw=>{
  const {invoke}=await fixture();const result=await invoke(undefined,raw);
  expect(result.error.code).toBe('PROTOCOL_ERROR');
 });
 it.each([
  {duration_ms:0},{duration_ms:60001},{duration_ms:true},{max_events:0},{max_events:513},
  {schema_version:2},{target:'relative.exe'},{target:'C:\\bad\u0000.exe'},
  {breakpoints_rva:['0x1','0x2','0x3','0x4','0x5']},{breakpoints_rva:['0x1','0x01']},
  {breakpoints_rva:['-0x1']},{breakpoints_rva:['0x100000000']},
  {ranges:[{rva:'0x1000',size_bytes:0}]},{ranges:[{rva:'0x1000',size_bytes:true}]},
  {ranges:[{rva:'0xffffffff',size_bytes:2}]},
  {ranges:Array.from({length:5},(_,i)=>({rva:'0x'+(i*0x100000).toString(16),size_bytes:1048576}))},
  {ranges:Array.from({length:9},(_,i)=>({module:'m'+i+'.dll',rva:'0x0',size_bytes:1}))},
  {ranges:Array.from({length:5},(_,i)=>({module:'m'+i+'.dll',rva:'0x0',size_bytes:1048576}))},
  {api_hooks:[{module:'../ntdll.dll',symbol:'NtProtectVirtualMemory'}]},
  {api_hooks:[{module:'ntdll.dll',symbol:''}]},
  {api_hooks:Array.from({length:17},()=>({module:'ntdll.dll',symbol:'NtProtectVirtualMemory'}))},
  {unexpected:'ignored fields must fail'},
 ])('rejects invalid limits and addresses before importing Frida (%#)',async patch=>{
  const {input,invoke}=await fixture();const result=await invoke({...input,...patch});
  expect(result.error.code).toBe('INVALID_REQUEST');
 });
 it('fails explicitly for absent target without touching the target fixture',async()=>{
  const {input,invoke,directory}=await fixture();const result=await invoke({...input,target:path.join(directory,'missing.exe')});
  expect(result.error.code).toBe('INVALID_TARGET');
 });
 it('reports a missing isolated Frida dependency without spawning the staged file',async()=>{
  const {invoke,directory}=await fixture();const result=await invoke();
  expect(result.error.code).toBe('FRIDA_UNAVAILABLE');expect(result.frida_version).toBeNull();
  expect(result.identities.frida).toBeNull();
  for(const [key,name] of [['worker','trace-worker.py'],['agent','trace-agent.js']]){
   const text=await readFile(path.join(directory,name!),'utf8');
   expect(result.identities[key!]).toEqual({file:name,sha256:createHash('sha256').update(text,'utf8').digest('hex'),size_bytes:Buffer.byteLength(text,'utf8')});
  }
  const checkpoint=JSON.parse(await readFile(path.join(directory,'trace-checkpoint.json'),'utf8'));
  expect(checkpoint.is_checkpoint).toBe(false);expect(checkpoint.error.code).toBe('FRIDA_UNAVAILABLE');
  expect(checkpoint.identities).toEqual(result.identities);expect(checkpoint.status).toBe('failed');
 });
 it('accepts scoped ranges and the same RVA in distinct scopes without loading Frida',async()=>{
  const {input,invoke}=await fixture();
  const result=await invoke({...input,ranges:[{rva:'0x0010',size_bytes:3},{module:'QtCore4.dll',rva:'0x10',size_bytes:3},{module:'MSVCR71.dll',rva:'0x10',size_bytes:3}]});
  expect(result.error.code).toBe('FRIDA_UNAVAILABLE');
 });
 it.each([
  [{module:'QtCore4.dll',rva:'0x10',size_bytes:3},{module:'qtcore4.DLL',rva:'0x0010',size_bytes:3}],
  [{rva:'0x10',size_bytes:3},{rva:'0x0010',size_bytes:3}],
  [{module:'../QtCore4.dll',rva:'0x10',size_bytes:3}],
  [{module:'..',rva:'0x10',size_bytes:3}],
  [{module:null,rva:'0x10',size_bytes:3}],
 ].map(ranges=>({ranges})))('rejects unsafe scoped names and duplicate normalized range identities (%#)',async({ranges})=>{
  const {input,invoke}=await fixture();expect((await invoke({...input,ranges})).error.code).toBe('INVALID_REQUEST');
 });
 it('preserves scoped success and explicit unavailable final metadata',async()=>{
  const {directory}=await fixture();
  const result=await pythonCollector(directory,"result=ns['initial_result']();collector=ns['Collector'](value,result);collector.snapshot({'phase':'initial','range_index':0,'rva':'0x10','size_bytes':3,'module':'qtcore4.DLL','module_base':'0x65000000','module_size':65536,'address':'0x65000010'},b'abc');collector.missing_final_snapshots();print(json.dumps(result))",{max_events:1,breakpoints_rva:[],ranges:[{module:'QtCore4.dll',rva:'0x10',size_bytes:3}]});
  expect(result.snapshots).toHaveLength(2);
  expect(result.snapshots[0]).toMatchObject({module:'QtCore4.dll',module_base:'0x65000000',module_size:65536,address:'0x65000010',file:'memory-initial-00.bin'});
  expect(result.snapshots[1]).toMatchObject({module:'QtCore4.dll',module_base:null,module_size:null,address:null,phase:'final',error:expect.any(String)});
  expect(result.snapshots[1]).not.toHaveProperty('file');expect(result.snapshots[1]).not.toHaveProperty('sha256');
 });
 it.each([
  {module:'injected.dll'}, {module:undefined}, {module_base:undefined}, {module_size:true},
  {address:'0x65000011'}, {module_base:'0x0'}, {module_base:'0xfffffffffffffff0',address:'0x0',module_size:65536},
  {module_size:16,address:'0x65000010'}, {module_size:0x100000000},
 ])('rejects inconsistent scoped metadata before creating a memory artifact (%#)',async patch=>{
  const {directory}=await fixture();
  const payload={kind:'snapshot',phase:'initial',range_index:0,rva:'0x10',size_bytes:3,module:'QtCore4.dll',module_base:'0x65000000',module_size:65536,address:'0x65000010',...patch};
  const result=await pythonCollector(directory,"result=ns['initial_result']();collector=ns['Collector'](value['config'],result);collector.on_message({'type':'send','payload':value['payload']},b'abc');print(json.dumps({'failure':None if collector.failure is None else collector.failure.code,'snapshots':result['snapshots']}))",{config:{max_events:1,breakpoints_rva:[],ranges:[{module:'QtCore4.dll',rva:'0x10',size_bytes:3}]},payload});
  expect(result).toEqual({failure:'AGENT_PROTOCOL_ERROR',snapshots:[]});expect((await readdir(directory)).filter(name=>name.startsWith('memory-'))).toEqual([]);
 });
 it('rejects module metadata injected into an unscoped snapshot',async()=>{
  const {directory}=await fixture();
  const result=await pythonCollector(directory,"result=ns['initial_result']();collector=ns['Collector']({'max_events':1,'breakpoints_rva':[],'ranges':[{'rva':'0x10','size_bytes':3}]},result);collector.on_message({'type':'send','payload':{'kind':'snapshot','phase':'initial','range_index':0,'rva':'0x10','size_bytes':3,'module':'evil.dll','module_base':'0x500000','module_size':65536,'address':'0x500010'}},b'abc');print(json.dumps({'failure':None if collector.failure is None else collector.failure.code,'snapshots':result['snapshots']}))");
  expect(result).toEqual({failure:'AGENT_PROTOCOL_ERROR',snapshots:[]});
 });
 it.each([
  {module_base:null,module_size:null,address:null,error:'Module not loaded'},
  {module_base:'0x65000000',module_size:16,address:null,error:'Range exceeds module'},
  {module_base:'0x65000000',module_size:65536,address:'0x65000010',error:'Memory is inaccessible'},
 ])('preserves explicit scoped error metadata without inventing captured bytes (%#)',async metadata=>{
  const {directory}=await fixture();
  const payload={kind:'snapshot',phase:'initial',range_index:0,rva:'0x10',size_bytes:3,module:'QtCore4.dll',...metadata};
  const result=await pythonCollector(directory,"result=ns['initial_result']();collector=ns['Collector'](value['config'],result);collector.on_message({'type':'send','payload':value['payload']},None);print(json.dumps({'failure':None if collector.failure is None else collector.failure.code,'snapshots':result['snapshots']}))",{config:{max_events:1,breakpoints_rva:[],ranges:[{module:'QtCore4.dll',rva:'0x10',size_bytes:3}]},payload});
  expect(result.failure).toBeNull();expect(result.snapshots).toEqual([{rva:'0x10',size_bytes:3,module:'QtCore4.dll',phase:'initial',...metadata}]);
  expect((await readdir(directory)).filter(name=>name.startsWith('memory-'))).toEqual([]);
 });
 it.each([
  {module_base:null,module_size:65536,address:null,error:'Unknown module'},
  {module_base:null,module_size:null,address:'0x65000010',error:'Unknown module'},
  {module_base:'0x65000000',module_size:16,address:'0x65000010',error:'Out of bounds'},
  {module_base:'0x65000000',module_size:65536,address:'0x65000011',error:'Wrong address'},
  {module_base:null,module_size:null,address:null,error:'',file:'injected.bin'},
  {module_base:null,module_size:null,address:null,error:'Unknown module',sha256:'a'.repeat(64)},
 ])('rejects invalid scoped error rows before retaining evidence (%#)',async metadata=>{
  const {directory}=await fixture();
  const result=await pythonCollector(directory,"result=ns['initial_result']();collector=ns['Collector'](value['config'],result);collector.on_message({'type':'send','payload':value['payload']},None);print(json.dumps({'failure':None if collector.failure is None else collector.failure.code,'snapshots':result['snapshots']}))",{config:{max_events:1,breakpoints_rva:[],ranges:[{module:'QtCore4.dll',rva:'0x10',size_bytes:3}]},payload:{kind:'snapshot',phase:'initial',range_index:0,rva:'0x10',size_bytes:3,module:'QtCore4.dll',...metadata}});
  expect(result).toEqual({failure:'AGENT_PROTOCOL_ERROR',snapshots:[]});
 });
 it('preserves scoped address metadata when exclusive output creation fails',async()=>{
  const {directory}=await fixture();await writeFile(path.join(directory,'memory-initial-00.bin'),'old','utf8');
  const result=await pythonCollector(directory,"result=ns['initial_result']();collector=ns['Collector'](value,result);collector.on_message({'type':'send','payload':{'kind':'snapshot','phase':'initial','range_index':0,'rva':'0x10','size_bytes':3,'module':'QtCore4.dll','module_base':'0x65000000','module_size':65536,'address':'0x65000010'}},b'abc');print(json.dumps({'failure':collector.failure.code,'snapshots':result['snapshots']}))",{max_events:1,breakpoints_rva:[],ranges:[{module:'QtCore4.dll',rva:'0x10',size_bytes:3}]});
  expect(result.failure).toBe('SNAPSHOT_WRITE_FAILED');expect(result.snapshots[0]).toMatchObject({module_base:'0x65000000',module_size:65536,address:'0x65000010',error:expect.any(String)});
  expect(result.snapshots[0]).not.toHaveProperty('file');expect(result.snapshots[0]).not.toHaveProperty('sha256');expect(await readFile(path.join(directory,'memory-initial-00.bin'),'utf8')).toBe('old');
 });
 it('accepts a valid 64-bit module ending at the exclusive pointer limit',async()=>{
  const {directory}=await fixture();
  const result=await pythonCollector(directory,"result=ns['initial_result']();collector=ns['Collector'](value,result);collector.on_message({'type':'send','payload':{'kind':'snapshot','phase':'initial','range_index':0,'rva':'0xfffd','size_bytes':3,'module':'high.dll','module_base':'0xffffffffffff0000','module_size':65536,'address':'0xfffffffffffffffd'}},b'abc');print(json.dumps({'failure':None if collector.failure is None else collector.failure.code,'snapshots':result['snapshots']}))",{max_events:1,breakpoints_rva:[],ranges:[{module:'high.dll',rva:'0xfffd',size_bytes:3}]});
  expect(result.failure).toBeNull();expect(result.snapshots[0].address).toBe('0xfffffffffffffffd');
 });
 it('retains all 48 separately scoped observations within a bounded checkpoint',async()=>{
  const {directory}=await fixture();
  const result=await pythonCollector(directory,"result=ns['initial_result']();checkpoint=ns['Checkpoint'](result);collector=ns['Collector'](value,result,checkpoint);phases=['initial','breakpoint-1','breakpoint-2','breakpoint-3','breakpoint-4','final'];[collector.snapshot({'phase':phase,'range_index':index,**entry,'module_base':'0x65000000','module_size':65536,'address':'0x65000010'},b'abc') for phase in phases for index,entry in enumerate(value['ranges'])];saved=json.loads(Path('trace-checkpoint.json').read_text(encoding='utf-8'));print(json.dumps({'snapshots':saved['snapshots'],'bytes':Path('trace-checkpoint.json').stat().st_size}))",{max_events:1,breakpoints_rva:['0x1','0x2','0x3','0x4'],ranges:Array.from({length:8},(_,i)=>({module:'m'+i+'.dll',rva:'0x10',size_bytes:3}))});
  expect(result.snapshots).toHaveLength(48);expect(result.bytes).toBeLessThan(4194304);expect(result.snapshots.every((row:any)=>row.module_base==='0x65000000'&&row.address==='0x65000010')).toBe(true);
 });
 it('bounds stdin before JSON parsing',async()=>{
  const {invoke}=await fixture();const result=await invoke(undefined,' '.repeat(65537));
  expect(result.error.code).toBe('PROTOCOL_ERROR');
 });
 it.skipIf(process.platform!=='win32')('creates and closes the kill-on-close Windows Job without opening any process',async()=>{
  const {directory}=await fixture();
  const code="import json,sys;from pathlib import Path;ns={'__name__':'worker_test'};exec(compile(Path(sys.argv[1]).read_text(encoding='utf-8'),sys.argv[1],'exec'),ns);job=ns['WindowsJob']();print(json.dumps(job.close()))";
  const result=await runProcess(process.env['WIREFIT_PYTHON']??'python',['-X','utf8','-I','-S','-c',code,worker],{cwd:directory,timeout_ms:10000});
  expect(result.code).toBe(0);expect(JSON.parse(result.stdout)).toEqual({owned_pid_terminated:false,windows_job_assigned:false,windows_job_closed:true,errors:[]});
 });
 it('refuses snapshot file collisions and never overwrites prior bytes',async()=>{
  const {directory}=await fixture();await writeFile(path.join(directory,'memory-initial-00.bin'),'prior evidence','utf8');
  const code="import json,sys;from pathlib import Path;ns={'__name__':'worker_test'};exec(compile(Path(sys.argv[1]).read_text(encoding='utf-8'),sys.argv[1],'exec'),ns);result={'events':[],'snapshots':[]};collector=ns['Collector']({'max_events':1,'breakpoints_rva':[],'ranges':[{'rva':'0x10','size_bytes':1}]},result);collector.on_message({'type':'send','payload':{'kind':'snapshot','phase':'initial','range_index':0,'rva':'0x10','size_bytes':1}},b'x');print(json.dumps({'failure':collector.failure.code,'snapshots':result['snapshots']}))";
  const execution=await runProcess(process.env['WIREFIT_PYTHON']??'python',['-X','utf8','-I','-S','-c',code,worker],{cwd:directory,timeout_ms:10000});
  expect(execution.code).toBe(0);const result=JSON.parse(execution.stdout);expect(result.failure).toBe('SNAPSHOT_WRITE_FAILED');
  expect(result.snapshots[0].phase).toBe('initial');expect(result.snapshots[0].error).toBeTypeOf('string');
  expect(await readFile(path.join(directory,'memory-initial-00.bin'),'utf8')).toBe('prior evidence');
 });
 it('retains a validated checkpoint and snapshot chain when a pure Python collector is killed',async()=>{
  const {directory}=await fixture();
  const code="import json,sys,threading;from pathlib import Path;ns={'__name__':'worker_test'};exec(compile(Path(sys.argv[1]).read_text(encoding='utf-8'),sys.argv[1],'exec'),ns);result=ns['initial_result']();checkpoint=ns['Checkpoint'](result);collector=ns['Collector']({'max_events':16,'breakpoints_rva':[],'ranges':[{'module':'QtCore4.dll','rva':'0x10','size_bytes':3}],'api_hooks':[]},result,checkpoint);[collector.event({'type':'recorded','index':i}) for i in range(8)];collector.snapshot({'phase':'initial','range_index':0,'rva':'0x10','size_bytes':3,'module':'QtCore4.dll','module_base':'0x65000000','module_size':65536,'address':'0x65000010'},b'abc');threading.Event().wait(60)";
  await expect(runProcess(process.env['WIREFIT_PYTHON']??'python',['-X','utf8','-I','-S','-c',code,worker],{cwd:directory,timeout_ms:1500})).rejects.toMatchObject({code:'TIMEOUT'});
  const checkpoint=JSON.parse(await readFile(path.join(directory,'trace-checkpoint.json'),'utf8'));
  expect(checkpoint.status).toBe('failed');expect(checkpoint.error.code).toBe('INTERRUPTED');expect(checkpoint.is_checkpoint).toBe(true);
  expect(checkpoint.events).toHaveLength(8);expect(checkpoint.omitted_events_complete).toBe(false);
  expect(checkpoint.cleanup.owned_pid_terminated).toBe(false);expect(checkpoint.snapshots).toHaveLength(1);
  expect(checkpoint.snapshots[0].sha256).toBe('ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
  expect(checkpoint.snapshots[0]).toMatchObject({module:'QtCore4.dll',module_base:'0x65000000',module_size:65536,address:'0x65000010'});
  expect(await readFile(path.join(directory,checkpoint.snapshots[0].file),'utf8')).toBe('abc');
  expect(await readdir(directory)).not.toContain('trace-checkpoint.tmp.json');
 });
 it.each(['trace-checkpoint.json','trace-checkpoint.tmp.json'])('refuses a pre-existing %s without changing its contents',async name=>{
  const {directory,input}=await fixture();const checkpoint=path.join(directory,name);await writeFile(checkpoint,'prior evidence','utf8');
  const execution=await runProcess(process.env['WIREFIT_PYTHON']??'python',['-X','utf8','-I','-S',worker,'--module-path',path.join(directory,'empty-modules')],{cwd:directory,input:JSON.stringify(input),timeout_ms:10000});
  expect(execution.code).toBe(1);expect(JSON.parse(execution.stdout).error.code).toBe('CHECKPOINT_COLLISION');
  expect(await readFile(checkpoint,'utf8')).toBe('prior evidence');
 });
 it('keeps a terminal receipt immutable when a late active checkpoint is requested',async()=>{
  const {directory}=await fixture();
  const code="import json,sys;from pathlib import Path;ns={'__name__':'worker_test'};exec(compile(Path(sys.argv[1]).read_text(encoding='utf-8'),sys.argv[1],'exec'),ns);result=ns['initial_result']();checkpoint=ns['Checkpoint'](result);result.update(error={'code':'CONTROLLED','message':'terminal failure'});checkpoint.flush(terminal=True);result['events'].append({'type':'late'});checkpoint.flush();print(Path('trace-checkpoint.json').read_text(encoding='utf-8'))";
  const execution=await runProcess(process.env['WIREFIT_PYTHON']??'python',['-X','utf8','-I','-S','-c',code,worker],{cwd:directory,timeout_ms:10000});
  expect(execution.code).toBe(0);const checkpoint=JSON.parse(execution.stdout);
  expect(checkpoint.is_checkpoint).toBe(false);expect(checkpoint.error.code).toBe('CONTROLLED');expect(checkpoint.events).toEqual([]);expect(checkpoint.checkpoint_sequence).toBe(2);
 });
 it('fails the cumulative event budget while retaining a bounded, readable checkpoint',async()=>{
  const {directory}=await fixture();
  const code="import json,sys;from pathlib import Path;ns={'__name__':'worker_test'};exec(compile(Path(sys.argv[1]).read_text(encoding='utf-8'),sys.argv[1],'exec'),ns);result=ns['initial_result']();checkpoint=ns['Checkpoint'](result);collector=ns['Collector']({'max_events':512,'breakpoints_rva':[],'ranges':[],'api_hooks':[]},result,checkpoint);[collector.on_message({'type':'send','payload':{'kind':'event','event':{'type':'bounded','text':'x'*20000,'index':i}}},None) for i in range(180)];saved=json.loads(Path('trace-checkpoint.json').read_text(encoding='utf-8'));print(json.dumps({'failure':collector.failure.code,'events':len(saved['events']),'bytes':Path('trace-checkpoint.json').stat().st_size,'last_error':saved['last_error']['code']}))";
  const execution=await runProcess(process.env['WIREFIT_PYTHON']??'python',['-X','utf8','-I','-S','-c',code,worker],{cwd:directory,timeout_ms:10000});
  expect(execution.code).toBe(0);const result=JSON.parse(execution.stdout);
  expect(result.failure).toBe('RESOURCE_LIMIT');expect(result.last_error).toBe('RESOURCE_LIMIT');expect(result.events).toBeGreaterThan(100);expect(result.events).toBeLessThan(180);expect(result.bytes).toBeLessThanOrEqual(4194304);
 });
});

// These fixtures model only the official Frida boundary. The actual agent is
// evaluated, so its exception ownership, capture order and limits are exercised.
type AgentOptions={moduleLoaded?:boolean;exportPresent?:boolean;attachFails?:boolean;exportType?:string;readFails?:boolean;arch?:'ia32'|'x64';ranges?:{rva:string;size_bytes:number;module?:string}[];api_hooks?:{module:string;symbol:string}[];modules?:{name:string;base:string;size:number}[]};
async function agentFixture(maxEvents=8,options:AgentOptions={}){
 const source=await readFile(new URL('../tools/native-trace/agent.js',import.meta.url),'utf8');
 const messages:any[]=[];const armed=new Map<string,number>();let reads=0;
 class Pointer{
  raw:bigint;
  constructor(value:unknown){this.raw=BigInt.asUintN(options.arch==='x64'?64:32,value instanceof Pointer?value.raw:BigInt(value as string|number|bigint));}
  get value(){return Number(this.raw);}
  add(value:unknown){return new Pointer(this.raw+new Pointer(value).raw);}
  sub(value:unknown){return new Pointer(this.raw-new Pointer(value).raw);}
  equals(value:unknown){return this.raw===new Pointer(value).raw;}
  compare(value:unknown){const other=new Pointer(value).raw;return this.raw<other?-1:this.raw>other?1:0;}
  toUInt32(){return this.value>>>0;}
  toString(){return '0x'+this.raw.toString(16);}
  readByteArray(size:number){reads++;const value=new Uint8Array(size);if(this.value===0x800000&&size>=4)value.set([0x00,0x20,0x40,0x00]);return value.buffer;}
  readVolatile(size:number){if(options.readFails)throw Error('Controlled volatile read failure');return this.readByteArray(size);}
 }
 let exceptionHandler:(details:any)=>boolean=()=>false;
 let observer:any;let moduleObserver:any;const apiCallbacks:any[]=[];let currentThread=7;let moduleLoaded=options.moduleLoaded??true;
 const thread=(id:number)=>({id,setHardwareBreakpoint(slot:number,address:Pointer){armed.set(id+':'+slot,address.value);},unsetHardwareBreakpoint(slot:number){armed.delete(id+':'+slot);}});
 const main={name:'stage.exe',base:new Pointer(0x400000),size:0x10000};
 let modules=options.modules?.map(entry=>({...entry,base:new Pointer(entry.base)}))??[main];
 const context={pc:new Pointer(0x401000),sp:new Pointer(0x800000),eax:new Pointer(0x23),ebp:new Pointer(0x800100)};
 const rpc:any={exports:{}};
 runInNewContext(source,{rpc,ptr:(value:unknown)=>new Pointer(value),Frida:{version:'17.2.17'},send:(payload:any,data:any)=>messages.push({payload,data}),
  setInterval:()=>1,clearInterval:()=>undefined,
  Process:{platform:'windows',arch:options.arch??'ia32',pointerSize:options.arch==='x64'?8:4,mainModule:main,getCurrentThreadId:()=>currentThread,
   findModuleByAddress:()=>main,findRangeByAddress:(address:Pointer)=>({base:new Pointer(address.value>=0x800000?0x800000:0x400000),size:0x10000,protection:'rwx'}),
   findModuleByName:()=>moduleLoaded?{findExportByName:()=>options.exportPresent===false?null:new Pointer(0x500000),enumerateExports:()=>[{name:'NtProtectVirtualMemory',type:options.exportType??'function',address:new Pointer(0x500000)}]}:null,
   setExceptionHandler:(callback:any)=>{exceptionHandler=callback;},
   attachThreadObserver:(callbacks:any)=>{observer=callbacks;callbacks.onAdded(thread(7));return {detach(){}};},
   attachModuleObserver:(callbacks:any)=>{moduleObserver=callbacks;callbacks.onAdded(main);return {detach(){}};},enumerateThreads:()=>[thread(7)],enumerateModules:()=>modules},
  Interceptor:{attach:(_address:any,callbacks:any)=>{if(options.attachFails)throw new Error('controlled attach failure');apiCallbacks.push(callbacks);return {detach(){}};}}});
 rpc.exports.setup({breakpoints_rva:['0x1000'],ranges:options.ranges??[{rva:'0x2000',size_bytes:16}],api_hooks:options.api_hooks??[{module:'ntdll.dll',symbol:'NtProtectVirtualMemory'}],max_events:maxEvents});
 return {messages,armed,context,apiCallbacks,rpc,observer,reads:()=>reads,
  exception:(type:string,pc=context.pc)=>exceptionHandler({type,address:pc,memory:null,context:{...context,pc}}),
  addThread:(id:number)=>{observer.onAdded(thread(id));currentThread=id;},
  loadModule:()=>{moduleLoaded=true;moduleObserver.onAdded(main);},hasModuleObserver:()=>moduleObserver!==undefined,
  setModules:(entries:{name:string;base:string;size:number}[])=>{modules=entries.map(entry=>({...entry,base:new Pointer(entry.base)}));}};
}
describe('native trace agent against a controlled API boundary',()=>{
 it('keeps the legacy unscoped snapshot metadata shape',async()=>{
  const agent=await agentFixture(8,{api_hooks:[]});const row=agent.messages.find(value=>value.payload.kind==='snapshot');
  expect(row.payload).toEqual({kind:'snapshot',phase:'initial',range_index:0,rva:'0x2000',size_bytes:16});expect(row.data.byteLength).toBe(16);
 });
 it('resolves scoped ranges independently at each phase and follows changed ASLR bases',async()=>{
  const agent=await agentFixture(8,{api_hooks:[],ranges:[{module:'QtCore4.dll',rva:'0x20',size_bytes:3}],modules:[{name:'qtcore4.DLL',base:'0x65000000',size:65536}]});
  expect(agent.hasModuleObserver()).toBe(false);
  agent.setModules([{name:'QTCORE4.dll',base:'0x66000000',size:65536}]);expect(agent.exception('single-step')).toBe(true);
  agent.setModules([{name:'QtCore4.dll',base:'0x67000000',size:65536}]);agent.rpc.exports.finish();
  const rows=agent.messages.filter(value=>value.payload.kind==='snapshot');
  expect(rows.map(row=>row.payload)).toEqual([
   {kind:'snapshot',phase:'initial',range_index:0,rva:'0x20',size_bytes:3,module:'QtCore4.dll',module_base:'0x65000000',module_size:65536,address:'0x65000020'},
   {kind:'snapshot',phase:'breakpoint-1000',range_index:0,rva:'0x20',size_bytes:3,module:'QtCore4.dll',module_base:'0x66000000',module_size:65536,address:'0x66000020'},
   {kind:'snapshot',phase:'final',range_index:0,rva:'0x20',size_bytes:3,module:'QtCore4.dll',module_base:'0x67000000',module_size:65536,address:'0x67000020'},
  ]);expect(rows.every(row=>row.data?.byteLength===3)).toBe(true);
 });
 it.each([[],[{name:'QtCore4.dll',base:'0x65000000',size:65536},{name:'QTCORE4.DLL',base:'0x66000000',size:65536}]].map(modules=>({modules})))('records missing or ambiguous scoped modules without reading main-module bytes (%#)',async({modules})=>{
  const agent=await agentFixture(8,{api_hooks:[],ranges:[{module:'QtCore4.dll',rva:'0x20',size_bytes:3}],modules});
  const row=agent.messages.find(value=>value.payload.kind==='snapshot');
  expect(row.payload).toMatchObject({module:'QtCore4.dll',module_base:null,module_size:null,address:null,error:expect.any(String)});
  expect(row.data).toBeUndefined();expect(agent.reads()).toBe(0);expect(agent.hasModuleObserver()).toBe(false);
 });
 it('retains loaded-module bounds when a scoped read exceeds the image',async()=>{
  const agent=await agentFixture(8,{api_hooks:[],ranges:[{module:'QtCore4.dll',rva:'0x10000',size_bytes:3}],modules:[{name:'QtCore4.dll',base:'0x65000000',size:65536}]});
  const row=agent.messages.find(value=>value.payload.kind==='snapshot');
  expect(row.payload).toMatchObject({module:'QtCore4.dll',module_base:'0x65000000',module_size:65536,address:null,error:expect.any(String)});
  expect(row.data).toBeUndefined();expect(agent.reads()).toBe(0);
 });
 it('retains the exact resolved address when a volatile read fails',async()=>{
  const agent=await agentFixture(8,{readFails:true,api_hooks:[],ranges:[{module:'QtCore4.dll',rva:'0x20',size_bytes:3}],modules:[{name:'QtCore4.dll',base:'0x65000000',size:65536}]});
  const row=agent.messages.find(value=>value.payload.kind==='snapshot');
  expect(row.payload).toMatchObject({module:'QtCore4.dll',module_base:'0x65000000',module_size:65536,address:'0x65000020',error:expect.any(String)});expect(row.data).toBeUndefined();
 });
 it('reports an unloaded module at final without reusing the initial base',async()=>{
  const agent=await agentFixture(8,{api_hooks:[],ranges:[{module:'QtCore4.dll',rva:'0x20',size_bytes:3}],modules:[{name:'QtCore4.dll',base:'0x65000000',size:65536}]});
  agent.setModules([]);agent.rpc.exports.finish();const row=agent.messages.find(value=>value.payload.kind==='snapshot'&&value.payload.phase==='final');
  expect(row.payload).toMatchObject({module:'QtCore4.dll',module_base:null,module_size:null,address:null,error:expect.any(String)});expect(row.data).toBeUndefined();
 });
 it('reads a valid high 64-bit interval without rounding its address',async()=>{
  const agent=await agentFixture(8,{arch:'x64',api_hooks:[],ranges:[{module:'high.dll',rva:'0xfffd',size_bytes:3}],modules:[{name:'high.dll',base:'0xffffffffffff0000',size:65536}]});
  const row=agent.messages.find(value=>value.payload.kind==='snapshot');
  expect(row.payload).toMatchObject({module:'high.dll',module_base:'0xffffffffffff0000',module_size:65536,address:'0xfffffffffffffffd'});expect(row.payload).not.toHaveProperty('error');expect(row.data.byteLength).toBe(3);
 });
 it.each([{arch:'ia32' as const,base:'0xfffffff0'},{arch:'x64' as const,base:'0xfffffffffffffff0'}])('rejects complete module intervals that wrap the actual pointer width (%#)',async options=>{
  const agent=await agentFixture(8,{...options,api_hooks:[],ranges:[{module:'QtCore4.dll',rva:'0x1',size_bytes:3}],modules:[{name:'QtCore4.dll',base:options.base,size:65536}]});
  const row=agent.messages.find(value=>value.payload.kind==='snapshot');
  expect(row.payload.error).toBeTypeOf('string');expect(row.payload.address).toBeNull();expect(row.data).toBeUndefined();expect(agent.reads()).toBe(0);
 });
 it('disarms only the matching thread trap and captures raw entry stack plus caller code',async()=>{
  const agent=await agentFixture();expect(agent.armed.get('7:0')).toBe(0x401000);
  expect(agent.exception('single-step')).toBe(true);expect(agent.armed.has('7:0')).toBe(false);
  const event=agent.messages.find(value=>value.payload.event?.type==='breakpoint').payload.event;
  expect(event.context.eax).toBe('0x23');expect(event.stack.size_bytes).toBe(256);
  expect(event.return_address.address).toBe('0x402000');expect(event.return_address_code.address).toBe('0x401fe0');
  expect(agent.context.pc.toString()).toBe('0x401000');expect(agent.exception('single-step')).toBe(false);
  agent.addThread(8);expect(agent.armed.get('8:0')).toBe(0x401000);expect(agent.exception('single-step')).toBe(true);
  expect(agent.messages.filter(value=>value.payload.phase==='breakpoint-1000')).toHaveLength(1);
 });
 it('forwards unrelated exceptions and caps API captures before performing memory reads',async()=>{
  const agent=await agentFixture(2);
  expect(agent.exception('access-violation')).toBe(false);
  const readsBefore=agent.reads();const callback=agent.apiCallbacks[0];
  callback.onEnter.call({threadId:7,context:agent.context,returnAddress:{toString:()=> '0x402000'}});
  expect(agent.reads()).toBe(readsBefore);
  const summary=agent.rpc.exports.finish();expect(summary.omitted_events).toBe(2);
  expect(agent.messages.filter(value=>value.payload.kind==='event')).toHaveLength(2);
  const inventories=agent.messages.filter(value=>value.payload.event?.type==='module_inventory').map(value=>value.payload.event);
  expect(inventories.map(value=>value.phase)).toEqual(['initial','final']);expect(inventories[1].modules[0].base).toBe('0x400000');
  expect(agent.messages.filter(value=>value.payload.kind==='snapshot'&&value.payload.phase==='final')).toHaveLength(1);
  expect(agent.armed.size).toBe(0);
 });
 it('records pending modules explicitly and marks unresolved hooks unobserved at finish',async()=>{
  const agent=await agentFixture(8,{moduleLoaded:false});
  const initial=agent.messages.find(value=>value.payload.kind==='hook_states'&&value.payload.phase==='initial');
  expect(initial?.payload.states[0]).toMatchObject({module:'ntdll.dll',symbol:'NtProtectVirtualMemory',status:'pending_module',observations:0});
  expect(agent.messages.some(value=>value.payload.kind==='fatal')).toBe(false);
  const final=agent.rpc.exports.finish();expect(final.hook_states[0].status).toBe('unobserved');
 });
 it('installs a pending hook when its module arrives and reports its observed call count',async()=>{
  const agent=await agentFixture(8,{moduleLoaded:false});agent.loadModule();
  expect(agent.apiCallbacks).toHaveLength(1);const callback=agent.apiCallbacks[0];
  callback.onEnter.call({threadId:7,context:agent.context,returnAddress:agent.context.pc});
  expect(agent.rpc.exports.finish().hook_states[0]).toMatchObject({status:'installed',observations:1,address:'0x500000'});
 });
 it.each([{exportPresent:false},{attachFails:true},{exportType:'variable'}])('fails explicitly for an unusable loaded-module export (%#)',async options=>{
  const agent=await agentFixture(8,options);
  expect(agent.messages.some(value=>value.payload.kind==='fatal')).toBe(true);
  const state=agent.rpc.exports.finish().hook_states[0];expect(state.status).toBe('error');expect(state.error).toBeTypeOf('string');
 });
});

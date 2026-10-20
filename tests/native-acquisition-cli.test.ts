import {afterEach,describe,expect,it} from 'vitest';
import {existsSync} from 'node:fs';
import {mkdtemp,readFile,realpath,rm,writeFile} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {runProcess} from '../src/process.js';
import {CaseStore} from '../src/store.js';

const root=path.resolve('.'),local=path.join(root,'.tools/runtime/node_modules/node-win-x64/bin/node.exe');
const runtime=process.platform==='win32'&&existsSync(local)?local:process.execPath;
const bridge=path.join(root,'src/native-acquisition-cli.ts');
const owned:string[]=[];
afterEach(async()=>{for(const directory of owned.splice(0)){
 const actual=await realpath(directory),temporary=await realpath(tmpdir());
 if(path.dirname(actual)!==temporary||!path.basename(actual).startsWith('wirefit-acquisition-cli-'))throw Error('Unsafe test cleanup path');
 await rm(actual,{recursive:true,force:true});
}});
async function temporary(){const directory=await mkdtemp(path.join(tmpdir(),'wirefit-acquisition-cli-'));owned.push(directory);return directory;}
function pe32(){
 // Source-owned PE bytes are inspected/staged as data and never executed.
 const bytes=Buffer.alloc(1024);bytes.write('MZ',0,'ascii');bytes.writeUInt32LE(0x80,0x3c);bytes.write('PE\0\0',0x80,'ascii');
 bytes.writeUInt16LE(0x14c,0x84);bytes.writeUInt16LE(1,0x86);bytes.writeUInt16LE(224,0x94);bytes.writeUInt16LE(0x102,0x96);
 const o=0x98;bytes.writeUInt16LE(0x10b,o);bytes.writeUInt32LE(0x200,o+4);bytes.writeUInt32LE(0x1000,o+16);bytes.writeUInt32LE(0x1000,o+20);
 bytes.writeUInt32LE(0x400000,o+28);bytes.writeUInt32LE(0x1000,o+32);bytes.writeUInt32LE(0x200,o+36);bytes.writeUInt32LE(0x2000,o+56);bytes.writeUInt32LE(0x200,o+60);bytes.writeUInt16LE(3,o+68);bytes.writeUInt32LE(16,o+92);
 const s=o+224;bytes.write('.text',s,'ascii');bytes.writeUInt32LE(1,s+8);bytes.writeUInt32LE(0x1000,s+12);bytes.writeUInt32LE(0x200,s+16);bytes.writeUInt32LE(0x200,s+20);bytes.writeUInt32LE(0x60000020,s+36);bytes[0x200]=0xc3;return bytes;
}
const cancel_ipc={message:{type:'wirefit_cancel'},grace_ms:10000};
const args=(...command:string[])=>['--import','tsx',bridge,...command];
async function traceFixture(finite=false){
 const directory=await temporary(),casePath=path.join(directory,'case');const store=await CaseStore.create(casePath);await store.close();
 const file=path.join(directory,'source.exe'),config=path.join(directory,'config.json'),plan=path.join(directory,'plan.json'),ready=path.join(directory,'synthetic-ready.txt'),tool=path.join(directory,'synthetic-worker.cjs');
 const bytes=pe32();await writeFile(file,bytes);
 await writeFile(tool,"require('node:fs').writeFileSync(process.argv[2],'ready','utf8');"+(finite?'setTimeout(()=>process.exit(0),250);':'setInterval(()=>{},1000);'),'utf8');
 await writeFile(config,JSON.stringify({command:runtime,args:[tool,ready]}),'utf8');
 await writeFile(plan,JSON.stringify({duration_ms:60000,breakpoints_rva:[],ranges:[],api_hooks:[],max_events:8}),'utf8');
 return {directory,casePath,file,bytes,ready,command:args('binary','trace','--case',casePath,'--file',file,'--config',config,'--plan',plan)};
}
describe('fixed public CLI acquisition bridge without PE execution',()=>{
 it('calls the public CLI once and disconnects IPC after a non-foreground command',async()=>{
  const directory=await temporary(),casePath=path.join(directory,'case');
  const result=await runProcess(runtime,args('case','create','--dir',casePath),{cwd:root,timeout_ms:10000,cancel_ipc});
  expect(result.code).toBe(0);expect(result.stdout.trim().split('\n')).toHaveLength(1);expect(JSON.parse(result.stdout).case_dir).toBe(await realpath(casePath));
  expect(existsSync(path.join(casePath,'.wirefit.lock'))).toBe(false);
 });
 it('routes cancellation through the actual public CLI owner and retains its cancelled job',async()=>{
  const f=await traceFixture(),controller=new AbortController();let closed=false;
  const pending=runProcess(runtime,f.command,{cwd:root,timeout_ms:20000,signal:controller.signal,cancel_ipc}).catch(error=>error).finally(()=>{closed=true;});
  const deadline=Date.now()+10000;while(!existsSync(f.ready)&&!closed&&Date.now()<deadline)await new Promise(resolve=>setTimeout(resolve,20));
  expect(existsSync(f.ready),'Public CLI must reach the synthetic Node worker').toBe(true);
  controller.abort();const error=await pending;
  expect(error).toMatchObject({code:'CANCELLED',details:{code:130,cancel_mode:'ipc_requested',cleanup:'closed'}});
  const record=JSON.parse(error.details.stdout);expect(record.job.status).toBe('cancelled');expect(record.result.status).toBe('cancelled');
  const reader=await CaseStore.open(f.casePath,false);try{const jobs=await reader.listObjects<any>('jobs');expect(jobs).toHaveLength(1);expect(jobs[0]!.value.status).toBe('cancelled');}finally{await reader.close();}
  expect((await readFile(f.file)).equals(f.bytes)).toBe(true);expect(existsSync(path.join(f.casePath,'.wirefit.lock'))).toBe(false);
 });
 it('keeps an early IPC cancellation until the public foreground handler exists',async()=>{
  const f=await traceFixture(),controller=new AbortController();
  const pending=runProcess(runtime,f.command,{cwd:root,timeout_ms:20000,signal:controller.signal,cancel_ipc}).catch(error=>error);controller.abort();
  const error=await pending;expect(error).toMatchObject({code:'CANCELLED',details:{code:130,cancel_mode:'ipc_requested'}});
  expect(JSON.parse(error.details.stdout).job.status).toBe('cancelled');expect((await readFile(f.file)).equals(f.bytes)).toBe(true);
  expect(existsSync(path.join(f.casePath,'.wirefit.lock'))).toBe(false);
 });
 it.each([{type:'other'}, {type:'wirefit_cancel',extra:true}])('ignores non-exact IPC messages while the public job owner is active (%#)',async message=>{
  const f=await traceFixture(true),controller=new AbortController();let closed=false;
  const pending=runProcess(runtime,f.command,{cwd:root,timeout_ms:20000,signal:controller.signal,cancel_ipc:{message,grace_ms:10000}}).catch(error=>error).finally(()=>{closed=true;});
  const deadline=Date.now()+10000;while(!existsSync(f.ready)&&!closed&&Date.now()<deadline)await new Promise(resolve=>setTimeout(resolve,10));
  expect(existsSync(f.ready)).toBe(true);controller.abort();const error=await pending;
  expect(error).toMatchObject({code:'CANCELLED',details:{code:1,cancel_mode:'ipc_requested'}});
  // The finite synthetic worker emits no trace protocol. Ignored IPC therefore
  // leaves its actual CLI job failed, rather than invoking the cancel handler.
  expect(JSON.parse(error.details.stdout).job.status).toBe('failed');
  expect(existsSync(path.join(f.casePath,'.wirefit.lock'))).toBe(false);
 });
 it('clears an undelivered early cancellation when a command has no foreground handler',async()=>{
  const directory=await temporary(),casePath=path.join(directory,'case'),controller=new AbortController();
  const pending=runProcess(runtime,args('case','create','--dir',casePath),{cwd:root,timeout_ms:20000,signal:controller.signal,cancel_ipc}).catch(error=>error);controller.abort();
  const error=await pending;expect(error).toMatchObject({code:'CANCELLED',details:{code:0,cancel_mode:'ipc_requested'}});
  expect(JSON.parse(error.details.stdout).case_dir).toBe(await realpath(casePath));
 });
});

import {afterEach,describe,it,expect} from 'vitest';
import {mkdtemp,readFile,realpath,rm,lstat} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {runProcess} from '../src/process.js';
const owned:string[]=[];
afterEach(async()=>{for(const directory of owned.splice(0)){
 const actual=await realpath(directory),root=await realpath(tmpdir());
 if(path.dirname(actual)!==root||!path.basename(actual).startsWith('wirefit-process-ipc-'))throw Error('Unexpected temporary cleanup path');
 await rm(actual,{recursive:true,force:true});
}});
async function marker(){const directory=await mkdtemp(path.join(tmpdir(),'wirefit-process-ipc-'));owned.push(directory);return path.join(directory,'ready.txt');}
async function ready(file:string){const end=Date.now()+7000;while(Date.now()<end){try{if(await readFile(file,'utf8')==='ready')return;}catch(error){if((error as NodeJS.ErrnoException).code!=='ENOENT')throw error;}await new Promise(resolve=>setTimeout(resolve,10));}throw Error('Child did not publish readiness');}
const ipc={message:{type:'wirefit_cancel'},grace_ms:2000};
const callbackChild="const fs=require('node:fs');process.on('message',message=>setTimeout(()=>process.stdout.write(JSON.stringify({message}),'utf8',()=>process.exit(0)),40));fs.writeFileSync(process.argv[1],'ready','utf8');setInterval(()=>{},1000);";
describe('owned worker supervisor',()=>{
 it('passes argv literally without shell expansion',async()=>{
  const result=await runProcess(process.execPath,['-e','process.stdout.write(process.argv[1])','$(this-is-data)&echo bad'],{timeout_ms:3000});
  expect(result.stdout).toBe('$(this-is-data)&echo bad');expect(result.code).toBe(0);
 });
 it('terminates its own timed out worker',async()=>{
  await expect(runProcess(process.execPath,['-e','setInterval(()=>{},1000)'],{timeout_ms:100})).rejects.toThrow(/timeout/i);
 });
 it('bounds protocol stdout',async()=>{
  await expect(runProcess(process.execPath,['-e','process.stdout.write("a".repeat(10000))'],{timeout_ms:3000,max_stdout_bytes:100})).rejects.toThrow(/limit/i);
 });
 it('cancels without letting a late result become success',async()=>{
  const controller=new AbortController();setTimeout(()=>controller.abort(),75);
  await expect(runProcess(process.execPath,['-e','setTimeout(()=>console.log("late"),10000)'],{timeout_ms:15000,signal:controller.signal})).rejects.toThrow(/cancel/i);
 });
 it('requests IPC cancellation, waits for actual close and keeps CANCELLED after code zero',async()=>{
  const file=await marker(),controller=new AbortController();
  const pending=runProcess(process.execPath,['-e',callbackChild,file],{timeout_ms:10000,signal:controller.signal,cancel_ipc:ipc}).catch(error=>error);
  await ready(file);controller.abort();const error=await pending;
  expect(error).toMatchObject({code:'CANCELLED',details:{code:0,cleanup:'closed',cancel_mode:'ipc_requested'}});
  expect(JSON.parse(error.details.stdout)).toEqual({message:{type:'wirefit_cancel'}});
  expect(error.details).not.toHaveProperty('owned_pid_terminated');
 });
 it('retains TIMEOUT when its graceful IPC handler exits successfully',async()=>{
  const file=await marker();
  const error=await runProcess(process.execPath,['-e',callbackChild,file],{timeout_ms:150,cancel_ipc:ipc}).catch(error=>error);
  expect(error).toMatchObject({code:'TIMEOUT',details:{code:0,cleanup:'closed',cancel_mode:'ipc_requested'}});
  expect(JSON.parse(error.details.stdout).message.type).toBe('wirefit_cancel');
 });
 it('forces its own unresponsive child only after the cancellation grace',async()=>{
  const started=performance.now();
  const error=await runProcess(process.execPath,['-e','process.on("message",()=>{});setInterval(()=>{},1000)'],{timeout_ms:100,cancel_ipc:{...ipc,grace_ms:250}}).catch(error=>error);
  expect(error).toMatchObject({code:'TIMEOUT',details:{cleanup:'closed',cancel_mode:'forced'}});expect(performance.now()-started).toBeGreaterThanOrEqual(300);
 });
 it('does not replace or force the first cancellation when the wall timeout follows',async()=>{
  const file=await marker(),controller=new AbortController();
  const child=callbackChild.replace(',40)',',1200)');
  const pending=runProcess(process.execPath,['-e',child,file],{timeout_ms:1000,signal:controller.signal,cancel_ipc:ipc}).catch(error=>error);
  await ready(file);controller.abort();
  const error=await pending;expect(error).toMatchObject({code:'CANCELLED',details:{code:0,cancel_mode:'ipc_requested'}});
 });
 it('forces immediately for an output limit reached during graceful cancellation',async()=>{
  const file=await marker(),controller=new AbortController();
  const child="const fs=require('node:fs');process.on('message',()=>process.stdout.write('x'.repeat(10000)));fs.writeFileSync(process.argv[1],'ready','utf8');setInterval(()=>{},1000);";
  const pending=runProcess(process.execPath,['-e',child,file],{timeout_ms:12000,max_stdout_bytes:100,signal:controller.signal,cancel_ipc:{...ipc,grace_ms:10000}}).catch(error=>error);
  await ready(file);const started=performance.now();controller.abort();const error=await pending;
  expect(error).toMatchObject({code:'CANCELLED',details:{cancel_mode:'forced',cleanup:'closed'}});expect(performance.now()-started).toBeLessThan(8000);
 });
 it('handles an already disconnected IPC channel without an unhandled send error',async()=>{
  const file=await marker(),controller=new AbortController();
  const child="const fs=require('node:fs');if(process.disconnect)process.disconnect();fs.writeFileSync(process.argv[1],'ready','utf8');setInterval(()=>{},1000);";
  const pending=runProcess(process.execPath,['-e',child,file],{timeout_ms:10000,signal:controller.signal,cancel_ipc:ipc}).catch(error=>error);
  await ready(file);controller.abort();expect(await pending).toMatchObject({code:'CANCELLED',details:{cancel_mode:'forced',cleanup:'closed'}});
 });
 it('snapshots the validated cancellation message before the caller can mutate it',async()=>{
  const file=await marker(),controller=new AbortController(),message={type:'wirefit_cancel',value:'original'};
  const pending=runProcess(process.execPath,['-e',callbackChild,file],{timeout_ms:10000,signal:controller.signal,cancel_ipc:{message,grace_ms:2000}}).catch(error=>error);
  message.value='mutated';await ready(file);controller.abort();const error=await pending;
  expect(error).toMatchObject({code:'CANCELLED',details:{cancel_mode:'ipc_requested'}});
  expect(JSON.parse(error.details.stdout).message).toEqual({type:'wirefit_cancel',value:'original'});
 });
 it('accepts an exact 4096-byte message and the maximum grace without truncation',async()=>{
  const file=await marker(),controller=new AbortController(),message={text:'a'.repeat(4085)};
  expect(Buffer.byteLength(JSON.stringify(message),'utf8')).toBe(4096);
  const pending=runProcess(process.execPath,['-e',callbackChild,file],{timeout_ms:10000,signal:controller.signal,cancel_ipc:{message,grace_ms:15000}}).catch(error=>error);
  await ready(file);controller.abort();const error=await pending;
  expect(error).toMatchObject({code:'CANCELLED',details:{code:0,cancel_mode:'ipc_requested'}});expect(JSON.parse(error.details.stdout).message.text).toHaveLength(4085);
 });
 it('keeps the IPC channel absent for existing callers and clears cancellation timers after natural close',async()=>{
  const plain=await runProcess(process.execPath,['-e','process.stdout.write(typeof process.send,"utf8")'],{timeout_ms:3000});expect(plain.stdout).toBe('undefined');
  const configured=await runProcess(process.execPath,['-e','process.stdout.write(typeof process.send,"utf8")'],{timeout_ms:3000,cancel_ipc:{...ipc,grace_ms:1}});expect(configured.stdout).toBe('function');expect(configured.code).toBe(0);
 });
 it('reports startup failure immediately with IPC configured',async()=>{
  const file=await marker();
  const error=await runProcess(file+'-missing',['unused'],{timeout_ms:10000,cancel_ipc:{...ipc,grace_ms:10000}}).catch(error=>error);
  expect(error).toMatchObject({code:'PROCESS_START_FAILED',details:{cleanup:'closed'}});
 });
 it('rejects accessor options without evaluating them or spawning a child',async()=>{
  const file=await marker();let evaluated=0;
  const cancel_ipc={get message(){evaluated++;return {type:'wirefit_cancel'};},grace_ms:1};
  await expect(runProcess(process.execPath,['-e',"require('node:fs').writeFileSync(process.argv[1],'spawned','utf8')",file],{timeout_ms:3000,cancel_ipc})).rejects.toMatchObject({code:'PROCESS_INVALID'});
  expect(evaluated).toBe(0);await expect(lstat(file)).rejects.toMatchObject({code:'ENOENT'});
 });
 const cyclic:Record<string,unknown>={};cyclic.self=cyclic;
 it.each([
  {message:{type:'x'},grace_ms:0},{message:{type:'x'},grace_ms:15001},{message:{type:'x'},grace_ms:1.5},
  {message:[],grace_ms:10},{message:null,grace_ms:10},{message:{text:'ü'.repeat(2100)},grace_ms:10},
  {message:{value:undefined},grace_ms:10},{message:{value:()=>1},grace_ms:10},{message:{value:1n},grace_ms:10},
  {message:{value:Number.NaN},grace_ms:10},{message:cyclic,grace_ms:10},{message:{type:'x'},grace_ms:10,unexpected:true},
 ])('rejects invalid IPC options before spawning any child (%#)',async cancel_ipc=>{
  const file=await marker();
  await expect(runProcess(process.execPath,['-e',"require('node:fs').writeFileSync(process.argv[1],'spawned','utf8')",file],{timeout_ms:3000,cancel_ipc:cancel_ipc as any})).rejects.toMatchObject({code:'PROCESS_INVALID'});
  await expect(lstat(file)).rejects.toMatchObject({code:'ENOENT'});
 });
});

import {describe,it,expect,afterEach} from 'vitest';
import {mkdtemp,writeFile,readFile,rm,readdir,mkdir,realpath,lstat} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {WirefitService} from '../src/service.js';
import {submitBinaryInspection,submitBinaryUnpack} from '../src/binary-service.js';
const temporary:string[]=[];
async function setup(){
 const root=await mkdtemp(path.join(tmpdir(),'wirefit binary '));temporary.push(root);
 const service=await WirefitService.create(path.join(root,'case'));
 const bytes=Buffer.alloc(1024);bytes.write('MZ');bytes.writeUInt32LE(128,60);bytes.write('PE\0\0',128);bytes.writeUInt16LE(0x14c,132);bytes.writeUInt16LE(1,134);bytes.writeUInt16LE(224,148);
 const o=152;bytes.writeUInt16LE(0x10b,o);bytes.writeUInt32LE(0x1000,o+16);bytes.writeUInt32LE(0x400000,o+28);bytes.writeUInt32LE(4096,o+32);bytes.writeUInt32LE(512,o+36);bytes.writeUInt32LE(8192,o+56);bytes.writeUInt32LE(512,o+60);bytes.writeUInt32LE(16,o+92);
 const s=o+224;bytes.write('.text',s);bytes.writeUInt32LE(512,s+8);bytes.writeUInt32LE(4096,s+12);bytes.writeUInt32LE(512,s+16);bytes.writeUInt32LE(512,s+20);bytes.writeUInt32LE(0x60000020,s+36);bytes[512]=0xc3;
 const file=path.join(root,'original sample.exe');await writeFile(file,bytes);
 return {root,service,bytes,file};
}
afterEach(async()=>{for(const root of temporary.splice(0)){const resolved=await realpath(root);expect((await lstat(root)).isSymbolicLink()).toBe(false);expect(resolved.toLowerCase().startsWith((path.resolve(tmpdir())+path.sep+'wirefit binary ').toLowerCase())).toBe(true);await rm(resolved,{recursive:true,force:true});}});
describe('binary workflow supervision',()=>{
 it('stores a verified immutable PE snapshot and a compact inspection result',async()=>{
  const {service,file,bytes}=await setup();
  try{
   const state=await service.jobs.wait((await submitBinaryInspection(service,{file})).job_id);
   expect(state.status).toBe('completed');
   const result:any=await service.getResult(state.result_id!);
   expect(result.operation).toBe('inspect_binary');expect(result.source.sha256).toMatch(/^[a-f0-9]{64}$/);
   expect(result.detector.status).toBe('not_configured');
   expect(await service.store.readArtifact(result.source.artifact)).toEqual(bytes);
   const inspection=JSON.parse((await service.store.readArtifact(result.inspection_artifact)).toString('utf8'));
   expect(inspection.format).toBe('PE32');expect(result.validation.runnable_verified).toBe(false);
  }finally{await service.close();}
 });
 it('rejects injected request fields and invalid input before backend execution',async()=>{
  const {service,file,root}=await setup();
  try{
   await expect(submitBinaryInspection(service,{file,verdict:'unpacked'} as any)).rejects.toThrow();
   await writeFile(path.join(root,'bad.exe'),'not a PE','utf8');
   await expect(submitBinaryUnpack(service,{file:path.join(root,'bad.exe'),backend:'unlicense',toolchain:{unpackers:{unlicense:{command:process.execPath}}}})).rejects.toThrow();
  }finally{await service.close();}
 });
 it('retains failed external stdout/stderr without modifying source or calling it unpacked',async()=>{
  const {service,file,root,bytes}=await setup();
  try{
   const script=path.join(root,'failure.mjs');await writeFile(script,"console.log('test-only fake provider');console.error('intentional failure');process.exitCode=17;",'utf8');
   const state=await service.jobs.wait((await submitBinaryUnpack(service,{file,backend:'unlicense',toolchain:{unpackers:{unlicense:{command:process.execPath,args:[script]}}},copy_dependencies:false})).job_id);
   expect(state.status).toBe('failed');expect(state.result_id).toBeTruthy();
   const result:any=await service.getResult(state.result_id!);expect(result.status).toBe('failed');expect(result.outputs).toEqual([]);
   const logs=await Promise.all(result.logs.map(async(ref:any)=>(await service.store.readArtifact(ref)).toString('utf8')));
   expect(logs.join('\n')).toContain('intentional failure');expect(await readFile(file)).toEqual(bytes);expect(result.validation.runnable_verified).toBe(false);
  }finally{await service.close();}
 });
 it('does not accept an exit-zero provider with no PE output',async()=>{
  const {service,file,root}=await setup();
  try{
   const script=path.join(root,'empty.mjs');await writeFile(script,"console.log('test-only provider, no derivative');",'utf8');
   const state=await service.jobs.wait((await submitBinaryUnpack(service,{file,backend:'unlicense',toolchain:{unpackers:{unlicense:{command:process.execPath,args:[script]}}},copy_dependencies:false})).job_id);
   expect(state.status).toBe('failed');const result:any=await service.getResult(state.result_id!);
   expect(result.error.code).toBe('UNPACK_OUTPUT_MISSING');
  }finally{await service.close();}
 });
 it('marks a synthetic PE derivative as an analysis dump with no executable or behavior claim',async()=>{
  const {service,file,root,bytes}=await setup();
  try{
   const script=path.join(root,'derivative.mjs');await writeFile(script,"import{readFile,writeFile}from'node:fs/promises';import path from'node:path';const input=process.argv[2];const bytes=await readFile(input);bytes[512]=0x90;await writeFile(path.join(process.cwd(),'synthetic-unpacked.exe'),bytes);console.log('test-only derivative, no unpacking performed');",'utf8');
   const state=await service.jobs.wait((await submitBinaryUnpack(service,{file,backend:'unlicense',toolchain:{unpackers:{unlicense:{command:process.execPath,args:[script]}}},copy_dependencies:false})).job_id);
   expect(state.status).toBe('completed');const result:any=await service.getResult(state.result_id!);
   expect(result.outputs).toHaveLength(1);expect(result.outputs[0].quality).toBe('analysis_dump');expect(result.outputs[0].runnable_verified).toBe(false);
   expect(await readFile(file)).toEqual(bytes);
   expect((await service.getReport(state.result_id!)).data.status).toBe('completed');
  }finally{await service.close();}
 });
 it('refuses an explicitly incompatible detected protector before running the backend',async()=>{
  const {service,file,root}=await setup();
  try{
   const detector=path.join(root,'detector.mjs');await writeFile(detector,"console.log(JSON.stringify({detects:[{values:[{type:'protector',name:'VMProtect',version:'3.x'}]}]}));",'utf8');
   const state=await service.jobs.wait((await submitBinaryUnpack(service,{file,backend:'unlicense',toolchain:{detector:{command:process.execPath,args:[detector]},unpackers:{unlicense:{command:'definitely-not-a-tool'}}},copy_dependencies:false})).job_id);
   expect(state.status).toBe('failed');const result:any=await service.getResult(state.result_id!);
   expect(result.error.code).toBe('UNPACK_BACKEND_MISMATCH');
  }finally{await service.close();}
 });
it('does not misclassify partially copied input DLLs as unpack output on staging failure',async()=>{
  const {service,file,root,bytes}=await setup();
  try{
   const dll=Buffer.from(bytes);dll[512]=0x90;await writeFile(path.join(root,'a.dll'),dll);await mkdir(path.join(root,'z.dll'));
   const state=await service.jobs.wait((await submitBinaryUnpack(service,{file,backend:'unlicense',toolchain:{unpackers:{unlicense:{command:process.execPath,args:['--version']}}}})).job_id);
   const result:any=await service.getResult(state.result_id!);
   expect(state.status).toBe('failed');expect(result.outputs).toEqual([]);
  }finally{await service.close();}
 });
it('does not attribute a detector-created PE to an empty unpack backend',async()=>{
  const {service,file,root}=await setup();
  try{
   const detector=path.join(root,'side-effect-detector.mjs');await writeFile(detector,"import{readFile,writeFile}from'node:fs/promises';import path from'node:path';const bytes=await readFile(process.argv.at(-1));bytes[512]=0x90;await writeFile(path.join(process.cwd(),'detector-side-effect.exe'),bytes);console.log(JSON.stringify({detects:[{values:[{type:'protector',name:'Themida',version:'2.x'}]}]}));",'utf8');
   const empty=path.join(root,'empty-backend.mjs');await writeFile(empty,"console.log('test-only backend with no output');",'utf8');
   const state=await service.jobs.wait((await submitBinaryUnpack(service,{file,backend:'unlicense',toolchain:{detector:{command:process.execPath,args:[detector]},unpackers:{unlicense:{command:process.execPath,args:[empty]}}},copy_dependencies:false})).job_id);
   const result:any=await service.getResult(state.result_id!);expect(state.status).toBe('failed');expect(result.outputs).toEqual([]);expect(result.error.code).toBe('UNPACK_OUTPUT_MISSING');
  }finally{await service.close();}
 });
 it('rejects a generated PE hardlink to a pre-existing unrelated file',async()=>{
  const {service,file,root,bytes}=await setup();
  try{
   const external=path.join(root,'unrelated.dll'),other=Buffer.from(bytes);other[512]=0x90;await writeFile(external,other);
   const script=path.join(root,'hardlink-provider.mjs');await writeFile(script,"import{link}from'node:fs/promises';import path from'node:path';await link(process.argv[2],path.join(process.cwd(),'unpacked.exe'));",'utf8');
   const state=await service.jobs.wait((await submitBinaryUnpack(service,{file,backend:'unlicense',toolchain:{unpackers:{unlicense:{command:process.execPath,args:[script,external]}}},copy_dependencies:false})).job_id);
   const result:any=await service.getResult(state.result_id!);expect(state.status).toBe('failed');expect(result.outputs).toEqual([]);expect(result.error.code).toBe('UNPACK_OUTPUT_ALIAS');
  }finally{await service.close();}
 });
 it('forwards Windows architecture identity required by the real backend preflight',async()=>{
  const {service,file,root}=await setup();const previous=process.env.PROCESSOR_ARCHITECTURE;
  try{
   process.env.PROCESSOR_ARCHITECTURE='AMD64';
   const script=path.join(root,'architecture.mjs');await writeFile(script,"console.log('architecture='+process.env.PROCESSOR_ARCHITECTURE);process.exitCode=17;",'utf8');
   const state=await service.jobs.wait((await submitBinaryUnpack(service,{file,backend:'unlicense',toolchain:{unpackers:{unlicense:{command:process.execPath,args:[script]}}},copy_dependencies:false})).job_id);
   const result:any=await service.getResult(state.result_id!);
   const logs=await Promise.all(result.logs.map(async(ref:any)=>(await service.store.readArtifact(ref)).toString('utf8')));
   expect(logs.join('\n')).toContain('architecture=AMD64');
  }finally{if(previous===undefined)delete process.env.PROCESSOR_ARCHITECTURE;else process.env.PROCESSOR_ARCHITECTURE=previous;await service.close();}
 });
it('retains a cancelled inspection result when cancellation arrives during metadata persistence',async()=>{
  const {service,file}=await setup();
  const original=service.store.putJson.bind(service.store);let enter!:()=>void,release!:()=>void,blocked=false;
  const entered=new Promise<void>(resolve=>{enter=resolve}),gate=new Promise<void>(resolve=>{release=resolve});
  service.store.putJson=async(value:unknown)=>{
   if(!blocked&&value&&typeof value==='object'&&'format' in value){blocked=true;enter();await gate;}
   return original(value);
  };
  try{
   const job=await submitBinaryInspection(service,{file});await entered;
   const cancelling=service.jobs.cancel(job.job_id);release();await cancelling;
   const state=await service.jobs.wait(job.job_id);expect(state.status).toBe('cancelled');expect(state.result_id).toBeTruthy();
   const result:any=await service.getResult(state.result_id!);expect(result.status).toBe('cancelled');expect(result.error.code).toBe('CANCELLED');
  }finally{release();await service.close();}
 });
it('links a terminal cancellation receipt if cancellation arrives during immutable run publication',async()=>{
  const {service,file}=await setup();
  const original=service.store.putObject.bind(service.store);let enter!:()=>void,release!:()=>void,blocked=false;
  const entered=new Promise<void>(resolve=>{enter=resolve}),gate=new Promise<void>(resolve=>{release=resolve});
  service.store.putObject=async(kind:string,objectId:string,value:unknown)=>{
   await original(kind,objectId,value);
   if(!blocked&&kind==='runs'){blocked=true;enter();await gate;}
  };
  try{
   const job=await submitBinaryInspection(service,{file});await entered;
   const cancelling=service.jobs.cancel(job.job_id);release();await cancelling;
   const state=await service.jobs.wait(job.job_id);expect(state.status).toBe('cancelled');expect(state.result_id).toBeTruthy();
   const result:any=await service.getResult(state.result_id!);expect(result.status).toBe('cancelled');expect(result.supersedes_result_id).toBeTruthy();
   const prior:any=await service.getResult(result.supersedes_result_id);expect(prior.status).toBe('completed');
  }finally{release();await service.close();}
 });
});

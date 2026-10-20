import {Client} from '@modelcontextprotocol/sdk/client/index.js';
import {InMemoryTransport} from '@modelcontextprotocol/sdk/inMemory.js';
import {createMcpServer} from '../src/mcp.js';
import {afterEach,describe,expect,it} from 'vitest';
import {mkdtemp,writeFile,readFile,cp,rm,lstat,realpath,mkdir,rename,symlink} from 'node:fs/promises';
import path from 'node:path';
import {tmpdir} from 'node:os';
import {WirefitService} from '../src/service.js';
import {submitBinaryInspection,submitBinaryUnpack} from '../src/binary-service.js';
import {exportReport} from '../src/reporting.js';
import {runProcess} from '../src/process.js';
import {sha256,rootDir} from '../src/shared.js';

const roots:string[]=[];
async function temporary(){
 const root=await mkdtemp(path.join(tmpdir(),'wirefit-binary-export-'));roots.push(root);return root;
}
async function removeOwned(target:string){
 const resolved=await realpath(target),base=path.resolve(tmpdir())+path.sep+'wirefit-binary-export-';
 expect(resolved.toLowerCase().startsWith(base.toLowerCase())).toBe(true);
 expect((await lstat(target)).isSymbolicLink()).toBe(false);
 await rm(resolved,{recursive:true,force:true});
}
afterEach(async()=>{for(const root of roots.splice(0)){try{await removeOwned(root);}catch(error){if((error as NodeJS.ErrnoException).code!=='ENOENT')throw error;}}});
function pe(){
 const b=Buffer.alloc(1024);b.write('MZ');b.writeUInt32LE(128,60);b.write('PE\0\0',128);b.writeUInt16LE(0x14c,132);b.writeUInt16LE(1,134);b.writeUInt16LE(224,148);
 const o=152;b.writeUInt16LE(0x10b,o);b.writeUInt32LE(0x1000,o+16);b.writeUInt32LE(0x400000,o+28);b.writeUInt32LE(4096,o+32);b.writeUInt32LE(512,o+36);b.writeUInt32LE(8192,o+56);b.writeUInt32LE(512,o+60);b.writeUInt32LE(16,o+92);
 const s=o+224;b.write('.text',s);b.writeUInt32LE(512,s+8);b.writeUInt32LE(4096,s+12);b.writeUInt32LE(512,s+16);b.writeUInt32LE(512,s+20);b.writeUInt32LE(0x60000020,s+36);b[512]=0xc3;return b;
}
async function fixture(unpack=false,exit=0){
 const root=await temporary(),service=await WirefitService.create(path.join(root,'case')),file=path.join(root,'original.exe');
 await writeFile(file,pe());
 let job;
 if(unpack){
  await writeFile(path.join(root,'support.dll'),pe());
  const script=path.join(root,'synthetic.mjs');
  await writeFile(script,"import{readFile,writeFile}from'node:fs/promises';const b=await readFile(process.argv[2]);b[512]=0x90;await writeFile('unpacked.exe',b);console.error('test-only derivative; no real unpacking');process.exitCode="+exit+";\n",'utf8');
  job=await submitBinaryUnpack(service,{file,backend:'unlicense',toolchain:{unpackers:{unlicense:{command:process.execPath,args:[script]}}}});
 }else job=await submitBinaryInspection(service,{file});
 const state=await service.jobs.wait(job.job_id);
 return {root,service,file,runId:state.result_id!,result:await service.getResult(state.result_id!) as any};
}
async function copiedExport(f:Awaited<ReturnType<typeof fixture>>){
 const out=path.join(f.root,'export'),manifest=await exportReport(f.service.store,f.runId,out);
 const independent=await temporary(),copied=path.join(independent,'copied');await cp(out,copied,{recursive:true});
 return {out,manifest,copied};
}
describe('portable binary report export',()=>{
 it('exports inspection snapshots and verifies independently after the original case is removed',async()=>{
  const f=await fixture();
  try{
   const {out,manifest,copied}=await copiedExport(f);
   expect((manifest as any).report_kind).toBe('binary');
   expect(manifest.manifest_sha256).toBe(sha256(await readFile(path.join(out,'manifest.json'))));
   await f.service.close();await removeOwned(path.join(f.root,'case'));
   const execution=await runProcess(process.execPath,[path.join(copied,'verify.mjs')],{cwd:copied,timeout_ms:10000});
   expect(execution.code).toBe(0);
   const verification=JSON.parse(execution.stdout);
   expect(verification.file_integrity.status).toBe('matched');
   expect(verification.runnable_verified).toBe(false);
   expect(verification.target_execution).toBe('not_run');
   expect(verification.original_operation).toBe('inspect_binary');
  }finally{await f.service.close();}
 });
 it('exports PE derivatives and nested DLL snapshots while preserving a failed backend result',async()=>{
  const f=await fixture(true,17);
  try{
   expect(f.result.status).toBe('failed');expect(f.result.outputs).toHaveLength(1);
   const {out,copied}=await copiedExport(f);
   expect(await readFile(path.join(out,'binaries/unpacked.exe'))).toEqual(await f.service.store.readArtifact(f.result.outputs[0].artifact));
   expect(await readFile(path.join(out,'binaries/support.dll'))).toEqual(pe());
   const verification=JSON.parse((await runProcess(process.execPath,[path.join(copied,'verify.mjs')],{timeout_ms:10000})).stdout);
   expect(verification.original_status).toBe('failed');expect(verification.runnable_verified).toBe(false);
   expect(JSON.parse(await readFile(path.join(out,'result.json'),'utf8'))).toEqual(f.result);
   const run=JSON.parse(await readFile(path.join(out,'run.json'),'utf8'));
   const dependencyLog=JSON.parse(await readFile(path.join(out,run.result.logs[0].relative_path),'utf8'));
   const dependencyRef=dependencyLog.dependencies[0];
   const dependency=JSON.parse(await readFile(path.join(out,dependencyRef.relative_path),'utf8'));
   expect(await readFile(path.join(out,dependency.artifact.relative_path))).toEqual(pe());
  }finally{await f.service.close();}
 });
 it('rejects tampering before reporting export consistency and never runs a PE',async()=>{
  const f=await fixture(true);
  try{
   const {copied}=await copiedExport(f);
   await writeFile(path.join(copied,'binaries/unpacked.exe'),'tampered','utf8');
   const execution=await runProcess(process.execPath,[path.join(copied,'verify.mjs')],{timeout_ms:10000});
   expect(execution.code).not.toBe(0);expect(execution.stderr).toContain('EXPORT_INTEGRITY_ERROR');
  }finally{await f.service.close();}
 });
 it('rejects a junction in a copied file ancestor even when all bytes match',async()=>{
  const f=await fixture(true);
  try{
   const {copied}=await copiedExport(f),old=path.join(copied,'binaries'),moved=path.join(copied,'saved-binaries');
   expect((await realpath(old)).toLowerCase().startsWith((copied+path.sep).toLowerCase())).toBe(true);
   expect(path.resolve(moved).toLowerCase().startsWith((copied+path.sep).toLowerCase())).toBe(true);
   await rename(old,moved);await symlink(moved,old,process.platform==='win32'?'junction':'dir');
   const execution=await runProcess(process.execPath,[path.join(copied,'verify.mjs')],{timeout_ms:10000});
   expect(execution.code).not.toBe(0);expect(execution.stderr).toContain('EXPORT_INTEGRITY_ERROR');
  }finally{await f.service.close();}
 });
 it('refuses populated destinations and junction aliases without replacing files',async()=>{
  const f=await fixture();
  try{
   const out=path.join(f.root,'existing');await mkdir(out);await writeFile(path.join(out,'keep.txt'),'retained','utf8');
   await expect(exportReport(f.service.store,f.runId,out)).rejects.toMatchObject({code:'EXPORT_DIRECTORY_NOT_EMPTY'});
   expect(await readFile(path.join(out,'keep.txt'),'utf8')).toBe('retained');
   const empty=path.join(f.root,'empty'),alias=path.join(f.root,'alias');await mkdir(empty);await symlink(empty,alias,process.platform==='win32'?'junction':'dir');
   await expect(exportReport(f.service.store,f.runId,alias)).rejects.toMatchObject({code:'EXPORT_PATH_INVALID'});
  }finally{await f.service.close();}
 });
 it('rejects conflicting case-insensitive dependency and derivative names',async()=>{
  const f=await fixture(true);
  try{
   const run:any=await f.service.store.getObject('runs',f.runId);
   run.result.result_id='binary_conflict';
   run.result.outputs[0].relative_path='.binary-work/original_run/SUPPORT.dll';
   await f.service.store.putObject('runs','binary_conflict',run);
   await expect(exportReport(f.service.store,'binary_conflict',path.join(f.root,'export'))).rejects.toMatchObject({code:'EXPORT_BINARY_NAME_CONFLICT'});
  }finally{await f.service.close();}
 });
 it('rejects path and reserved-device output names',async()=>{
  const f=await fixture(true);
  try{
   for(const [i,name] of ['../escape.exe','CON.exe','trailing.exe.'].entries()){
    const run:any=await f.service.store.getObject('runs',f.runId);
    const id='binary_bad_name_'+i;run.result.result_id=id;run.result.outputs[0].relative_path='.binary-work/original_run/'+name;
    await f.service.store.putObject('runs',id,run);
    await expect(exportReport(f.service.store,id,path.join(f.root,'export-'+i))).rejects.toMatchObject({code:'EXPORT_PATH_INVALID'});
   }
  }finally{await f.service.close();}
 });
 it('refuses changed case artifacts and malformed nested artifact references',async()=>{
  const f=await fixture();
  try{
   const nested=await f.service.store.putJson({attachment:{relative_path:'artifacts/'+'a'.repeat(64),sha256:'a'.repeat(64),media_type:'application/json',size_bytes:'wrong'}});
   const run:any=await f.service.store.getObject('runs',f.runId);run.result.result_id='binary_bad_ref';run.result.logs.push(nested);
   await f.service.store.putObject('runs','binary_bad_ref',run);
   await expect(exportReport(f.service.store,'binary_bad_ref',path.join(f.root,'bad-ref'))).rejects.toMatchObject({code:'EXPORT_REFERENCE_INVALID'});
   const source=f.result.source.artifact;
   await writeFile(path.join(f.service.store.root,source.relative_path),Buffer.alloc(source.size_bytes));
   await expect(exportReport(f.service.store,f.runId,path.join(f.root,'changed'))).rejects.toMatchObject({code:'ARTIFACT_DIGEST_MISMATCH'});
  }finally{await f.service.close();}
 });
 it('does not accept an injected runnable verdict as a trusted binary result',async()=>{
  const f=await fixture();
  try{
   const run:any=await f.service.store.getObject('runs',f.runId);run.result.result_id='binary_promoted';run.result.validation.runnable_verified=true;
   await f.service.store.putObject('runs','binary_promoted',run);
   await expect(exportReport(f.service.store,'binary_promoted',path.join(f.root,'promoted'))).rejects.toMatchObject({code:'EXPORT_BINARY_INVALID'});
  }finally{await f.service.close();}
 });
it('exposes the binary package through the existing MCP report export tool',async()=>{
  const f=await fixture();
  const server=await createMcpServer(f.service),client=new Client({name:'binary-export-test',version:'1.0'});
  const [left,right]=InMemoryTransport.createLinkedPair();
  await server.connect(right);await client.connect(left);
  try{
   const out=path.join(f.root,'mcp-export');
   const reply=await client.callTool({name:'wirefit_export_report',arguments:{result_id:f.runId,out}});
   expect(reply.isError).not.toBe(true);
   expect(reply.structuredContent).toMatchObject({report_kind:'binary',operation:'inspect_binary',verification:{target_execution:'not_run',runnable_verified:false}});
   expect(JSON.parse(await readFile(path.join(out,'verification-receipt.json'),'utf8')).verification.file_integrity.status).toBe('matched');
  }finally{await client.close();await server.close();await f.service.close();}
 });
 it('exposes the binary package through the production CLI report export command',async()=>{
  const f=await fixture();
  try{
   await f.service.close();const out=path.join(f.root,'cli-export');
   const execution=await runProcess(process.execPath,['--import','tsx',path.join(rootDir,'src/cli.ts'),'report','export','--case',path.join(f.root,'case'),'--run',f.runId,'--out',out],{cwd:rootDir,timeout_ms:20000});
   expect(execution.code,execution.stderr+execution.stdout).toBe(0);
   expect(JSON.parse(execution.stdout)).toMatchObject({report_kind:'binary',operation:'inspect_binary',original_status:'completed'});
  }finally{await f.service.close();}
 });
it.each(['application/x-ndjson','application/jsonl'])('retains nested artifact closure from %s including an unterminated final row',async media=>{
  const f=await fixture();
  try{
   const leaf=await f.service.store.putArtifact(Buffer.from('independent retained bytes','utf8'));
   const parent=await f.service.store.putJson({child:leaf});
   const container=await f.service.store.putArtifact(Buffer.from(JSON.stringify({first:parent})+'\n'+JSON.stringify({again:leaf}),'utf8'),media);
   const run:any=await f.service.store.getObject('runs',f.runId);run.result.result_id='binary_json_lines';run.result.logs.push(container);
   await f.service.store.putObject('runs','binary_json_lines',run);
   const out=path.join(f.root,'json-lines'),manifest=await exportReport(f.service.store,'binary_json_lines',out);
   expect(manifest.files.some(entry=>entry.relative_path===leaf.relative_path)).toBe(true);
   expect(await readFile(path.join(out,leaf.relative_path))).toEqual(Buffer.from('independent retained bytes','utf8'));
  }finally{await f.service.close();}
 });
 it.each(['application/x-ndjson','application/jsonl'])('rejects malformed trailing JSON rows in %s instead of exporting only a valid prefix',async media=>{
  const f=await fixture();
  try{
   const container=await f.service.store.putArtifact(Buffer.from('{"valid":true}\n{invalid','utf8'),media);
   const run:any=await f.service.store.getObject('runs',f.runId);run.result.result_id='binary_bad_json_lines';run.result.logs.push(container);
   await f.service.store.putObject('runs','binary_bad_json_lines',run);
   await expect(exportReport(f.service.store,'binary_bad_json_lines',path.join(f.root,'bad-json-lines'))).rejects.toMatchObject({code:'EXPORT_REFERENCE_INVALID'});
  }finally{await f.service.close();}
 });
 it('retains cancelled operation status even when portable file verification succeeds',async()=>{
  const f=await fixture();
  try{
   const run:any=await f.service.store.getObject('runs',f.runId);run.result.result_id='binary_cancelled_export';run.result.status='cancelled';
   await f.service.store.putObject('runs','binary_cancelled_export',run);
   const out=path.join(f.root,'cancelled');
   await exportReport(f.service.store,'binary_cancelled_export',out);
   const observed=JSON.parse(await readFile(path.join(out,'verification-receipt.json'),'utf8')).verification;
   expect(observed.original_status).toBe('cancelled');expect(observed.file_integrity.status).toBe('matched');expect(observed.runnable_verified).toBe(false);
  }finally{await f.service.close();}
 });
});

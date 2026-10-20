import {describe,it,expect,beforeAll,afterAll} from 'vitest';
import {cp,mkdtemp,rm,mkdir,writeFile} from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import {rootDir} from '../src/shared.js';
import type {JobState} from '../src/jobs.js';
import {WorkbenchWorkspace} from '../src/web/workspace.js';
describe('real workbench actions',()=>{
 let directory:string;let workspace:WorkbenchWorkspace;
 beforeAll(async()=>{directory=await mkdtemp(path.join(os.tmpdir(),'wirefit-web-actions-'));await cp(path.join(rootDir,'examples'),path.join(directory,'examples'),{recursive:true});await mkdir(path.join(directory,'.local'));await writeFile(path.join(directory,'.local','native-trace.json'),JSON.stringify({command:process.execPath,args:[]}),'utf8');workspace=await WorkbenchWorkspace.open(directory);});
 afterAll(async()=>{await workspace?.close();await rm(directory,{recursive:true,force:true});});
 async function done(job:JobState):Promise<JobState>{const deadline=Date.now()+30000;while(Date.now()<deadline){const state=await workspace.job('workbench',job.job_id);if(['completed','failed','cancelled'].includes(state.status))return state;await new Promise(resolve=>setTimeout(resolve,20));}throw new Error('job timed out');}
 it('runs genuine Handwired fitting and exact simplification and exports a registered package',async()=>{
  const presets=workspace.presets();
  const fit=await done(await workspace.submit('workbench',{kind:'experiment',request:presets.find(item=>item.id==='fit-handwired')!.request}));
  expect(fit.status).toBe('completed');
  const simplify=await done(await workspace.submit('workbench',{kind:'experiment',request:presets.find(item=>item.id==='simplify-mba')!.request}));
  expect(simplify.status).toBe('completed');
  const data=await workspace.caseData('workbench');expect(data.runs.find(run=>run.id===simplify.result_id)).toMatchObject({status:'completed',result:{model_check:{status:'proved'}}});
  expect(data.runs.find(run=>run.id===fit.result_id)?.result).toMatchObject({target_validation:{status:'unavailable'},fit:{backend:'handwired'}});
  const exported=await workspace.export('workbench',simplify.result_id!);expect(exported.path.startsWith(path.join(directory,'exports','workbench')+path.sep)).toBe(true);
  expect((await workspace.exportFile(exported.id,'report.md')).bytes.toString('utf8')).toContain('Wirefit report');
  await expect(workspace.exportFile(exported.id,'../case.json')).rejects.toThrow();await expect(workspace.exportFile('unknown','report.md')).rejects.toThrow();
  await writeFile(path.join(exported.path,'report.md'),'tampered package','utf8');await expect(workspace.exportFile(exported.id,'report.md')).rejects.toMatchObject({code:'EXPORT_FILE_CHANGED'});
 },60000);
 it('cancels only a server-owned queued or running job',async()=>{
  const preset=workspace.presets().find(item=>item.id==='simplify-mba')!;const job=await workspace.submit('workbench',{kind:'experiment',request:preset.request});
  const cancelled=await workspace.cancel('workbench',job.job_id);expect(['cancelling','cancelled','completed']).toContain(cancelled.status);
  expect(['cancelled','completed']).toContain((await done(job)).status);
  await expect(workspace.cancel('workbench','job_foreign')).rejects.toMatchObject({code:'JOB_NOT_OWNED'});
 });
 it('rejects executable payloads and unknown tool profiles before task execution',async()=>{
  await expect(workspace.submit('workbench',{kind:'trace',file:'target.exe',profileId:'custom',tool:{command:'cmd.exe'}} as any)).rejects.toThrow();
  await expect(workspace.submit('workbench',{kind:'inspect',file:'target.exe',profileId:'custom'})).rejects.toMatchObject({code:'PROFILE_UNAVAILABLE'});
  await expect(workspace.submit('workbench',{kind:'trace',file:'target.exe',profileId:'native-trace',plan:{duration_ms:60001,breakpoints_rva:[],ranges:[],api_hooks:[],max_events:128}})).rejects.toMatchObject({code:'NATIVE_TRACE_REQUEST_INVALID'});
  await expect(workspace.submit('vmde',{kind:'experiment',request:{}})).rejects.toMatchObject({code:'CASE_READ_ONLY'});
 });
 it('serves only artifact references registered by case records',async()=>{
  const data=await workspace.caseData('workbench');const sha=data.jobs.find(job=>job.request_artifact)?.request_artifact!.sha256;
  expect(sha).toBeDefined();expect((await workspace.artifact('workbench',sha!)).mediaType).toBe('application/json');
  await expect(workspace.artifact('workbench','../case.json')).rejects.toThrow();await expect(workspace.artifact('workbench','0'.repeat(64))).rejects.toThrow();
 });
});

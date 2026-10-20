import {describe,it,expect,beforeEach,afterEach} from 'vitest';
import {cp,mkdtemp,mkdir,readFile,rm,symlink} from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import {rootDir} from '../src/shared.js';
import {CaseStore} from '../src/store.js';
import {WorkbenchWorkspace} from '../src/web/workspace.js';
describe('workbench workspace',()=>{
 let directory:string;let workspace:WorkbenchWorkspace|undefined;
 beforeEach(async()=>{directory=await mkdtemp(path.join(os.tmpdir(),'wirefit-web-workspace-'));await cp(path.join(rootDir,'examples'),path.join(directory,'examples'),{recursive:true});});
 afterEach(async()=>{await workspace?.close();workspace=undefined;await rm(directory,{recursive:true,force:true});});
 it('bootstraps real examples and expected fixture data in a separate mutable case',async()=>{
  workspace=await WorkbenchWorkspace.open(directory);const data=await workspace.caseData('workbench');
  expect(data.models.map(model=>model.model_id)).toEqual(expect.arrayContaining(['mba_u8','add_u8','affine_clamp_initial']));
  expect(data.datasets).toHaveLength(1);expect(data.case.path).toBe(path.join(directory,'.local','workbench','case'));
  expect((await workspace.cases()).find(item=>item.id==='vmde')).toMatchObject({kind:'research',writable:false});
 });
 it('discovers historical cases read only and never recovers running foreign jobs on view',async()=>{
  const selected=path.join(directory,'cases','history');const store=await CaseStore.create(selected);
  const job={job_id:'job_foreign',operation:'simplify',status:'running',created_at:new Date().toISOString(),started_at:null,finished_at:null,result_id:null,error:null};
  await store.putObject('jobs',job.job_id,job);await store.close();
  const before=await readFile(path.join(selected,'jobs',(await import('../src/shared.js')).sha256(job.job_id)+'.json'),'utf8');
  workspace=await WorkbenchWorkspace.open(directory);const entry=(await workspace.cases()).find(item=>item.path===selected)!;
  expect(entry).toBeDefined();const data=await workspace.caseData(entry.id);expect(data.jobs[0]).toMatchObject({status:'running',owned:false});
  await expect(workspace.cancel(entry.id,job.job_id)).rejects.toMatchObject({code:'JOB_NOT_OWNED'});
  expect(await readFile(path.join(selected,'jobs',(await import('../src/shared.js')).sha256(job.job_id)+'.json'),'utf8')).toBe(before);
 });
 it('reports full collection totals when a bounded historical list is truncated',async()=>{
  const selected=path.join(directory,'cases','many-jobs'),store=await CaseStore.create(selected);
  for(let index=0;index<513;index++)await store.putObject('jobs','job_'+index,{job_id:'job_'+index,operation:'simplify',status:'completed',created_at:new Date(index*1000).toISOString(),started_at:null,finished_at:null,result_id:null,error:null});
  await store.close();workspace=await WorkbenchWorkspace.open(directory);
  const entry=(await workspace.cases()).find(item=>item.path===selected)!,data=await workspace.caseData(entry.id);
  expect(data.jobs).toHaveLength(512);expect(data.jobs[0]?.job_id).toBe('job_512');
  expect(data.collections?.jobs).toEqual({total:513,shown:512,truncated:true});
  expect(data.collections?.models).toEqual({total:0,shown:0,truncated:false});
 });
 it('creates bounded named cases and refuses model imports that are file paths',async()=>{
  workspace=await WorkbenchWorkspace.open(directory);const created=await workspace.createCase('实验案例');
  expect(created.label).toBe('实验案例');expect((await workspace.caseData(created.id)).models.length).toBeGreaterThan(0);
  await expect(workspace.createCase('x'.repeat(121))).rejects.toThrow();
  await expect(workspace.importModel('workbench',path.join(directory,'examples/model.add-u8.json'))).rejects.toMatchObject({code:'MODEL_INVALID'});
  await workspace.close();workspace=await WorkbenchWorkspace.open(directory);
  expect((await workspace.cases()).find(item=>item.id===created.id)).toMatchObject({label:'实验案例',writable:true});
 });
 it.each(['task','model'])('rejects historical %s mutation without recovery or a writer lease',async kind=>{
  const selected=path.join(directory,'cases','history');const store=await CaseStore.create(selected);
  const job={job_id:'job_running',operation:'simplify',status:'running',created_at:new Date().toISOString(),started_at:null,finished_at:null,result_id:null,error:null};
  await store.putObject('jobs',job.job_id,job);await store.close();
  const file=path.join(selected,'jobs',(await import('../src/shared.js')).sha256(job.job_id)+'.json'),before=await readFile(file,'utf8');
  workspace=await WorkbenchWorkspace.open(directory);const entry=(await workspace.cases()).find(item=>item.path===selected)!;
  if(kind==='task')await expect(workspace.submit(entry.id,{kind:'invalid'} as never)).rejects.toThrow();
  else await expect(workspace.importModel(entry.id,{})).rejects.toThrow();
  expect(await readFile(file,'utf8')).toBe(before);expect(entry.writable).toBe(false);
  const reopened=await CaseStore.open(selected,false);await reopened.close();
  await expect(readFile(path.join(selected,'.wirefit.lock'),'utf8')).rejects.toMatchObject({code:'ENOENT'});
 });
 it('rejects symlink discovery and state directory aliases',async()=>{
  const target=await CaseStore.create(path.join(directory,'outside'));await target.close();await mkdir(path.join(directory,'cases'));
  await symlink(path.join(directory,'outside'),path.join(directory,'cases','alias'),'junction');
  workspace=await WorkbenchWorkspace.open(directory);expect((await workspace.cases()).some(item=>item.path.endsWith('alias'))).toBe(false);
  await expect(WorkbenchWorkspace.open(directory,{stateDir:path.join(directory,'cases','alias')})).rejects.toMatchObject({code:'WEB_PATH_INVALID'});
 });
 it('waits for an in-flight case creation before releasing every writer lease',async()=>{
  workspace=await WorkbenchWorkspace.open(directory);const created=workspace.createCase('shutdown race');
  await workspace.close();const selected=await created;workspace=undefined;
  const reopened=await CaseStore.open(selected.path);await reopened.close();
 });
 it.each(['raw','normalized'])('does not register artifact references supplied by IDA %s replies',async placement=>{
  const selected=path.join(directory,'cases','ida-history'),store=await CaseStore.create(selected);
  const orphan=await store.putArtifact(Buffer.from('private orphan, not registered by a run','utf8'),'text/plain');
  const source=await store.putArtifact(Buffer.from('fixture input','utf8'),'application/octet-stream');
  const reply=await store.putJson(placement==='raw'?{kind:'tool_reply',reply:{metadata:{forged:orphan}}}:{kind:'tool_reply',reply:{code:'retained'}});
  await store.putObject('runs','ida_untrusted',{result:{operation:'analyze_ida',result_id:'ida_untrusted',status:'completed',source:{artifact:source},artifacts:[reply],queries:[{query:{kind:'overview'},status:'completed',data:placement==='normalized'?{metadata:{forged:orphan}}:{},artifacts:[reply]}]}});
  await store.close();workspace=await WorkbenchWorkspace.open(directory);const entry=(await workspace.cases()).find(item=>item.path===selected)!;
  expect((await workspace.artifact(entry.id,reply.sha256)).bytes.toString('utf8')).toContain('tool_reply');
  await expect(workspace.artifact(entry.id,orphan.sha256)).rejects.toMatchObject({code:'ARTIFACT_NOT_FOUND'});
 });
});

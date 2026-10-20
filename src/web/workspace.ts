import path from 'node:path';
import {lstat} from 'node:fs/promises';
import {CaseStore} from '../store.js';
import {WirefitService} from '../service.js';
import {loadModel} from '../repository.js';
import {assert,id} from '../shared.js';
import type {Model} from '../types.js';
import type {JobState} from '../jobs.js';
import type {WebCase,WebCaseData,WebProfile,WebPreset,WebTaskRequest,WebRun,WebExport,LabRequest,LabResult} from './types.js';
import {WorkbenchActions} from './actions.js';
import {evaluateLab} from './lab.js';
import {describeCase,discoverCases,caseLabel,saveLabel} from './workspace-cases.js';
import {WorkbenchExports,artifactReferences} from './workspace-exports.js';
import {directory,jsonFile,noLinks} from './workspace-paths.js';
import {idaCapabilities} from '../ida/index.js';

const MODELS=['model.mba-u8.json','model.add-u8.json','model.affine-initial.json','model.affine-clamp-initial.json','model.piecewise-initial.json'];
const PRESETS=[
 {id:'fit-handwired',label:'Handwired 数值拟合',description:'拟合独立期望夹具；不执行原目标，不授予原目标保真度',file:'request.fit-handwired.json'},
 {id:'simplify-mba',label:'MBA 精确简化',description:'对 BV8 模型搜索更小表达式并用 Z3 检查',file:'request.simplify-mba.json'},
 {id:'verify-recorded',label:'验证保留集',description:'比较初始数值模型与保留期望夹具，保留实际失败',file:'request.verify-initial-recorded.json'},
 {id:'compare-equivalent',label:'BV 模型等价验证',description:'验证 MBA 与加法模型的声明输出',file:'request.compare-equivalent.json'},
];
const collectionSummary=(total:number,limit:number)=>({total,shown:Math.min(total,limit),truncated:total>limit});
export class WorkbenchWorkspace {
 private readonly descriptors=new Map<string,WebCase>();
 private readonly services=new Map<string,Promise<WirefitService>>();
 private readonly owned=new Map<string,Set<string>>();
 private readonly mutations=new Set<Promise<unknown>>();
 private readonly exports:WorkbenchExports;
 private closed=false;
 private closeTask:Promise<void>|undefined;
 private constructor(private readonly root:string,private readonly stateDir:string,private readonly actions:WorkbenchActions,private readonly suppliedPresets:WebPreset[]){this.exports=new WorkbenchExports(root);}
 static async open(root:string,options:{stateDir?:string}={}):Promise<WorkbenchWorkspace>{
  const selected=path.resolve(root);await noLinks(selected);assert((await lstat(selected)).isDirectory(),'WORKSPACE_INVALID','Workspace root must exist');
  const stateDir=await directory(path.resolve(options.stateDir??path.join(selected,'.local','workbench')));
  const actions=await WorkbenchActions.open(selected),presets:WebPreset[]=[];
  for(const preset of PRESETS)presets.push({id:preset.id,label:preset.label,description:preset.description,request:await jsonFile(path.join(selected,'examples',preset.file))});
  const workspace=new WorkbenchWorkspace(selected,stateDir,actions,presets);
  try{
   const casePath=path.join(stateDir,'case');await noLinks(casePath);
   let service:WirefitService;
   try{await lstat(path.join(casePath,'case.json'));service=await WirefitService.open(casePath);}
   catch(error){if((error as NodeJS.ErrnoException).code!=='ENOENT')throw error;await directory(casePath);service=await WirefitService.create(casePath);}
   workspace.services.set('workbench',Promise.resolve(service));
   workspace.descriptors.set('workbench',{...await describeCase(service.store.root,'workbench'),label:'工作台实验区'});
   await workspace.bootstrap(service);
   workspace.descriptors.set('vmde',{id:'vmde',label:'vmde 研究归档',path:path.join(selected,'artifacts','research','vmde'),case_id:'vmde',kind:'research',writable:false,created_at:null});
   await discoverCases([path.join(selected,'cases'),path.join(selected,'artifacts','research','vmde'),path.join(stateDir,'cases')],workspace.descriptors,[path.join(stateDir,'cases')]);
   return workspace;
  }catch(error){await workspace.close();throw error;}
 }
 private available():void{assert(!this.closed,'SERVICE_CLOSED','Workbench workspace is closed');}
 private mutation<T>(execute:()=>Promise<T>):Promise<T>{
  this.available();const task=execute();this.mutations.add(task);return task.finally(()=>this.mutations.delete(task));
 }
 private selected(caseId:string):WebCase{this.available();const selected=this.descriptors.get(caseId);assert(selected,'CASE_NOT_FOUND','Unknown case');return selected;}
 private async bootstrap(service:WirefitService):Promise<void>{
  const models=new Set((await service.store.listObjects<Model>('models')).map(entry=>entry.id));
  for(const file of MODELS){const model=await jsonFile<Model>(path.join(this.root,'examples',file));if(!models.has(model.model_id))await service.importModel(model);}
  if(!(await service.store.listObjects('datasets')).some(item=>item.id==='numeric_expected_fixture'))await service.importDataset(path.join(this.root,'examples','dataset.numeric-expected.json'),this.root);
 }
 private async reader<T>(caseId:string,read:(store:CaseStore)=>Promise<T>):Promise<T>{
  const selected=this.selected(caseId);assert(selected.kind==='managed','CASE_READ_ONLY','Research archive has no managed objects');
  const owned=this.services.get(caseId);if(owned)return read((await owned).store);
  await noLinks(selected.path);const store=await CaseStore.open(selected.path,false);try{return await read(store);}finally{await store.close();}
 }
 private async writer(caseId:string):Promise<WirefitService>{
  const selected=this.selected(caseId);assert(selected.kind==='managed'&&selected.writable,'CASE_READ_ONLY','Selected case is read only');
  let pending=this.services.get(caseId);
  if(!pending){pending=(async()=>{await noLinks(selected.path);return WirefitService.open(selected.path);})();this.services.set(caseId,pending);pending.catch(()=>{if(this.services.get(caseId)===pending)this.services.delete(caseId);});}
  return pending;
 }
 async cases():Promise<WebCase[]>{this.available();return [...this.descriptors.values()].map(item=>({...item}));}
 async createCase(label:string):Promise<WebCase>{
  return this.mutation(async()=>{
   caseLabel(label);const parent=await directory(path.join(this.stateDir,'cases')),caseId=id('case'),target=path.join(parent,caseId);
   await noLinks(target);const service=await WirefitService.create(target);
   try{await saveLabel(target,label.trim());await this.bootstrap(service);const selected=await describeCase(service.store.root);this.descriptors.set(selected.id,selected);this.services.set(selected.id,Promise.resolve(service));return {...selected};}
   catch(error){await service.close();throw error;}
  });
 }
 async caseData(caseId:string):Promise<WebCaseData>{
  const selected=this.selected(caseId);
  if(selected.kind==='research')return {case:{...selected},models:[],jobs:[],runs:[],datasets:[],oracles:[],collections:{models:collectionSummary(0,512),jobs:collectionSummary(0,512),runs:collectionSummary(0,512),datasets:collectionSummary(0,256),oracles:collectionSummary(0,256)}};
  return this.reader(caseId,async store=>{
   const [models,jobs,runs,datasets,oracles]=await Promise.all([store.listObjects<Model>('models'),store.listObjects<JobState>('jobs'),store.listObjects<{result:unknown;request?:{operation?:string}}>('runs'),store.listObjects('datasets'),store.listObjects('oracles')]);
   const runJobs=new Map(jobs.filter(entry=>entry.value.result_id!==null).map(entry=>[entry.value.result_id,entry.value]));
   const normalized:WebRun[]=runs.map(entry=>{
    const result=entry.value.result as Record<string,unknown>|null,job=runJobs.get(entry.id);
    return {id:entry.id,operation:typeof result?.operation==='string'?result.operation:entry.value.request?.operation??'unknown',status:typeof result?.status==='string'?result.status:typeof result?.job_status==='string'?result.job_status:job?.status??'recorded',created_at:job?.created_at??null,result:entry.value.result};
   });
   normalized.sort((a,b)=>(b.created_at??'').localeCompare(a.created_at??'')||a.id.localeCompare(b.id));
   return {case:{...selected},models:models.slice(0,512).map(entry=>entry.value),jobs:jobs.map(entry=>({...entry.value,owned:this.owned.get(caseId)?.has(entry.id)??false})).sort((a,b)=>b.created_at.localeCompare(a.created_at)).slice(0,512),runs:normalized.slice(0,512),datasets:datasets.slice(0,256).map(entry=>entry.value),oracles:oracles.slice(0,256).map(entry=>entry.value),collections:{models:collectionSummary(models.length,512),jobs:collectionSummary(jobs.length,512),runs:collectionSummary(runs.length,512),datasets:collectionSummary(datasets.length,256),oracles:collectionSummary(oracles.length,256)}};
  });
 }
 async model(caseId:string,modelId:string):Promise<Model>{return this.reader(caseId,store=>loadModel(store,modelId));}
 async evaluate(caseId:string,modelId:string,body:LabRequest):Promise<LabResult>{return evaluateLab(await this.model(caseId,modelId),body);}
 async importModel(caseId:string,model:unknown):Promise<unknown>{return this.mutation(async()=>{assert(model!==null&&typeof model==='object'&&!Array.isArray(model),'MODEL_INVALID','Import requires an explicit model object');return (await this.writer(caseId)).importModel(model);});}
 async submit(caseId:string,request:WebTaskRequest):Promise<JobState>{
  return this.mutation(async()=>{const job=await this.actions.submit(await this.writer(caseId),request);let owned=this.owned.get(caseId);if(!owned){owned=new Set();this.owned.set(caseId,owned);}owned.add(job.job_id);return job;});
 }
 async cancel(caseId:string,jobId:string):Promise<JobState>{this.selected(caseId);assert(this.owned.get(caseId)?.has(jobId),'JOB_NOT_OWNED','Only jobs submitted by this workbench session can be cancelled');return (await this.services.get(caseId)!).jobs.cancel(jobId);}
 async job(caseId:string,jobId:string):Promise<JobState>{return this.reader(caseId,store=>store.getObject<JobState>('jobs',jobId));}
 async artifact(caseId:string,sha:string):Promise<{bytes:Buffer;mediaType:string}>{
  assert(typeof sha==='string'&&/^[0-9a-f]{64}$/.test(sha),'ARTIFACT_INVALID','Artifact SHA-256 is invalid');
  return this.reader(caseId,async store=>{
   const kinds=['models','runs','jobs','datasets','oracles','evidence','reports'];
   const values=await Promise.all(kinds.map(kind=>store.listObjects(kind))),opaque=new Set<string>();
   // IDA replies are untrusted content. Only the adapter's explicit envelopes
   // register artifacts; neither normalized upstream metadata nor raw JSON may do so.
   const trusted=values.map((entries,index)=>entries.map(entry=>{
    if(kinds[index]!=='runs'||!entry.value||typeof entry.value!=='object')return entry;
    const result=(entry.value as {result?:Record<string,any>}).result;
    if(result?.operation!=='analyze_ida')return entry;
    const queries=Array.isArray(result.queries)?result.queries:[];
    assert(queries.length<=16,'RESOURCE_LIMIT','IDA query envelope exceeds budget');
    const registered=artifactReferences([result.source?.artifact,result.artifacts,result.tool_catalog_artifact,queries.map(item=>({artifact:item?.artifact,artifacts:item?.artifacts}))]);
    for(const ref of registered)opaque.add(ref.sha256);
    return {registered};
   }));
   const refs=artifactReferences(trusted),seen=new Set<string>();let total=0;
   for(let index=0;index<refs.length;index++){
    assert(index<8192,'RESOURCE_LIMIT','Artifact reference closure exceeds budget');const ref=refs[index]!;if(seen.has(ref.sha256))continue;seen.add(ref.sha256);
    if(ref.sha256===sha){assert(ref.size_bytes<=16*1024*1024,'RESOURCE_LIMIT','Artifact preview exceeds 16 MiB');return {bytes:await store.readArtifact(ref),mediaType:ref.media_type};}
    if(!opaque.has(ref.sha256)&&ref.media_type==='application/json'&&ref.size_bytes<=1024*1024){total+=ref.size_bytes;assert(total<=16*1024*1024,'RESOURCE_LIMIT','Artifact lookup exceeds 16 MiB');const parsed=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(await store.readArtifact(ref)));refs.push(...artifactReferences([parsed]));}
   }
   assert(false,'ARTIFACT_NOT_FOUND','Artifact is not registered by this case');
  });
 }
 async export(caseId:string,runId:string):Promise<WebExport>{return this.mutation(()=>this.reader(caseId,store=>this.exports.create(store,runId)));}
 async exportFile(exportId:string,relative:string):Promise<{bytes:Buffer;mediaType:string}>{this.available();return this.exports.file(exportId,relative);}
 profiles():WebProfile[]{this.available();return this.actions.profiles();}
 async idaCapabilities(){this.available();return idaCapabilities(this.root);}
 presets():WebPreset[]{this.available();return structuredClone(this.suppliedPresets);}
 async close():Promise<void>{
  if(this.closeTask)return this.closeTask;this.closed=true;
  this.closeTask=(async()=>{
   await Promise.allSettled([...this.mutations]);
   const results=await Promise.allSettled([...this.services.values()].map(async service=>(await service).close()));
   const failures=results.filter((result):result is PromiseRejectedResult=>result.status==='rejected');if(failures.length)throw new AggregateError(failures.map(item=>item.reason),'Workbench services did not close cleanly');
  })();return this.closeTask;
 }
}

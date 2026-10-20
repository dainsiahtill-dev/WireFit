import {CaseStore} from './store.js';
import {assert,errorRecord,id,WirefitError} from './shared.js';
import type {ArtifactRef,StructuredError} from './types.js';

export interface JobState {
 job_id:string;operation:string;status:'queued'|'running'|'cancelling'|'completed'|'failed'|'cancelled'|'interrupted';
 created_at:string;started_at:string|null;finished_at:string|null;result_id:string|null;error:StructuredError|null;
 request_artifact?:ArtifactRef;
}
export interface JobExecutionResult {result_id:string;status?:'completed'|'failed'|'cancelled';error?:StructuredError}
type Executor=(signal:AbortSignal,job:JobState)=>Promise<JobExecutionResult>;
interface Entry {
 job:JobState;controller:AbortController;execute:Executor;done:Promise<JobState>;resolve:(value:JobState)=>void;
 timeout_ms:number;persistence:Promise<void>;finishing:Promise<void>|null;settled:boolean;persistenceFailure:StructuredError|null;
}
const terminal=new Set<JobState['status']>(['completed','failed','cancelled','interrupted']);
export class JobManager {
 private queue:Entry[]=[];
 private entries=new Map<string,Entry>();
 private submissions=new Set<Promise<JobState>>();
 private pumpTask:Promise<void>|null=null;
 private closing=false;
 private closeTask:Promise<void>|null=null;
 constructor(private store:CaseStore){}
 async submit(operation:string,request:unknown,execute:Executor,timeout_ms=120000):Promise<JobState> {
  assert(!this.closing,'SERVICE_CLOSED','Job service is closing');
  assert(typeof operation==='string'&&operation.length>0&&operation.length<=128&&typeof execute==='function','JOB_INVALID','Job operation and executor are required');
  assert(Number.isInteger(timeout_ms)&&timeout_ms>0&&timeout_ms<=86400000,'JOB_INVALID','Invalid job timeout');
  const pending=this.createEntry(operation,request,execute,timeout_ms);this.submissions.add(pending);
  try{return await pending;}finally{this.submissions.delete(pending);}
 }
 private async createEntry(operation:string,request:unknown,execute:Executor,timeout_ms:number):Promise<JobState> {
  // The immutable request is durable before a runnable lifecycle record exists.
  const request_artifact=await this.store.putJson(request);
  assert(!this.closing,'SERVICE_CLOSED','Job service closed while persisting request');
  const job:JobState={job_id:id('job'),operation,status:'queued',created_at:new Date().toISOString(),started_at:null,finished_at:null,result_id:null,error:null,request_artifact};
  let resolve!:(value:JobState)=>void;const done=new Promise<JobState>(yes=>{resolve=yes;});
  const entry:Entry={job,execute,controller:new AbortController(),done,resolve,timeout_ms,persistence:Promise.resolve(),finishing:null,settled:false,persistenceFailure:null};
  await this.persist(entry);
  this.entries.set(job.job_id,entry);
  if(this.closing)await this.cancelEntry(entry);
  else {this.queue.push(entry);this.kick();}
  return structuredClone(entry.job);
 }
 private persist(entry:Entry):Promise<void> {
  const snapshot=structuredClone(entry.job);
  const next=entry.persistence.catch(()=>undefined).then(()=>this.store.updateObject('jobs',snapshot.job_id,snapshot));
  entry.persistence=next;return next;
 }
 private persistenceFailed(entry:Entry,error:unknown):void {
  const detail=error instanceof Error?error.message:String(error);
  entry.persistenceFailure=errorRecord(new WirefitError('PERSISTENCE_FAILED','Job lifecycle persistence failed: '+detail),'job');
  entry.job.status='failed';entry.job.error=entry.persistenceFailure;
 }
 private async finish(entry:Entry):Promise<void> {
  if(entry.finishing)return entry.finishing;
  entry.finishing=(async()=>{
   entry.job.finished_at??=new Date().toISOString();
   if(entry.persistenceFailure){entry.job.status='failed';entry.job.error=entry.persistenceFailure;}
   try {await this.persist(entry);}
   catch(error) {
    this.persistenceFailed(entry,error);
    // A transient write failure must still be recorded when the store recovers.
    try{await this.persist(entry);}catch{/* Returned in-memory state remains an explicit persistence failure. */}
   } finally {
    entry.settled=true;entry.resolve(structuredClone(entry.job));
   }
  })();
  return entry.finishing;
 }
 private kick():void {
  if(this.pumpTask)return;
  this.pumpTask=this.pump();
 }
 private async pump():Promise<void> {
  try {
   while(this.queue.length) {
    const entry=this.queue.shift()!;
    if(entry.settled)continue;
    try{await this.runEntry(entry);}
    catch(error){entry.job.status='failed';entry.job.error=errorRecord(error,'job');await this.finish(entry);}
   }
  } finally {this.pumpTask=null;if(this.queue.length)this.kick();}
 }
 private async runEntry(entry:Entry):Promise<void> {
  if(entry.job.status==='cancelled'||entry.controller.signal.aborted){await this.finish(entry);return;}
  entry.job.status='running';entry.job.started_at=new Date().toISOString();
  try{await this.persist(entry);}catch(error){this.persistenceFailed(entry,error);await this.finish(entry);return;}
  let timedOut=false;
  const timer=setTimeout(()=>{timedOut=true;entry.controller.abort(new WirefitError('TIMEOUT','Job wall timeout'));},entry.timeout_ms);
  try {
   if(entry.controller.signal.aborted)throw new WirefitError('CANCELLED','Job cancelled before execution');
   const result=await entry.execute(entry.controller.signal,structuredClone(entry.job));
   assert(result&&typeof result==='object'&&typeof result.result_id==='string'&&/^[A-Za-z][A-Za-z0-9_.:-]{0,127}$/.test(result.result_id),'JOB_RESULT_INVALID','Executor returned invalid result identity');
   const status=result.status??'completed';
   assert(['completed','failed','cancelled'].includes(status),'JOB_RESULT_INVALID','Executor returned invalid terminal status');
   // Only explicit non-success results may retain artifacts after cancellation.
   if(entry.controller.signal.aborted&&status==='completed')throw new WirefitError(timedOut?'TIMEOUT':'CANCELLED',timedOut?'Job wall timeout':'Job cancelled; late success rejected');
   entry.job.result_id=result.result_id;entry.job.status=timedOut?'failed':status;
   entry.job.error=timedOut?errorRecord(new WirefitError('TIMEOUT','Job wall timeout'),'job'):status==='completed'?null:result.error??errorRecord(new WirefitError(status==='cancelled'?'CANCELLED':'EXPERIMENT_FAILED',`Experiment ${status}`),'job');
  } catch(error) {
   entry.job.result_id=null;entry.job.status=entry.controller.signal.aborted&&!timedOut?'cancelled':'failed';
   entry.job.error=errorRecord(timedOut?new WirefitError('TIMEOUT','Job wall timeout'):error,'job');
  } finally {clearTimeout(timer);await this.finish(entry);}
 }
 async get(jobId:string):Promise<JobState> {
  const entry=this.entries.get(jobId);return entry?structuredClone(entry.job):this.store.getObject<JobState>('jobs',jobId);
 }
 private async cancelEntry(entry:Entry):Promise<JobState> {
  if(entry.settled||terminal.has(entry.job.status))return structuredClone(entry.job);
  const queued=entry.job.status==='queued';
  entry.job.status=queued?'cancelled':'cancelling';
  entry.job.error=queued?errorRecord(new WirefitError('CANCELLED','Queued job cancelled'),'job'):entry.job.error;
  entry.controller.abort();
  if(queued)await this.finish(entry);
  else {try{await this.persist(entry);}catch(error){this.persistenceFailed(entry,error);}}
  return structuredClone(entry.job);
 }
 async cancel(jobId:string):Promise<JobState> {
  const entry=this.entries.get(jobId);assert(entry,'JOB_NOT_OWNED','Only the owning service instance can cancel a job');return this.cancelEntry(entry);
 }
 async wait(jobId:string):Promise<JobState> {const entry=this.entries.get(jobId);return entry?entry.done:this.get(jobId);}
 async close():Promise<void> {
  if(this.closeTask)return this.closeTask;
  this.closing=true;
  this.closeTask=(async()=>{
   await Promise.allSettled([...this.submissions]);
   await Promise.all([...this.entries.values()].filter(entry=>!entry.settled).map(entry=>this.cancelEntry(entry)));
   await Promise.all([...this.entries.values()].map(entry=>entry.done));
   await this.pumpTask;
  })();
  return this.closeTask;
 }
}

import {describe,it,expect,vi} from 'vitest';
import {mkdtemp,rm} from 'node:fs/promises';
import path from 'node:path';
import {tmpdir} from 'node:os';
import {CaseStore} from '../src/store.js';
import {JobManager} from '../src/jobs.js';
import {runProcess} from '../src/process.js';
describe('persisted jobs',()=>{
 it('cancels active work and rejects a late success',async()=>{
  const dir=await mkdtemp(path.join(tmpdir(),'wirefit-jobs-'));const store=await CaseStore.create(dir);const jobs=new JobManager(store);
  try{
   const job=await jobs.submit('cancel-test',{},async(signal:AbortSignal)=>{await runProcess(process.execPath,['-e','setTimeout(()=>console.log("late"),10000)'],{signal});return {result_id:'late'};});
   await new Promise(resolve=>setTimeout(resolve,100));
   await jobs.cancel(job.job_id);
   const final=await jobs.wait(job.job_id);
   expect(final.status).toBe('cancelled');expect(final.result_id).toBe(null);
  }finally{await jobs.close();await store.close();await rm(dir,{recursive:true,force:true});}
 });
 it('marks abandoned jobs interrupted on writer reopen',async()=>{
  const dir=await mkdtemp(path.join(tmpdir(),'wirefit-jobs-'));let store=await CaseStore.create(dir);
  try{
   await store.updateObject('jobs','abandoned',{job_id:'abandoned',status:'running'});
   await store.close();store=await CaseStore.open(dir);
   expect((await store.getObject<any>('jobs','abandoned')).status).toBe('interrupted');
  }finally{await store.close();await rm(dir,{recursive:true,force:true});}
 });
});


function settleWithin<T>(promise:Promise<T>,ms=700):Promise<T|{status:'did_not_settle'}>{return new Promise(resolve=>{const timer=setTimeout(()=>resolve({status:'did_not_settle'}),ms);promise.then(value=>{clearTimeout(timer);resolve(value);});});}
it('does not leave a queued orphan when persisting the request fails',async()=>{
 const dir=await mkdtemp(path.join(tmpdir(),'wirefit-jobs-'));const store=await CaseStore.create(dir),jobs=new JobManager(store);
 try{vi.spyOn(store,'putJson').mockRejectedValueOnce(new Error('request disk failure'));await expect(jobs.submit('test',{},async()=>({result_id:'unused'}))).rejects.toThrow('request disk failure');expect(await store.listObjects('jobs')).toEqual([]);}
 finally{vi.restoreAllMocks();await settleWithin(jobs.close());await store.close();await rm(dir,{recursive:true,force:true});}
});
it('settles a running-state persistence failure and continues the next queued job',async()=>{
 const dir=await mkdtemp(path.join(tmpdir(),'wirefit-jobs-'));const store=await CaseStore.create(dir),jobs=new JobManager(store);const persist=store.updateObject.bind(store);let fail=true;
 vi.spyOn(store,'updateObject').mockImplementation(async(kind,key,value:any)=>{if(fail&&value.status==='running'){fail=false;throw Error('running disk failure');}return persist(kind,key,value);});
 try{const broken=await jobs.submit('first',{},async()=>({result_id:'must_not_run'}));const first:any=await settleWithin(jobs.wait(broken.job_id));expect(first.status).toBe('failed');expect(first.error.code).toBe('PERSISTENCE_FAILED');const next=await jobs.submit('second',{},async()=>({result_id:'second_result'}));expect((await jobs.wait(next.job_id)).status).toBe('completed');}
 finally{vi.restoreAllMocks();await settleWithin(jobs.close());await store.close();await rm(dir,{recursive:true,force:true});}
});
it('settles terminal persistence failures without hanging wait or close',async()=>{
 const dir=await mkdtemp(path.join(tmpdir(),'wirefit-jobs-'));const store=await CaseStore.create(dir),jobs=new JobManager(store);const persist=store.updateObject.bind(store);let fail=true;
 vi.spyOn(store,'updateObject').mockImplementation(async(kind,key,value:any)=>{if(fail&&value.status==='completed'){fail=false;throw Error('terminal disk failure');}return persist(kind,key,value);});
 try{const job=await jobs.submit('test',{},async()=>({result_id:'computed'}));const final:any=await settleWithin(jobs.wait(job.job_id));expect(final.status).toBe('failed');expect(final.error.code).toBe('PERSISTENCE_FAILED');expect((await jobs.get(job.job_id)).status).toBe('failed');}
 finally{vi.restoreAllMocks();await settleWithin(jobs.close());await store.close();await rm(dir,{recursive:true,force:true});}
});
it('retains genuine failed and cancelled partial result identities',async()=>{
 const dir=await mkdtemp(path.join(tmpdir(),'wirefit-jobs-'));const store=await CaseStore.create(dir),jobs=new JobManager(store);
 try{const failed=await jobs.submit('failure',{},async()=>({result_id:'failed_run',status:'failed'} as any));expect(await jobs.wait(failed.job_id)).toMatchObject({status:'failed',result_id:'failed_run'});let started!:()=>void;const active=new Promise<void>(resolve=>{started=resolve;});const cancelled=await jobs.submit('partial',{},async(signal)=>{started();await new Promise<void>(resolve=>signal.addEventListener('abort',()=>resolve(),{once:true}));return {result_id:'cancelled_run',status:'cancelled'} as any;});await active;await jobs.cancel(cancelled.job_id);expect(await jobs.wait(cancelled.job_id)).toMatchObject({status:'cancelled',result_id:'cancelled_run'});}
 finally{await jobs.close();await store.close();await rm(dir,{recursive:true,force:true});}
});

it('does not resolve a queued cancellation before its terminal record is durable',async()=>{
 const dir=await mkdtemp(path.join(tmpdir(),'wirefit-jobs-'));const store=await CaseStore.create(dir),jobs=new JobManager(store);let releaseFirst!:()=>void;const firstGate=new Promise<void>(resolve=>{releaseFirst=resolve;});let reached!:()=>void;const reachedCancel=new Promise<void>(resolve=>{reached=resolve;});let releaseCancel!:()=>void;const cancelGate=new Promise<void>(resolve=>{releaseCancel=resolve;});let secondId='';const persist=store.updateObject.bind(store);
 vi.spyOn(store,'updateObject').mockImplementation(async(kind,key,value:any)=>{if(key===secondId&&value.status==='cancelled'){reached();await cancelGate;}return persist(kind,key,value);});
 try{await jobs.submit('blocking',{},async()=>{await firstGate;return {result_id:'first'};});const queued=await jobs.submit('queued',{},async()=>{throw Error('cancelled queued executor ran');});secondId=queued.job_id;const cancelling=jobs.cancel(secondId);await reachedCancel;releaseFirst();expect(await settleWithin(jobs.wait(secondId),40)).toEqual({status:'did_not_settle'});releaseCancel();await cancelling;const final=await jobs.wait(secondId);expect(final.status).toBe('cancelled');expect(final.started_at).toBe(null);expect(final.finished_at).not.toBe(null);}
 finally{releaseFirst();releaseCancel();vi.restoreAllMocks();await jobs.close();await store.close();await rm(dir,{recursive:true,force:true});}
});
it('retains an explicit timeout partial result while rejecting success after the same deadline',async()=>{
 const dir=await mkdtemp(path.join(tmpdir(),'wirefit-jobs-'));const store=await CaseStore.create(dir),jobs=new JobManager(store);
 try{const partial=await jobs.submit('timeout-partial',{},async(signal)=>{await new Promise<void>(resolve=>signal.addEventListener('abort',()=>resolve(),{once:true}));return {result_id:'timeout_run',status:'cancelled'};},25);expect(await jobs.wait(partial.job_id)).toMatchObject({status:'failed',result_id:'timeout_run',error:{code:'TIMEOUT'}});const late=await jobs.submit('late',{},async()=>{await new Promise(resolve=>setTimeout(resolve,60));return {result_id:'late_success'};},10);expect(await jobs.wait(late.job_id)).toMatchObject({status:'failed',result_id:null,error:{code:'TIMEOUT'}});}
 finally{await jobs.close();await store.close();await rm(dir,{recursive:true,force:true});}
});

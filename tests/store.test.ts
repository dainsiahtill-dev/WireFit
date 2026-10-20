import {describe,it,expect} from 'vitest';
import {mkdtemp,rm,readFile,writeFile,readdir,realpath,lstat} from 'node:fs/promises';
import path from 'node:path';
import {tmpdir} from 'node:os';
import {CaseStore} from '../src/store.js';
const roots:string[]=[];
async function workspace(){const root=await mkdtemp(path.join(tmpdir(),'wirefit-store-'));roots.push(root);return root;}
describe('case storage',()=>{
 it('holds one writer lease and permits read-only inspection',async()=>{
  const dir=await workspace();const first=await CaseStore.create(dir);
  try{
   await expect(CaseStore.open(dir)).rejects.toThrow(/busy/i);
   const reader=await CaseStore.open(dir,false);await reader.close();
  }finally{await first.close();await rm(dir,{recursive:true,force:true});}
 });
 it('acquires a writer without recovering historical jobs before the caller validates them',async()=>{
  const dir=await workspace();const initial=await CaseStore.create(dir);
  await initial.putObject('jobs','pending_evidence_job',{status:'queued',created_at:'2026-10-20T00:00:00Z'});await initial.close();
  const jobPath=path.join(dir,'jobs',(await readdir(path.join(dir,'jobs')))[0]!);
  const before=await readFile(jobPath);
  let append:CaseStore|undefined;
  try{
   append=await CaseStore.openWithoutRecovery(dir);
   expect(append.writable).toBe(true);expect(await readFile(jobPath)).toEqual(before);
   expect((await append.getObject<any>('jobs','pending_evidence_job')).status).toBe('queued');
   await expect(CaseStore.openWithoutRecovery(dir)).rejects.toThrow(/busy/i);
   await append.close();append=undefined;
   const recovering=await CaseStore.open(dir);
   try{expect((await recovering.getObject<any>('jobs','pending_evidence_job')).status).toBe('interrupted');}
   finally{await recovering.close();}
  }finally{
   await append?.close();const safe=await realpath(dir),parent=await realpath(tmpdir());
   expect(path.dirname(safe)).toBe(parent);expect(path.basename(safe).startsWith('wirefit-store-')).toBe(true);
   expect((await lstat(dir)).isSymbolicLink()).toBe(false);await rm(safe,{recursive:true,force:true});
  }
 });
 it('stores arbitrary valid IDs without using IDs as disk paths',async()=>{
  const dir=await workspace();const store=await CaseStore.create(dir);
  try{
   await store.putObject('models','model:version1',{payload:'0x0020000000000001'});
   expect(await store.getObject('models','model:version1')).toEqual({payload:'0x0020000000000001'});
   await expect(store.putObject('models','model:version1',{payload:'other'})).rejects.toThrow(/immutable/i);
   await expect(store.putObject('models','../../bad',{})).rejects.toThrow();
  }finally{await store.close();await rm(dir,{recursive:true,force:true});}
 });
 it('checks artifact bytes and rejects traversal and alias paths',async()=>{
  const dir=await workspace();const store=await CaseStore.create(dir);
  try{
   const bytes=Buffer.from('原始证据','utf8');const ref=await store.putArtifact(bytes,'text/plain;charset=utf-8');
   expect(await store.readArtifact(ref)).toEqual(bytes);
   await expect(store.readArtifact({...ref,relative_path:'../outside'})).rejects.toThrow();
   await expect(store.readArtifact({...ref,sha256:'0'.repeat(64)})).rejects.toThrow(/digest|hash/i);
   await writeFile(path.join(dir,ref.relative_path),'tampered','utf8');
   await expect(store.readArtifact(ref)).rejects.toThrow(/digest|hash|size/i);
  }finally{await store.close();await rm(dir,{recursive:true,force:true});}
 });
it('releases the writer lease when recovery rejects malformed persisted jobs',async()=>{
  const dir=await workspace();const store=await CaseStore.create(dir);
  await store.putObject('jobs','broken_job',{status:'running'});
  await store.close();
  const files=await readdir(path.join(dir,'jobs'));
  const jobPath=path.join(dir,'jobs',files[0]!);
  try{
   await writeFile(jobPath,'{invalid json','utf8');
   await expect(CaseStore.open(dir)).rejects.toThrow(/json/i);
   await expect(readFile(path.join(dir,'.wirefit.lock'),'utf8')).rejects.toMatchObject({code:'ENOENT'});
   await writeFile(jobPath,JSON.stringify({id:'broken_job',value:{status:'completed'}})+'\n','utf8');
   const recovered=await CaseStore.open(dir);await recovered.close();
  }finally{await rm(dir,{recursive:true,force:true});}
 });
 it('snapshots caller-owned artifact bytes before scheduling publication',async()=>{
  const dir=await workspace();const store=await CaseStore.create(dir);
  try{
   const bytes=Buffer.from('old','utf8');
   const saving=store.putArtifact(bytes);
   bytes.set(Buffer.from('new','utf8'));
   const ref=await saving;
   expect((await store.readArtifact(ref)).toString('utf8')).toBe('old');
  }finally{await store.close();await rm(dir,{recursive:true,force:true});}
 });
 it('snapshots object and job values before queued writes',async()=>{
  const dir=await workspace();const store=await CaseStore.create(dir);
  try{
   const model={nested:{value:'original'}};
   const saving=store.putObject('models','snapshot_model',model);
   model.nested.value='mutated';
   await saving;
   expect(await store.getObject('models','snapshot_model')).toEqual({nested:{value:'original'}});
   const job={status:'running',progress:{completed:1}};
   const updating=store.updateObject('jobs','snapshot_job',job);
   job.status='completed';job.progress.completed=9;
   await updating;
   expect(await store.getObject('jobs','snapshot_job')).toEqual({status:'running',progress:{completed:1}});
  }finally{await store.close();await rm(dir,{recursive:true,force:true});}
 });
});

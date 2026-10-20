import {describe,it,expect,vi} from 'vitest';
import {mkdtemp,rm,readFile,readdir} from 'node:fs/promises';
import path from 'node:path';
import {tmpdir} from 'node:os';
const fault=vi.hoisted(()=>({code:'',remaining:0,calls:0}));
vi.mock('node:fs/promises',async importOriginal=>{
 const actual=await importOriginal<typeof import('node:fs/promises')>();
 return {...actual,rename:async(...args:Parameters<typeof actual.rename>)=>{
  fault.calls++;
  if(fault.remaining>0){fault.remaining--;throw Object.assign(new Error('Injected publication failure'),{code:fault.code});}
  return actual.rename(...args);
 }};
});
import {CaseStore} from '../src/store.js';
async function fixture(){
 const dir=await mkdtemp(path.join(tmpdir(),'wirefit-atomic-'));
 const store=await CaseStore.create(dir);await store.updateObject('jobs','publication_job',{status:'queued'});
 const file=path.join(dir,'jobs',(await readdir(path.join(dir,'jobs')))[0]!);
 return {dir,store,file,async close(){fault.remaining=0;await store.close();await rm(dir,{recursive:true,force:true});}};
}
describe('atomic case publication under file contention',()=>{
 for(const code of ['EPERM','EACCES','EBUSY'])it.skipIf(process.platform!=='win32')(`retries transient Windows ${code} without losing the previous snapshot`,async()=>{
  const f=await fixture();
  try{fault.code=code;fault.remaining=2;fault.calls=0;
   await f.store.updateObject('jobs','publication_job',{status:'running'});
   expect(fault.calls).toBe(3);expect(await f.store.getObject('jobs','publication_job')).toEqual({status:'running'});
   expect((await readdir(path.dirname(f.file))).filter(name=>name.includes('.tmp-'))).toEqual([]);
  }finally{await f.close();}
 });
 it('bounds persistent contention, preserves the old snapshot and permits a later write',async()=>{
  const f=await fixture();
  try{const before=await readFile(f.file);fault.code='EPERM';fault.remaining=100;fault.calls=0;
   await expect(f.store.updateObject('jobs','publication_job',{status:'running'})).rejects.toMatchObject({code:'EPERM'});
   expect(fault.calls).toBe(process.platform==='win32'?7:1);expect(await readFile(f.file)).toEqual(before);
   expect((await readdir(path.dirname(f.file))).filter(name=>name.includes('.tmp-'))).toEqual([]);
   fault.remaining=0;await f.store.updateObject('jobs','publication_job',{status:'completed'});
   expect(await f.store.getObject('jobs','publication_job')).toEqual({status:'completed'});
  }finally{await f.close();}
 });
 it('does not retry unrelated filesystem failures',async()=>{
  const f=await fixture();
  try{fault.code='ENOSPC';fault.remaining=100;fault.calls=0;
   await expect(f.store.updateObject('jobs','publication_job',{})).rejects.toMatchObject({code:'ENOSPC'});expect(fault.calls).toBe(1);
   expect((await readdir(path.dirname(f.file))).filter(name=>name.includes('.tmp-'))).toEqual([]);
  }finally{await f.close();}
 });
});
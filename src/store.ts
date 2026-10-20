import {mkdir,open,readFile,writeFile,rename,unlink,realpath,lstat,readdir,stat} from 'node:fs/promises';
import path from 'node:path';
import {randomUUID} from 'node:crypto';
import {assert,WirefitError,sha256,readJson,id} from './shared.js';
import type {ArtifactRef} from './types.js';

const categories=new Set(['models','oracles','datasets','jobs','runs','evidence','reports']);
const idPattern=/^[A-Za-z][A-Za-z0-9_.:-]{0,127}$/;
interface Envelope<T>{id:string;value:T}
export class CaseStore {
 private lease:string|null=null;
 private pending:Promise<unknown>=Promise.resolve();
 private constructor(public readonly root:string,public readonly writable:boolean){}
 static async create(dir:string):Promise<CaseStore>{
  await mkdir(path.resolve(dir),{recursive:true});
  const root=await realpath(path.resolve(dir));
  const handle=await open(path.join(root,'case.json'),'wx').catch(error=>{throw new WirefitError('CASE_EXISTS','Case already exists: '+root,error);});
  try{await handle.writeFile(JSON.stringify({schema_version:1,case_id:id('case'),product:'Wirefit',created_at:new Date().toISOString()},null,2)+'\n','utf8');await handle.sync();}
  finally{await handle.close();}
  return this.open(root);
 }
 static async open(dir:string,write=true):Promise<CaseStore>{
  return this.openExisting(dir,write,true);
 }
 // Evidence-only writers validate terminal jobs while holding the lease. Opening
 // their store must not first mutate the historical jobs they are validating.
 static async openWithoutRecovery(dir:string):Promise<CaseStore>{
  return this.openExisting(dir,true,false);
 }
 private static async openExisting(dir:string,write:boolean,recover:boolean):Promise<CaseStore>{
  const root=await realpath(path.resolve(dir));
  const manifest=await readJson<{schema_version:number;case_id:string}>(path.join(root,'case.json'));
  assert(manifest.schema_version===1&&typeof manifest.case_id==='string','CASE_INVALID','Unsupported case manifest');
  const store=new CaseStore(root,write);
  if(write){
   await store.acquire();
   try{if(recover)await store.recover();}
   catch(error){
    try{await store.close();}
    catch(cleanupError){throw new AggregateError([error,cleanupError],'Case recovery and writer lease cleanup failed',{cause:error});}
    throw error;
   }
  }
  return store;
 }
 private async acquire():Promise<void>{
  const lockPath=path.join(this.root,'.wirefit.lock');
  const nonce=randomUUID();
  for(let attempt=0;attempt<2;attempt++){
   try{
    const handle=await open(lockPath,'wx');
    try{await handle.writeFile(JSON.stringify({pid:process.pid,nonce,created_at:new Date().toISOString()})+'\n','utf8');await handle.sync();}
    finally{await handle.close();}
    this.lease=nonce;return;
   }catch(error){
    if((error as NodeJS.ErrnoException).code!=='EEXIST')throw error;
    const lock=await readJson<{pid:number;nonce:string}>(lockPath);
    assert(Number.isSafeInteger(lock.pid)&&lock.pid>0&&typeof lock.nonce==='string','CASE_LOCK_INVALID','Case lock is invalid; manual inspection required');
    let alive=true;try{process.kill(lock.pid,0);}catch(probe){if((probe as NodeJS.ErrnoException).code==='ESRCH')alive=false;}
    assert(!alive,'CASE_BUSY','Case busy: another writer holds its lease');
    const unchanged=await readJson<{nonce:string}>(lockPath);
    assert(unchanged.nonce===lock.nonce,'CASE_BUSY','Case lock changed while checking stale owner');
    await unlink(lockPath);
   }
  }
  throw new WirefitError('CASE_BUSY','Case busy: could not acquire writer lease');
 }
 private async recover():Promise<void>{
  for(const job of await this.listObjects<Record<string,unknown>>('jobs')){
   if(['queued','running','cancelling'].includes(String(job.value.status))){
    await this.updateObject('jobs',job.id,{...job.value,status:'interrupted',finished_at:new Date().toISOString(),error:{code:'INTERRUPTED',message:'Owning process exited before job completed'}});
   }
  }
 }
 private requireWriter():void{assert(this.writable&&this.lease!==null,'CASE_READ_ONLY','A writer lease is required');}
 private serial<T>(action:()=>Promise<T>):Promise<T>{
  this.requireWriter();
  const result=this.pending.then(action,action);
  this.pending=result.catch(()=>undefined);
  return result;
 }
 async close():Promise<void>{
  await this.pending;
  if(this.lease!==null){
   const lockPath=path.join(this.root,'.wirefit.lock');
   const lock=await readJson<{nonce:string}>(lockPath);
   assert(lock.nonce===this.lease,'CASE_LOCK_INVALID','Writer lease ownership changed');
   await unlink(lockPath);this.lease=null;
  }
 }
 private objectRelative(kind:string,objectId:string):string{
  assert(categories.has(kind),'OBJECT_KIND_INVALID','Unknown object category');
  assert(idPattern.test(objectId),'OBJECT_ID_INVALID','Invalid local object ID');
  return kind+'/'+sha256(objectId)+'.json';
 }
 async resolveRelative(relative:string,mustExist=true):Promise<string>{
  assert(typeof relative==='string'&&relative.length>0&&!relative.includes('\\')&&!relative.includes(':')&&!relative.includes('\0'),'ARTIFACT_PATH_INVALID','Invalid relative path');
  const parts=relative.split('/');
  assert(parts.every(part=>part!==''&&part!=='.'&&part!=='..'),'ARTIFACT_PATH_INVALID','Relative path contains traversal or alias');
  const target=path.resolve(this.root,...parts);
  assert(target.startsWith(this.root+path.sep),'ARTIFACT_PATH_INVALID','Path escapes case');
  let current=this.root;
  for(const part of parts){
   current=path.join(current,part);
   try{const info=await lstat(current);assert(!info.isSymbolicLink(),'ARTIFACT_PATH_INVALID','Symlink/junction artifact paths are not accepted');}
   catch(error){if((error as NodeJS.ErrnoException).code!=='ENOENT')throw error;if(mustExist)throw error;break;}
  }
  if(mustExist){
   const resolved=await realpath(target);
   assert(resolved.startsWith(this.root+path.sep),'ARTIFACT_PATH_INVALID','Resolved artifact escapes case');
  }
  return target;
 }
 private async atomic(relative:string,bytes:Uint8Array):Promise<void>{
  const target=await this.resolveRelative(relative,false);
  await mkdir(path.dirname(target),{recursive:true});
  await this.resolveRelative(relative,false);
  const temp=target+'.tmp-'+randomUUID();
  const handle=await open(temp,'wx');
  try{await handle.writeFile(bytes);await handle.sync();}
  finally{await handle.close();}
  // Windows readers and scanners may briefly deny replacement of an existing
  // file. Retry the same atomic rename; never remove or rewrite the old target.
  const delays=[10,25,50,100,200,400];
  try{
   for(let attempt=0;;attempt++){
    try{await rename(temp,target);break;}
    catch(error){
     const code=(error as NodeJS.ErrnoException).code;
     if(process.platform!=='win32'||!['EPERM','EACCES','EBUSY'].includes(code??'')||attempt>=delays.length)throw error;
     await new Promise<void>(resolve=>setTimeout(resolve,delays[attempt]!));
     await this.resolveRelative(relative,false);
    }
   }
  }catch(error){await unlink(temp).catch(()=>undefined);throw error;}
 }
 async putObject(kind:string,objectId:string,value:unknown):Promise<void>{
  const relative=this.objectRelative(kind,objectId);
  const bytes=Buffer.from(JSON.stringify({id:objectId,value})+'\n','utf8');
  return this.serial(async()=>{
   try{
    const previous=await readFile(await this.resolveRelative(relative));
    assert(previous.equals(bytes),'OBJECT_IMMUTABLE','Immutable object ID already has different content');
    return;
   }catch(error){if((error as NodeJS.ErrnoException).code!=='ENOENT')throw error;}
   await this.atomic(relative,bytes);
  });
 }
 async updateObject(kind:string,objectId:string,value:unknown):Promise<void>{
  assert(kind==='jobs','OBJECT_IMMUTABLE','Only job lifecycle records are mutable');
  const relative=this.objectRelative(kind,objectId);
  const bytes=Buffer.from(JSON.stringify({id:objectId,value})+'\n','utf8');
  return this.serial(()=>this.atomic(relative,bytes));
 }
 async getObject<T=unknown>(kind:string,objectId:string):Promise<T>{
  const object=await readJson<Envelope<T>>(await this.resolveRelative(this.objectRelative(kind,objectId)));
  assert(object.id===objectId,'OBJECT_ID_INVALID','Stored object ID mismatch');
  return object.value;
 }
 async listObjects<T=unknown>(kind:string):Promise<Envelope<T>[]>{
  assert(categories.has(kind),'OBJECT_KIND_INVALID','Unknown object category');
  let names:string[];try{names=await readdir(path.join(this.root,kind));}catch(error){if((error as NodeJS.ErrnoException).code==='ENOENT')return [];throw error;}
  const output:Envelope<T>[]=[];
  for(const name of names.filter(name=>/^[0-9a-f]{64}\.json$/.test(name))){
   const entry=await readJson<Envelope<T>>(await this.resolveRelative(kind+'/'+name));
   assert(this.objectRelative(kind,entry.id)===kind+'/'+name,'OBJECT_ID_INVALID','Object filename identity mismatch');output.push(entry);
  }
  return output;
 }
 async putArtifact(bytes:Uint8Array,media='application/octet-stream'):Promise<ArtifactRef>{
  assert(bytes instanceof Uint8Array&&bytes.byteLength<=128*1024*1024,'ARTIFACT_SIZE_MISMATCH','Artifact must be bytes within the 128 MiB read limit');
  const snapshot=Buffer.from(bytes);
  const digest=sha256(snapshot);const relative='artifacts/'+digest;
  await this.serial(async()=>{
   try{
    const existing=await readFile(await this.resolveRelative(relative));
    assert(existing.length===snapshot.byteLength&&sha256(existing)===digest,'ARTIFACT_DIGEST_MISMATCH','Existing artifact hash mismatch');
   }catch(error){if((error as NodeJS.ErrnoException).code!=='ENOENT')throw error;await this.atomic(relative,snapshot);}
  });
  return {sha256:digest,relative_path:relative,media_type:media,size_bytes:snapshot.byteLength};
 }
 async putJson(value:unknown):Promise<ArtifactRef>{return this.putArtifact(Buffer.from(JSON.stringify(value,null,2)+'\n','utf8'),'application/json');}
 async putJsonl(rows:unknown[]):Promise<ArtifactRef>{return this.putArtifact(Buffer.from(rows.map(row=>JSON.stringify(row)).join('\n')+(rows.length?'\n':''),'utf8'),'application/x-ndjson');}
 async readArtifact(ref:ArtifactRef):Promise<Buffer>{
  assert(ref!==null&&typeof ref==='object'&&/^[0-9a-f]{64}$/.test(ref.sha256)&&Number.isSafeInteger(ref.size_bytes)&&ref.size_bytes>=0,'ARTIFACT_INVALID','Invalid artifact metadata');
  const target=await this.resolveRelative(ref.relative_path);
  const info=await stat(target);
  assert(info.isFile()&&info.size===ref.size_bytes&&info.size<=128*1024*1024,'ARTIFACT_SIZE_MISMATCH','Artifact size mismatch or limit exceeded');
  const bytes=await readFile(target);
  assert(sha256(bytes)===ref.sha256,'ARTIFACT_DIGEST_MISMATCH','Artifact hash mismatch');
  return bytes;
 }
}

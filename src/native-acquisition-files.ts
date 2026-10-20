import {lstat,open,realpath} from 'node:fs/promises';
import type {BigIntStats} from 'node:fs';
import path from 'node:path';
import type {Snapshot} from './binary-files.js';
import {assert,sha256,WirefitError} from './shared.js';

const CODE='ACQUISITION_PATH_INVALID',CHANGED='ACQUISITION_FILE_CHANGED';
const equal=(a:string,b:string)=>process.platform==='win32'?a.toLowerCase()===b.toLowerCase():a===b;
const absent=(error:unknown)=>['ENOENT','ENOTDIR'].includes((error as NodeJS.ErrnoException)?.code??'');
export async function assertAcquisitionPath(file:string):Promise<string>{
 const selected=path.resolve(file);let missing:unknown;
 // Inspect ancestors even when the leaf disappeared: a dangling junction must
 // remain a path violation rather than masquerading as a retryable replacement.
 for(let current=selected;;current=path.dirname(current)){
  try{assert(!(await lstat(current)).isSymbolicLink(),CODE,'Acquisition paths may not contain links or junctions');}
  catch(error){if(!absent(error))throw error;missing??=error;}
  if(path.dirname(current)===current)break;
 }
 if(missing)throw missing;
 assert(equal(selected,await realpath(selected)),CODE,'Acquisition path resolves through an alias');
 return selected;
}
function same(a:BigIntStats,b:BigIntStats):boolean{
 return a.dev===b.dev&&a.ino===b.ino&&a.size===b.size&&a.mtimeNs===b.mtimeNs&&a.ctimeNs===b.ctimeNs&&a.nlink===b.nlink&&b.nlink>=1n;
}
function boundedFile(stat:BigIntStats,limit:number,unique:boolean):void{
 assert(stat.isFile()&&stat.size>0n&&stat.size<=BigInt(limit)&&(!unique||stat.nlink<=1n),CODE,'Acquisition file is aliased or outside its byte bound');
}
async function currentFile(selected:string,limit:number,unique:boolean):Promise<BigIntStats>{
 try{await assertAcquisitionPath(selected);const stat=await lstat(selected,{bigint:true});boundedFile(stat,limit,unique);return stat;}
 catch(error){if(absent(error))throw new WirefitError(CHANGED,'Acquisition file disappeared while taking its snapshot');throw error;}
}
export async function readAcquisitionFile(file:string,limit=67108864,unique=false):Promise<Snapshot>{
 assert(Number.isSafeInteger(limit)&&limit>=1&&limit<=134217728,CODE,'Invalid acquisition file byte limit');
 const selected=await assertAcquisitionPath(file),entry=await currentFile(selected,limit,unique);
 const handle=await open(selected,'r').catch(async error=>{
  // Recheck aliases before classifying an open race, including missing leaves.
  await currentFile(selected,limit,unique);
  if(absent(error))throw new WirefitError(CHANGED,'Acquisition file changed before its HANDLE opened');throw error;
 });
 try{
  const before=await handle.stat({bigint:true});boundedFile(before,limit,unique);
  const opened=await currentFile(selected,limit,unique);
  assert(same(entry,before)&&same(before,opened),CHANGED,'Acquisition file changed between entry inspection and HANDLE open');
  const bytes=Buffer.alloc(Number(before.size)+1);let length=0;
  while(length<bytes.length){const next=await handle.read(bytes,length,bytes.length-length,length);if(next.bytesRead===0)break;length+=next.bytesRead;}
  const after=await handle.stat({bigint:true}),current=await currentFile(selected,limit,unique);boundedFile(after,limit,unique);
  assert(length===Number(before.size)&&same(before,after)&&same(after,current),CHANGED,'Acquisition file changed while reading');
  const captured=bytes.subarray(0,length);return {path:selected,bytes:captured,size_bytes:length,sha256:sha256(captured)};
 }finally{await handle.close();}
}
export async function assertNewAcquisitionOutput(file:string):Promise<void>{
 const selected=path.resolve(file),name=path.basename(selected);
 assert(name.length>0&&name.length<=255&&!/[<>:"/\\|?*\x00-\x1f]/.test(name)&&!/[. ]$/.test(name)&&!['.','..'].includes(name)&&!/^(con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\.|$)/i.test(name),CODE,'Invalid new acquisition directory name');
 const parent=await assertAcquisitionPath(path.dirname(selected));assert((await lstat(parent)).isDirectory(),CODE,'Acquisition parent must be an existing ordinary directory');
 try{await lstat(selected);}catch(error){if((error as NodeJS.ErrnoException).code==='ENOENT')return;throw error;}
 throw new WirefitError(CODE,'Acquisition output already exists; previous evidence will not be replaced');
}
async function writeNew(file:string,text:string):Promise<void>{
 assert(typeof text==='string'&&Buffer.byteLength(text,'utf8')<=16777216,'RESOURCE_LIMIT','Acquisition text exceeds sixteen MiB');
 await assertAcquisitionPath(path.dirname(file));const handle=await open(file,'wx');
 try{await handle.writeFile(text,'utf8');await handle.sync();}finally{await handle.close();}
 await assertAcquisitionPath(file);assert((await lstat(file)).nlink===1,CODE,'New acquisition output became aliased');
}
export async function writeAcquisitionJson(file:string,value:unknown):Promise<void>{await writeNew(file,JSON.stringify(value,null,2)+'\n');}
export async function writeAcquisitionText(file:string,text:string):Promise<void>{await writeNew(file,text);}
export function decodeAcquisitionJson(bytes:Uint8Array):unknown{
 assert(bytes.length>0&&bytes.length<=16777216,'RESOURCE_LIMIT','Acquisition JSON exceeds its byte bound');
 try{return JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(bytes)) as unknown;}
 catch(error){throw new WirefitError('ACQUISITION_JSON_INVALID','Acquisition input is not strict UTF-8 JSON',error);}
}

import {open,lstat,realpath,mkdir,writeFile,readdir} from 'node:fs/promises';
import path from 'node:path';
import {assert,sha256} from './shared.js';
import type {ArtifactRef} from './types.js';
import type {WirefitService} from './service.js';
export interface Snapshot {path:string;bytes:Buffer;sha256:string;size_bytes:number}
export interface BinarySource {path:string;sha256:string;size_bytes:number;artifact:ArtifactRef}
const MAX_INPUT=64*1024*1024;
function equivalentPath(left:string,right:string){return process.platform==='win32'?left.toLowerCase()===right.toLowerCase():left===right;}
export async function snapshot(file:string,limit=MAX_INPUT,unique=false):Promise<Snapshot>{
 const requested=path.resolve(file),selected=await realpath(requested);
 assert(equivalentPath(requested,selected)&&!(await lstat(requested)).isSymbolicLink(),'BINARY_PATH_ALIAS','Binary inputs may not use symlink/junction aliases');
 const handle=await open(selected,'r');
 try{
  const before=await handle.stat();if(unique)assert(before.nlink===1,'UNPACK_OUTPUT_ALIAS','Generated outputs may not be hardlinks');assert(before.isFile()&&before.size>0&&before.size<=limit,'RESOURCE_LIMIT','Binary file must be a bounded nonempty regular file');
  const bytes=Buffer.alloc(before.size+1);let length=0;
  while(length<bytes.length){const next=await handle.read(bytes,length,bytes.length-length,length);if(next.bytesRead===0)break;length+=next.bytesRead;}
  const after=await handle.stat();if(unique)assert(after.nlink===1,'UNPACK_OUTPUT_ALIAS','Generated output link identity changed');
  assert(length===before.size&&before.size===after.size&&before.mtimeMs===after.mtimeMs&&before.ctimeMs===after.ctimeMs&&equivalentPath(await realpath(requested),selected),'BINARY_CHANGED','Binary changed while taking its snapshot');
  const owned=Buffer.from(bytes.subarray(0,length));
  return {path:requested,bytes:owned,sha256:sha256(owned),size_bytes:owned.length};
 }finally{await handle.close();}
}
export async function sameSource(source:BinarySource){try{return (await snapshot(source.path)).sha256===source.sha256;}catch{return false;}}
export function environment():NodeJS.ProcessEnv{
 const allowed=new Set(['path','systemroot','windir','temp','tmp','userprofile','appdata','localappdata','programdata','programfiles','programfiles(x86)','commonprogramfiles','comspec','pathext','systemdrive','homedrive','homepath','home','lang','processor_architecture','processor_architew6432','processor_identifier','number_of_processors']);
 return Object.fromEntries(Object.entries(process.env).filter(([key,value])=>value!==undefined&&allowed.has(key.toLowerCase())));
}

export async function putSnapshot(service:WirefitService,source:Snapshot):Promise<BinarySource>{
 return {path:source.path,sha256:source.sha256,size_bytes:source.size_bytes,artifact:await service.store.putArtifact(source.bytes,'application/vnd.microsoft.portable-executable')};
}

export async function stage(service:WirefitService,source:BinarySource,resultId:string){
 const relative='.binary-work/'+resultId;
 const folder=await service.store.resolveRelative(relative,false);await mkdir(folder,{recursive:true});
 const base=path.basename(source.path);assert(base.length>0&&base.length<=255&&!/[<>:"|?*]/.test(base),'BINARY_FILENAME_INVALID','Binary filename is not supported');
 const input=await service.store.resolveRelative(relative+'/'+base,false);
 await writeFile(input,await service.store.readArtifact(source.artifact),{flag:'wx'});
 return {folder,input,relative};
}
export async function copyDependencies(service:WirefitService,source:BinarySource,relative:string):Promise<ArtifactRef[]>{
 const files=(await readdir(path.dirname(source.path),{withFileTypes:true})).filter(entry=>entry.name.toLowerCase().endsWith('.dll'));
 assert(files.length<=64,'RESOURCE_LIMIT','Adjacent DLL count exceeds 64');const references:ArtifactRef[]=[];let total=0;
 for(const entry of files){
  assert(entry.isFile()&&!entry.isSymbolicLink(),'BINARY_PATH_ALIAS','Adjacent dependencies must be regular files');
  const dependency=await snapshot(path.join(path.dirname(source.path),entry.name));total+=dependency.size_bytes;
  assert(total<=256*1024*1024,'RESOURCE_LIMIT','Adjacent DLL snapshots exceed 256 MiB');
  const artifact=await service.store.putArtifact(dependency.bytes,'application/vnd.microsoft.portable-executable');
  const target=await service.store.resolveRelative(relative+'/'+entry.name,false);await writeFile(target,dependency.bytes,{flag:'wx'});
  references.push(await service.store.putJson({file:entry.name,...{sha256:dependency.sha256,size_bytes:dependency.size_bytes},artifact}));
 }
 return references;
}

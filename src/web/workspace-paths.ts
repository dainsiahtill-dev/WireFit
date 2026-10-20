import {lstat,mkdir,realpath,open} from 'node:fs/promises';
import path from 'node:path';
import {assert} from '../shared.js';

/** Reject junctions at every existing component, including ancestors. */
export async function noLinks(absolute:string):Promise<void>{
 const selected=path.resolve(absolute),root=path.parse(selected).root;let current=root;
 for(const part of selected.slice(root.length).split(path.sep).filter(Boolean)){
  current=path.join(current,part);
  try{assert(!(await lstat(current)).isSymbolicLink(),'WEB_PATH_INVALID','Symbolic links and junctions are not accepted');}
  catch(error){if((error as NodeJS.ErrnoException).code==='ENOENT')return;throw error;}
 }
}
export async function directory(absolute:string):Promise<string>{
 await noLinks(absolute);await mkdir(absolute,{recursive:true});await noLinks(absolute);return realpath(absolute);
}
export function relativeFile(relative:string):string[]{
 assert(typeof relative==='string'&&relative.length>0&&relative.length<=1024&&!relative.includes('\\')&&!relative.includes(':')&&!relative.includes('\0'),'WEB_PATH_INVALID','Invalid package filename');
 const parts=relative.split('/');assert(parts.every(part=>part!==''&&part!=='.'&&part!=='..'),'WEB_PATH_INVALID','Package path traversal rejected');return parts;
}
export async function readBounded(file:string,maximum=16*1024*1024):Promise<Buffer>{
 await noLinks(file);const handle=await open(file,'r');
 try{
  const before=await handle.stat();assert(before.isFile()&&before.size<=maximum,'RESOURCE_LIMIT','File exceeds the bounded read limit');
  const bytes=Buffer.alloc(before.size+1);let length=0;
  while(length<bytes.length){const result=await handle.read(bytes,length,bytes.length-length,null);if(!result.bytesRead)break;length+=result.bytesRead;}
  const after=await handle.stat();assert(length===before.size&&after.size===before.size&&after.mtimeMs===before.mtimeMs,'SOURCE_CHANGED','File changed while being read');return bytes.subarray(0,length);
 }finally{await handle.close();}
}
export async function jsonFile<T=unknown>(file:string):Promise<T>{return JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(await readBounded(file))) as T;}

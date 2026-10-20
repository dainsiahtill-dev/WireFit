import {lstat,readdir,writeFile} from 'node:fs/promises';
import path from 'node:path';
import {CaseStore} from '../store.js';
import {assert,sha256} from '../shared.js';
import type {WebCase} from './types.js';
import {jsonFile,noLinks} from './workspace-paths.js';

interface Manifest {case_id:string;created_at?:string}
function identityPath(directory:string):string{const resolved=path.resolve(directory);return process.platform==='win32'?resolved.toLowerCase():resolved;}
export function caseKey(directory:string):string{return 'case_'+sha256(identityPath(directory)).slice(0,20);}
export function caseLabel(label:unknown):asserts label is string{
 assert(typeof label==='string'&&label.trim().length>0&&label.length<=120&&!/[\x00-\x1f\x7f]/.test(label),'CASE_LABEL_INVALID','Case label must contain 1..120 printable characters');
}
export async function describeCase(directory:string,selectedId?:string):Promise<WebCase>{
 await noLinks(directory);const manifest=await jsonFile<Manifest>(path.join(directory,'case.json'));
 assert(typeof manifest.case_id==='string'&&manifest.case_id.length<=128,'CASE_INVALID','Case identity is invalid');
 let label=path.basename(directory);
 try{const meta=await jsonFile<{label:string}>(path.join(directory,'workbench-label.json'));caseLabel(meta.label);label=meta.label;}catch{/* Historical cases have no workbench label. */}
 return {id:selectedId??caseKey(directory),label,path:directory,case_id:manifest.case_id,kind:'managed',writable:true,created_at:typeof manifest.created_at==='string'?manifest.created_at:null};
}
export async function saveLabel(directory:string,label:string):Promise<void>{caseLabel(label);await noLinks(path.join(directory,'workbench-label.json'));await writeFile(path.join(directory,'workbench-label.json'),JSON.stringify({label})+'\n',{encoding:'utf8',flag:'wx'});}
/** Bounded discovery intentionally opens all historical stores without a writer lease. */
export async function discoverCases(roots:string[],known:Map<string,WebCase>,writableRoots:string[]=[]):Promise<void>{
 let visited=0,found=0;const seen=new Set([...known.values()].map(item=>identityPath(item.path)));
 async function visit(directory:string,depth:number):Promise<void>{
  if(depth>6||visited>=4096||found>=256)return;visited++;
  try{
   await noLinks(directory);const info=await lstat(directory);if(!info.isDirectory()||info.isSymbolicLink())return;
   const key=identityPath(directory);
   try{
    const store=await CaseStore.open(directory,false);
    try{if(!seen.has(key)){const item=await describeCase(store.root);item.writable=writableRoots.some(root=>{const allowed=identityPath(root);return key===allowed||key.startsWith(allowed+path.sep);});known.set(item.id,item);seen.add(key);found++;}}finally{await store.close();}
    return;
   }catch(error){if((error as NodeJS.ErrnoException).code!=='ENOENT')return;}
   const entries=await readdir(directory,{withFileTypes:true});
   for(const entry of entries.sort((a,b)=>a.name.localeCompare(b.name))){if(visited>=4096||found>=256)break;if(entry.isDirectory()&&!entry.isSymbolicLink())await visit(path.join(directory,entry.name),depth+1);}
  }catch(error){if((error as NodeJS.ErrnoException).code==='ENOENT'||(error as NodeJS.ErrnoException).code==='EACCES'||(error as {code?:string}).code==='WEB_PATH_INVALID')return;throw error;}
 }
 for(const root of roots)await visit(root,0);
}

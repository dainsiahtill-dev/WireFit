import path from 'node:path';
import {CaseStore} from '../store.js';
import {exportReport} from '../reporting.js';
import {assert,id,sha256} from '../shared.js';
import type {WebExport} from './types.js';
import type {ArtifactRef} from '../types.js';
import {directory,noLinks,readBounded,relativeFile} from './workspace-paths.js';

interface PackageFile {name:string;size_bytes:number;sha256:string;media_type:string}
interface Package {root:string;files:Map<string,PackageFile>}
export class WorkbenchExports {
 private readonly packages=new Map<string,Package>();
 constructor(private readonly root:string){}
 async create(store:CaseStore,runId:string):Promise<WebExport>{
  const parent=await directory(path.join(this.root,'exports','workbench')),exportId=id('export');
  const output=path.join(parent,exportId);await noLinks(output);const manifest=await exportReport(store,runId,output);
  const files=new Map<string,PackageFile>();
  for(const file of manifest.files){relativeFile(file.relative_path);assert(!files.has(file.relative_path),'EXPORT_REFERENCE_CONFLICT','Duplicate package filename');files.set(file.relative_path,{name:file.relative_path,size_bytes:file.size_bytes,sha256:file.sha256,media_type:file.media_type});}
  for(const name of ['manifest.json','manifest.sha256']){const bytes=await readBounded(path.join(output,name));files.set(name,{name,size_bytes:bytes.length,sha256:sha256(bytes),media_type:name.endsWith('.json')?'application/json':'text/plain; charset=utf-8'});}
  this.packages.set(exportId,{root:output,files});
  return {id:exportId,path:output,files:[...files.values()].map(({name,size_bytes})=>({name,size_bytes})),report_url:`/api/exports/${exportId}/file?path=report.md`};
 }
 async file(exportId:string,relative:string):Promise<{bytes:Buffer;mediaType:string}>{
  const parts=relativeFile(relative),selected=this.packages.get(exportId);assert(selected,'EXPORT_NOT_FOUND','Export package is not registered in this session');
  const entry=selected.files.get(relative);assert(entry,'EXPORT_FILE_NOT_FOUND','File is not registered in this package');
  const target=path.join(selected.root,...parts);await noLinks(target);const bytes=await readBounded(target,128*1024*1024);
  assert(bytes.length===entry.size_bytes&&sha256(bytes)===entry.sha256,'EXPORT_FILE_CHANGED','Export file identity changed');return {bytes,mediaType:entry.media_type};
 }
}
/** Only host-registered artifact envelopes can enter a download lookup. */
export function artifactReferences(values:unknown[]):ArtifactRef[]{
 const pending:unknown[]=[],refs:ArtifactRef[]=[];let examined=0;
 const append=(items:unknown[])=>{assert(pending.length+items.length<=100000,'RESOURCE_LIMIT','Case reference graph exceeds its budget');for(const item of items)pending.push(item);};append(values);
 while(pending.length){
  assert(examined++<100000,'RESOURCE_LIMIT','Case reference graph exceeds its budget');const value=pending.pop();
  if(!value||typeof value!=='object')continue;
  if(Array.isArray(value)){append(value);continue;}
  const record=value as Record<string,unknown>;
  if(typeof record.sha256==='string'&&/^[0-9a-f]{64}$/.test(record.sha256)&&record.relative_path==='artifacts/'+record.sha256&&typeof record.media_type==='string'&&Number.isSafeInteger(record.size_bytes)&&Number(record.size_bytes)>=0){refs.push(record as unknown as ArtifactRef);continue;}
  append(Object.values(record));
 }
 return refs;
}

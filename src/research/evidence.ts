import {createHash} from 'node:crypto';
import {open,readFile,readdir,stat} from 'node:fs/promises';
import path from 'node:path';
import {assert,WirefitError} from '../shared.js';
import type {EvidencePin,EvidencePinSpec} from './types.js';

export const DEFAULT_ALLOWED_ROOTS:readonly string[]=['artifacts/','exports/','fixtures/','tools/'];
export const MAX_EVIDENCE_BYTES=64*1024*1024;

export interface EvidenceResolverOptions{
 /** Directory the relative pin paths are resolved against. */
 rootDir:string;
 allowedRoots?:readonly string[];
 maxBytes?:number;
}

interface CacheEntry{ mtimeMs:number; size:number; sha256:string; }

function isHex64(value:string):boolean{return /^[0-9a-f]{64}$/.test(value);}

/**
 * Resolves pre-registered evidence pins against the repository tree.
 *
 * The resolver is deliberately hostile to anything that is not a plain file
 * inside an allowed root: no parent traversal, no absolute paths, no drive
 * letters, no NUL bytes, no directories, no oversized files. Every read is
 * hashed before and after so that a concurrently rewritten source is reported
 * instead of silently mixed into a result.
 */
export class EvidenceResolver{
 private readonly cache=new Map<string,CacheEntry>();
 readonly allowedRoots:readonly string[];
 readonly maxBytes:number;
 constructor(private readonly options:EvidenceResolverOptions){
  this.allowedRoots=options.allowedRoots??DEFAULT_ALLOWED_ROOTS;
  this.maxBytes=options.maxBytes??MAX_EVIDENCE_BYTES;
 }
 /** Validates a relative pin path against the whitelist. */
 resolvePath(relative:string):string{
  assert(typeof relative==='string'&&relative.length>0,'EVIDENCE_PATH_INVALID','Evidence path must be a nonempty string');
  assert(!relative.includes('\0'),'EVIDENCE_PATH_INVALID','Evidence path must not contain NUL');
  assert(!path.isAbsolute(relative),'EVIDENCE_PATH_INVALID','Evidence path must be relative');
  assert(!/^[A-Za-z]:/.test(relative),'EVIDENCE_PATH_INVALID','Evidence path must not carry a drive letter');
  assert(!relative.includes('\\'),'EVIDENCE_PATH_INVALID','Evidence path must use forward slashes');
  const normalized=path.posix.normalize(relative);
  assert(normalized!=='.'&&!normalized.startsWith('../')&&!normalized.includes('/../')&&!normalized.endsWith('/..'),
   'EVIDENCE_PATH_INVALID','Evidence path must not escape the repository');
  const allowed=this.allowedRoots.some((root)=>normalized===root.replace(/\/$/,'')||normalized.startsWith(root));
  assert(allowed,'EVIDENCE_PATH_INVALID','Evidence path is outside the allowed roots');
  const resolved=path.resolve(this.options.rootDir,...normalized.split('/'));
  const root=path.resolve(this.options.rootDir);
  assert(resolved.startsWith(root+path.sep),'EVIDENCE_PATH_INVALID','Resolved evidence path escapes the repository');
  return resolved;
 }
 private async hashFile(file:string):Promise<{sha256:string;size:number;mtimeMs:number}>{
  const info=await stat(file);
  assert(info.isFile(),'EVIDENCE_NOT_A_FILE','Evidence path is not a regular file');
  assert(info.size<=this.maxBytes,'RESOURCE_LIMIT','Evidence file exceeds the size limit');
  const cached=this.cache.get(file);
  if(cached&&cached.mtimeMs===info.mtimeMs&&cached.size===info.size)return cached;
  const digest=createHash('sha256');
  const handle=await open(file,'r');
  try{
   const buffer=Buffer.allocUnsafe(1024*1024);
   for(;;){
    const {bytesRead}=await handle.read(buffer,0,buffer.length,null);
    if(bytesRead===0)break;
    digest.update(buffer.subarray(0,bytesRead));
   }
  }finally{await handle.close();}
  const entry={sha256:digest.digest('hex'),size:info.size,mtimeMs:info.mtimeMs};
  this.cache.set(file,entry);
  return entry;
 }
 /**
  * Reads one pinned artifact.
  *
  * `expected_sha256` is enforced for stable corpora. For lane artifacts the
  * expected digest is `null` and the observed digest is only recorded, because
  * a lane re-run may legitimately rewrite its own outputs.
  */
 async resolve(pin:EvidencePinSpec):Promise<{bytes:Buffer;observed:EvidencePin}>{
  assert(pin&&typeof pin==='object','EVIDENCE_PIN_INVALID','Evidence pin must be an object');
  assert(typeof pin.role==='string'&&pin.role.length>0,'EVIDENCE_PIN_INVALID','Evidence pin role is required');
  if(pin.kind==='stable_corpus')
   assert(typeof pin.expected_sha256==='string'&&isHex64(pin.expected_sha256),
    'EVIDENCE_PIN_INVALID','Stable corpus pins must declare a 64-hex expected sha256');
  const file=this.resolvePath(pin.path);
  const before=await this.hashFile(file);
  if(pin.expected_sha256!==null)
   assert(before.sha256===pin.expected_sha256,'EVIDENCE_PIN_MISMATCH',
    'Evidence '+pin.role+' does not match its pinned digest: expected '+pin.expected_sha256+' observed '+before.sha256);
  if(pin.size_bytes!==null)
   assert(before.size===pin.size_bytes,'EVIDENCE_PIN_MISMATCH',
    'Evidence '+pin.role+' does not match its pinned size: expected '+pin.size_bytes+' observed '+before.size);
  const bytes=await this.readBounded(file,before.size);
  const after=await this.hashFile(file);
  assert(after.sha256===before.sha256&&after.size===before.size&&after.mtimeMs===before.mtimeMs,
   'SOURCE_CHANGED','Evidence '+pin.role+' changed while it was being read');
  const observed:EvidencePin={
   ...pin,
   observed_sha256_before:before.sha256,
   observed_sha256_after:after.sha256,
   verified:before.sha256===after.sha256,
  };
  return {bytes,observed};
 }
 private async readBounded(file:string,size:number):Promise<Buffer>{
  const handle=await open(file,'r');
  try{
   const buffer=Buffer.allocUnsafe(size+1);
   let read=0;
   while(read<size+1){
    const {bytesRead}=await handle.read(buffer,read,size+1-read,null);
    if(bytesRead===0)break;
    read+=bytesRead;
   }
   assert(read===size,'SOURCE_CHANGED','Evidence file changed size while it was being read');
   return buffer.subarray(0,size);
  }finally{await handle.close();}
 }
 /** Reads and parses a pinned JSON document. */
 async resolveJson(pin:EvidencePinSpec):Promise<{value:unknown;observed:EvidencePin}>{
  const {bytes,observed}=await this.resolve(pin);
  let text:string;
  try{text=new TextDecoder('utf-8',{fatal:true}).decode(bytes);}
  catch{throw new WirefitError('JSON_INVALID','Evidence '+pin.role+' is not valid UTF-8');}
  try{return {value:JSON.parse(text) as unknown,observed};}
  catch(error){throw new WirefitError('JSON_INVALID','Evidence '+pin.role+' is not valid JSON: '+(error as Error).message);}
 }
 /** Reads and parses a pinned JSON Lines document. */
 async resolveJsonl(pin:EvidencePinSpec):Promise<{rows:unknown[];observed:EvidencePin}>{
  const {bytes,observed}=await this.resolve(pin);
  const text=new TextDecoder('utf-8',{fatal:true}).decode(bytes);
  const rows:unknown[]=[];
  const lines=text.split(/\r?\n/);
  for(const [index,line] of lines.entries()){
   if(line==='')continue;
   try{rows.push(JSON.parse(line) as unknown);}
   catch(error){throw new WirefitError('JSON_INVALID','Evidence '+pin.role+' line '+(index+1)+' is not valid JSON: '+(error as Error).message);}
  }
  return {rows,observed};
 }
 /**
  * Walks a whitelisted directory and parses every JSON document it contains.
  *
  * This exists for the negative scan of D12: the claim is about the whole
  * tree, so the enumeration has to be exhaustive and the unreadable files
  * have to be reported rather than skipped silently.
  */
 async scanJson(relativeDir:string):Promise<{files:string[];documents:{path:string;value:unknown}[];unreadable:string[]}>{
  const base=this.resolvePath(relativeDir.replace(/\/$/,'')+'/');
  const files:string[]=[];
  const documents:{path:string;value:unknown}[]=[];
  const unreadable:string[]=[];
  const walk=async(current:string,prefix:string):Promise<void>=>{
   let entries:import('node:fs').Dirent[];
   try{entries=await readdir(current,{withFileTypes:true});}
   catch{unreadable.push(prefix);return;}
   for(const entry of entries.sort((left,right)=>left.name<right.name?-1:left.name>right.name?1:0)){
    const child=path.join(current,entry.name);
    const relative=prefix+'/'+entry.name;
    if(entry.isDirectory())await walk(child,relative);
    else if(entry.isFile()&&entry.name.endsWith('.json')){
     files.push(relative);
     try{
      const info=await stat(child);
      if(info.size>this.maxBytes){unreadable.push(relative);continue;}
      const bytes=await readFile(child);
      documents.push({path:relative,value:JSON.parse(bytes.toString('utf8')) as unknown});
     }catch{unreadable.push(relative);}
    }
   }
  };
  await walk(base,relativeDir.replace(/\/$/,''));
  return {files,documents,unreadable};
 }
}

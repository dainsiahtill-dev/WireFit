import {constants} from 'node:fs';
import {lstat, open, realpath} from 'node:fs/promises';
import path from 'node:path';
import {createHash} from 'node:crypto';
import type {WebEvidence} from './types.js';

export type JsonObject=Record<string,unknown>;
export const object=(value:unknown):JsonObject=>value!==null&&typeof value==='object'&&!Array.isArray(value)?value as JsonObject:{};
export const list=(value:unknown):unknown[]=>Array.isArray(value)?value:[];
export const string=(value:unknown):string|null=>typeof value==='string'?value:null;
export const integer=(value:unknown):number|null=>typeof value==='number'&&Number.isSafeInteger(value)&&value>=0?value:null;
export function failure(code:string,message:string):Error&{code:string}{return Object.assign(new Error(message),{code});}
export function reason(error:unknown):string{return error instanceof Error?error.message:'Evidence unavailable';}
interface Registration {id:string;relative:string;label:string;format:WebEvidence['format'];expected?:{sha256:string;size_bytes:number}}
interface ReadResult {bytes:Buffer;size:number;sha256:string;truncated:boolean}
const PREVIEW_BYTES=96*1024,JSON_BYTES=16*1024*1024,MAX_FILE_BYTES=64*1024*1024;
const equalPath=(left:string,right:string)=>process.platform==='win32'?left.toLowerCase()===right.toLowerCase():left===right;

/** The browser receives opaque IDs only. Every registration originates in the curated catalog
 * or a validated hash reference inside one of its fixed, local case directories. */
export class ResearchFiles {
  private readonly root:string;
  private readonly registrations=new Map<string,Registration>();
  constructor(root:string){this.root=path.resolve(root);}
  register(relative:string,label:string,format:WebEvidence['format']='json',expected?:Registration['expected']):string{
    if(!relative||relative.includes('\\')||relative.split('/').some(part=>!part||part==='.'||part==='..'||part.includes(':'))||path.isAbsolute(relative))throw failure('EVIDENCE_UNAVAILABLE','Invalid curated relative path');
    const id='ev_'+createHash('sha256').update(relative,'utf8').digest('hex').slice(0,24);
    const existing=this.registrations.get(id);
    if(existing&&expected&&existing.expected&&(existing.expected.sha256!==expected.sha256||existing.expected.size_bytes!==expected.size_bytes))throw failure('EVIDENCE_CHANGED','Conflicting evidence identities');
    this.registrations.set(id,{id,relative,label,format,expected:expected??existing?.expected});return id;
  }
  async json(relative:string,label=relative,expected?:Registration['expected']):Promise<JsonObject>{
    const id=this.register(relative,label,'json',expected),entry=this.registrations.get(id)!;
    const read=await this.read(entry,JSON_BYTES);
    if(read.truncated)throw failure('EVIDENCE_UNAVAILABLE','JSON exceeds the research read budget');
    try{
      const parsed:unknown=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(read.bytes).replace(/^\uFEFF/,''));
      if(!parsed||typeof parsed!=='object'||Array.isArray(parsed))throw new Error('Expected an object');
      return parsed as JsonObject;
    }catch{throw failure('EVIDENCE_UNAVAILABLE','Malformed UTF-8 JSON: '+relative);}
  }
  async evidence(id:string):Promise<WebEvidence>{
    const entry=this.registrations.get(id);if(!entry)throw failure('NOT_FOUND','Unknown evidence ID');
    const read=await this.read(entry,entry.format==='hex'?4096:PREVIEW_BYTES);
    let text:string;
    if(entry.format==='hex')text=Array.from({length:Math.ceil(read.bytes.length/16)},(_,i)=>`${(i*16).toString(16).padStart(8,'0')}  ${read.bytes.subarray(i*16,i*16+16).toString('hex').match(/../g)?.join(' ')??''}`).join('\n');
    else {
      // A capped prefix may end within one UTF-8 code point. Decode only complete characters;
      // malformed data inside the prefix is an unavailable text file, not replacement text.
      let end=read.bytes.length;
      for(let trim=0;;trim++)try{text=new TextDecoder('utf-8',{fatal:true}).decode(read.bytes.subarray(0,end));break;}catch{
        if(!read.truncated||trim===3)throw failure('EVIDENCE_UNAVAILABLE','Evidence is not valid UTF-8 text');end--;
      }
    }
    return {id:entry.id,label:entry.label,path:entry.relative,sha256:read.sha256,size_bytes:read.size,format:entry.format,text,truncated:read.truncated};
  }
  private async checkedPath(relative:string):Promise<string>{
    const rootStat=await lstat(this.root);
    if(rootStat.isSymbolicLink()||!rootStat.isDirectory()||!equalPath(await realpath(this.root),this.root))throw failure('EVIDENCE_UNAVAILABLE','Archive root is an alias or is not a directory');
    let current=this.root;
    const parts=relative.split('/');
    for(let index=0;index<parts.length;index++){
      current=path.join(current,parts[index]!);const stat=await lstat(current);
      if(stat.isSymbolicLink()||!equalPath(await realpath(current),current)||(index<parts.length-1?!stat.isDirectory():!stat.isFile()))throw failure('EVIDENCE_UNAVAILABLE','Evidence aliases and non-regular files are not allowed');
    }
    return current;
  }
  private async read(entry:Registration,cap:number):Promise<ReadResult>{
    try{
      const filename=await this.checkedPath(entry.relative);
      const handle=await open(filename,constants.O_RDONLY|(constants.O_NOFOLLOW??0));
      try{
        const before=await handle.stat();
        if(!before.isFile()||before.size>MAX_FILE_BYTES)throw failure('EVIDENCE_UNAVAILABLE','Evidence exceeds the file read budget');
        const hash=createHash('sha256'),prefix:Buffer[]=[];let position=0,captured=0;
        const block=Buffer.allocUnsafe(64*1024);
        while(position<before.size){
          const read=await handle.read(block,0,Math.min(block.length,before.size-position),position);
          if(read.bytesRead===0)throw failure('EVIDENCE_CHANGED','Evidence changed during read');
          const bytes=block.subarray(0,read.bytesRead);hash.update(bytes);
          if(captured<cap){const slice=bytes.subarray(0,cap-captured);prefix.push(Buffer.from(slice));captured+=slice.length;}
          position+=read.bytesRead;
        }
        const after=await handle.stat();
        const finalPath=await this.checkedPath(entry.relative),current=await lstat(finalPath);
        if(before.size!==after.size||before.mtimeMs!==after.mtimeMs||before.ctimeMs!==after.ctimeMs||before.ino!==after.ino||before.dev!==after.dev||current.ino!==after.ino||current.dev!==after.dev||current.size!==after.size||current.mtimeMs!==after.mtimeMs||current.ctimeMs!==after.ctimeMs||!equalPath(finalPath,filename))throw failure('EVIDENCE_CHANGED','Evidence changed during read');
        const sha256=hash.digest('hex');
        if(entry.expected&&(entry.expected.sha256!==sha256||entry.expected.size_bytes!==before.size))throw failure('EVIDENCE_CHANGED','Evidence no longer matches its recorded identity');
        return {bytes:Buffer.concat(prefix),size:before.size,sha256,truncated:before.size>cap};
      }finally{await handle.close();}
    }catch(error){if(typeof error==='object'&&error&&'code' in error&&String(error.code).startsWith('EVIDENCE_'))throw error;throw failure('EVIDENCE_UNAVAILABLE','Evidence unavailable: '+entry.relative);}
  }
}

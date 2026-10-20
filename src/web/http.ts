import type {IncomingMessage,ServerResponse} from 'node:http';
import {timingSafeEqual} from 'node:crypto';
import type {PageQuery,WebEvidence} from './types.js';
import {sha256} from '../shared.js';

export const BODY_LIMIT=1024*1024;
export class HttpError extends Error {constructor(public status:number,public code:string,message:string){super(message);}}
export function requireValue(value:unknown,status:number,code:string,message:string):asserts value{if(!value)throw new HttpError(status,code,message);}
export function headers(response:ServerResponse){
 response.setHeader('Cache-Control','no-store');response.setHeader('X-Content-Type-Options','nosniff');response.setHeader('Referrer-Policy','no-referrer');
 response.setHeader('Content-Security-Policy',"default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; font-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'");
}
export function json(response:ServerResponse,status:number,value:unknown){const bytes=Buffer.from(JSON.stringify(value)+'\n','utf8');response.writeHead(status,{'Content-Type':'application/json; charset=utf-8','Content-Length':bytes.length});response.end(bytes);}
export function fail(response:ServerResponse,error:unknown){
 if(response.headersSent){response.destroy();return;}
 const e=error as {status?:unknown;code?:unknown;message?:unknown};const code=typeof e?.code==='string'?e.code:'INTERNAL_ERROR';
 const missing=code==='ENOENT'||code==='NOT_FOUND'||code.endsWith('_NOT_FOUND'),conflict=['EEXIST','CASE_BUSY','CASE_EXISTS','JOB_NOT_OWNED','PROFILE_UNAVAILABLE'].includes(code);
 const invalid=/^(INVALID_|.*_INVALID$|UNSUPPORTED_|OUT_OF_DOMAIN|NONFINITE|SCHEMA_)/.test(code);
 const status=typeof e?.status==='number'?e.status:code==='CASE_READ_ONLY'?403:missing?404:conflict?409:code==='RESOURCE_LIMIT'?413:invalid?400:500;
 const message=typeof e?.message==='string'?e.message.replace(/\0/g,'?').slice(0,2048):'请求失败';json(response,status,{error:{code,message}});
}
export function authorize(request:IncomingMessage,origin:string,token:string,mutation:boolean){
 requireValue(request.headers.host===new URL(origin).host,403,'WEB_FORBIDDEN','Host must match the local workbench');
 const supplied=request.headers.origin;
 requireValue(supplied===undefined||supplied===origin,403,'WEB_FORBIDDEN','Origin does not match the local workbench');
 if(mutation){
  requireValue(supplied===origin,403,'WEB_FORBIDDEN','Mutations require the workbench Origin');
  const candidate=request.headers['x-wirefit-token'];const expected=Buffer.from(token,'utf8');
  requireValue(typeof candidate==='string'&&Buffer.byteLength(candidate,'utf8')===expected.length&&timingSafeEqual(Buffer.from(candidate,'utf8'),expected),403,'WEB_FORBIDDEN','Session token is missing or invalid');
 }
}
export async function body(request:IncomingMessage):Promise<Record<string,unknown>>{
 requireValue(/^application\/json(?:\s*;\s*charset=utf-8)?$/i.test(request.headers['content-type']??''),415,'WEB_CONTENT_TYPE','Use application/json with UTF-8');
 const declared=request.headers['content-length'];if(declared!==undefined)requireValue(/^\d+$/.test(declared)&&Number(declared)<=BODY_LIMIT,413,'WEB_RESOURCE_LIMIT','JSON request exceeds one MiB');
 const chunks:Buffer[]=[];let length=0;
 for await(const chunk of request){const bytes=Buffer.isBuffer(chunk)?chunk:Buffer.from(chunk);length+=bytes.length;requireValue(length<=BODY_LIMIT,413,'WEB_RESOURCE_LIMIT','JSON request exceeds one MiB');chunks.push(bytes);}
 let value:unknown;try{value=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(Buffer.concat(chunks,length)));}catch{throw new HttpError(400,'WEB_BAD_REQUEST','Request must be valid UTF-8 JSON');}
 requireValue(value!==null&&typeof value==='object'&&!Array.isArray(value),400,'WEB_BAD_REQUEST','Request must be a JSON object');return value as Record<string,unknown>;
}
export function id(value:string){requireValue(/^[A-Za-z][A-Za-z0-9_.:-]{0,127}$/.test(value),400,'WEB_BAD_REQUEST','Invalid resource ID');return value;}
export function relative(value:unknown){requireValue(typeof value==='string'&&value.length>0&&value.length<=4096&&!/[\\:\x00-\x1f]/.test(value)&&value.split('/').every(x=>x!==''&&x!=='.'&&x!=='..'),400,'WEB_BAD_REQUEST','Invalid relative file path');return value;}
export function pageQuery(url:URL):PageQuery{
 const result:PageQuery={};for(const key of url.searchParams.keys())requireValue(['offset','limit','type','q','status'].includes(key)&&url.searchParams.getAll(key).length===1,400,'WEB_BAD_REQUEST','Unknown or duplicate query parameter');
 for(const key of ['offset','limit'] as const){const v=url.searchParams.get(key);if(v!==null){requireValue(/^(0|[1-9][0-9]*)$/.test(v)&&Number.isSafeInteger(Number(v))&&Number(v)>=(key==='limit'?1:0)&&Number(v)<=(key==='limit'?200:1000000),400,'WEB_BAD_REQUEST','Page range is invalid');result[key]=Number(v);}}
 for(const key of ['type','q','status'] as const){const v=url.searchParams.get(key);if(v!==null){requireValue(v.length<=(key==='q'?256:64)&&!/[\x00-\x1f]/.test(v),400,'WEB_BAD_REQUEST','Filter is invalid');result[key]=v;}}
 return result;
}
export function artifactView(caseId:string,digest:string,bytes:Buffer,media:string):WebEvidence{
 let text='',format:WebEvidence['format']='text';const shown=bytes.subarray(0,96*1024);
 try{text=new TextDecoder('utf-8',{fatal:true}).decode(shown);requireValue(!/[\x00-\x08\x0e-\x1f]/.test(text),400,'BINARY','binary');if(media.includes('json'))format='json';}
 catch{format='hex';text=Array.from(bytes.subarray(0,8192)).map(v=>v.toString(16).padStart(2,'0')).join(' ');}
 requireValue(sha256(bytes)===digest,500,'ARTIFACT_DIGEST_MISMATCH','Artifact bytes differ from the registered identity');
 return {id:digest,label:digest.slice(0,16),path:`${caseId}/artifacts/${digest}`,sha256:digest,size_bytes:bytes.length,format,text,truncated:bytes.length>(format==='hex'?8192:96*1024)};
}

import http from 'node:http';
import path from 'node:path';
import {lstat,realpath} from 'node:fs/promises';
import {randomBytes} from 'node:crypto';
import type {WorkbenchWorkspace} from './workspace.js';
import type {ResearchArchive} from './research.js';
import type {LabRequest,WebTaskRequest} from './types.js';
import {HttpError,requireValue,headers,json,fail,authorize,body,id,relative,pageQuery,artifactView} from './http.js';
import {noLinks,readBounded} from './workspace-paths.js';

export interface WorkbenchOptions {root:string;port?:number;host?:string;staticDir?:string;workspace?:WorkbenchWorkspace;research?:ResearchArchive}
export interface WorkbenchServer {url:string;token:string;instanceId:string;server:http.Server;close():Promise<void>}
export async function startWorkbench(options:WorkbenchOptions):Promise<WorkbenchServer>{
 requireValue(options.host===undefined||options.host==='127.0.0.1',400,'WEB_BAD_REQUEST','Workbench listens only on 127.0.0.1');
 const port=options.port??4318;requireValue(Number.isInteger(port)&&port>=0&&port<=65535,400,'WEB_BAD_REQUEST','Port must be 0..65535');
 await noLinks(path.resolve(options.root));const root=await realpath(path.resolve(options.root));const staticDir=path.resolve(options.staticDir??path.join(root,'apps/web/public'));await noLinks(staticDir);
 const workspace=options.workspace??await (await import('./workspace.js')).WorkbenchWorkspace.open(root);
 const research=options.research??new (await import('./research.js')).ResearchArchive(root);
 const token=randomBytes(32).toString('base64url'),instanceId=randomBytes(16).toString('hex');let origin='',closing=false,closeTask:Promise<void>|undefined;
 const server=http.createServer({maxHeaderSize:16384},(request,response)=>{
  headers(response);void route(request,response).catch(error=>fail(response,error));
 });
 server.requestTimeout=30000;server.headersTimeout=10000;server.keepAliveTimeout=3000;
 async function route(request:http.IncomingMessage,response:http.ServerResponse){
  requireValue(!closing,503,'WEB_CLOSING','Workbench is shutting down');
  const method=request.method??'GET';
  authorize(request,origin,token,method==='POST');
  let url:URL;try{url=new URL(request.url??'/',origin);}catch{throw new HttpError(400,'WEB_BAD_REQUEST','Malformed URL');}
  requireValue(url.origin===origin,403,'WEB_FORBIDDEN','Request target must be local');
  let pathname:string;try{pathname=decodeURIComponent(url.pathname);}catch{throw new HttpError(400,'WEB_BAD_REQUEST','Invalid URL encoding');}
  requireValue(!/[\\\x00-\x1f]/.test(pathname)&&!pathname.split('/').some(x=>x==='..'||x==='.'),400,'WEB_BAD_REQUEST','Invalid URL path');
  const parts=pathname.split('/').filter(Boolean);
  if(parts[0]!=='api'){
   requireValue(method==='GET'||method==='HEAD',405,'WEB_METHOD_NOT_ALLOWED','Only GET and HEAD are supported for assets');
   const name=pathname==='/'?'index.html':relative(pathname.slice(1));
   requireValue(/\.(?:html|js|css|svg|ico)$/.test(name),404,'WEB_NOT_FOUND','Asset not found');
   await noLinks(staticDir);let current=staticDir;for(const part of name.split('/')){current=path.join(current,part);const info=await lstat(current);requireValue(!info.isSymbolicLink(),400,'WEB_BAD_REQUEST','Linked assets are not served');}
   const resolved=await realpath(current);requireValue(resolved.startsWith((await realpath(staticDir))+path.sep),400,'WEB_BAD_REQUEST','Asset path is outside the workbench');
   const info=await lstat(resolved);requireValue(info.isFile()&&info.size<=2*1024*1024,404,'WEB_NOT_FOUND','Asset is not a bounded file');
   const bytes=await readBounded(resolved,2*1024*1024);if(path.extname(name)!=='.ico')new TextDecoder('utf-8',{fatal:true}).decode(bytes);const types:Record<string,string>={'.html':'text/html; charset=utf-8','.js':'text/javascript; charset=utf-8','.css':'text/css; charset=utf-8','.svg':'image/svg+xml','.ico':'image/x-icon'};
   response.writeHead(200,{'Content-Type':types[path.extname(name)]!,'Content-Length':bytes.length});response.end(method==='HEAD'?undefined:bytes);return;
  }
  requireValue(method==='GET'||method==='POST',405,'WEB_METHOD_NOT_ALLOWED','API supports GET and POST only');
  const send=(data:unknown)=>json(response,200,{data});const match=(...values:string[])=>parts.length===values.length&&values.every((value,i)=>value===parts[i]);
  if(method==='GET'&&match('api','bootstrap')){const [cases,overview,ida]=await Promise.all([workspace.cases(),research.overview(),workspace.idaCapabilities?.()]);send({product:'WireFit',version:'0.1.0',token,pid:process.pid,instance_id:instanceId,workspace:root,cases,defaultCaseId:'vmde',writableCaseId:'workbench',profiles:workspace.profiles(),presets:workspace.presets(),research:overview,ida});return;}
  if(method==='GET'&&match('api','ida','status')){send(await workspace.idaCapabilities?.()??{configured:false,installed:false,status:'not_configured'});return;}
  if(method==='POST'&&match('api','shutdown')){await body(request);send({status:'closing'});setImmediate(()=>{void close().catch(error=>process.stderr.write(JSON.stringify({error:{code:'WEB_CLOSE_FAILED',message:String(error)}})+'\n','utf8'));});return;}
  if(match('api','cases')){if(method==='GET')send(await workspace.cases());else{const b=await body(request);requireValue(typeof b.label==='string',400,'WEB_BAD_REQUEST','A case label is required');send(await workspace.createCase(b.label));}return;}
  if(parts[1]==='cases'&&parts[2]){
   const caseId=id(parts[2]);
   if(parts.length===3&&method==='GET'){send(await workspace.caseData(caseId));return;}
   if(parts[3]==='models'){
    if(parts.length===4&&method==='POST'){send(await workspace.importModel(caseId,await body(request)));return;}
    if(parts[4]){const modelId=id(parts[4]);if(parts.length===5&&method==='GET'){send(await workspace.model(caseId,modelId));return;}
     if(parts.length===6&&parts[5]==='evaluate'&&method==='POST'){send(await workspace.evaluate(caseId,modelId,await body(request) as unknown as LabRequest));return;}}
   }
   if(parts.length===4&&parts[3]==='tasks'&&method==='POST'){send(await workspace.submit(caseId,await body(request) as unknown as WebTaskRequest));return;}
   if(parts[3]==='jobs'&&parts[4]){const jobId=id(parts[4]);if(parts.length===5&&method==='GET'){send(await workspace.job(caseId,jobId));return;}
    if(parts.length===6&&parts[5]==='cancel'&&method==='POST'){await body(request);send(await workspace.cancel(caseId,jobId));return;}}
   if(parts.length===4&&parts[3]==='exports'&&method==='POST'){const b=await body(request);requireValue(typeof b.runId==='string',400,'WEB_BAD_REQUEST','Run ID is required');send(await workspace.export(caseId,id(b.runId)));return;}
   if(parts.length===5&&parts[3]==='artifacts'&&method==='GET'){const sha=parts[4]!;requireValue(/^[a-f0-9]{64}$/.test(sha),400,'WEB_BAD_REQUEST','Invalid artifact digest');const file=await workspace.artifact(caseId,sha);send(artifactView(caseId,sha,file.bytes,file.mediaType));return;}
  }
  if(parts[1]==='exports'&&parts[2]&&parts.length===4&&parts[3]==='file'&&method==='GET'){
   requireValue(url.searchParams.getAll('path').length===1&&Array.from(url.searchParams.keys()).every(x=>x==='path'),400,'WEB_BAD_REQUEST','One file path is required');
   const name=relative(url.searchParams.get('path')),file=await workspace.exportFile(id(parts[2]),name);
   const filename=path.basename(name).replace(/[^A-Za-z0-9_.-]/g,'_');response.writeHead(200,{'Content-Type':'application/octet-stream','Content-Disposition':`attachment; filename="${filename}"`,'Content-Length':file.bytes.length});response.end(file.bytes);return;
  }
  if(parts[1]==='research'&&method==='GET'){
   if(parts.length===2){send(await research.overview());return;}
   if(parts.length===4&&parts[3]){const key=id(parts[3]);
    if(parts[2]==='functions'){send(await research.function(key));return;}
    if(parts[2]==='traces'){send(await research.trace(key,pageQuery(url)));return;}
    if(parts[2]==='validation'){send(await research.validation(key,pageQuery(url)));return;}
    if(parts[2]==='evidence'){send(await research.evidence(key));return;}
   }
  }
  throw new HttpError(404,'WEB_NOT_FOUND','API resource not found');
 }
 try{await new Promise<void>((resolve,reject)=>{server.once('error',reject);server.listen(port,'127.0.0.1',()=>{server.removeListener('error',reject);resolve();});});}
 catch(error){await workspace.close();throw error;}
 const address=server.address();requireValue(address!==null&&typeof address==='object',500,'WEB_START_FAILED','Server did not obtain an address');origin=`http://127.0.0.1:${address.port}`;
 function close(){return closeTask??=(async()=>{closing=true;const stopped=new Promise<void>((resolve,reject)=>server.close(error=>error?reject(error):resolve()));server.closeIdleConnections();await Promise.all([stopped,workspace.close()]);})();}
 return {url:origin,token,instanceId,server,close};
}

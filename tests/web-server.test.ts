import {afterEach,describe,expect,it} from 'vitest';
import {mkdtemp,mkdir,writeFile,rm,symlink} from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import {request as httpRequest} from 'node:http';
import {sha256} from '../src/shared.js';
import {startWorkbench} from '../src/web/server.js';

const cleanups:(()=>Promise<void>)[]=[];
afterEach(async()=>{for(const cleanup of cleanups.splice(0).reverse())await cleanup();});
async function fixture(){
 const root=await mkdtemp(path.join(os.tmpdir(),'wirefit-web-http-'));cleanups.push(()=>rm(root,{recursive:true,force:true}));
 const assets=path.join(root,'public');await mkdir(assets);await writeFile(path.join(assets,'index.html'),'<!doctype html><title>WireFit</title>','utf8');await writeFile(path.join(assets,'app.js'),'export const ready = true;','utf8');
 const calls:unknown[]=[];
 const workspace={cases:async()=>[{id:'workbench',label:'实验',kind:'managed'}],profiles:()=>[],presets:()=>[],
  createCase:async(label:string)=>({id:'new',label}),caseData:async(id:string)=>({case:{id},models:[],jobs:[],runs:[]}),
  model:async()=>({model_id:'model'}),evaluate:async(...args:unknown[])=>{calls.push(args);return {outputs:{answer:42},trace:[],curve:[]};},
  importModel:async()=>({model_id:'new'}),submit:async()=>({job_id:'job_123',status:'queued'}),job:async()=>({job_id:'job_123',status:'running'}),
  cancel:async()=>({job_id:'job_123',status:'cancelling'}),artifact:async()=>({bytes:Buffer.from('<script>bad()</script>','utf8'),mediaType:'text/html'}),
  export:async()=>({id:'export_123',path:'exports/new',files:[],report_url:'/api/exports/export_123/file?path=report.md'}),
  exportFile:async(_id:string,name:string)=>{if(name.includes('..'))throw Object.assign(new Error('Traversal'),{code:'ARTIFACT_PATH_INVALID'});return {bytes:Buffer.from('# report','utf8'),mediaType:'text/markdown'};},
  close:async()=>{calls.push('closed');}};
 const research={overview:async()=>({title:'vmde',functions:[],traces:[],validations:[]}),function:async(id:string)=>({id}),
  trace:async(id:string,query:unknown)=>({trace:{id},items:[],total:0,...query as object}),validation:async(id:string)=>({validation:{id},items:[],total:0}),
  evidence:async(id:string)=>({id,text:'actual',sha256:'a'.repeat(64)})};
 const app=await startWorkbench({root,port:0,staticDir:assets,workspace:workspace as never,research:research as never});cleanups.push(()=>app.close());
 const mutation=(body:unknown)=>({method:'POST',headers:{'Content-Type':'application/json','X-Wirefit-Token':app.token,Origin:app.url},body:JSON.stringify(body)});
 return {app,calls,mutation,root,workspace,research};
}
describe('local workbench HTTP boundary',()=>{
 it('serves local assets and the real structured bootstrap',async()=>{const {app}=await fixture();const html=await fetch(app.url);expect(html.status).toBe(200);expect(await html.text()).toContain('WireFit');expect(html.headers.get('content-security-policy')).toContain("script-src 'self'");const js=await fetch(app.url+'/app.js');expect(js.headers.get('content-type')).toContain('javascript');const data=await (await fetch(app.url+'/api/bootstrap')).json();expect(data.data.token).toBe(app.token);expect(data.data.writableCaseId).toBe('workbench');expect(data.data.research.title).toBe('vmde');});
 it('rejects cross-origin reads, DNS-rebound Host and missing mutation tokens',async()=>{const {app,mutation}=await fixture();expect((await fetch(app.url+'/api/bootstrap',{headers:{Origin:'https://other.test'}})).status).toBe(403);const rebound=await new Promise<number|undefined>((resolve,reject)=>{const r=httpRequest(app.url+'/api/bootstrap',{headers:{Host:'rebound.test'}},response=>{response.resume();response.on('end',()=>resolve(response.statusCode));});r.on('error',reject);r.end();});expect(rebound).toBe(403);expect((await fetch(app.url+'/api/cases',{method:'POST',headers:{'Content-Type':'application/json',Origin:app.url},body:'{}'})).status).toBe(403);const request=mutation({label:'new'});request.headers.Origin='https://other.test';expect((await fetch(app.url+'/api/cases',request)).status).toBe(403);});
 it('routes model evaluation, actual task lifecycle and exports through adapters',async()=>{const {app,calls,mutation}=await fixture();const response=await fetch(app.url+'/api/cases/workbench/models/mba/evaluate',mutation({inputs:{x:{kind:'bv',width:8,bits:'0x01'}}}));expect(response.status).toBe(200);expect((await response.json()).data.outputs.answer).toBe(42);expect(calls[0]).toEqual(['workbench','mba',{inputs:{x:{kind:'bv',width:8,bits:'0x01'}}}]);const job=await (await fetch(app.url+'/api/cases/workbench/tasks',mutation({kind:'experiment',request:{operation:'simplify'}}))).json();expect(job.data.status).toBe('queued');expect((await (await fetch(app.url+'/api/cases/workbench/jobs/job_123/cancel',mutation({}))).json()).data.status).toBe('cancelling');const exported=await (await fetch(app.url+'/api/cases/workbench/exports',mutation({runId:'run_123'}))).json();expect(exported.data.id).toBe('export_123');const report=await fetch(app.url+'/api/exports/export_123/file?path=report.md');expect(report.headers.get('content-disposition')).toContain('attachment');expect(await report.text()).toBe('# report');});
 it('rejects malformed JSON, wrong content type and excessive bodies before actions',async()=>{const {app,mutation,calls}=await fixture();const bad=mutation({});bad.body='{';expect((await fetch(app.url+'/api/cases',bad)).status).toBe(400);bad.headers['Content-Type']='text/plain';expect((await fetch(app.url+'/api/cases',bad)).status).toBe(415);const big=mutation({label:'x'.repeat(1024*1024)});expect((await fetch(app.url+'/api/cases',big)).status).toBe(413);expect(calls).toHaveLength(0);});
 it('blocks traversal and ambiguous query input and returns explicit route errors',async()=>{const {app}=await fixture();expect((await fetch(app.url+'/%2e%2e%5csecret')).status).toBe(400);expect((await fetch(app.url+'/api/research/traces/startup?limit=50000')).status).toBe(400);expect((await fetch(app.url+'/api/research/traces/startup?limit=1&limit=2')).status).toBe(400);expect((await fetch(app.url+'/api/exports/export_123/file?path=../secret')).status).toBe(400);expect((await fetch(app.url+'/missing.js')).status).toBe(404);expect((await fetch(app.url+'/api/cases',{method:'DELETE'})).status).toBe(405);});
 it('keeps artifact text inert and never serves it as HTML',async()=>{const {app}=await fixture();const response=await fetch(app.url+'/api/cases/workbench/artifacts/'+sha256(Buffer.from('<script>bad()</script>','utf8')));expect(response.headers.get('content-type')).toContain('application/json');const body=await response.json();expect(body.data.text).toContain('<script>');expect(body.data.sha256).toMatch(/^[a-f0-9]{64}$/);});
 it('closes the owned workspace exactly once',async()=>{const {app,calls}=await fixture();await app.close();await app.close();expect(calls.filter(x=>x==='closed')).toHaveLength(1);});
 it.each([['CASE_READ_ONLY',403],['CASE_NOT_FOUND',404],['PROFILE_UNAVAILABLE',409],['RESOURCE_LIMIT',413]])('returns a meaningful HTTP status for %s',async(code,status)=>{
  const {app,workspace,mutation}=await fixture();workspace.submit=async()=>{throw Object.assign(new Error(code),{code});};
  const response=await fetch(app.url+'/api/cases/workbench/tasks',mutation({kind:'experiment',request:{}}));
  expect(response.status).toBe(status);expect((await response.json()).error.code).toBe(code);
 });
 it('exposes actual IDA availability and routes IDA requests through the same protected task boundary',async()=>{
  const {app,workspace,mutation}=await fixture();
  Object.assign(workspace,{idaCapabilities:async()=>({configured:true,installed:true,status:'not_probed',provider:{id:'ida',version:'9.3'}})});
  const bootstrap=await (await fetch(app.url+'/api/bootstrap')).json();expect(bootstrap.data.ida.status).toBe('not_probed');
  const status=await (await fetch(app.url+'/api/ida/status')).json();expect(status.data.provider.version).toBe('9.3');
  let received:unknown;workspace.submit=async(...args:unknown[])=>{received=args;return {job_id:'job_ida',status:'queued'};};
  const request={kind:'ida',file:'E:/owned/sample.exe',queries:[{kind:'function',address:'0x401000'}]};
  const response=await fetch(app.url+'/api/cases/workbench/tasks',mutation(request));
  expect(response.status).toBe(200);expect(received).toEqual(['workbench',request]);
 });
 it('rejects a junction used as the static root before exposing external files',async()=>{
  const {app,root,workspace,research}=await fixture();await app.close();
  const outside=path.join(root,'private');await mkdir(outside);await writeFile(path.join(outside,'secret.js'),'private-source','utf8');const linked=path.join(root,'linked');await symlink(outside,linked,'junction');
  let unexpected:Awaited<ReturnType<typeof startWorkbench>>|undefined;
  try{await expect((async()=>{unexpected=await startWorkbench({root,port:0,staticDir:linked,workspace:workspace as never,research:research as never});})()).rejects.toMatchObject({code:'WEB_PATH_INVALID'});}finally{await unexpected?.close();}
 });
});

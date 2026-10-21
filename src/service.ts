import {readFile,mkdir,open,stat} from 'node:fs/promises';
import {existsSync} from 'node:fs';
import path from 'node:path';
import {CaseStore} from './store.js';
import {JobManager,type JobState} from './jobs.js';
import {rootDir,id,readJson,readJsonl,validateSchema,resolveBudget,sha256,assert,semanticHash} from './shared.js';
import {importModel,loadModel} from './repository.js';
import {evaluateModel} from './verification.js';
import {bindOracle,type OracleBinding,type InputSample} from './oracle.js';
import {importDataset,collectDataset,type StoredDataset} from './dataset.js';
import {importPortableEvidence,acquireEvidence,REA_ADAPTER_IDENTITY,type ReaAcquireOptions} from './rea.js';
import {liftPcode} from './pcode.js';
import {runExperiment} from './experiments.js';
import type {ArtifactRef,ComparisonPolicy,ValueMap} from './types.js';
import type {StoredRun,ExperimentRequest} from './run-types.js';
import type {ResearchRequest} from './research/types.js';
import {loadNativeStatus} from './native-status.js';

async function readEvidenceBytes(file:string):Promise<Buffer>{
 const maximum=64*1024*1024;
 const selected=await stat(file);
 assert(selected.isFile()&&selected.size<=maximum,'RESOURCE_LIMIT','Evidence input must be a regular file of at most 64 MiB');
 const handle=await open(file,'r');
 try{
  const before=await handle.stat();
  assert(before.isFile()&&before.size<=maximum,'RESOURCE_LIMIT','Evidence input must be a regular file of at most 64 MiB');
  // Read one byte beyond the declared size so concurrent growth cannot turn a
  // bounded import into an unbounded readFile allocation.
  const buffer=Buffer.alloc(before.size+1);let length=0;
  while(length<buffer.length){const read=await handle.read(buffer,length,buffer.length-length,null);if(read.bytesRead===0)break;length+=read.bytesRead;}
  const after=await handle.stat();
  assert(length===before.size&&after.size===before.size&&after.mtimeMs===before.mtimeMs,'SOURCE_CHANGED','Evidence file changed while being copied');
  return buffer.subarray(0,length);
 }finally{await handle.close();}
}

export class WirefitService {
 readonly jobs:JobManager;
 private constructor(public readonly store:CaseStore){this.jobs=new JobManager(store);}
 static async create(dir:string):Promise<WirefitService>{return new WirefitService(await CaseStore.create(dir));}
 static async open(dir:string):Promise<WirefitService>{return new WirefitService(await CaseStore.open(dir));}
 async close():Promise<void>{await this.jobs.close();await this.store.close();}
 static async capabilities(){
  const native=await loadNativeStatus(rootDir);
  const ida=await (await import('./ida/index.js')).idaCapabilities(rootDir);
  return {product:'Wirefit',version:'0.1.0',runtime:{node:process.version,platform:process.platform,arch:process.arch},semantics_profiles:['wirefix.bv.total.v1','wirefix.fp32.templates.v1'],exact:{widths:[8,16,32,64],bool:true,solver:'z3-solver@5.3.1',solver_isolation:'owned_child_process',full_binary_equivalence:false},numeric:{templates:['affine','affine_clamp','piecewise_affine'],backends:['analytic_baseline','reference','handwired'],handwired_commit:'257856e3b221140acb4cc4460626b850c0bd4ff1',oracle_calls:'explicit_fresh_process',gpu:false},binary:{formats:['PE32','PE32+'],inspection:'bounded_static_parser',detectors:['external_die_json'],unpack_backends:['external_unlicense'],configuration:'explicit_toolchain',local_x86_toolchain_present:existsSync(path.join(rootDir,'.local/binary-tools.x86.json')),output_quality:'analysis_dump',runnable_verified_automatically:false,handwired_used_for_unpacking:false},ida,rea:{adapter:REA_ADAPTER_IDENTITY,portable:true,public_mcp_runtime_installed:existsSync(path.join(rootDir,'.upstream/rea-runtime/node_modules/rea-agents/scripts/rea.mjs')),...native,phi:'UNSUPPORTED_PHI_MAPPING'},limitations:['Only explicitly supported pure scalar models are executable.','Z3 model equivalence and original-target observations are independent.','Worker processes provide lifecycle isolation, not a security sandbox.']};
 }
 async capabilities(){return WirefitService.capabilities();}
 async importModel(input:unknown){return importModel(this.store,input);}
 async evaluateModel(modelId:string,inputs:ValueMap){return evaluateModel(await loadModel(this.store,modelId),inputs);}
 async registerOracle(file:string){
  const binding=await bindOracle(file);
  await this.store.putObject('oracles',binding.oracle_id,binding);
  await this.store.putArtifact(await readFile(file),'application/json');
  return {oracle_id:binding.oracle_id,identity_sha256:binding.identity_sha256,source_kind:binding.manifest.source_kind,executable:binding.executable,registered_at:binding.registered_at};
 }
 async importDataset(manifest:string,artifactRoot:string){const result=await importDataset(this.store,manifest,artifactRoot);return {dataset_id:result.manifest.dataset_id,complete:result.complete,source:result.manifest.source,determinism:result.determinism};}
 async collectDataset(oracleId:string,inputs:InputSample[],policy:ComparisonPolicy,maxCalls=512):Promise<JobState>{
  inputs=structuredClone(inputs);policy=structuredClone(policy);const binding=await this.store.getObject<OracleBinding>('oracles',oracleId);
  const request={operation:'collect_dataset',oracle_id:oracleId,inputs,policy,max_calls:maxCalls};
  return this.jobs.submit('collect_dataset',request,async signal=>{
   const dataset=await collectDataset(this.store,binding,inputs,policy,{signal,max_oracle_calls:maxCalls});
   const result_id=id('collection');
   await this.store.putObject('runs',result_id,{result:{result_id,operation:'collect_dataset',dataset_id:dataset.manifest.dataset_id,complete:dataset.complete,actual_oracle_calls:dataset.actual_oracle_calls,determinism:dataset.determinism},request});
   return {result_id,status:signal.aborted?'cancelled':'completed'};
  },binding.manifest.batch_timeout_ms);
 }
 async importEvidence(file:string){
  assert(typeof file==='string'&&file.length>0&&!file.includes('\0'),'EVIDENCE_PATH_INVALID','Evidence path must be a nonempty local path');
  assert(!file.startsWith('ev_'),'SESSION_REFERENCE_UNAVAILABLE','Retained IDs from another MCP connection require a portable bundle');
  const bytes=await readEvidenceBytes(file);const syntaxDiagnostics:{code:string;message:string}[]=[];
  let text:string|undefined,parsed:unknown;
  try{text=new TextDecoder('utf-8',{fatal:true}).decode(bytes);}
  catch(error){syntaxDiagnostics.push({code:'INVALID_REA_UTF8',message:error instanceof Error?error.message:String(error)});}
  if(text!==undefined)try{parsed=JSON.parse(text);}
  catch(error){syntaxDiagnostics.push({code:'INVALID_REA_JSON',message:error instanceof Error?error.message:String(error)});}
  const ref=await this.store.putArtifact(bytes,syntaxDiagnostics.length?'application/octet-stream':'application/json');
  const bundle=syntaxDiagnostics.length?{status:'attachment_only' as const,records:[],identity:REA_ADAPTER_IDENTITY,diagnostics:syntaxDiagnostics}:importPortableEvidence(parsed,ref.sha256);
  const recordIds:string[]=[];
  if(bundle.status==='supported')for(const [index,record]of bundle.records.entries()){
   const localId=id('evidence');await this.store.putObject('evidence',localId,{bundle_artifact:ref,evidence_id:record.evidence_id,record_index:index,adapter:bundle.identity});recordIds.push(localId);
  }
  const attachmentId=id('bundle');await this.store.putObject('evidence',attachmentId,{bundle_artifact:ref,status:bundle.status,record_ids:recordIds,diagnostics:bundle.diagnostics,adapter:bundle.identity});
  return {bundle_id:attachmentId,status:bundle.status,record_ids:recordIds,diagnostics:bundle.diagnostics,artifact:ref};
 }
 async liftModel(evidenceId:string,outputId:string,cutpoints:string[]=[]){
  const record=await this.store.getObject<{bundle_artifact:ArtifactRef;evidence_id:string;record_index:number}>('evidence',evidenceId);
  const bytes=await this.store.readArtifact(record.bundle_artifact);
  const imported=importPortableEvidence(JSON.parse(bytes.toString('utf8')),record.bundle_artifact.sha256);
  assert(imported.status==='supported','UNSUPPORTED_SOURCE_CONTRACT','Bundle no longer authenticates');
  const item=imported.records[record.record_index];
  assert(item?.evidence_id===record.evidence_id,'EVIDENCE_ID_MISMATCH','Stored evidence identity changed');
  const lifted=liftPcode(item,outputId,[...cutpoints]);
  const source_map=await this.store.putJson({sourceMap:lifted.sourceMap,selectedOperations:lifted.selectedOperations,limitations:lifted.limitations,targetReplayEligible:lifted.targetReplayEligible});
  lifted.model.provenance.source_artifacts.push(record.bundle_artifact,source_map);
  lifted.model.model_id=id('model');
  const model=await importModel(this.store,lifted.model);
  return {...model,source_map,scope:lifted.model.scope,limitations:lifted.limitations,target_replay_eligible:lifted.targetReplayEligible};
 }
 async acquireEvidence(options:Omit<ReaAcquireOptions,'destination'|'persist'>):Promise<JobState>{
  options=structuredClone(options);return this.jobs.submit('acquire_evidence',options,async signal=>{
   const relative='evidence/acquisition-'+id('capture')+'/bundle.json';const destination=await this.store.resolveRelative(relative,false);await mkdir(path.dirname(destination),{recursive:true});await this.store.resolveRelative(relative,false);
   let saved:unknown=null;
   const result=await acquireEvidence({...options,destination,persist:async(_evidence,bytes)=>{
    const artifact=await this.store.putArtifact(bytes,'application/json');
    saved=await this.importEvidence(await this.store.resolveRelative(artifact.relative_path));
   }},signal);
   const result_id=id('acquisition');
   const raw_artifact=await this.store.putJson({...result,imported:undefined,saved});
   const cleanup=result.cleanup.diagnostic===undefined?result.cleanup:{closed:result.cleanup.closed,diagnostic_summary:JSON.stringify(result.cleanup.diagnostic).slice(0,2048)};
   const diagnostics=result.diagnostics.slice(0,8).map(diagnostic=>({...diagnostic,message:diagnostic.message.length>1024?diagnostic.message.slice(0,1024)+' [truncated; see raw_artifact]':diagnostic.message}));
   const compact={result_id,operation:'acquire_evidence',status:result.status,server:result.server,tool_count:result.tools.length,persisted:result.persisted,cleanup,diagnostics,saved,bundleSha256:result.bundleSha256??null,raw_artifact};
   await this.store.putObject('runs',result_id,{result:compact,request:options});
   return {result_id,status:result.status==='completed'?'completed':result.status==='cancelled'?'cancelled':'failed'};
  },options.timeoutMs??120000);
 }
 async submitExperiment(input:unknown):Promise<JobState>{
  assert(input!==null&&typeof input==='object'&&!Array.isArray(input),'REQUEST_INVALID','Experiment request must be an object');
  const source=input as Record<string,unknown>;
  const request=validateSchema<ExperimentRequest>('experiment-request',structuredClone({...source,budget:resolveBudget(source.budget??{})}));
  return this.jobs.submit(request.operation,request,(signal,job)=>runExperiment(this.store,request,job,signal),request.budget.wall_time_ms);
 }
 async submitResearch(input:unknown):Promise<JobState>{
  assert(input!==null&&typeof input==='object'&&!Array.isArray(input),'REQUEST_INVALID','Research request must be an object');
  const source=input as Record<string,unknown>;
  const request=validateSchema<ResearchRequest>('research-request',structuredClone({...source,budget:resolveBudget(source.budget??{})}));
  const {runResearchExperiment}=await import('./research/runner.js');
  return this.jobs.submit('research_experiment',request,(signal,job)=>runResearchExperiment(this.store,request,job,signal),request.budget.wall_time_ms);
 }
 async getResult(resultId:string){const record=await this.store.getObject<{result:unknown}>('runs',resultId);return record.result;}
 async getReport(resultId:string,section='result',offset=0,limit=100){
  assert(Number.isSafeInteger(offset)&&offset>=0&&Number.isSafeInteger(limit)&&limit>0&&limit<=1000,'PAGINATION_INVALID','Invalid report page');
  const record=await this.store.getObject<StoredRun>('runs',resultId);
  const value=section==='result'?record.result:section==='request'?record.request:section==='audit'?(record.result as {audit?:unknown})?.audit??null:section==='counterexamples'&&record.comparison_artifact?JSON.parse((await this.store.readArtifact(record.comparison_artifact)).toString('utf8')):null;
  assert(value!==null,'REPORT_SECTION_UNAVAILABLE','Requested report section is not available');
  if(Array.isArray(value))return {section,candidate_model_id:record.candidate_model_id,model_ids:record.model_ids,dataset_id:record.dataset_id,offset,limit,total:value.length,data:value.slice(offset,offset+limit)};
  const bytes=Buffer.byteLength(JSON.stringify(value),'utf8');
  assert(bytes<=65536,'REPORT_TOO_LARGE','This report section exceeds 64 KiB; export it as an artifact');
  return {section,candidate_model_id:record.candidate_model_id,model_ids:record.model_ids,dataset_id:record.dataset_id,data:value};
 }
 async exportReport(resultId:string,out:string){const module=await import('./reporting.js');return module.exportReport(this.store,resultId,out);}
}

import {readFile,realpath,lstat,stat} from 'node:fs/promises';
import path from 'node:path';
import {CaseStore} from './store.js';
import {assert,validateSchema,readJson,sha256,hashObject,canonical,id,WirefitError} from './shared.js';
import {validateInputs,validateDomain,domainContainsPoint} from './model.js';
import {validateNumericPolicy} from './numeric.js';
import {fp32Number} from './values.js';
import {callOracle,type OracleBinding,type InputSample} from './oracle.js';
import type {Signature,Domain,ComparisonPolicy,ArtifactRef,Observation,ValueMap} from './types.js';
export type Split='train'|'validation'|'holdout';
export interface DatasetManifest {
 schema_version:1;dataset_id:string;signature:Signature;domain:Domain;comparison_policy:ComparisonPolicy;
 source:{kind:Observation['source_kind'];source_id:string;source_identity_sha256:string;oracle_id:string|null};
 sampling_plan:{strategy:'explicit'|'boundary_seeded'|'random_seeded';seed:number|null;planned:number;inputs_artifact:ArtifactRef};
 splits:Record<Split,{artifact:ArtifactRef;sample_ids:string[]}>;notes:string;
}
export interface StoredDataset {manifest:DatasetManifest;original_manifest:ArtifactRef|null;locally_collected:boolean;complete:boolean;actual_oracle_calls:number;determinism:{checked_pairs:number;status:'consistent_on_repeats'|'not_checked'|'nondeterministic'};collection_artifact?:ArtifactRef}
export function parseJsonl<T>(bytes:Uint8Array):T[]{
 const text=new TextDecoder('utf-8',{fatal:true}).decode(bytes);
 const lines=text.split(/\r?\n/);if(lines.at(-1)==='')lines.pop();
 return lines.map((line,index)=>{
  assert(line.length>0&&Buffer.byteLength(line,'utf8')<=1048576,'JSON_INVALID','Invalid/oversized JSONL line '+(index+1));
  try{return JSON.parse(line) as T;}catch{throw new WirefitError('JSON_INVALID','Malformed JSONL line '+(index+1));}
 });
}
export async function readExternalArtifact(root:string,ref:ArtifactRef):Promise<Buffer>{
 assert(ref.relative_path.length>0&&!ref.relative_path.includes('\\')&&!ref.relative_path.includes(':')&&!ref.relative_path.includes('\0'),'ARTIFACT_PATH_INVALID','Invalid external artifact path');
 const parts=ref.relative_path.split('/');
 assert(parts.every(part=>part!==''&&part!=='.'&&part!=='..'),'ARTIFACT_PATH_INVALID','External artifact traversal/alias rejected');
 const base=await realpath(path.resolve(root));let target=base;
 for(const part of parts){target=path.join(target,part);assert(!(await lstat(target)).isSymbolicLink(),'ARTIFACT_PATH_INVALID','External artifact symlink/junction rejected');}
 const final=await realpath(target);assert(final.startsWith(base+path.sep),'ARTIFACT_PATH_INVALID','External artifact escapes root');
 const info=await stat(final);assert(info.isFile()&&info.size===ref.size_bytes&&info.size<=128*1024*1024,'ARTIFACT_SIZE_MISMATCH','External artifact size mismatch/limit');
 const bytes=await readFile(final);assert(sha256(bytes)===ref.sha256,'ARTIFACT_DIGEST_MISMATCH','External artifact hash mismatch');return bytes;
}
export function validatePolicy(policy:ComparisonPolicy,signature:Signature):void{
 if(policy.kind==='exact-bv')assert(signature.outputs.every(port=>port.type.kind!=='fp32'),'POLICY_INVALID','exact-bv requires BV/Bool outputs');
 else {validateNumericPolicy(policy);assert(signature.outputs.every(port=>port.type.kind==='fp32'),'POLICY_INVALID','FP32 policy requires FP32 outputs');}
}
function validatePlan(manifest:DatasetManifest,plan:InputSample[]):void{
 assert(plan.length===manifest.sampling_plan.planned,'DATASET_INVALID','Sampling plan denominator mismatch');
 const ids=new Set<string>();const splits=new Map<string,Split>();
 for(const sample of plan){
  validateSchema('input-sample',sample);validateInputs(manifest.signature.inputs,sample.inputs);
  assert(!ids.has(sample.sample_id),'DATASET_INVALID','Duplicate sample_id');ids.add(sample.sample_id);
  const key=hashObject(sample.inputs);const previous=splits.get(key);
  assert(previous===undefined||previous===sample.split,'DATASET_LEAKAGE','Same typed input appears in different splits');
  splits.set(key,sample.split);
 }
 const listed=new Set<string>();
 for(const split of ['train','validation','holdout'] as const){
  const actual=plan.filter(sample=>sample.split===split).map(sample=>sample.sample_id);
  const declared=manifest.splits[split].sample_ids,declaredSet=new Set(declared);
  assert(actual.length===declared.length&&actual.every(sample=>declaredSet.has(sample))&&declaredSet.size===declared.length,'DATASET_INVALID','Split sample IDs do not match input plan');
  for(const sample of declared){assert(!listed.has(sample),'DATASET_INVALID','Sample listed in multiple splits');listed.add(sample);}
 }
}
function validateRows(manifest:DatasetManifest,plan:InputSample[],split:Split,rows:Observation[]):void{
 const expected=manifest.splits[split].sample_ids;
 assert(rows.length===expected.length,'INCOMPLETE_DATASET','Observation count does not cover planned split');
 const seen=new Set<string>();const planById=new Map(plan.map(sample=>[sample.sample_id,sample]));const expectedIds=new Set(expected);
 for(const row of rows){
  validateSchema('observation',row);
  assert(!seen.has(row.sample_id)&&expectedIds.has(row.sample_id)&&row.split===split,'DATASET_INVALID','Observation split or ID mismatch');seen.add(row.sample_id);
  const input=planById.get(row.sample_id);
  assert(input&&canonical(input.inputs)===canonical(row.inputs),'DATASET_INVALID','Observation input differs from plan');
  assert(row.source_kind===manifest.source.kind&&row.source_id===manifest.source.source_id&&row.source_identity_sha256===manifest.source.source_identity_sha256,'DATASET_SOURCE_INVALID','Observation source identity mismatch');
  validateInputs(manifest.signature.inputs,row.inputs);
  if(row.status==='ok'){
   validateInputs(manifest.signature.outputs,row.outputs);
   for(const value of [...Object.values(row.inputs),...Object.values(row.outputs)])if(value.kind==='fp32')assert(Number.isFinite(fp32Number(value)),'DATASET_NONFINITE','Successful observation must have finite FP32 inputs and outputs');
   assert(domainContainsPoint(manifest.domain,row.inputs),'DATASET_INVALID','Successful observation outside declared domain');
  }
  if(row.record_kind==='expected_fixture'){assert(row.source_kind==='reference_fixture','DATASET_SOURCE_INVALID','Expected fixture cannot claim original-target or model observation provenance');assert(row.observed_at===null&&row.duration_ms===null,'DATASET_INVALID','Expected fixtures cannot claim actual observation time');}
  else assert(row.observed_at!==null&&row.duration_ms!==null,'DATASET_INVALID','Observed rows need real time and duration');
 }
}
function determinismTracker() {
 const prior=new Map<string,string>();let checked_pairs=0,nondeterministic=false;
 return {
  observe(row:Observation):void {if(row.status!=='ok')return;const key=hashObject(row.inputs),outputs=canonical(row.outputs);const previous=prior.get(key);if(previous!==undefined){checked_pairs++;if(previous!==outputs)nondeterministic=true;}else prior.set(key,outputs);},
  snapshot():StoredDataset['determinism'] {return {checked_pairs,status:nondeterministic?'nondeterministic':checked_pairs?'consistent_on_repeats':'not_checked'};}
 };
}
function observationCounts(planned:number,rows:Observation[]) {
 const completed=rows.filter(row=>row.status==='ok').length,out_of_domain=rows.filter(row=>row.status==='out_of_domain').length;
 return {planned,attempted:rows.length,completed,failed:rows.length-completed-out_of_domain,out_of_domain,not_attempted:planned-rows.length};
}
export async function importDataset(store:CaseStore,manifestPath:string,artifactRoot:string):Promise<StoredDataset>{
 const manifest=validateSchema<DatasetManifest>('dataset',await readJson(manifestPath));
 validateDomain(manifest.domain,manifest.signature.inputs);validatePolicy(manifest.comparison_policy,manifest.signature);
 const original_manifest=await store.putArtifact(await readFile(manifestPath),'application/json');
 const planBytes=await readExternalArtifact(artifactRoot,manifest.sampling_plan.inputs_artifact);
 const plan=parseJsonl<InputSample>(planBytes);validatePlan(manifest,plan);
 const local=structuredClone(manifest);const determinism=determinismTracker();
 local.sampling_plan.inputs_artifact=await store.putArtifact(planBytes,'application/x-ndjson');
 for(const split of ['train','validation','holdout'] as const){
  const raw=await readExternalArtifact(artifactRoot,manifest.splits[split].artifact);
  await store.putArtifact(raw,'application/x-ndjson');
  const rows=parseJsonl<Observation>(raw);validateRows(manifest,plan,split,rows);for(const row of rows)determinism.observe(row);
  for(const row of rows)row.raw_artifacts=await Promise.all(row.raw_artifacts.map(async ref=>store.putArtifact(await readExternalArtifact(artifactRoot,ref),ref.media_type)));
  local.splits[split].artifact=await store.putJsonl(rows);
 }
 validateSchema('dataset',local);
 const dataset:StoredDataset={manifest:local,original_manifest,locally_collected:false,complete:true,actual_oracle_calls:0,determinism:determinism.snapshot()};
 await store.putObject('datasets',local.dataset_id,dataset);
 return dataset;
}
export async function readDatasetSplit(store:CaseStore,dataset:StoredDataset,split:Split):Promise<Observation[]>{
 assert(dataset.complete,'INCOMPLETE_DATASET','Incomplete dataset is not eligible for fitting');
 const rows=parseJsonl<Observation>(await store.readArtifact(dataset.manifest.splits[split].artifact));
 const plan=parseJsonl<InputSample>(await store.readArtifact(dataset.manifest.sampling_plan.inputs_artifact));
 validateRows(dataset.manifest,plan,split,rows);return rows;
}
export async function collectDataset(store:CaseStore,binding:OracleBinding,plan:InputSample[],policy:ComparisonPolicy,options:{signal?:AbortSignal;max_oracle_calls?:number;dataset_id?:string}={}):Promise<StoredDataset>{
 assert(Number.isInteger(options.max_oracle_calls??512)&&(options.max_oracle_calls??512)>=0&&(options.max_oracle_calls??512)<=10000000,'BUDGET_INVALID','Invalid Oracle call budget');
 plan=structuredClone(plan);policy=structuredClone(policy);
 validatePolicy(policy,binding.manifest.signature);
 const blank=await store.putJsonl([]);
 const splits={} as DatasetManifest['splits'];
 for(const split of ['train','validation','holdout'] as const)splits[split]={artifact:blank,sample_ids:plan.filter(sample=>sample.split===split).map(sample=>sample.sample_id)};
 const manifest:DatasetManifest={schema_version:1,dataset_id:options.dataset_id??id('dataset'),signature:structuredClone(binding.manifest.signature),domain:structuredClone(binding.manifest.domain),comparison_policy:policy,source:{kind:binding.manifest.source_kind,source_id:binding.oracle_id,source_identity_sha256:binding.identity_sha256,oracle_id:binding.oracle_id},sampling_plan:{strategy:'explicit',seed:null,planned:plan.length,inputs_artifact:await store.putJsonl(plan)},splits,notes:'Observed from explicitly bound fresh-process Oracle; failures retained.'};
 validateSchema('dataset',manifest);validatePlan(manifest,plan);
 const rows:Observation[]=[];const executions:unknown[]=[];let calls=0;
 const started=Date.now();const deadline=started+binding.manifest.batch_timeout_ms;
 const determinism=determinismTracker();
 for(const sample of plan){
  if(options.signal?.aborted||Date.now()>=deadline||calls>=(options.max_oracle_calls??512))break;
  const call=await callOracle(binding,sample,{signal:options.signal,timeout_ms:Math.max(1,deadline-Date.now())});
  calls+=call.actual_calls;
  if(call.execution){
   call.observation.raw_artifacts.push(await store.putJson(call.execution));
  }
  rows.push(call.observation);executions.push({sample_id:sample.sample_id,actual_calls:call.actual_calls,status:call.observation.status});
  determinism.observe(call.observation);
 }
 for(const split of ['train','validation','holdout'] as const)manifest.splits[split].artifact=await store.putJsonl(rows.filter(row=>row.split===split));
 const complete=rows.length===plan.length;
 const collection_artifact=await store.putJson({started_at:new Date(started).toISOString(),finished_at:new Date().toISOString(),planned:plan.length,attempted:rows.length,actual_oracle_calls:calls,counts:observationCounts(plan.length,rows),executions,complete});
 const dataset:StoredDataset={manifest,original_manifest:null,locally_collected:true,complete,actual_oracle_calls:calls,determinism:determinism.snapshot(),collection_artifact};
 await store.putObject('datasets',manifest.dataset_id,dataset);
 return dataset;
}



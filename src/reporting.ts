import {exportBinaryReport} from './binary-reporting.js';
import {exportIdaReport} from './ida-reporting.js';
import { mkdir, lstat, realpath, readdir, writeFile, unlink } from 'node:fs/promises';
import path from 'node:path';
import type { ArtifactRef, ComparisonPolicy, Mapping, Model, Observation, TypedValue, ValueMap } from './types.js';
import type { StoredDataset } from './dataset.js';
import { parseJsonl } from './dataset.js';
import { CaseStore } from './store.js';
import { assert, sha256, semanticHash, sourceHash, hashObject, validateSchema } from './shared.js';
import { validateBvModel, validateInputs, domainContainsPoint } from './model.js';
import { validateNumericModel, exportNumericModelSource } from './numeric.js';
import { exportModelSource } from './export-model.js';
import { evaluateModel } from './verification.js';
import { runProcess } from './process.js';

interface StoredExportRun {
  result: Record<string,any>; request: Record<string,unknown>; model_ids: string[];
  candidate_model_id: string|null; dataset_id: string|null;
  observations_artifact: ArtifactRef|null; comparison_artifact: ArtifactRef|null; test_inputs_artifact: ArtifactRef|null;
}
interface ExportFile {relative_path:string;sha256:string;size_bytes:number;media_type:string}
interface ExportModel {model_id:string;semantic_sha256:string;source_sha256:string;json:string;module:string;typescript:string;role:'reference_model'|'lifted_model'|'candidate_model'}
interface ManifestPayload {
  schema_version:1;product:'Wirefit';run_id:string;files:ExportFile[];models:ExportModel[];candidate_module:string|null;
  external_dependencies:{kind:string;identity:unknown;reason:string}[];
  fresh_target_replay:{status:'unavailable';reason:string};
}
export interface ExportManifest extends ManifestPayload {manifest_sha256:string;output_directory:string}
interface ReplayCase {model_id:string;sample_id:string;source_kind:ExportModel['role'];inputs:ValueMap;expected:{status:'ok';outputs:ValueMap}|{status:'model_error';message:string}}

function artifact(value: unknown): value is ArtifactRef {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  const object=value as Record<string,unknown>;
  return Object.keys(object).sort().join(',')==='media_type,relative_path,sha256,size_bytes' && typeof object.relative_path==='string' && typeof object.media_type==='string' && typeof object.sha256==='string' && /^[0-9a-f]{64}$/.test(object.sha256) && Number.isSafeInteger(object.size_bytes) && Number(object.size_bytes)>=0;
}
function collectRefs(value:unknown):ArtifactRef[]{
  const refs:ArtifactRef[]=[];const pending=[value];let examined=0;
  while(pending.length){
    assert(examined++<1_000_000,'EXPORT_BUDGET','Export reference graph exceeds budget');
    const item=pending.pop();
    if(artifact(item)){refs.push(item);continue;}
    if(Array.isArray(item))pending.push(...item);
    else if(item&&typeof item==='object')pending.push(...Object.values(item));
  }
  return refs;
}
function parseArtifact(bytes:Uint8Array,ref:ArtifactRef):unknown {
  if(ref.media_type==='application/x-ndjson'||ref.media_type==='application/jsonl')return parseJsonl(bytes);
  if(ref.media_type==='application/json')return JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(bytes));
  return null;
}
function rowsFrom(value:unknown):Observation[]{
  const list:unknown[]=Array.isArray(value)?value:(value&&typeof value==='object'&&Array.isArray((value as any).observations)?(value as any).observations:[]);
  return list.filter((item):item is Observation=>!!item&&typeof item==='object'&&(item as any).schema_version===1&&typeof (item as any).source_kind==='string'&&typeof (item as any).observation_id==='string').map(item=>{
    validateSchema('observation',item);
    assert(!(item.source_kind==='original_target'&&item.record_kind!=='observed'),'EXPORT_SOURCE_INVALID','Original-target rows must be actual observations');
    return item as Observation;
  });
}
function inputMaps(value:unknown):{sample_id:string;inputs:ValueMap}[]{
  const output:{sample_id:string;inputs:ValueMap}[]=[];const pending=[value];let examined=0;
  while(pending.length){
    assert(examined++<100_000,'EXPORT_BUDGET','Export sample graph exceeds budget');
    const item=pending.pop();
    if(Array.isArray(item)){pending.push(...item);continue;}
    if(!item||typeof item!=='object')continue;
    const object=item as Record<string,unknown>;
    if(object.inputs&&typeof object.inputs==='object'&&!Array.isArray(object.inputs)){
      const values=Object.values(object.inputs);
      if(values.length&&values.every(v=>v&&typeof v==='object'&&['bv','bool','fp32'].includes((v as any).kind)))output.push({sample_id:typeof object.sample_id==='string'?object.sample_id:`sample_${output.length}`,inputs:object.inputs as ValueMap});
    }
    pending.push(...Object.values(object));
    assert(output.length<=4096,'EXPORT_BUDGET','Export sample count exceeds budget');
  }
  return output;
}
async function ensureNoLinks(absolute:string):Promise<void>{
  const parsed=path.parse(absolute);let current=parsed.root;
  for(const part of absolute.slice(parsed.root.length).split(path.sep).filter(Boolean)){
    current=path.join(current,part);
    try{assert(!(await lstat(current)).isSymbolicLink(),'EXPORT_PATH_INVALID','Export path contains a symlink or junction');}
    catch(error){if((error as NodeJS.ErrnoException).code!=='ENOENT')throw error;}
  }
}
function asMapping(value:unknown):Mapping|null{
  if(!value||typeof value!=='object'||!Array.isArray((value as any).inputs)||!Array.isArray((value as any).outputs))return null;
  const mapping=value as Mapping;
  assert([...mapping.inputs,...mapping.outputs].every(pair=>pair&&typeof pair.left==='string'&&typeof pair.right==='string'),'EXPORT_MAPPING_INVALID','Malformed replay mapping');
  return mapping;
}
function boundInputs(model:Model,values:ValueMap,mapping:Mapping|null,direction:'direct'|'left'|'right'):ValueMap{
  let mapped=values;
  if(mapping&&direction!=='direct')mapped=Object.fromEntries(mapping.inputs.map(pair=>direction==='left'?[pair.left,values[pair.right]]:[pair.right,values[pair.left]])) as ValueMap;
  validateInputs(model.inputs,mapped);return mapped;
}
function generatedSmoke(model:Model):ValueMap|null{
  const inputs:ValueMap={};
  for(const port of model.inputs){
    const zero:TypedValue=port.type.kind==='bool'?{kind:'bool',value:false}:port.type.kind==='fp32'?{kind:'fp32',bits:'0x00000000'}:{...port.type,bits:'0x'+'0'.repeat(port.type.width/4)};
    const options:TypedValue[]=[zero,...model.domain.constraints.filter(c=>c.input===port.id).map(c=>c.value)];
    if(port.type.kind==='bool')options.push({kind:'bool',value:true});
    else if(port.type.kind==='bv'){
      const width=port.type.width;
      for(const value of [1n,(1n<<BigInt(width))-1n,...options.filter((v):v is Extract<TypedValue,{kind:'bv'}>=>v.kind==='bv').flatMap(v=>[BigInt(v.bits)+1n,BigInt(v.bits)-1n])])options.push({kind:'bv',width,bits:'0x'+BigInt.asUintN(width,value).toString(16).padStart(width/4,'0')});
    }else options.push({kind:'fp32',bits:'0x3f800000'},{kind:'fp32',bits:'0xbf800000'});
    const selected=options.find(value=>domainContainsPoint({constraints:model.domain.constraints.filter(c=>c.input===port.id)},{[port.id]:value}));
    if(!selected)return null;inputs[port.id]=selected;
  }
  return inputs;
}

/** Export immutable evidence and generated modules without elevating stored verdicts. */
export async function exportReport(store:CaseStore,runId:string,outDir:string):Promise<ExportManifest>{
  const stored=await store.getObject<StoredExportRun>('runs',runId);
  if(stored.result?.operation==='analyze_ida')return exportIdaReport(store,runId,outDir);
  if(stored.result?.operation==='inspect_binary'||stored.result?.operation==='unpack_binary'||stored.result?.operation==='trace_binary')return exportBinaryReport(store,runId,outDir);
  assert(typeof outDir==='string'&&outDir.length>0&&!outDir.includes('\0'),'EXPORT_PATH_INVALID','Export destination must be nonempty');
  const destination=path.resolve(outDir);await ensureNoLinks(destination);
  try{assert((await readdir(destination)).length===0,'EXPORT_DIRECTORY_NOT_EMPTY','Export destination must be absent or empty');}
  catch(error){if((error as NodeJS.ErrnoException).code!=='ENOENT')throw error;}
  await mkdir(destination,{recursive:true});await ensureNoLinks(destination);
  const resolved=await realpath(destination);assert(resolved===destination||process.platform==='win32'&&resolved.toLowerCase()===destination.toLowerCase(),'EXPORT_PATH_INVALID','Export destination resolves through an alias');
  const reservation=path.join(destination,'.wirefit-export.lock');
  await writeFile(reservation,runId+'\n',{encoding:'utf8',flag:'wx'});
  const files:ExportFile[]=[];
  const write=async(relative:string,value:string|Uint8Array,media:string)=>{
    const parts=relative.split('/');assert(parts.every(p=>p!==''&&p!=='.'&&p!=='..'&&!p.includes('\\')&&!p.includes(':')&&!p.includes('\0')),'EXPORT_PATH_INVALID','Export relative path is invalid');
    const target=path.resolve(destination,...parts);assert(target.startsWith(destination+path.sep),'EXPORT_PATH_INVALID','Export file escapes destination');
    await ensureNoLinks(path.dirname(target));await mkdir(path.dirname(target),{recursive:true});await ensureNoLinks(path.dirname(target));
    const bytes=typeof value==='string'?Buffer.from(value,'utf8'):Buffer.from(value);
    await writeFile(target,bytes,{flag:'wx'});
    files.push({relative_path:relative,sha256:sha256(bytes),size_bytes:bytes.length,media_type:media});
  };
  const json=async(relative:string,value:unknown)=>write(relative,JSON.stringify(value,null,2)+'\n','application/json');
  try{
    const run=await store.getObject<StoredExportRun>('runs',runId);
    validateSchema('experiment-result',run.result);
    assert(hashObject(run.request)===run.result.identity.request_sha256,'EXPORT_REQUEST_IDENTITY_MISMATCH','Stored request differs from the verifier request binding');
    assert(Array.isArray(run.model_ids)&&new Set(run.model_ids).size===run.model_ids.length,'EXPORT_RUN_INVALID','Run model IDs must be unique');
    const models=await Promise.all(run.model_ids.map(id=>store.getObject<Model>('models',id)));
    models.forEach(model=>model.kind==='bv_dag'?validateBvModel(model):validateNumericModel(model));
    const hashes=run.result.identity.model_semantic_hashes;
    assert(Array.isArray(hashes)&&hashes.length===models.length&&models.every((model,index)=>semanticHash(model)===hashes[index]),'EXPORT_MODEL_IDENTITY_MISMATCH','Stored model semantics differ from the verifier result');
    const sourceHashes=run.result.identity.source_envelope_hashes;
    assert(sourceHashes.length===models.length&&models.every((model,index)=>sourceHash(model)===sourceHashes[index]),'EXPORT_SOURCE_IDENTITY_MISMATCH','Stored model source envelope differs from verifier bindings');
    const candidate=run.candidate_model_id===null?null:await store.getObject<Model>('models',run.candidate_model_id);
    if(candidate){candidate.kind==='bv_dag'?validateBvModel(candidate):validateNumericModel(candidate);assert(hashes.includes(semanticHash(candidate)),'EXPORT_MODEL_IDENTITY_MISMATCH','Candidate semantic identity is absent from verifier bindings');}
    const dataset=run.dataset_id===null?null:await store.getObject<StoredDataset>('datasets',run.dataset_id);
    const mapping=asMapping(run.request.mapping);
    const candidatePolicy=(run.request.comparison_policy??dataset?.manifest.comparison_policy??(candidate?.kind==='bv_dag'?{kind:'exact-bv'}:null)) as ComparisonPolicy|null;
    const opaque=new Set(dataset?.original_manifest?[dataset.original_manifest.sha256]:[]);
    const queue=collectRefs([run,...models,candidate,dataset]);
    const seen=new Map<string,string>();const artifactValues=new Map<string,unknown>();
    let totalBytes=0;
    for(let index=0;index<queue.length;index++){
      assert(queue.length<=8192,'EXPORT_BUDGET','Export artifact count exceeds budget');
      const ref=queue[index]!;
      const previous=seen.get(ref.relative_path);if(previous!==undefined){assert(previous===ref.sha256,'EXPORT_REFERENCE_CONFLICT','Artifact path has conflicting identities');continue;}
      const bytes=await store.readArtifact(ref);totalBytes+=bytes.length;assert(totalBytes<=512*1024*1024,'EXPORT_BUDGET','Export closure exceeds 512 MiB');
      seen.set(ref.relative_path,ref.sha256);await write(ref.relative_path,bytes,ref.media_type);
      if(!opaque.has(ref.sha256)){
        const value=parseArtifact(bytes,ref);artifactValues.set(ref.sha256,value);
        if(value!==null)queue.push(...collectRefs(value));
      }
    }
    const rows:Observation[]=[];
    if(run.observations_artifact)rows.push(...rowsFrom(artifactValues.get(run.observations_artifact.sha256)));
    else if(dataset)for(const split of Object.values(dataset.manifest.splits))rows.push(...rowsFrom(artifactValues.get(split.artifact.sha256)));
    const sampleValues:unknown[]=[rows];
    if(run.test_inputs_artifact)sampleValues.push(artifactValues.get(run.test_inputs_artifact.sha256));
    if(run.comparison_artifact)sampleValues.push(artifactValues.get(run.comparison_artifact.sha256));
    if(dataset)sampleValues.push(artifactValues.get(dataset.manifest.sampling_plan.inputs_artifact.sha256));
    const samples=inputMaps(sampleValues);const modelEntries:ExportModel[]=[];const cases:ReplayCase[]=[];
    for(let index=0;index<models.length;index++){
      const model=models[index]!;const stem='models/model-'+sha256(model.model_id).slice(0,20);
      const role:ExportModel['role']=model.model_id===candidate?.model_id?'candidate_model':model.provenance.source_kind==='rea_portable'||model.provenance.source_kind==='rea_live'?'lifted_model':'reference_model';
      const entry:ExportModel={model_id:model.model_id,semantic_sha256:semanticHash(model),source_sha256:sourceHash(model),json:stem+'.json',module:stem+'.mjs',typescript:stem+'.ts',role};
      await json(entry.json,model);
      await write(entry.module,model.kind==='bv_dag'?exportModelSource(model):exportNumericModelSource(model),'text/javascript');
      await write(entry.typescript,model.kind==='bv_dag'?exportModelSource(model,'ts'):exportNumericModelSource(model,'ts'),'text/typescript');
      modelEntries.push(entry);
      const possible=samples.length?samples:[{sample_id:'generated_model_smoke',inputs:generatedSmoke(model)}];
      const seenInputs=new Set<string>();
      for(const sample of possible){
        if(!sample.inputs)continue;
        let inputs:ValueMap;
        try{
          const direction=samples.length===0?'direct':run.request.operation==='verify_candidate'||run.request.operation==='fit_numeric'?'left':index===0?'direct':'right';
          inputs=boundInputs(model,sample.inputs,mapping,direction);
        }catch{continue;}
        const identity=JSON.stringify(inputs);if(seenInputs.has(identity))continue;seenInputs.add(identity);
        let expected:ReplayCase['expected'];
        try{expected={status:'ok',outputs:evaluateModel(model,inputs)};}
        catch(error){expected={status:'model_error',message:error instanceof Error?error.message:String(error)};}
        cases.push({model_id:model.model_id,sample_id:sample.sample_id,source_kind:role,inputs,expected});
      }
    }
    const candidateEntry=modelEntries.find(entry=>entry.model_id===candidate?.model_id);
    if(candidateEntry){
      await write('candidate.mjs',candidate!.kind==='bv_dag'?exportModelSource(candidate!):exportNumericModelSource(candidate!),'text/javascript');
      await write('candidate.ts',candidate!.kind==='bv_dag'?exportModelSource(candidate!,'ts'):exportNumericModelSource(candidate!,'ts'),'text/typescript');
    }
    const replayRows=rows.map(row=>{
      let inputs:ValueMap|null=null;
      if(candidate)try{inputs=boundInputs(candidate,row.inputs,mapping,'left');}catch{}
      return {observation:row,candidate_inputs:inputs};
    });
    await json('result.json',run.result);await json('request.json',run.request);await json('run.json',run);
    if(dataset)await json('dataset.json',dataset);
    if(candidatePolicy)await json('comparison-policy.json',candidatePolicy);
    await json('domains.json',models.map(model=>({model_id:model.model_id,domain:model.domain})));
    const targetBindingEligible=!!candidate&&!['rea_portable','rea_live'].includes(candidate.provenance.source_kind)&&candidate.scope.execution_guard.kind==='all_inputs'&&candidate.scope.observation_point.kind!=='local_value';
    await json('replay-data.json',{cases,rows:replayRows,candidate_model_id:candidate?.model_id??null,mapping,comparison_policy:candidatePolicy,target_binding_eligible:targetBindingEligible});
    const external:ManifestPayload['external_dependencies']=[{kind:'node_runtime',identity:{minimum_major:24,observed:process.version},reason:'A compatible Node runtime is required to execute the standalone modules.'}];
    const sourceTargets=new Set<string>();
    for(const model of models){
      const source=model.provenance.source_ref;
      if(source?.target_sha256&&!sourceTargets.has(source.target_sha256)){
        sourceTargets.add(source.target_sha256);
        external.push({kind:'source_target',identity:{target_sha256:source.target_sha256,bundle_sha256:source.bundle_sha256,evidence_id:source.evidence_id,provider_id:source.provider_id,analysis_profile_digest:source.analysis_profile_digest},reason:'Portable Evidence preserves observations; the original analyzed target is not embedded by that bundle or executed by this replay.'});
      }
    }
    const oracleIds=new Set<string>();
    for(const [key,value] of Object.entries(run.request))if((key==='oracle_id'||key.endsWith('_oracle_id'))&&typeof value==='string')oracleIds.add(value);
    if(dataset?.manifest.source.oracle_id)oracleIds.add(dataset.manifest.source.oracle_id);
    for(const id of oracleIds){
      const binding=await store.getObject<Record<string,unknown>>('oracles',id);
      const identity={oracle_id:id,identity_sha256:binding.identity_sha256,manifest:binding.manifest,executable:binding.executable,executable_sha256:binding.executable_sha256,files:binding.files,runtime:binding.runtime,environment_values_included:false};
      await json('oracles/oracle-'+sha256(id).slice(0,20)+'.json',identity);
      external.push({kind:'original_oracle',identity,reason:'Target executables, wrappers, environment values and their external runtime are not copied or executed by this export.'});
    }
    if(rows.some(row=>row.source_kind==='original_target')&&oracleIds.size===0)external.push({kind:'original_target',identity:{source_ids:[...new Set(rows.filter(row=>row.source_kind==='original_target').map(row=>row.source_id))]},reason:'Recorded observations are included. No executable Oracle binding is available for a fresh replay.'});
    const payload:ManifestPayload={schema_version:1,product:'Wirefit',run_id:runId,files,models:modelEntries,candidate_module:candidateEntry?'candidate.mjs':null,external_dependencies:external,fresh_target_replay:{status:'unavailable',reason:'This package replays recorded data and exported models. Original targets are external and no fresh target call is made.'}};
    await write('replay.mjs',replayHelper,'text/javascript');
    const report=`# Wirefit report\n\nRun: ${runId}\n\nModel check: **${run.result.model_check.status}**. ${run.result.model_check.reason}\n\nTarget validation: **${run.result.target_validation.status}**, mode ${run.result.target_validation.mode}. ${run.result.target_validation.reason}\n\nFit: **${run.result.fit.status}**. ${run.result.fit.reason}\n\nModel sample comparison: **${run.result.sample_comparison.status}**.\n\nFidelity: **${run.result.fidelity.status}**.\n\nRun \`node replay.mjs\` from this directory to verify file hashes and replay exported modules against independent model snapshots and recorded observations. A reproduced candidate mismatch remains a mismatch. Replay consistency is separate from original-target validation.\n\nFresh original-target replay: **unavailable**. External target dependencies are listed in manifest.json. Recorded observations do not count as new target executions.\n\n${run.result.limitations.map((text:string)=>'- '+text).join('\n')}\n`;
    await write('report.md',report,'text/markdown');
    let manifestBytes=Buffer.from(JSON.stringify(payload,null,2)+'\n','utf8');await writeFile(path.join(destination,'manifest.json'),manifestBytes,{flag:'wx'});
    const execution=await runProcess(process.execPath,[path.join(destination,'replay.mjs')],{cwd:destination,timeout_ms:30000,max_stdout_bytes:4*1024*1024});
    assert(execution.code===0,'EXPORT_REPLAY_FAILED','Fresh-process standalone replay failed: '+execution.stderr);
    const replay=JSON.parse(execution.stdout);assert(replay.export_consistency?.status!=='mismatch','EXPORT_REPLAY_FAILED','Compiled modules differ from independent evaluator snapshots');
    await json('replay-verification.json',{record_kind:'observed',kind:'fresh_process_export_replay',executed_at:new Date().toISOString(),runtime:process.version,execution,replay});
    manifestBytes=Buffer.from(JSON.stringify(payload,null,2)+'\n','utf8');await writeFile(path.join(destination,'manifest.json'),manifestBytes);
    const manifest_sha256=sha256(manifestBytes);await writeFile(path.join(destination,'manifest.sha256'),manifest_sha256+'  manifest.json\n',{encoding:'utf8',flag:'wx'});
    return {...payload,manifest_sha256,output_directory:destination};
  }finally{await unlink(reservation).catch(()=>undefined);}
}

const replayHelper=String.raw`// Standalone Wirefit replay. No case directory or installed Wirefit package is used.
import {readFile,lstat} from 'node:fs/promises';
import path from 'node:path';
import {fileURLToPath,pathToFileURL} from 'node:url';
import {createHash} from 'node:crypto';
const root=path.dirname(fileURLToPath(import.meta.url));
const digest=bytes=>createHash('sha256').update(bytes).digest('hex');
const json=async name=>JSON.parse(await readFile(path.join(root,name),'utf8'));
const equal=(a,b)=>{
 if(a===null||b===null||typeof a!=='object'||typeof b!=='object')return a===b;
 const ak=Object.keys(a).sort(),bk=Object.keys(b).sort();return JSON.stringify(ak)===JSON.stringify(bk)&&ak.every(k=>equal(a[k],b[k]));
};
const counts=planned=>({planned,attempted:0,completed:0,matched:0,mismatched:0,failed:0,out_of_domain:0});
function f32(v){if(!v||v.kind!=='fp32'||!/^0x[0-9a-f]{8}$/.test(v.bits))throw Error('INVALID_FP32');const d=new DataView(new ArrayBuffer(4));d.setUint32(0,parseInt(v.bits.slice(2),16));const n=d.getFloat32(0);if(!Number.isFinite(n))throw Error('NONFINITE');return n;}
function compare(left,right,policy){
 const keys=Object.keys(left).sort();if(!keys.length||!equal(keys,Object.keys(right).sort()))throw Error('OUTPUT_MAPPING_INVALID');
 return keys.every(key=>{
  const a=left[key],b=right[key];
  if(policy.kind==='exact-bv'){if(!a||!b||a.kind==='fp32'||b.kind==='fp32')throw Error('POLICY_INVALID');return equal(a,b);}
  const x=f32(a),y=f32(b);
  if(policy.kind==='bitwise-fp32')return a.bits===b.bits;
  if(policy.kind!=='tolerance-fp32'||policy.nonfinite!=='reject')throw Error('POLICY_INVALID');
  const atol=Number(policy.atol),rtol=Number(policy.rtol);if(!Number.isFinite(atol)||!Number.isFinite(rtol)||atol<0||rtol<0)throw Error('POLICY_INVALID');
  return Math.abs(x-y)<=atol+rtol*Math.max(Math.abs(x),Math.abs(y));
 });
}
try{
 const manifest=await json('manifest.json');
 const paths=new Set();
 for(const entry of manifest.files){
  if(typeof entry.relative_path!=='string'||paths.has(entry.relative_path)||entry.relative_path.includes(String.fromCharCode(92)))throw Error('EXPORT_INTEGRITY_ERROR duplicate or invalid path');paths.add(entry.relative_path);
  const parts=entry.relative_path.split('/');if(parts.some(p=>!p||p==='.'||p==='..'||p.includes('\\')||p.includes(':')))throw Error('EXPORT_INTEGRITY_ERROR path');
  let target=root;for(const part of parts){target=path.join(target,part);if((await lstat(target)).isSymbolicLink())throw Error('EXPORT_INTEGRITY_ERROR symlink');}
  const bytes=await readFile(target);if(bytes.length!==entry.size_bytes||digest(bytes)!==entry.sha256)throw Error('EXPORT_INTEGRITY_ERROR '+entry.relative_path);
 }
 const data=await json('replay-data.json'),stored=await json('result.json');
 const modules=new Map();
 for(const entry of manifest.models){if(!paths.has(entry.module)||!entry.module.endsWith('.mjs'))throw Error('EXPORT_INTEGRITY_ERROR unverified module');modules.set(entry.model_id,await import(pathToFileURL(path.join(root,entry.module)).href));}
 const consistency=counts(data.cases.length);const caseResults=[];let modelErrors=0;
 for(const sample of data.cases){
  consistency.attempted++;let matched=false;let actual=null;
  try{actual=modules.get(sample.model_id).evaluate(sample.inputs);matched=sample.expected.status==='ok'&&equal(actual,sample.expected.outputs);}
  catch(error){modelErrors++;matched=sample.expected.status==='model_error';actual={status:'model_error',message:error.message};}
  consistency.completed++;consistency[matched?'matched':'mismatched']++;
  caseResults.push({model_id:sample.model_id,sample_id:sample.sample_id,source_kind:sample.source_kind,matched,actual});
 }
 const originalRows=data.rows.filter(item=>item.observation.source_kind==='original_target'&&item.observation.record_kind==='observed');
 const target=counts(Math.max(originalRows.length,stored.target_validation.counts.planned)),details=[];const candidate=modules.get(data.candidate_model_id);
 for(const item of originalRows){
  target.attempted++;const row=item.observation;
  if(!candidate||!data.target_binding_eligible||!data.comparison_policy||!item.candidate_inputs||row.status!=='ok'){target[row.status==='out_of_domain'?'out_of_domain':'failed']++;details.push({sample_id:row.sample_id,status:row.status,source_kind:row.source_kind,reason:'Missing or unvalidated candidate/policy/guard/observation binding, or unsuccessful recorded observation'});continue;}
  try{
   const outputs=candidate.evaluate(item.candidate_inputs);let left=outputs,right=row.outputs;
   if(data.mapping){left=Object.fromEntries(data.mapping.outputs.map(pair=>[pair.left,outputs[pair.left]]));right=Object.fromEntries(data.mapping.outputs.map(pair=>[pair.left,row.outputs[pair.right]]));}
   const matched=compare(left,right,data.comparison_policy);target.completed++;target[matched?'matched':'mismatched']++;
   details.push({sample_id:row.sample_id,source_kind:row.source_kind,mode:'recorded',observed_outputs:row.outputs,candidate_outputs:outputs,matched});
  }catch(error){target.failed++;details.push({sample_id:row.sample_id,status:'failed',message:error.message});}
 }
 const targetStatus=!candidate||!data.target_binding_eligible||!data.comparison_policy||target.planned===0?'unavailable':target.mismatched?'mismatch':target.completed===target.planned?'matched':'partial';
 const sourceCounts={};for(const item of data.rows){const key=item.observation.record_kind+':'+item.observation.source_kind;sourceCounts[key]=(sourceCounts[key]??0)+1;}
 const output={export_consistency:{status:consistency.planned===0?'not_run':consistency.mismatched?'mismatch':'matched',counts:consistency,model_error_cases:modelErrors,cases:caseResults},recorded_target_comparison:{status:targetStatus,mode:'recorded',counts:target,details},recorded_source_counts:sourceCounts,fresh_target_replay:manifest.fresh_target_replay,solver_replay:{status:'not_run',reason:'Historical solver evidence is included; this helper does not invoke a solver.'},original_verifier_result:{model_check:stored.model_check.status,target_validation:stored.target_validation.status,fit:stored.fit.status,fidelity:stored.fidelity.status}};
 console.log(JSON.stringify(output));if(consistency.mismatched)process.exitCode=1;
}catch(error){console.error(JSON.stringify({error:{code:'EXPORT_INTEGRITY_ERROR',message:error.message}}));process.exitCode=1;}
`;

import {existsSync} from 'node:fs';
import {fileURLToPath} from 'node:url';
import {setImmediate as yieldEventLoop} from 'node:timers/promises';
import {CaseStore} from './store.js';
import {assert,WirefitError,errorRecord,id,hashObject,semanticHash,sourceHash,validateSchema,readJson} from './shared.js';
import {loadModel,importModel} from './repository.js';
import {defaultMapping,validateMapping,validateDomain,domainContainsPoint,validateInputs} from './model.js';
import {compareBv,type ExactCheck} from './solver.js';
import {simplifyBv,suggestBvInputs} from './synthesis.js';
import {evaluateModel,verifyRows,onlyCounts,emptyCounts,deriveStatus,compareOutputs,mappedOutputs,checkNumericComparisonDomain,checkOracleDomains,verificationBinding} from './verification.js';
import {readDatasetSplit,parseJsonl,validatePolicy,type StoredDataset,type Split} from './dataset.js';
import {callOracle,type OracleBinding,type InputSample} from './oracle.js';
import {runProcess} from './process.js';
import {fp32Bits,fp32Number} from './values.js';
import type {JobState} from './jobs.js';
import type {ArtifactRef,Model,BvModel,NumericModel,Mapping,Domain,ValueMap,Observation,ComparisonPolicy,BvOp,CoreValue} from './types.js';
import type {FitOptions,fitNumeric} from './numeric.js';
import type {ExperimentRequest,ExperimentResult,StoredRun} from './run-types.js';

function initialResult(request:ExperimentRequest):ExperimentResult{
 return {schema_version:1,result_id:id('run'),experiment_id:request.experiment_id,operation:request.operation,job_status:'completed',
 identity:{request_sha256:hashObject(request),model_semantic_hashes:[],source_envelope_hashes:[],oracle_binding_hashes:[],input_plan_sha256:null,policy_sha256:null,observation_binding_sha256:null},
 model_check:{status:'not_run',reason:'No exact model query was run.',artifacts:[],solver_record:null},
 target_validation:{status:'not_run',reason:'No independent target observations were compared.',artifacts:[],mode:'none',counts:emptyCounts(),source_counts:[]},
 fit:{status:'not_run',reason:'No numeric fitting was requested.',artifacts:[],candidate_model_id:null,backend:null,train_counts:emptyCounts(),validation_counts:emptyCounts(),holdout_counts:emptyCounts()},
 sample_comparison:{status:'not_run',reason:'No sampled model comparison was requested.',artifacts:[],counts:emptyCounts()},
 fidelity:{status:'not_applicable',reason:'No original-target binding has been independently validated.',artifacts:[],binding_identity_sha256:null},
 dependencies:[],artifacts:[],limitations:['An exact model result does not prove whole-binary equivalence.'],error:null};
}
function eligibleTarget(model:Model):boolean{
 return !['rea_portable','rea_live'].includes(model.provenance.source_kind)&&model.scope.execution_guard.kind==='all_inputs'&&model.scope.observation_point.kind!=='local_value';
}
function rejectNondeterminism(dataset:StoredDataset):void{
 assert(dataset.determinism.status!=='nondeterministic','NONDETERMINISTIC_ORACLE','Contradictory repeated observations cannot support deterministic fitting/validation');
}
export async function runExperiment(store:CaseStore,request:ExperimentRequest,job:JobState,signal:AbortSignal):Promise<{result_id:string;status:'completed'|'failed'|'cancelled';error?:import('./types.js').StructuredError}>{
 const result=initialResult(request);
 const record:StoredRun={result,request,model_ids:[],candidate_model_id:null,dataset_id:null,observations_artifact:null,comparison_artifact:null,test_inputs_artifact:null};
 const checkCancelled=()=>{if(signal.aborted)throw signal.reason instanceof WirefitError?signal.reason:new WirefitError('CANCELLED','Experiment cancelled');};
 const track=async(modelId:string):Promise<Model>=>{
  const model=await loadModel(store,modelId);
  if(!record.model_ids.includes(modelId)){record.model_ids.push(modelId);result.identity.model_semantic_hashes.push(semanticHash(model));result.identity.source_envelope_hashes.push(sourceHash(model));result.dependencies.push(await store.putJson(model));if(model.provenance.source_ref!==null)result.fidelity={status:'unvalidated',reason:'Source-bound model has not been validated against an independently bound original target.',artifacts:[],binding_identity_sha256:null};}
  return model;
 };
 const saveCheck=async(check:ExactCheck)=>{
  const artifact=await store.putJson(check);
  result.model_check={status:check.status==='disproved'?'refuted':check.status,reason:check.reason??(check.status==='proved'?'Z3 UNSAT for the declared nonempty domain and selected model outputs.':'Z3 returned a replayed model counterexample.'),artifacts:[artifact],solver_record:artifact};
  for(const query of check.queries)result.model_check.artifacts.push(await store.putArtifact(Buffer.from(query.smtlib,'utf8'),'application/smtlib'));
  result.artifacts.push(artifact);record.comparison_artifact=artifact;
  if(check.counterexample){record.test_inputs_artifact=await store.putJsonl([{sample_id:'counterexample',split:'holdout',inputs:check.counterexample.inputs}]);}
 };
 const setTarget=async(model:Model,dataset:StoredDataset,verified:ReturnType<typeof verifyRows>,mode:'recorded'|'live',policy:ComparisonPolicy,mapping:Mapping)=>{
  const artifact=await store.putJson(verified);if(dataset.manifest.source.kind==='original_target')result.fidelity={status:'unvalidated',reason:'Original-target provenance requires a valid local observation binding.',artifacts:[artifact],binding_identity_sha256:null};
  result.target_validation={status:eligibleTarget(model)?verified.target_status:'unavailable',reason:eligibleTarget(model)?'Only independent observed rows are counted; expected fixtures are excluded.':'REA guard/return binding is unvalidated; observations are not promoted to target fidelity.',artifacts:[artifact],mode,counts:verified.target_counts,source_counts:verified.source_counts.map(entry=>({...entry,mode}))};
  if(dataset.manifest.source.kind==='original_target'&&(dataset.locally_collected||mode==='live')&&eligibleTarget(model)){
   const binding=verificationBinding(model,dataset.manifest.source.source_identity_sha256,dataset.manifest.sampling_plan.inputs_artifact.sha256,policy,sourceHash(model),mapping);
   result.identity.observation_binding_sha256=binding;
   result.fidelity={status:verified.target_status==='matched'?'sampled_match':verified.target_status==='mismatch'?'sampled_mismatch':'unvalidated',reason:'Derived from locally bound original-target observations for this model, source, input plan and policy only.',artifacts:[artifact],binding_identity_sha256:binding};
  }
 };
 try{
  checkCancelled();
  if(request.operation==='compare_models'){
   const left=await track(request.left_model_id as string),right=await track(request.right_model_id as string);
   const mapping=validateMapping(left,right,request.mapping);
   const domain=validateDomain(request.domain,left.inputs);
   record.candidate_model_id=right.model_id;
   if(request.mode==='exact_bv'){
    assert(left.kind==='bv_dag'&&right.kind==='bv_dag','PROFILE_MISMATCH','Exact model comparison requires BV/Bool models');
    await saveCheck(await compareBv(left,right,domain,mapping,request.budget,signal));
   }else{
    assert(left.kind==='numeric_template'&&right.kind==='numeric_template','PROFILE_MISMATCH','Sampled FP32 comparison requires numeric templates');
    checkNumericComparisonDomain(left,right,domain,mapping);
    const policy=request.comparison_policy as ComparisonPolicy;validatePolicy(policy,left);
    result.identity.policy_sha256=hashObject(policy);
    const sample=request.sample_source as {kind:'inputs_artifact';artifact:ArtifactRef}|{kind:'dataset';dataset_id:string};
    let inputs:InputSample[];
    if(sample.kind==='inputs_artifact'){inputs=parseJsonl<InputSample>(await store.readArtifact(sample.artifact));record.test_inputs_artifact=sample.artifact;}
    else{
     const dataset=await store.getObject<StoredDataset>('datasets',sample.dataset_id);record.dataset_id=sample.dataset_id;
     inputs=parseJsonl<InputSample>(await store.readArtifact(dataset.manifest.sampling_plan.inputs_artifact));
     record.test_inputs_artifact=dataset.manifest.sampling_plan.inputs_artifact;
    }
    assert(inputs.length>0,'EMPTY_SAMPLES','Sampled model comparison requires nonempty explicit inputs');
    result.identity.input_plan_sha256=record.test_inputs_artifact.sha256;
    const counts=emptyCounts(inputs.length);const comparisons:unknown[]=[];
    try{
     for(const [index,sample] of inputs.entries()){
      if(index>0&&index%32===0)await yieldEventLoop();
      checkCancelled();counts.attempted++;
      try{
       validateSchema('input-sample',sample);validateInputs(left.inputs,sample.inputs);
       assert(domainContainsPoint(domain,sample.inputs),'OUT_OF_DOMAIN','Comparison input outside requested domain');
       const rInputs=Object.fromEntries(mapping.inputs.map(pair=>[pair.right,sample.inputs[pair.left]!]));
       const l=evaluateModel(left,sample.inputs),r=evaluateModel(right,rInputs);const [a,b]=mappedOutputs(mapping,l,r);
       const matched=compareOutputs(a,b,policy);counts.completed++;counts[matched?'matched':'mismatched']++;
       comparisons.push({sample_id:sample.sample_id,inputs:sample.inputs,left_outputs:l,right_outputs:r,matched});
      }catch(error){counts[error instanceof WirefitError&&error.code==='OUT_OF_DOMAIN'?'out_of_domain':'failed']++;comparisons.push({sample_id:sample.sample_id,error:errorRecord(error,'sample-comparison')});}
     }
    }finally{
     const artifact=await store.putJson(comparisons);record.comparison_artifact=artifact;
     const status=deriveStatus(counts);
     result.sample_comparison={status:status==='unavailable'?'partial':status,reason:'Relationship on these explicit input samples only; all completed comparisons and the planned denominator are retained, including cancellation. No SMT proof or original-target validation.',artifacts:[artifact],counts};
    }
   }
  }else if(request.operation==='simplify'){
   const model=await track(request.reference_model_id as string);assert(model.kind==='bv_dag','PROFILE_MISMATCH','Simplification requires an exact BV model');
   const search=request.search as {grammar:BvOp[];constants:CoreValue[]};
   const simplified=await simplifyBv(model,request.budget,signal,{domain:request.domain as Domain,grammar:search.grammar,constants:search.constants});
   const candidate=structuredClone(simplified.candidate);candidate.model_id=id('model');
   await importModel(store,candidate);await track(candidate.model_id);record.candidate_model_id=candidate.model_id;
   await saveCheck(simplified.check);result.artifacts.push(await store.putJson(simplified.search));
  }else if(request.operation==='fit_numeric'){
   const dataset=await store.getObject<StoredDataset>('datasets',request.dataset_id as string);record.dataset_id=dataset.manifest.dataset_id;rejectNondeterminism(dataset);
   const template=await track(request.template_model_id as string);assert(template.kind==='numeric_template','PROFILE_MISMATCH','Numeric fitting needs a numeric template');
   assert(hashObject({inputs:template.inputs,outputs:template.outputs})===hashObject(dataset.manifest.signature),'SIGNATURE_MISMATCH','Template and dataset signatures must match exactly');
   const holdoutId='holdout_'+hashObject({artifact:dataset.manifest.splits.holdout.artifact.sha256,source:dataset.manifest.source.source_identity_sha256,policy:dataset.manifest.comparison_policy}).slice(0,40);
   try{await store.getObject('reports',holdoutId);throw new WirefitError('HOLDOUT_CONSUMED','Holdout was already consumed; collect a new independent dataset version before another fitting attempt');}
   catch(error){if((error as NodeJS.ErrnoException).code!=='ENOENT')throw error;}
   const train=await readDatasetSplit(store,dataset,'train'),validation=await readDatasetSplit(store,dataset,'validation');
   const options:FitOptions={backend:request.backend as FitOptions['backend'],training:request.training as FitOptions['training'],budget:request.budget,comparison_policy:dataset.manifest.comparison_policy};
   const js=new URL('./workers/numeric.js',import.meta.url),worker=existsSync(js)?js:new URL('./workers/numeric.ts',import.meta.url);
   const args=worker.pathname.endsWith('.ts')?['--import','tsx',fileURLToPath(worker)]:[fileURLToPath(worker)];
   const processResult=await runProcess(process.execPath,args,{input:JSON.stringify({protocol_version:1,job_id:job.job_id,template,train,validation,options})+'\n',timeout_ms:request.budget.wall_time_ms,max_stdout_bytes:32*1024*1024,signal});
   const lines=processResult.stdout.trimEnd().split(/\r?\n/);assert(lines.length===1,'WORKER_PROTOCOL_INVALID','Numeric worker must produce exactly one response');
   const response=JSON.parse(lines[0]!) as {protocol_version:number;job_id:string;status:string;result:ReturnType<typeof fitNumeric>;error?:{code:string;message:string}};
   assert(response.protocol_version===1&&response.job_id===job.job_id,'WORKER_PROTOCOL_INVALID','Numeric worker response identity mismatch');
   assert(response.status==='completed'&&processResult.code===0,response.error?.code??'NUMERIC_WORKER_FAILED',response.error?.message??'Numeric worker failed');
   checkCancelled();
   const fitted=response.result;const candidate=structuredClone(fitted.candidate);
   assert(semanticHash(candidate)===fitted.frozen_sha256,'FROZEN_MODEL_CHANGED','Numeric frozen candidate hash mismatch');
   candidate.model_id=id('model');candidate.provenance={source_kind:'oracle_fit',source_ref:null,source_artifacts:[dataset.manifest.sampling_plan.inputs_artifact],notes:'Fitted from declared train/validation observations; frozen before holdout access.'};
   await importModel(store,candidate);await track(candidate.model_id);record.candidate_model_id=candidate.model_id;
   const freeze=await store.putJson({candidate_model_id:candidate.model_id,model_sha256:semanticHash(candidate),source_sha256:sourceHash(candidate),policy_sha256:hashObject(dataset.manifest.comparison_policy),frozen_at:new Date().toISOString(),holdout_state:'not_read'});
   await store.putObject('reports',holdoutId,{run_id:result.result_id,candidate_model_id:candidate.model_id,freeze,consumed_at:new Date().toISOString()});
   const holdout=await readDatasetSplit(store,dataset,'holdout');
   const mapping=defaultMapping(candidate,dataset.manifest.signature);
   const trainCheck=verifyRows(candidate,train,dataset.manifest.comparison_policy,mapping),validationCheck=verifyRows(candidate,validation,dataset.manifest.comparison_policy,mapping),holdoutCheck=verifyRows(candidate,holdout,dataset.manifest.comparison_policy,mapping);
   const success=[trainCheck,validationCheck,holdoutCheck].every(part=>part.counts.planned>0&&deriveStatus(part.counts)==='matched');
   const fitArtifact=await store.putJson({fitted,freeze,worker:{duration_ms:processResult.duration_ms,pid:processResult.pid,stderr:processResult.stderr},train:trainCheck,validation:validationCheck,holdout:holdoutCheck});
   result.fit={status:success?'fitted':'failed',reason:success?'Frozen candidate satisfies the fixed policy on all nonempty train, validation and independent holdout slots.':'The candidate was frozen and evaluated, but one or more fixed dataset policies did not pass; failures are retained.',artifacts:[fitArtifact,freeze],candidate_model_id:candidate.model_id,backend:options.backend,train_counts:onlyCounts(trainCheck.counts),validation_counts:onlyCounts(validationCheck.counts),holdout_counts:onlyCounts(holdoutCheck.counts)};
   result.identity.oracle_binding_hashes=dataset.manifest.source.oracle_id?[dataset.manifest.source.source_identity_sha256]:[];
   result.identity.input_plan_sha256=dataset.manifest.sampling_plan.inputs_artifact.sha256;result.identity.policy_sha256=hashObject(dataset.manifest.comparison_policy);
   record.observations_artifact=await store.putJsonl([...validation,...holdout]);record.test_inputs_artifact=dataset.manifest.sampling_plan.inputs_artifact;
   record.comparison_artifact=await store.putJson([...trainCheck.details,...validationCheck.details,...holdoutCheck.details]);
   await setTarget(candidate,dataset,verifyRows(candidate,[...validation,...holdout],dataset.manifest.comparison_policy,mapping),'recorded',dataset.manifest.comparison_policy,mapping);
  }else if(request.operation==='verify_candidate'){
   const candidate=await track(request.candidate_model_id as string);record.candidate_model_id=candidate.model_id;
   const dataset=await store.getObject<StoredDataset>('datasets',request.dataset_id as string);record.dataset_id=dataset.manifest.dataset_id;rejectNondeterminism(dataset);
   const mapping=validateMapping(candidate,dataset.manifest.signature,request.mapping),policy=dataset.manifest.comparison_policy;
   let rows:Observation[]=[];for(const split of request.splits as Split[])rows.push(...await readDatasetSplit(store,dataset,split));
   const planned=rows.length;
   assert(planned>0,'EMPTY_SAMPLES','Candidate verification needs nonempty planned observations');
   if(request.source_mode==='live'){
    const binding=await store.getObject<OracleBinding>('oracles',request.oracle_id as string);
    assert(binding.identity_sha256===dataset.manifest.source.source_identity_sha256&&hashObject(binding.manifest.signature)===hashObject(dataset.manifest.signature)&&hashObject(binding.manifest.domain)===hashObject(dataset.manifest.domain),'ORACLE_BINDING_MISMATCH','Live Oracle identity/signature/domain differs from the dataset binding');
    assert(eligibleTarget(candidate),'OBSERVATION_BINDING_UNAVAILABLE','REA local slices lack validated guard and function-return binding');
    result.identity.oracle_binding_hashes.push(binding.identity_sha256);
    const fresh:Observation[]=[];let calls=0;
    for(const row of rows){
     if(signal.aborted||calls>=request.budget.max_oracle_calls)break;
     const called=await callOracle(binding,{sample_id:row.sample_id,split:row.split,inputs:row.inputs},{signal});
     calls+=called.actual_calls;if(called.execution)called.observation.raw_artifacts.push(await store.putJson(called.execution));fresh.push(called.observation);
    }
    rows=fresh;result.artifacts.push(await store.putJson({actual_oracle_calls:calls,planned}));
   }
   const verified=verifyRows(candidate,rows,policy,mapping);
   if(request.source_mode==='live'){verified.counts.planned=planned;verified.target_counts.planned=planned;verified.target_status=deriveStatus(verified.target_counts);}
   result.identity.input_plan_sha256=dataset.manifest.sampling_plan.inputs_artifact.sha256;result.identity.policy_sha256=hashObject(policy);
   record.observations_artifact=await store.putJsonl(rows);record.comparison_artifact=await store.putJson(verified.details);record.test_inputs_artifact=dataset.manifest.sampling_plan.inputs_artifact;
   await setTarget(candidate,dataset,verified,request.source_mode as 'recorded'|'live',policy,mapping);
  }else if(request.operation==='compare_oracles'){
   const left=await store.getObject<OracleBinding>('oracles',request.left_oracle_id as string),right=await store.getObject<OracleBinding>('oracles',request.right_oracle_id as string);
   assert(hashObject(left.manifest.signature)===hashObject(request.signature),'SIGNATURE_MISMATCH','Oracle request signature must explicitly match the left target'); const mapping=validateMapping(left.manifest.signature,right.manifest.signature,request.mapping); const domain=validateDomain(request.domain,left.manifest.signature.inputs); result.artifacts.push(await store.putJson(await checkOracleDomains(left.manifest,right.manifest,domain,mapping,request.budget,signal)));
   const policy=request.comparison_policy as ComparisonPolicy;validatePolicy(policy,left.manifest.signature);
   const ref=request.inputs_artifact as ArtifactRef;const samples=parseJsonl<InputSample>(await store.readArtifact(ref));assert(samples.length>0,'EMPTY_SAMPLES','Oracle comparison requires nonempty explicit inputs');
   record.test_inputs_artifact=ref;result.identity.input_plan_sha256=ref.sha256;result.identity.policy_sha256=hashObject(policy);result.identity.oracle_binding_hashes=[left.identity_sha256,right.identity_sha256];
   const counts=emptyCounts(samples.length);let leftCalls=0,rightCalls=0;const comparisons:unknown[]=[],observations:Observation[]=[];
   const planIds=new Set<string>();
   for(const [index,sample] of samples.entries()){
    if(index>0&&index%256===0)await yieldEventLoop();checkCancelled();
    validateSchema('input-sample',sample);validateInputs(left.manifest.signature.inputs,sample.inputs);
    assert(!planIds.has(sample.sample_id),'INPUT_PLAN_INVALID','Oracle comparison sample IDs must be unique');planIds.add(sample.sample_id);
    assert(domainContainsPoint(domain,sample.inputs),'OUT_OF_DOMAIN','Oracle comparison plan contains an input outside its requested domain');
   }
   for(const sample of samples){
    if(signal.aborted||leftCalls+rightCalls+2>request.budget.max_oracle_calls)break;
    counts.attempted++;
    const l=await callOracle(left,sample,{signal});leftCalls+=l.actual_calls;if(l.execution)l.observation.raw_artifacts.push(await store.putJson(l.execution));
    const rightSample={...sample,inputs:Object.fromEntries(mapping.inputs.map(pair=>[pair.right,sample.inputs[pair.left]!]))}; const r=await callOracle(right,rightSample,{signal});rightCalls+=r.actual_calls;if(r.execution)r.observation.raw_artifacts.push(await store.putJson(r.execution));
    observations.push(l.observation,r.observation);
    if(l.observation.status==='out_of_domain'||r.observation.status==='out_of_domain'){counts.out_of_domain++;comparisons.push({sample_id:sample.sample_id,left:l.observation,right:r.observation,status:'out_of_domain'});continue;}
    if(l.observation.status!=='ok'||r.observation.status!=='ok'){counts.failed++;comparisons.push({sample_id:sample.sample_id,left:l.observation,right:r.observation,status:'failed'});continue;}
    const [leftMapped,rightMapped]=mappedOutputs(mapping,l.observation.outputs,r.observation.outputs);const matched=compareOutputs(leftMapped,rightMapped,policy);counts.completed++;counts[matched?'matched':'mismatched']++;
    comparisons.push({sample_id:sample.sample_id,inputs:sample.inputs,left:l.observation,right:r.observation,matched});
   }
   const artifact=await store.putJson({comparisons,left_calls:leftCalls,right_calls:rightCalls});record.comparison_artifact=artifact;record.observations_artifact=await store.putJsonl(observations);
   result.target_validation={status:deriveStatus(counts),reason:'Paired observed outputs from two explicitly bound fresh-process targets; failures and planned denominator retained.',artifacts:[artifact],mode:'live',counts,source_counts:[{kind:left.manifest.source_kind,mode:'live',count:leftCalls},{kind:right.manifest.source_kind,mode:'live',count:rightCalls}]};
  }else if(request.operation==='suggest_inputs'){
   const models=await Promise.all((request.model_ids as string[]).map(track));const domain=request.domain as Domain;
   const first=models[0]!;for(const model of models)assert(hashObject({inputs:model.inputs,outputs:model.outputs})===hashObject({inputs:first.inputs,outputs:first.outputs}),'SIGNATURE_MISMATCH','Suggestion models require identical signatures');
   if(models.every((model):model is BvModel=>model.kind==='bv_dag')){
    const suggested=await suggestBvInputs(models,domain,request.budget,signal,{strategy:request.strategy as 'disagreement'|'boundaries',max_inputs:request.max_inputs as number});
    record.comparison_artifact=await store.putJson(suggested);record.test_inputs_artifact=await store.putJsonl(suggested.inputs.map((entry,index)=>({sample_id:'suggested_'+index,split:'holdout',inputs:entry.inputs})));
    result.artifacts.push(record.comparison_artifact,record.test_inputs_artifact);
   }else{
    assert(models.every((model):model is NumericModel=>model.kind==='numeric_template'),'PROFILE_MISMATCH','Cannot mix numeric and BV models in suggestions');
    for(const model of models)checkNumericComparisonDomain(first as NumericModel,model,domain,defaultMapping(first,model));
    const numbers=new Set<number>([-1,0,1]);
    for(const model of models){for(const c of [...domain.constraints,...model.domain.constraints])if(c.value.kind==='fp32')numbers.add(fp32Number(c.value));for(const knot of model.definition.fixed.knots??[])numbers.add(fp32Number(knot));}
    const suggestions:unknown[]=[];
    for(const value of numbers){
     const input={[first.inputs[0]!.id]:fp32Bits(value)};if(!domainContainsPoint(domain,input)||models.some(model=>!domainContainsPoint(model.domain,input)))continue;
     const outputs=models.map(model=>evaluateModel(model,input));const disagreement=outputs.some(output=>hashObject(output)!==hashObject(outputs[0]));
     if(request.strategy==='boundaries'||disagreement)suggestions.push({inputs:input,reason:disagreement?'disagreement':'boundary'});
     if(suggestions.length>=(request.max_inputs as number))break;
    }
    record.comparison_artifact=await store.putJson({status:'partial',reason:'Finite boundary suggestions, not exhaustive FP32 search',inputs:suggestions});result.artifacts.push(record.comparison_artifact);
   }
  }
  checkCancelled();
 }catch(error){
  const actual=signal.aborted&&signal.reason instanceof WirefitError?signal.reason:error;
  result.job_status=signal.aborted&&(!(actual instanceof WirefitError)||actual.code!=='TIMEOUT')?'cancelled':'failed';
  result.error=errorRecord(actual,'experiment');
  if(result.model_check.status==='not_run'&&(request.operation==='simplify'||request.operation==='compare_models'&&request.mode==='exact_bv'))result.model_check={status:'inconclusive',reason:result.error.code+': '+result.error.message,artifacts:[],solver_record:null};
  if(actual instanceof WirefitError&&actual.details!==undefined)result.artifacts.push(await store.putJson(actual.details));
 }
 validateSchema('experiment-result',result);
 await store.putObject('runs',result.result_id,record);
 return {result_id:result.result_id,status:result.job_status==='cancelled'?'cancelled':result.job_status==='failed'?'failed':'completed',...(result.error?{error:result.error}:{})};
}

import {readFileSync,writeFileSync,mkdirSync} from 'node:fs';
import {spawnSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import path from 'node:path';
import os from 'node:os';
import {fitNumeric,evaluateNumeric,compareNumericOutputs,type FitOptions} from './numeric.js';
import {fp32Bits,fp32Number} from './values.js';
import {rootDir,hashObject,semanticHash,errorRecord,sha256} from './shared.js';
import type {NumericModel,Observation,ComparisonPolicy,FP32Value} from './types.js';

type TemplateName=NumericModel['definition']['template'];
const templates:TemplateName[]=['affine','affine_clamp','piecewise_affine'];
const backends:FitOptions['backend'][]=['analytic_baseline','reference','handwired'];
const policy:ComparisonPolicy={kind:'tolerance-fp32',atol:'0.00002',rtol:'0.00002',nonfinite:'reject'};
function targetParameters(template:TemplateName,seed:number):Record<string,number> {
  if(template==='piecewise_affine')return [{a0:0.75,b0:-0.25,a1:1.5,b1:0.5},{a0:-1.25,b0:0.5,a1:0.5,b1:-0.75},{a0:1.5,b0:0.75,a1:-0.75,b1:0.25}][seed]!;
  return template==='affine'?[{a:1.5,b:-0.5},{a:-0.75,b:0.25},{a:2.25,b:0.75}][seed]!:[{a:1.25,b:-0.5},{a:-0.75,b:0.25},{a:1.75,b:0.75}][seed]!;
}
function expected(template:TemplateName,p:Record<string,number>,x:number):number {
  const suffix=template==='piecewise_affine'?(x<0?'0':'1'):'';
  const product=Math.fround(p[`a${suffix}`]!*x),value=Math.fround(product+p[`b${suffix}`]!);
  return template==='affine_clamp'?(value< -2?-2:value>2?2:value):value;
}
function observations(template:TemplateName,p:Record<string,number>,split:Observation['split'],xs:number[]):Observation[] {
  const identity=hashObject({source:'independent_source_owned_fixture',template,parameters:Object.fromEntries(Object.entries(p).map(([k,v])=>[k,fp32Bits(v)]))});
  return xs.map((x,i)=>({schema_version:1,observation_id:`bench_${split}_${i}`,sample_id:`bench_${split}_${i}`,request_id:`request_${split}_${i}`,record_kind:'expected_fixture',source_kind:'reference_fixture',source_id:'benchmark_source_fixture',source_identity_sha256:identity,split,inputs:{x:fp32Bits(x)},outputs:{result:fp32Bits(expected(template,p,x))},status:'ok',error:null,observed_at:null,duration_ms:null,raw_artifacts:[]}));
}
function childTrials(template:TemplateName,parameterSeed:number,backend:FitOptions['backend']) {
  const childStart=performance.now(),filename=template==='affine'?'model.affine-initial.json':template==='affine_clamp'?'model.affine-clamp-initial.json':'model.piecewise-initial.json';
  const model=JSON.parse(readFileSync(path.join(rootDir,'examples',filename),'utf8')) as NumericModel,p=targetParameters(template,parameterSeed);
  const train=observations(template,p,'train',Array.from({length:33},(_,i)=>(i-16)/4));
  const validation=observations(template,p,'validation',Array.from({length:16},(_,i)=>-3.875+i*0.5));
  const options:FitOptions={backend,training:{optimizer:backend==='analytic_baseline'?'closed_form':'adam',learning_rate:'0.03',loss:'mse',batch_size:32,restarts:2,validation_interval:20},budget:{wall_time_ms:15000,solver_soft_time_ms:1000,solver_hard_time_ms:2000,max_candidates:500,max_ast_nodes:9,max_oracle_calls:0,max_iterations:2400,seed:1000+parameterSeed},comparison_policy:policy};
  const common={template_semantic_sha256:semanticHash(model),benchmark_source_sha256:sha256(readFileSync(fileURLToPath(import.meta.url))),train_observations:train,validation_observations:validation,template,parameter_seed:parameterSeed,backend,options,source_kind:'reference_fixture',target_parameters:Object.fromEntries(Object.entries(p).map(([k,v])=>[k,fp32Bits(v)])),training_hash:hashObject(train.map(r=>({inputs:r.inputs,outputs:r.outputs}))),validation_hash:hashObject(validation.map(r=>({inputs:r.inputs,outputs:r.outputs})))};
  if(backend==='analytic_baseline'&&template!=='affine')return {...common,status:'UNSUPPORTED',reason:'Official analytic_baseline supports affine/closed_form only; structure-aware LS is not silently substituted',trials:[]};
  const trials=[];
  for(const mode of ['cold','warm'] as const) {
    try {
      const rssBefore=process.memoryUsage().rss,trialStart=performance.now();
      const fit=fitNumeric(model,train,validation,options),frozenHash=fit.frozen_sha256;
      const holdoutStart=performance.now();
      // Holdout observations are only materialized after the learner returned a frozen candidate.
      const holdoutRows=observations(template,p,'holdout',[-4,-3.0625,-1.0625,-(2**-20),-0,0,2**-20,0.9375,2.9375,4]);
      let matched=0,max_absolute_error=0,max_relative_error=0,mse=0;
      for(const row of holdoutRows){const actual=evaluateNumeric(fit.candidate,row.inputs),comparison=compareNumericOutputs(actual,row.outputs,policy);matched+=Number(comparison.matched);max_absolute_error=Math.max(max_absolute_error,comparison.max_absolute_error);max_relative_error=Math.max(max_relative_error,comparison.max_relative_error);mse+=(fp32Number(actual.result as FP32Value)-fp32Number(row.outputs.result as FP32Value))**2;}
      const holdout={planned:holdoutRows.length,attempted:holdoutRows.length,completed:holdoutRows.length,matched,mismatched:holdoutRows.length-matched,failed:0,out_of_domain:0,mse:mse/holdoutRows.length,max_absolute_error,max_relative_error};
      const status=holdout.mismatched===0&&fit.validation_metrics.mismatched===0?'PASS':'FAIL';
      trials.push({mode,status,backend_identity:fit.backend_identity,backend_semantics:fit.backend_semantics,iterations:fit.iterations,candidates:fit.candidates,gradient_calls:fit.gradient_calls,termination:fit.termination,candidate_parameters:fit.candidate.definition.parameters,frozen_sha256:frozenHash,unchanged_after_holdout:semanticHash(fit.candidate)===frozenHash,holdout_read_after_freeze:true,holdout_observations:holdoutRows,train:fit.train_metrics,validation:fit.validation_metrics,holdout,original_target_calls:0,distinct_inputs:new Set([...train,...validation,...holdoutRows].map(r=>(r.inputs.x as FP32Value).bits)).size,timing:{...fit.timing,holdout_ms:performance.now()-holdoutStart,trial_ms:performance.now()-trialStart},memory:{rss_before_bytes:rssBefore,rss_after_bytes:process.memoryUsage().rss,process_lifetime_max_rss_kib:process.resourceUsage().maxRSS,method:'RSS checkpoints plus OS process-lifetime maxRSS; warm maxRSS includes prior cold trial, not isolated per-fit peak'},logs:fit.logs});
    } catch(error) {trials.push({mode,status:'FAIL',error:errorRecord(error,'numeric-benchmark')});}
  }
  return {...common,status:trials.every(t=>t.status==='PASS')?'PASS':'FAIL',child_total_ms:performance.now()-childStart,trials};
}

const args=process.argv.slice(2);
if(args[0]==='--child') {
  const request=JSON.parse(readFileSync(0,'utf8')) as {template:TemplateName;parameterSeed:number;backend:FitOptions['backend']};
  process.stdout.write(JSON.stringify(childTrials(request.template,request.parameterSeed,request.backend))+'\n');
} else {
  const smoke=args.includes('--smoke'),outputIndex=args.indexOf('--output'),output=outputIndex>=0?path.resolve(args[outputIndex+1]!):path.join(rootDir,'artifacts','acceptance','handwired-benchmark.json');
  const runner=fileURLToPath(import.meta.url),entries:Record<string,unknown>[]=[],runStart=performance.now();
  for(const template of smoke?['affine'] as const:templates)for(const parameterSeed of smoke?[0]:[0,1,2])for(const backend of backends) {
    const start=performance.now(),argv=runner.endsWith('.ts')?['--import','tsx',runner,'--child']:[runner,'--child'];
    const child=spawnSync(process.execPath,argv,{input:JSON.stringify({template,parameterSeed,backend}),encoding:'utf8',timeout:40000,maxBuffer:8*1024*1024,cwd:rootDir});
    const process_wall_ms=performance.now()-start;
    let entry:Record<string,unknown>;
    try {if(child.error||child.status!==0)throw child.error??new Error(child.stderr||`Child exited ${child.status}`);entry=JSON.parse(child.stdout) as Record<string,unknown>;}
    catch(error){entry={template,parameter_seed:parameterSeed,backend,status:'FAIL',error:errorRecord(error,'numeric-benchmark-process'),raw_stdout:child.stdout,raw_stderr:child.stderr};}
    entries.push({...entry,process_wall_ms,raw_stderr:child.stderr});
  }
  const counts=Object.fromEntries(backends.map(backend=>{const records=entries.filter(e=>e.backend===backend);return[backend,{planned:records.length,completed:records.filter(e=>e.status==='PASS'||e.status==='FAIL').length,passed:records.filter(e=>e.status==='PASS').length,failed:records.filter(e=>e.status==='FAIL').length,unsupported:records.filter(e=>e.status==='UNSUPPORTED').length}];}));
  const result={schema_version:1,generated_at:new Date().toISOString(),scope:'synthetic source-owned numerical fixtures; no original-binary fidelity claim',runtime:{node:process.versions.node,platform:process.platform,arch:process.arch,cpu:os.cpus()[0]?.model,cpu_count:os.cpus().length},policy,plan:{template_classes:smoke?1:3,parameter_seeds_per_class:smoke?1:3,backends:3,trials_per_supported_configuration:2,process_isolation:'Fresh child for each configuration; cold first fit, warm second fit in same process',oracle_call_budget:0,original_target_calls:0,holdout:'Generated only after each returned candidate was frozen',memory:'RSS checkpoints and per-child OS lifetime maxRSS; no GPU or per-fit sampled peak claim'},counts,entries,total_ms:performance.now()-runStart,conclusion:'Measured fixture outcomes only. No Handwired speed or recovery advantage is presumed; affine closed-form baseline remains fully enabled.'};
  mkdirSync(path.dirname(output),{recursive:true});writeFileSync(output,JSON.stringify(result,null,2)+'\n','utf8');
  process.stdout.write(JSON.stringify({artifact:output,counts,total_ms:result.total_ms})+'\n');
  if(entries.some(e=>e.status==='FAIL'))process.exitCode=1;
}



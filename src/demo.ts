import {mkdir,readFile,writeFile,readdir} from 'node:fs/promises';
import {existsSync} from 'node:fs';
import path from 'node:path';
import {homedir} from 'node:os';
import {fileURLToPath,pathToFileURL} from 'node:url';
import {WirefitService} from './service.js';
import {rootDir,id,readJson,readJsonl,defaultBudget,sha256,assert,errorRecord} from './shared.js';
import {defaultMapping} from './model.js';
import {loadModel} from './repository.js';
import {runProcess} from './process.js';
import type {InputSample,OracleManifest} from './oracle.js';
import type {StoredDataset} from './dataset.js';
import type {StoredRun,ExperimentResult} from './run-types.js';

interface DemoReceipt {id:string;status:'PASS'|'FAIL'|'BLOCKED';scope:string;started_at:string;finished_at:string;artifacts:unknown[];details:unknown;reason?:string}
async function save(file:string,value:unknown){await mkdir(path.dirname(file),{recursive:true});await writeFile(file,JSON.stringify(value,null,2)+'\n','utf8');}
async function waitExperiment(service:WirefitService,request:unknown){
 const job=await service.submitExperiment(request);const final=await service.jobs.wait(job.job_id);
 assert(final.result_id,'DEMO_JOB_FAILED','Demo job ended without persisted result: '+JSON.stringify(final));
 const run=await service.store.getObject<StoredRun>('runs',final.result_id);
 assert(final.status==='completed','DEMO_JOB_FAILED','Demo job failed: '+JSON.stringify(run.result.error));
 return run;
}
async function pythonRuntime():Promise<string>{
 const candidates:string[]=[];
 if(process.env.WIREFIT_PYTHON)candidates.push(process.env.WIREFIT_PYTHON);
 if(process.platform==='win32'){
  const base=path.join(homedir(),'AppData/Local/Python');
  if(existsSync(base))for(const name of await readdir(base))if(/^pythoncore-/.test(name))candidates.push(path.join(base,name,'python.exe'));
 }
 candidates.push(process.platform==='win32'?'python.exe':'python3');
 for(const command of candidates){
  try{const result=await runProcess(command,['--version'],{timeout_ms:5000});if(result.code===0&&/^Python 3\./.test(result.stdout+result.stderr))return command;}catch{}
 }
 throw new Error('Independent Python3 fixture runtime is unavailable; set WIREFIT_PYTHON to its executable');
}
export async function runDemos():Promise<{run_directory:string;demos:DemoReceipt[]}>{
 const runDirectory=path.join(rootDir,'artifacts/demo',id('demo'));
 await mkdir(runDirectory,{recursive:true});const receipts:DemoReceipt[]=[];
 const record=async(receipt:DemoReceipt)=>{receipts.push(receipt);await save(path.join(runDirectory,'demo-'+receipt.id.toLowerCase()+'.json'),receipt);await save(path.join(rootDir,'artifacts/demo','demo-'+receipt.id.toLowerCase()+'.json'),receipt);};
 let started=new Date().toISOString();
 let service:WirefitService|null=null;
 try{
  service=await WirefitService.create(path.join(runDirectory,'case-a'));
  await service.importModel(path.join(rootDir,'examples/model.mba-u8.json'));
  const simplify=await readJson<Record<string,unknown>>(path.join(rootDir,'examples/request.simplify-mba.json'));
  const run=await waitExperiment(service,simplify);
  assert(run.result.model_check.status==='proved'&&run.candidate_model_id,'DEMO_A_FAILED','Simplification did not produce an exact checked candidate');
  await service.importModel(path.join(rootDir,'examples/model.add-u8-wrong.json'));
  const left=await loadModel(service.store,run.candidate_model_id),right=await loadModel(service.store,'add_u8_wrong');
  const different=await waitExperiment(service,{schema_version:1,experiment_id:'demo_a_counterexample',operation:'compare_models',mode:'exact_bv',budget:defaultBudget,left_model_id:left.model_id,right_model_id:right.model_id,domain:left.domain,mapping:defaultMapping(left,right)});
  assert(different.result.model_check.status==='refuted','DEMO_A_FAILED','Changed expression did not produce a model counterexample');
  const exported=await service.exportReport(run.result.result_id,path.join(runDirectory,'export-a'));
  assert(exported.candidate_module,'DEMO_A_FAILED','Export has no candidate module');
  const program="import {evaluate} from "+JSON.stringify('./export-a/'+exported.candidate_module)+";let count=0;const v=n=>({kind:'bv',width:8,bits:'0x'+n.toString(16).padStart(2,'0')});for(let a=0;a<256;a++)for(let b=0;b<256;b++){const out=evaluate({a:v(a),b:v(b)}).result;if(out.bits!==v((a+b)%256).bits)throw Error('export mismatch');count++;}console.log(JSON.stringify({pairs:count,matched:count,reference:'independent modular addition, not an original binary'}));\n";
  const checker=path.join(runDirectory,'exhaustive-a.mjs');await writeFile(checker,program,'utf8');
  const fresh=await runProcess(process.execPath,[checker],{timeout_ms:30000});
  assert(fresh.code===0,'DEMO_A_FAILED','Fresh exhaustive export validation failed');
  const exhaustive=JSON.parse(fresh.stdout.trim());assert(exhaustive.pairs===65536,'DEMO_A_FAILED','BV8 exhaustive denominator mismatch');
  await record({id:'A',status:'PASS',scope:'Offline model simplification, model-only proof/counterexample, independently executed export.',started_at:started,finished_at:new Date().toISOString(),artifacts:[{case_directory:service.store.root,run_id:run.result.result_id,counterexample_run_id:different.result.result_id},exported,{exhaustive_checker:checker,checker_sha256:sha256(Buffer.from(program,'utf8')),execution:fresh}],details:{model_check:run.result.model_check.status,counterexample_check:different.result.model_check.status,exhaustive}});
 }catch(error){await record({id:'A',status:'FAIL',scope:'Offline model simplification',started_at:started,finished_at:new Date().toISOString(),artifacts:[],details:errorRecord(error,'demo-a'),reason:error instanceof Error?error.message:String(error)});}
 finally{if(service)await service.close();service=null;}
 started=new Date().toISOString();
 try{
  const python=await pythonRuntime();
  const pythonVersion=await runProcess(python,['--version'],{timeout_ms:5000});
  const fixture=path.join(rootDir,'fixtures/oracle_fp32.py');
  service=await WirefitService.create(path.join(runDirectory,'case-b'));
  const original=await readJson<OracleManifest>(path.join(rootDir,'examples/oracle.reference-fp32.json'));
  const manifest:OracleManifest={...original,oracle_id:'demo_fp32_target',argv:[python,fixture],cwd:rootDir,target_files:[{path:fixture,sha256:sha256(await readFile(fixture)),role:'target'}],allowed_env_keys:process.platform==='win32'?['PATH','SYSTEMROOT','WINDIR']:['PATH','LANG'],notes:'Explicit independent source-owned rational FP32 target. The learner receives only train/validation rows.'};
  const manifestFile=path.join(runDirectory,'oracle-b.json');await save(manifestFile,manifest);
  await service.registerOracle(manifestFile);
  const plan=await readJsonl<InputSample>(path.join(rootDir,'examples/numeric-inputs.jsonl'));
  plan.push({...structuredClone(plan[0]!),sample_id:'repeat_train_first'});
  // This policy and budget are fixed before any observations or fitting outcomes.
  const policy={kind:'tolerance-fp32' as const,atol:'0.00002',rtol:'0.00002',nonfinite:'reject' as const};
  const collection=await service.jobs.wait((await service.collectDataset(manifest.oracle_id,plan,policy,512)).job_id);
  assert(collection.status==='completed'&&collection.result_id,'DEMO_B_FAILED','Independent target collection failed');
  const collected=await service.getResult(collection.result_id) as {dataset_id:string};
  const dataset=await service.store.getObject<StoredDataset>('datasets',collected.dataset_id);
  assert(dataset.complete&&dataset.actual_oracle_calls===33&&dataset.determinism.status==='consistent_on_repeats','DEMO_B_FAILED','Collection/repeat verification was incomplete');
  const template=await service.importModel(path.join(rootDir,'examples/model.affine-clamp-initial.json'));
  const request=await readJson<Record<string,unknown>>(path.join(rootDir,'examples/request.fit-handwired.json'));
  request.dataset_id=dataset.manifest.dataset_id;request.template_model_id=template.model_id;request.budget={...defaultBudget,max_iterations:6000};
  const fit=await waitExperiment(service,request);
  assert(fit.candidate_model_id,'DEMO_B_FAILED','No frozen candidate was produced');
  const candidate=await loadModel(service.store,fit.candidate_model_id);
  const fresh=await waitExperiment(service,{schema_version:1,experiment_id:'demo_b_fresh_holdout',operation:'verify_candidate',candidate_model_id:candidate.model_id,dataset_id:dataset.manifest.dataset_id,mapping:defaultMapping(candidate,dataset.manifest.signature),splits:['holdout'],source_mode:'live',oracle_id:manifest.oracle_id,budget:defaultBudget});
  const exported=await service.exportReport(fit.result.result_id,path.join(runDirectory,'export-b'));
  const passed=fit.result.fit.status==='fitted'&&fresh.result.target_validation.status==='matched';
  await record({id:'B',status:passed?'PASS':'FAIL',scope:'Independent source-owned FP32 Oracle -> actual Handwired training -> frozen holdout -> fresh target replay -> standalone export.',started_at:started,finished_at:new Date().toISOString(),artifacts:[{case_directory:service.store.root,dataset_id:dataset.manifest.dataset_id,fit_run_id:fit.result.result_id,fresh_holdout_run_id:fresh.result.result_id},exported],details:{python_version:pythonVersion.stdout.trim()||pythonVersion.stderr.trim(),source_kind:'reference_fixture',collection:{planned:33,actual_calls:dataset.actual_oracle_calls,determinism:dataset.determinism},fit:fit.result.fit,target:fit.result.target_validation,fresh_target_replay:fresh.result.target_validation,model_check:fit.result.model_check,comparison_policy:policy,notes:'Original-source fixture is independent of learner and is not represented as a recovered third-party binary.'},...(passed?{}:{reason:'Candidate failed the fixed fitting policy or fresh target replay; holdout is consumed and was not used for retuning.'})});
 }catch(error){await record({id:'B',status:error instanceof Error&&error.message.includes('Python3')?'BLOCKED':'FAIL',scope:'Independent numerical target recovery',started_at:started,finished_at:new Date().toISOString(),artifacts:[],details:errorRecord(error,'demo-b'),reason:error instanceof Error?error.message:String(error)});}
 finally{if(service)await service.close();service=null;}
 started=new Date().toISOString();
 const rea=await readJson<unknown>(path.join(rootDir,'artifacts/rea/live-discovery.json'));
 await record({id:'C',status:'BLOCKED',scope:'Native source fixture -> binary -> real REA/Ghidra -> lift -> original target replay -> export.',started_at:started,finished_at:new Date().toISOString(),artifacts:[{real_rea_discovery:'artifacts/rea/live-discovery.json',real_rea_lock:'artifacts/rea/rea-lock.json',real_portable_js_bundle:'artifacts/rea/real-js-bundle.json'}],details:{reason:'Actual REA provider probe returned not_configured: Ghidra/JDK unavailable. Actual JS portable evidence was collected, but does not substitute for a native binary gate.',native_binary_chain:'NOT_RUN',real_discovery_present:rea!==null},reason:'The configured Windows host has no verified Ghidra/JDK native analysis chain.'});
 const summary={run_directory:runDirectory,demos:receipts};
 await save(path.join(runDirectory,'summary.json'),summary);await save(path.join(rootDir,'artifacts/demo/summary.json'),summary);
 return summary;
}
if(process.argv[1]&&pathToFileURL(path.resolve(process.argv[1])).href===import.meta.url){
 runDemos().then(result=>{const summary={run_directory:result.run_directory,demos:result.demos.map(({id,status,scope,reason})=>({id,status,scope,...(reason?{reason}:{})})),receipts:'artifacts/demo/summary.json'};process.stdout.write(JSON.stringify(summary,null,2)+'\n');process.exitCode=result.demos.some(demo=>demo.status==='FAIL')?1:0;}).catch(error=>{process.stderr.write(JSON.stringify(errorRecord(error,'demo'))+'\n');process.exitCode=1;});
}

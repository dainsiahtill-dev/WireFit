import {describe,it,expect,vi} from 'vitest';
import {mkdtemp,rm,writeFile,readFile} from 'node:fs/promises';
import path from 'node:path';
import {tmpdir} from 'node:os';
import {WirefitService} from '../src/service.js';
import {readJson,rootDir,defaultBudget,sha256} from '../src/shared.js';
import type {InputSample} from '../src/oracle.js';
import * as verification from '../src/verification.js';

async function counterOracleFixture(){
 const root=await mkdtemp(path.join(tmpdir(),'wirefit-oracle-plan-'));const service=await WirefitService.create(path.join(root,'case'));
 const log=path.join(root,'calls.txt');
 for(const name of ['left','right']){
  const file=path.join(root,name+'.cjs');const inputName=name==='right'?'other':'x';
  const source=`require('node:fs').appendFileSync(${JSON.stringify(log)},'called\\n','utf8');let text='';process.stdin.setEncoding('utf8');process.stdin.on('data',chunk=>text+=chunk);process.stdin.on('end',()=>{const q=JSON.parse(text);console.log(JSON.stringify({protocol_version:1,request_id:q.request_id,status:'ok',outputs:{result:q.inputs.${inputName}}}));});`;
  await writeFile(file,source,'utf8');
  const manifest={schema_version:1,oracle_id:name,kind:'process_jsonl',source_kind:'reference_fixture',argv:[process.execPath,file],cwd:'.',signature:{inputs:[{id:inputName,type:{kind:'bv',width:8}}],outputs:[{id:'result',type:{kind:'bv',width:8}}]},domain:{constraints:[]},target_files:[{path:name+'.cjs',sha256:sha256(await readFile(file)),role:'target'}],protocol_version:1,reset_strategy:'fresh_process',request_timeout_ms:2000,batch_timeout_ms:10000,max_stdout_line_bytes:1048576,max_stderr_bytes:1048576,allowed_env_keys:[],notes:'Actual child-process fixture with a call log for full-plan admission tests.'};
  const manifestFile=path.join(root,name+'.json');await writeFile(manifestFile,JSON.stringify(manifest),'utf8');await service.registerOracle(manifestFile);
 }
 return {root,service,log};
}
function pairedRequest(artifact:unknown){return {schema_version:1,experiment_id:'plan_validation',operation:'compare_oracles',budget:defaultBudget,left_oracle_id:'left',right_oracle_id:'right',signature:{inputs:[{id:'x',type:{kind:'bv',width:8}}],outputs:[{id:'result',type:{kind:'bv',width:8}}]},domain:{constraints:[{input:'x',op:'ule',value:{kind:'bv',width:8,bits:'0x7f'}}]},mapping:{inputs:[{left:'x',right:'other'}],outputs:[{left:'result',right:'result'}]},inputs_artifact:artifact,comparison_policy:{kind:'exact-bv'}};}

async function collectedOriginalFixture(){
 const root=await mkdtemp(path.join(tmpdir(),'wirefit-original-binding-'));const service=await WirefitService.create(path.join(root,'case'));const log=path.join(root,'calls.txt');
 const target=path.join(root,'original.cjs');
 const source=`require('node:fs').appendFileSync(${JSON.stringify(log)},'called\\n','utf8');let text='';process.stdin.setEncoding('utf8');process.stdin.on('data',chunk=>text+=chunk);process.stdin.on('end',()=>{const q=JSON.parse(text);const n=(BigInt(q.inputs.a.bits)+BigInt(q.inputs.b.bits))&255n;console.log(JSON.stringify({protocol_version:1,request_id:q.request_id,status:'ok',outputs:{result:{kind:'bv',width:8,bits:'0x'+n.toString(16).padStart(2,'0')}}}));});`;
 await writeFile(target,source,'utf8');
 const manifest={schema_version:1,oracle_id:'original',kind:'process_jsonl',source_kind:'original_target',argv:[process.execPath,target],cwd:'.',signature:{inputs:[{id:'a',type:{kind:'bv',width:8}},{id:'b',type:{kind:'bv',width:8}}],outputs:[{id:'result',type:{kind:'bv',width:8}}]},domain:{constraints:[]},target_files:[{path:'original.cjs',sha256:sha256(await readFile(target)),role:'target'}],protocol_version:1,reset_strategy:'fresh_process',request_timeout_ms:2000,batch_timeout_ms:10000,max_stdout_line_bytes:1048576,max_stderr_bytes:1048576,allowed_env_keys:[],notes:'Source-owned original process target for observation-binding integration tests.'};
 const file=path.join(root,'oracle.json');await writeFile(file,JSON.stringify(manifest),'utf8');await service.registerOracle(file);
 const plan:InputSample[]=(['train','validation','holdout'] as const).map((split,i)=>({sample_id:'point_'+i,split,inputs:{a:{kind:'bv',width:8,bits:'0x0'+(i+1)},b:{kind:'bv',width:8,bits:'0x02'}}}));
 const state=await service.jobs.wait((await service.collectDataset('original',plan,{kind:'exact-bv'})).job_id);expect(state.status).toBe('completed');
 const collected=await service.getResult(state.result_id!) as any;return {root,service,log,datasetId:collected.dataset_id};
}
function recordedRequest(candidateId:string,datasetId:string){return {schema_version:1,experiment_id:'observation_binding',operation:'verify_candidate',budget:defaultBudget,candidate_model_id:candidateId,dataset_id:datasetId,mapping:{inputs:[{left:'a',right:'a'},{left:'b',right:'b'}],outputs:[{left:'result',right:'result'}]},splits:['holdout'],source_mode:'recorded'};}

describe('independent experiment dimensions',()=>{
 it('freezes numeric candidate before holdout and blocks reuse without upgrading fixtures to targets',async()=>{
  const dir=await mkdtemp(path.join(tmpdir(),'wirefit-fit-service-'));const service=await WirefitService.create(dir);
  try{
   await service.importModel(path.join(rootDir,'examples/model.affine-clamp-initial.json'));
   await service.importDataset(path.join(rootDir,'examples/dataset.numeric-expected.json'),rootDir);
   const request=await readJson<any>(path.join(rootDir,'examples/request.fit-handwired.json'));
   request.budget={...defaultBudget,max_iterations:500};
   const state=await service.jobs.wait((await service.submitExperiment(request)).job_id);
   expect(state.status).toBe('completed');
   const result=await service.getResult(state.result_id) as any;
   expect(result.model_check.status).toBe('not_run');
   expect(result.fit.backend).toBe('handwired');
   expect(result.fit.holdout_counts.planned).toBe(8);
   expect(result.fit.holdout_counts.attempted).toBe(8);
   expect(result.target_validation.status).toBe('unavailable');
   expect(result.target_validation.counts.planned).toBe(0);
   const stored=await service.store.getObject<any>('runs',state.result_id!);
   const observed=(await service.store.readArtifact(stored.observations_artifact)).toString('utf8').trim().split('\n').map(line=>JSON.parse(line));
   expect(observed.length).toBeGreaterThan(0);expect(observed.every(row=>row.split!=='train')).toBe(true);
   const dataset=await service.store.getObject<any>('datasets',stored.dataset_id);
   expect((await service.store.readArtifact(dataset.manifest.splits.train.artifact)).length).toBeGreaterThan(0);
   const repeated=await service.jobs.wait((await service.submitExperiment(request)).job_id);
   expect(repeated.status).toBe('failed');
   expect((await service.getResult(repeated.result_id) as any).error.code).toBe('HOLDOUT_CONSUMED');
  }finally{await service.close();await rm(dir,{recursive:true,force:true});}
 },60000);
 it('compares numeric models only on explicit samples and leaves model proof untouched',async()=>{
  const dir=await mkdtemp(path.join(tmpdir(),'wirefit-fp32-compare-'));const service=await WirefitService.create(dir);
  try{
   const left=await readJson<any>(path.join(rootDir,'examples/model.affine-initial.json'));
   const right=structuredClone(left);right.model_id='affine_changed';right.definition.parameters.b={kind:'fp32',bits:'0x3f800000'};
   await service.importModel(left);await service.importModel(right);
   const artifact=await service.store.putJsonl([{sample_id:'zero',split:'holdout',inputs:{x:{kind:'fp32',bits:'0x00000000'}}}]);
   const request={schema_version:1,experiment_id:'sampled',operation:'compare_models',budget:defaultBudget,mode:'sampled_fp32',left_model_id:left.model_id,right_model_id:right.model_id,domain:left.domain,mapping:{inputs:[{left:'x',right:'x'}],outputs:[{left:'result',right:'result'}]},sample_source:{kind:'inputs_artifact',artifact},comparison_policy:{kind:'bitwise-fp32',nonfinite:'reject'}};
   const state=await service.jobs.wait((await service.submitExperiment(request)).job_id);
   expect(state.status).toBe('completed');const result=await service.getResult(state.result_id) as any;
   expect(result.sample_comparison.status).toBe('mismatch');expect(result.model_check.status).toBe('not_run');expect(result.target_validation.status).toBe('not_run');
  }finally{await service.close();await rm(dir,{recursive:true,force:true});}
 });
 it('finds boundary100 using two real fresh-process fixture targets and keeps paired-call counts',async()=>{
  const dir=await mkdtemp(path.join(tmpdir(),'wirefit-oracle-diff-'));const service=await WirefitService.create(path.join(dir,'case'));
  try{
   for(const [name,operator] of [['left','<='],['right','<']] as const){
    const target=path.join(dir,name+'.cjs');
    const code='let s="";process.stdin.setEncoding("utf8");process.stdin.on("data",d=>s+=d);process.stdin.on("end",()=>{const q=JSON.parse(s);const value=BigInt(q.inputs.'+(name==='right'?'other':'x')+'.bits)'+operator+'100n?1:0;console.log(JSON.stringify({protocol_version:1,request_id:q.request_id,status:"ok",outputs:{result:{kind:"bv",width:8,bits:"0x"+value.toString(16).padStart(2,"0")}}}));});';
    await writeFile(target,code,'utf8');
    const manifest={schema_version:1,oracle_id:name,kind:'process_jsonl',source_kind:'reference_fixture',argv:[process.execPath,target],cwd:'.',signature:{inputs:[{id:name==='right'?'other':'x',type:{kind:'bv',width:8}}],outputs:[{id:'result',type:{kind:'bv',width:8}}]},domain:{constraints:[]},target_files:[{path:name+'.cjs',sha256:sha256(await readFile(target)),role:'target'}],protocol_version:1,reset_strategy:'fresh_process',request_timeout_ms:2000,batch_timeout_ms:10000,max_stdout_line_bytes:1048576,max_stderr_bytes:1048576,allowed_env_keys:[],notes:'Independent source-owned versioned boundary fixture'};
    const file=path.join(dir,name+'.json');await writeFile(file,JSON.stringify(manifest),'utf8');await service.registerOracle(file);
   }
   const samples:InputSample[]=[99,100,101].map(x=>({sample_id:'n'+x,split:'holdout',inputs:{x:{kind:'bv',width:8,bits:'0x'+x.toString(16).padStart(2,'0')}}}));
   const artifact=await service.store.putJsonl(samples);
   const request={schema_version:1,experiment_id:'versions',operation:'compare_oracles',budget:defaultBudget,left_oracle_id:'left',right_oracle_id:'right',signature:{inputs:[{id:'x',type:{kind:'bv',width:8}}],outputs:[{id:'result',type:{kind:'bv',width:8}}]},domain:{constraints:[]},mapping:{inputs:[{left:'x',right:'other'}],outputs:[{left:'result',right:'result'}]},inputs_artifact:artifact,comparison_policy:{kind:'exact-bv'}};
   const state=await service.jobs.wait((await service.submitExperiment(request)).job_id);
   expect(state.status).toBe('completed');const result=await service.getResult(state.result_id) as any;
   expect(result.target_validation.status).toBe('mismatch');expect(result.target_validation.counts).toMatchObject({planned:3,completed:3,matched:2,mismatched:1});
   expect(result.model_check.status).toBe('not_run');
   const run=await service.store.getObject<any>('runs',state.result_id);
   const compared=JSON.parse((await service.store.readArtifact(run.comparison_artifact)).toString('utf8'));
   expect(compared.left_calls).toBe(3);expect(compared.right_calls).toBe(3);expect(compared.comparisons.find((row:any)=>row.matched===false).sample_id).toBe('n100');
  }finally{await service.close();await rm(dir,{recursive:true,force:true});}
 },30000);
 it.each(['outside_domain','duplicate_sample_id'])('validates the entire Oracle plan before any target call: %s',async(kind)=>{
  const fixture=await counterOracleFixture();
  try{
   const plan=[{sample_id:'first',split:'holdout',inputs:{x:{kind:'bv',width:8,bits:'0x01'}}},{sample_id:kind==='duplicate_sample_id'?'first':'late',split:'holdout',inputs:{x:{kind:'bv',width:8,bits:kind==='outside_domain'?'0xff':'0x02'}}}];
   const artifact=await fixture.service.store.putJsonl(plan);const state=await fixture.service.jobs.wait((await fixture.service.submitExperiment(pairedRequest(artifact))).job_id);
   expect(state.status).toBe('failed');expect(state.error?.code).toBe(kind==='outside_domain'?'OUT_OF_DOMAIN':'INPUT_PLAN_INVALID');
   expect(await readFile(fixture.log,'utf8').catch(()=> '')).toBe('');
   const stored=await fixture.service.getResult(state.result_id!) as any;expect(stored.target_validation.status).not.toBe('matched');
  }finally{await fixture.service.close();await rm(fixture.root,{recursive:true,force:true});}
 },30000);
 it('persists completed sampled comparisons and planned denominator when cancellation occurs between samples',async()=>{
  const root=await mkdtemp(path.join(tmpdir(),'wirefit-sampled-cancel-'));const service=await WirefitService.create(root);
  const actualEvaluate=verification.evaluateModel;let jobId:string|undefined;let cancellation:Promise<unknown>|undefined;
  const evaluate=vi.spyOn(verification,'evaluateModel').mockImplementation((model,inputs)=>{
   const output=actualEvaluate(model,inputs);
   // Real math and the real cancellation API; interception only selects the
   // deterministic between-sample boundary without fabricating an outcome.
   if(!cancellation&&jobId)cancellation=service.jobs.cancel(jobId);
   return output;
  });
  try{
   const left=await readJson<any>(path.join(rootDir,'examples/model.affine-initial.json'));const right=structuredClone(left);right.model_id='cancel_right';
   await service.importModel(left);await service.importModel(right);
   const artifact=await service.store.putJsonl([0,1,2].map(i=>({sample_id:'sample_'+i,split:'holdout',inputs:{x:{kind:'fp32',bits:'0x00000000'}}})));
   const request={schema_version:1,experiment_id:'cancel_sampled',operation:'compare_models',budget:defaultBudget,mode:'sampled_fp32',left_model_id:left.model_id,right_model_id:right.model_id,domain:left.domain,mapping:{inputs:[{left:'x',right:'x'}],outputs:[{left:'result',right:'result'}]},sample_source:{kind:'inputs_artifact',artifact},comparison_policy:{kind:'bitwise-fp32',nonfinite:'reject'}};
   const job=await service.submitExperiment(request);jobId=job.job_id;const state=await service.jobs.wait(job.job_id);await cancellation;
   expect(state.status).toBe('cancelled');expect(state.result_id).not.toBeNull();
   const run=await service.store.getObject<any>('runs',state.result_id!);
   expect(run.result.sample_comparison.status).toBe('partial');expect(run.result.sample_comparison.counts).toEqual({planned:3,attempted:1,completed:1,matched:1,mismatched:0,failed:0,out_of_domain:0});
   expect(run.result.model_check.status).toBe('not_run');expect(run.comparison_artifact).not.toBeNull();
   const rows=JSON.parse((await service.store.readArtifact(run.comparison_artifact)).toString('utf8'));
   expect(rows).toHaveLength(1);expect(rows[0].sample_id).toBe('sample_0');expect(rows[0].left_outputs).toEqual(rows[0].right_outputs);
  }finally{evaluate.mockRestore();await service.close();await rm(root,{recursive:true,force:true});}
 },15000);
 it.each(['unknown_guard','local_value','rea_provenance'])('blocks original-target promotion and fresh calls for unbound observations: %s',async(kind)=>{
  const fixture=await collectedOriginalFixture();
  try{
   const model=await readJson<any>(path.join(rootDir,'examples/model.add-u8.json'));model.model_id='unbound_'+kind;
   if(kind==='unknown_guard')model.scope.execution_guard={kind:'unknown'};
   if(kind==='local_value')model.scope.observation_point.kind='local_value';
   if(kind==='rea_provenance'){model.provenance.source_kind='rea_portable';model.provenance.notes='Synthetic source declaration for the provenance gate; no native run is claimed.';}
   await fixture.service.importModel(model);
   const request=recordedRequest(model.model_id,fixture.datasetId);
   const recorded=await fixture.service.jobs.wait((await fixture.service.submitExperiment(request)).job_id);expect(recorded.status).toBe('completed');
   const result=await fixture.service.getResult(recorded.result_id!) as any;
   expect(result.target_validation.status).toBe('unavailable');expect(result.fidelity.status).toBe('unvalidated');expect(result.identity.observation_binding_sha256).toBeNull();
   const before=await readFile(fixture.log,'utf8');
   const fresh=await fixture.service.jobs.wait((await fixture.service.submitExperiment({...request,source_mode:'live',oracle_id:'original'})).job_id);
   expect(fresh.status).toBe('failed');expect(fresh.error?.code).toBe('OBSERVATION_BINDING_UNAVAILABLE');expect(await readFile(fixture.log,'utf8')).toBe(before);
  }finally{await fixture.service.close();await rm(fixture.root,{recursive:true,force:true});}
 },20000);
 it('retains imported original observations without inheriting locally validated fidelity',async()=>{
  const fixture=await collectedOriginalFixture();
  try{
   const dataset=await fixture.service.store.getObject<any>('datasets',fixture.datasetId);const manifest=structuredClone(dataset.manifest);manifest.dataset_id='imported_original_history';
   const file=path.join(fixture.root,'history.json');await writeFile(file,JSON.stringify(manifest),'utf8');await fixture.service.importDataset(file,fixture.service.store.root);
   const model=await readJson<any>(path.join(rootDir,'examples/model.add-u8.json'));await fixture.service.importModel(model);
   const state=await fixture.service.jobs.wait((await fixture.service.submitExperiment(recordedRequest(model.model_id,manifest.dataset_id))).job_id);expect(state.status).toBe('completed');
   const result=await fixture.service.getResult(state.result_id!) as any;
   expect(result.target_validation.status).toBe('matched');expect(result.target_validation.mode).toBe('recorded');expect(result.fidelity.status).toBe('unvalidated');expect(result.identity.observation_binding_sha256).toBeNull();
  }finally{await fixture.service.close();await rm(fixture.root,{recursive:true,force:true});}
 },20000);
});

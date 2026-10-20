import { describe, expect, it } from 'vitest';
import { cp, mkdir, mkdtemp, readFile, rm, symlink, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { tmpdir } from 'node:os';
import { CaseStore } from '../src/store.js';
import { exportReport } from '../src/reporting.js';
import { readJson, rootDir, sha256, semanticHash, sourceHash, hashObject } from '../src/shared.js';
import { runProcess } from '../src/process.js';

const counts=(planned=0,matched=0,mismatched=0)=>({planned,attempted:planned,completed:matched+mismatched,matched,mismatched,failed:0,out_of_domain:0});
// Synthetic canonical result envelope for reporting tests. Original-target
// observations below come from a real, independent child-process fixture.
function result(target='not_run',planned=0){return {
  schema_version:1,result_id:'report_result',experiment_id:'report_experiment',operation:'verify_candidate',job_status:'completed',
  identity:{request_sha256:'0'.repeat(64),model_semantic_hashes:[],source_envelope_hashes:[],oracle_binding_hashes:[],input_plan_sha256:null,policy_sha256:null,observation_binding_sha256:null},
  model_check:{status:'not_run',reason:'Reporting boundary fixture; solver not run.',artifacts:[],solver_record:null},
  target_validation:{status:target,reason:'Actual independent fixture observations when present.',artifacts:[],mode:planned?'live':'none',counts:counts(planned,0,planned),source_counts:planned?[{kind:'original_target',mode:'live',count:planned}]:[]},
  fit:{status:'not_run',reason:'No fitting.',artifacts:[],candidate_model_id:null,backend:null,train_counts:counts(),validation_counts:counts(),holdout_counts:counts()},
  sample_comparison:{status:'not_run',reason:'No sample model comparison.',artifacts:[],counts:counts()},
  fidelity:{status:'unavailable',reason:'No local fidelity binding.',artifacts:[],binding_identity_sha256:null},dependencies:[],artifacts:[],limitations:[],error:null,
};}
async function setup(withCandidate=true){
  const root=await mkdtemp(path.join(tmpdir(),'wirefit-report-'));
  const store=await CaseStore.create(path.join(root,'case'));
  const candidate=await readJson<any>(path.join(rootDir,'examples/model.add-u8-wrong.json'));
  const reference=await readJson<any>(path.join(rootDir,'examples/model.add-u8.json'));
  const portable=await store.putArtifact(await readFile(path.join(rootDir,'artifacts/rea/real-js-bundle.json')),'application/json');
  candidate.provenance.source_artifacts.push(portable);
  await store.putObject('models',reference.model_id,reference);
  await store.putObject('models',candidate.model_id,candidate);
  const target=path.join(root,'independent-target.mjs');
  await writeFile(target,"import {readFileSync} from 'node:fs';const x=JSON.parse(readFileSync(0,'utf8')).inputs;console.log(JSON.stringify({result:{kind:'bv',width:8,bits:'0x'+((BigInt(x.a.bits)+BigInt(x.b.bits))&255n).toString(16).padStart(2,'0')}}));\n",'utf8');
  const inputs={a:{kind:'bv',width:8,bits:'0x01'},b:{kind:'bv',width:8,bits:'0x02'}};
  const execution=await runProcess(process.execPath,[target],{input:JSON.stringify({inputs}),timeout_ms:5000});
  expect(execution.code).toBe(0);
  const raw=await store.putJson(execution);
  const observation={schema_version:1,observation_id:'real_fixture_observation',sample_id:'sample_1',request_id:'real_fixture_request',record_kind:'observed',source_kind:'original_target',source_id:'independent_fixture_target',source_identity_sha256:sha256(await readFile(target)),split:'holdout',inputs,observed_at:new Date().toISOString(),duration_ms:Math.ceil(execution.duration_ms),raw_artifacts:[raw],status:'ok',outputs:JSON.parse(execution.stdout),error:null};
  const observations=await store.putJsonl([observation]);
  const plan=await store.putJsonl([{sample_id:'sample_1',split:'holdout',inputs}]);
  const comparison=await store.putJson({counterexample:{inputs,left_outputs:observation.outputs,right_outputs:{result:{kind:'bv',width:8,bits:'0x04'}}},policy:{kind:'exact-bv'}});
  const storedResult=result('mismatch',1);storedResult.identity.model_semantic_hashes=withCandidate?[semanticHash(reference),semanticHash(candidate)]:[];
  storedResult.identity.source_envelope_hashes=withCandidate?[sourceHash(reference),sourceHash(candidate)]:[];
  const request={operation:'verify_candidate',candidate_model_id:candidate.model_id,comparison_policy:{kind:'exact-bv'},mapping:{inputs:[{left:'a',right:'a'},{left:'b',right:'b'}],outputs:[{left:'result',right:'result'}]}};
  storedResult.identity.request_sha256=hashObject(request);
  await store.putObject('runs','report_run',{result:storedResult,request,model_ids:withCandidate?[reference.model_id,candidate.model_id]:[],candidate_model_id:withCandidate?candidate.model_id:null,dataset_id:null,observations_artifact:observations,comparison_artifact:comparison,test_inputs_artifact:plan});
  return {root,store,portable,raw,observations,inputs};
}

describe('standalone evidence-preserving report export',()=>{
  it('replays from a copied directory after the original case is removed and retains the actual mismatch',async()=>{
    const fixture=await setup();
    try{
      const destination=path.join(fixture.root,'first export');
      const manifest=await exportReport(fixture.store,'report_run',destination);
      expect(manifest.manifest_sha256).toBe(sha256(await readFile(path.join(destination,'manifest.json'))));
      expect(manifest.files.some(file=>file.sha256===fixture.portable.sha256)).toBe(true);
      expect(manifest.files.some(file=>file.sha256===fixture.raw.sha256)).toBe(true);
      await fixture.store.close();
      const copied=path.join(fixture.root,'independent copy');
      await cp(destination,copied,{recursive:true});
      await rm(path.join(fixture.root,'case'),{recursive:true,force:true});
      const execution=await runProcess(process.execPath,[path.join(copied,'replay.mjs')],{cwd:copied,timeout_ms:10000});
      expect(execution.code).toBe(0);
      const replay=JSON.parse(execution.stdout);
      expect(replay.export_consistency.status).toBe('matched');
      expect(replay.recorded_target_comparison.status).toBe('mismatch');
      expect(replay.recorded_target_comparison.counts.mismatched).toBe(1);
      expect(replay.fresh_target_replay.status).toBe('unavailable');
      expect(JSON.parse(await readFile(path.join(copied,'result.json'),'utf8')).target_validation.status).toBe('mismatch');
      expect(await readFile(path.join(copied,'report.md'),'utf8')).toContain('mismatch');
    }finally{await fixture.store.close();await rm(fixture.root,{recursive:true,force:true});}
  },20000);
  it('detects changed exported module bytes before executing the replay',async()=>{
    const fixture=await setup();
    try{
      const destination=path.join(fixture.root,'export');await exportReport(fixture.store,'report_run',destination);
      await writeFile(path.join(destination,'candidate.mjs'),'throw new Error("must not execute tampered code");\n','utf8');
      const execution=await runProcess(process.execPath,[path.join(destination,'replay.mjs')],{timeout_ms:10000});
      expect(execution.code).not.toBe(0);
      expect(execution.stderr+execution.stdout).toContain('EXPORT_INTEGRITY_ERROR');
      expect(execution.stderr+execution.stdout).not.toContain('must not execute tampered code');
    }finally{await fixture.store.close();await rm(fixture.root,{recursive:true,force:true});}
  },20000);
  it('refuses nonempty destinations and symlink/junction escapes without replacing existing files',async()=>{
    const fixture=await setup();
    try{
      const destination=path.join(fixture.root,'existing');await mkdir(destination);await writeFile(path.join(destination,'keep.txt'),'retained','utf8');
      await expect(exportReport(fixture.store,'report_run',destination)).rejects.toMatchObject({code:'EXPORT_DIRECTORY_NOT_EMPTY'});
      expect(await readFile(path.join(destination,'keep.txt'),'utf8')).toBe('retained');
      const external=path.join(fixture.root,'external');await mkdir(external);
      const link=path.join(fixture.root,'link');await symlink(external,link,process.platform==='win32'?'junction':'dir');
      await expect(exportReport(fixture.store,'report_run',path.join(link,'escape'))).rejects.toMatchObject({code:'EXPORT_PATH_INVALID'});
    }finally{await fixture.store.close();await rm(fixture.root,{recursive:true,force:true});}
  },20000);
  it('exports evidence without claiming candidate replay when a run has no model',async()=>{
    const fixture=await setup(false);
    try{
      const destination=path.join(fixture.root,'export');const manifest=await exportReport(fixture.store,'report_run',destination);
      expect(manifest.candidate_module).toBeNull();
      const execution=await runProcess(process.execPath,[path.join(destination,'replay.mjs')],{timeout_ms:10000});
      expect(execution.code).toBe(0);
      const replay=JSON.parse(execution.stdout);
      expect(replay.export_consistency.status).toBe('not_run');
      expect(replay.recorded_target_comparison.status).toBe('unavailable');
    }finally{await fixture.store.close();await rm(fixture.root,{recursive:true,force:true});}
  },20000);
  it('refuses a model whose semantics changed after verifier identity binding',async()=>{
    const fixture=await setup();
    try{
      const model=await fixture.store.getObject<any>('models','add_u8_wrong');model.nodes.at(-1).op='bv_sub';
      const file=await fixture.store.resolveRelative('models/'+sha256(model.model_id)+'.json');
      await writeFile(file,JSON.stringify({id:model.model_id,value:model})+'\n','utf8');
      await expect(exportReport(fixture.store,'report_run',path.join(fixture.root,'changed'))).rejects.toMatchObject({code:'EXPORT_MODEL_IDENTITY_MISMATCH'});
    }finally{await fixture.store.close();await rm(fixture.root,{recursive:true,force:true});}
  },10000);
  it('exports and strictly typechecks FP32 modules while preserving signed zero',async()=>{
    const root=await mkdtemp(path.join(tmpdir(),'wirefit-report-fp32-'));const store=await CaseStore.create(path.join(root,'case'));
    try{
      const model=await readJson<any>(path.join(rootDir,'examples/model.affine-initial.json'));
      model.definition.parameters={a:{kind:'fp32',bits:'0x3f800000'},b:{kind:'fp32',bits:'0x80000000'}};
      await store.putObject('models',model.model_id,model);
      const plan=await store.putJsonl([{sample_id:'negative_zero',split:'holdout',inputs:{x:{kind:'fp32',bits:'0x80000000'}}}]);
      const storedResult=result();storedResult.identity.model_semantic_hashes=[semanticHash(model)];
      storedResult.identity.source_envelope_hashes=[sourceHash(model)];
      const request={operation:'verify_candidate',comparison_policy:{kind:'bitwise-fp32',nonfinite:'reject'}};storedResult.identity.request_sha256=hashObject(request);
      await store.putObject('runs','fp32_run',{result:storedResult,request,model_ids:[model.model_id],candidate_model_id:model.model_id,dataset_id:null,observations_artifact:null,comparison_artifact:null,test_inputs_artifact:plan});
      const destination=path.join(root,'export');await exportReport(store,'fp32_run',destination);
      const execution=await runProcess(process.execPath,[path.join(destination,'replay.mjs')],{timeout_ms:10000});
      const replay=JSON.parse(execution.stdout);
      expect(replay.export_consistency.status).toBe('matched');
      expect(replay.export_consistency.cases[0].actual.result.bits).toBe('0x80000000');
      const typed=await runProcess(process.execPath,[path.join(rootDir,'node_modules/typescript/bin/tsc'),'--strict','--noUncheckedIndexedAccess','--target','ES2023','--module','NodeNext','--skipLibCheck','--noEmit',path.join(destination,'candidate.ts')],{cwd:root,timeout_ms:15000});
      expect(typed.code,typed.stdout+typed.stderr).toBe(0);
    }finally{await store.close();await rm(root,{recursive:true,force:true});}
  },25000);
  it('keeps REA local slices with unknown guards unavailable for original-target comparison',async()=>{
    const fixture=await setup();
    try{
      const old=await fixture.store.getObject<any>('runs','report_run');
      const model=await fixture.store.getObject<any>('models','add_u8_wrong');
      model.model_id='rea_local_candidate';model.provenance.source_kind='rea_portable';model.scope.execution_guard={kind:'unknown'};model.scope.observation_point.kind='local_value';
      model.provenance.source_ref={bundle_sha256:fixture.portable.sha256,evidence_id:'synthetic_evidence_reference',provider_id:'ghidra',analysis_profile_digest:null,target_sha256:'f'.repeat(64),location:'0x401000'};
      await fixture.store.putObject('models',model.model_id,model);
      const reference=await fixture.store.getObject<any>('models','add_u8');
      old.model_ids=[reference.model_id,model.model_id];old.candidate_model_id=model.model_id;old.request.candidate_model_id=model.model_id;
      old.result.identity.request_sha256=hashObject(old.request);old.result.identity.model_semantic_hashes=[semanticHash(reference),semanticHash(model)];old.result.identity.source_envelope_hashes=[sourceHash(reference),sourceHash(model)];
      await fixture.store.putObject('runs','local_run',old);
      const destination=path.join(fixture.root,'local export');const manifest=await exportReport(fixture.store,'local_run',destination);
      expect(manifest.external_dependencies.some(dependency=>dependency.kind==='source_target')).toBe(true);
      const execution=await runProcess(process.execPath,[path.join(destination,'replay.mjs')],{timeout_ms:10000});
      expect(JSON.parse(execution.stdout).recorded_target_comparison.status).toBe('unavailable');
    }finally{await fixture.store.close();await rm(fixture.root,{recursive:true,force:true});}
  },20000);
  it('retains uncompleted planned original observations instead of upgrading a partial run',async()=>{
    const fixture=await setup();
    try{
      const old=await fixture.store.getObject<any>('runs','report_run');const model=await fixture.store.getObject<any>('models','add_u8');
      old.model_ids=[model.model_id];old.candidate_model_id=model.model_id;old.request.candidate_model_id=model.model_id;
      old.result.target_validation.status='partial';old.result.target_validation.counts={planned:2,attempted:1,completed:1,matched:1,mismatched:0,failed:0,out_of_domain:0};
      old.result.identity.request_sha256=hashObject(old.request);old.result.identity.model_semantic_hashes=[semanticHash(model)];old.result.identity.source_envelope_hashes=[sourceHash(model)];
      await fixture.store.putObject('runs','partial_run',old);
      const destination=path.join(fixture.root,'partial export');await exportReport(fixture.store,'partial_run',destination);
      const execution=await runProcess(process.execPath,[path.join(destination,'replay.mjs')],{timeout_ms:10000});const replay=JSON.parse(execution.stdout);
      expect(replay.recorded_target_comparison.status).toBe('partial');
      expect(replay.recorded_target_comparison.counts).toEqual({planned:2,attempted:1,completed:1,matched:1,mismatched:0,failed:0,out_of_domain:0});
    }finally{await fixture.store.close();await rm(fixture.root,{recursive:true,force:true});}
  },20000);
});

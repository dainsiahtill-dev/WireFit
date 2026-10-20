import {describe,it,expect} from 'vitest';
import {mkdtemp,rm,writeFile} from 'node:fs/promises';
import path from 'node:path';
import {tmpdir} from 'node:os';
import {CaseStore} from '../src/store.js';
import {importDataset,collectDataset,parseJsonl} from '../src/dataset.js';
import {bindOracle} from '../src/oracle.js';
import {readJson,rootDir,sha256} from '../src/shared.js';
describe('immutable dataset import',()=>{
 it('imports expected fixtures without calling them target observations',async()=>{
  const dir=await mkdtemp(path.join(tmpdir(),'wirefit-dataset-'));const store=await CaseStore.create(dir);
  try{const dataset=await importDataset(store,path.join(rootDir,'examples/dataset.numeric-expected.json'),rootDir);expect(dataset.manifest.sampling_plan.planned).toBe(32);expect(dataset.locally_collected).toBe(false);expect(dataset.complete).toBe(true);}
  finally{await store.close();await rm(dir,{recursive:true,force:true});}
 });
 it('rejects cross-split leakage and altered artifact hashes',async()=>{
  const dir=await mkdtemp(path.join(tmpdir(),'wirefit-dataset-'));const store=await CaseStore.create(path.join(dir,'case'));
  try{
   const manifest=await readJson<any>(path.join(rootDir,'examples/dataset.numeric-expected.json'));
   manifest.splits.train.artifact.sha256='0'.repeat(64);
   const file=path.join(dir,'changed.json');await writeFile(file,JSON.stringify(manifest),'utf8');
   await expect(importDataset(store,file,rootDir)).rejects.toThrow(/hash|digest/i);
  }finally{await store.close();await rm(dir,{recursive:true,force:true});}
 });
});

async function generatedDataset(store:CaseStore,original=false,conflict=true){
 const source={kind:original?'original_target':'reference_fixture',source_id:'generated_source',source_identity_sha256:'1'.repeat(64),oracle_id:null};
 const samples=[{sample_id:'repeat_a',split:'train',inputs:{x:{kind:'bv',width:8,bits:'0x00'}}},{sample_id:'repeat_b',split:'train',inputs:{x:{kind:'bv',width:8,bits:'0x00'}}},{sample_id:'validation_a',split:'validation',inputs:{x:{kind:'bv',width:8,bits:'0x01'}}},{sample_id:'holdout_a',split:'holdout',inputs:{x:{kind:'bv',width:8,bits:'0x02'}}}];
 const rows=samples.map((sample,index)=>({schema_version:1,observation_id:'observation_'+index,request_id:'request_'+index,...sample,record_kind:'expected_fixture',source_kind:source.kind,source_id:source.source_id,source_identity_sha256:source.source_identity_sha256,observed_at:null,duration_ms:null,raw_artifacts:[],status:'ok',outputs:{result:{kind:'bv',width:8,bits:index===1&&conflict?'0x01':'0x00'}},error:null}));
 const splits:any={};for(const split of ['train','validation','holdout'])splits[split]={artifact:await store.putJsonl(rows.filter(r=>r.split===split)),sample_ids:samples.filter(s=>s.split===split).map(s=>s.sample_id)};
 const manifest={schema_version:1,dataset_id:'generated_dataset',signature:{inputs:[{id:'x',type:{kind:'bv',width:8}}],outputs:[{id:'result',type:{kind:'bv',width:8}}]},domain:{constraints:[]},comparison_policy:{kind:'exact-bv'},source,sampling_plan:{strategy:'explicit',seed:null,planned:4,inputs_artifact:await store.putJsonl(samples)},splits,notes:'generated source-owned import regression'};
 const file=path.join(store.root,'generated.json');await writeFile(file,JSON.stringify(manifest),'utf8');return file;
}
it('records conflicting imported repeats as nondeterministic rather than not_checked',async()=>{
 const dir=await mkdtemp(path.join(tmpdir(),'wirefit-dataset-'));const store=await CaseStore.create(dir);
 try{const file=await generatedDataset(store);const dataset=await importDataset(store,file,store.root);expect(dataset.determinism).toEqual({checked_pairs:1,status:'nondeterministic'});expect(dataset.actual_oracle_calls).toBe(0);}
 finally{await store.close();await rm(dir,{recursive:true,force:true});}
});
it('rejects expected fixture rows presented as original-target observations',async()=>{
 const dir=await mkdtemp(path.join(tmpdir(),'wirefit-dataset-'));const store=await CaseStore.create(dir);
 try{const file=await generatedDataset(store,true,false);await expect(importDataset(store,file,store.root)).rejects.toThrow(/fixture.*original|original.*observ/i);}
 finally{await store.close();await rm(dir,{recursive:true,force:true});}
});


it('keeps failed raw calls and unattempted slots in a budget-limited collection',async()=>{
 const dir=await mkdtemp(path.join(tmpdir(),'wirefit-dataset-'));const store=await CaseStore.create(path.join(dir,'case'));
 try {
  const target=path.join(dir,'target.cjs');await writeFile(target,'process.stdout.write("invalid target response");','utf8');
  const manifest={schema_version:1,oracle_id:'collection_fixture',kind:'process_jsonl',source_kind:'reference_fixture',argv:[process.execPath,target],cwd:'.',signature:{inputs:[{id:'x',type:{kind:'bv',width:8}}],outputs:[{id:'result',type:{kind:'bv',width:8}}]},domain:{constraints:[]},target_files:[{path:'target.cjs',sha256:sha256(Buffer.from('process.stdout.write("invalid target response");','utf8')),role:'target'}],protocol_version:1,reset_strategy:'fresh_process',request_timeout_ms:2000,batch_timeout_ms:10000,max_stdout_line_bytes:1048576,max_stderr_bytes:1048576,allowed_env_keys:[],notes:'failure fixture'};
  const file=path.join(dir,'oracle.json');await writeFile(file,JSON.stringify(manifest),'utf8');
  const samples:any=[{sample_id:'a',split:'train',inputs:{x:{kind:'bv',width:8,bits:'0x00'}}},{sample_id:'b',split:'validation',inputs:{x:{kind:'bv',width:8,bits:'0x01'}}},{sample_id:'c',split:'holdout',inputs:{x:{kind:'bv',width:8,bits:'0x02'}}}];
  const dataset=await collectDataset(store,await bindOracle(file),samples,{kind:'exact-bv'},{max_oracle_calls:2});
  expect(dataset.complete).toBe(false);expect(dataset.actual_oracle_calls).toBe(2);
  const collection=JSON.parse((await store.readArtifact(dataset.collection_artifact!)).toString('utf8'));expect(collection.counts).toEqual({planned:3,attempted:2,completed:0,failed:2,out_of_domain:0,not_attempted:1});
  const rows=parseJsonl<any>(await store.readArtifact(dataset.manifest.splits.train.artifact));expect(rows[0].status).toBe('protocol_error');expect(rows[0].raw_artifacts).toHaveLength(1);expect(JSON.parse((await store.readArtifact(rows[0].raw_artifacts[0])).toString('utf8')).stdout).toBe('invalid target response');
 } finally{await store.close();await rm(dir,{recursive:true,force:true});}
});

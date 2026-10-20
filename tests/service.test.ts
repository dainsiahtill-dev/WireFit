import {describe,it,expect} from 'vitest';
import {mkdtemp,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {WirefitService} from '../src/service.js';
import {readJson,rootDir} from '../src/shared.js';
describe('application service',()=>{
 it('runs actual import -> exact compare -> persisted report without a target claim',async()=>{
  const dir=await mkdtemp(path.join(tmpdir(),'wirefit-service-'));const service=await WirefitService.create(dir);
  try{
   await service.importModel(path.join(rootDir,'examples/model.mba-u8.json'));
   await service.importModel(path.join(rootDir,'examples/model.add-u8.json'));
   const job=await service.submitExperiment(await readJson(path.join(rootDir,'examples/request.compare-equivalent.json')));
   const state=await service.jobs.wait(job.job_id);
   expect(state.status).toBe('completed');
   const result=await service.getResult(state.result_id);
   expect(result.model_check.status).toBe('proved');
   expect(result.target_validation.status).not.toBe('matched');
   expect(result.fit.status).toBe('not_run');
  }finally{await service.close();await rm(dir,{recursive:true,force:true});}
 },60000);
 it('rejects request verdict injection before scheduling work',async()=>{
  const dir=await mkdtemp(path.join(tmpdir(),'wirefit-service-'));const service=await WirefitService.create(dir);
  try{const request=await readJson<any>(path.join(rootDir,'examples/request.compare-equivalent.json'));await expect(service.submitExperiment({...request,verdict:'proved'})).rejects.toThrow();}
  finally{await service.close();await rm(dir,{recursive:true,force:true});}
 });
 it('persists an empty-domain failure as failure, never a proof',async()=>{
  const dir=await mkdtemp(path.join(tmpdir(),'wirefit-service-'));const service=await WirefitService.create(dir);
  try{
   await service.importModel(path.join(rootDir,'examples/model.mba-u8.json'));await service.importModel(path.join(rootDir,'examples/model.add-u8.json'));
   const request=await readJson<any>(path.join(rootDir,'examples/request.compare-equivalent.json'));
   request.domain={constraints:[{input:'a',op:'eq',value:{kind:'bv',width:8,bits:'0x00'}},{input:'a',op:'eq',value:{kind:'bv',width:8,bits:'0x01'}}]};
   const state=await service.jobs.wait((await service.submitExperiment(request)).job_id);
   expect(state.status).toBe('failed');
   const result=await service.getResult(state.result_id);
   expect(result.model_check.status).not.toBe('proved');expect(result.error.code).toBe('DOMAIN_EMPTY');
  }finally{await service.close();await rm(dir,{recursive:true,force:true});}
 },60000);
});

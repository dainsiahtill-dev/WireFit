import {describe,it,expect} from 'vitest';
import {readFile} from 'node:fs/promises';
import {schemaNames,validateSchema} from '../src/shared.js';
import {researchCatalog,researchDirection} from '../src/research/catalog.js';
import {validateDirectionSemantics} from '../src/research/runner.js';

describe('research contracts',()=>{
 it('compiles the three research contracts offline and keeps the catalogue at fifteen',()=>{
  expect(schemaNames()).toHaveLength(15);
  expect(schemaNames()).toContain('research-direction');
  expect(schemaNames()).toContain('research-request');
  expect(schemaNames()).toContain('research-result');
 });
 it('accepts a well formed research request and rejects unknown fields and unknown directions',()=>{
  const request={schema_version:1,research_id:'research_demo',direction_id:'D07',
   budget:{wall_time_ms:1000,solver_soft_time_ms:100,solver_hard_time_ms:200,max_candidates:10,max_ast_nodes:4,max_oracle_calls:4,max_iterations:10,seed:20261019}};
  expect(()=>validateSchema('research-request',request)).not.toThrow();
  expect(()=>validateSchema('research-request',{...request,verdict:'supported'})).toThrow();
  expect(()=>validateSchema('research-request',{...request,direction_id:'D99'})).toThrow();
  expect(()=>validateSchema('research-request',{...request,direction_id:'d07'})).toThrow();
 });
 it('keeps the union types out of anyOf free positions so Ajv strict mode accepts the contracts',async()=>{
  const direction=JSON.parse(await readFile('contracts/research-direction.schema.json','utf8'));
  const request=JSON.parse(await readFile('contracts/research-request.schema.json','utf8'));
  const result=JSON.parse(await readFile('contracts/research-result.schema.json','utf8'));
  for(const schema of [direction,request,result]){
   const walk=(node:unknown):void=>{
    if(Array.isArray(node)){node.forEach(walk);return;}
    if(node!==null&&typeof node==='object'){
     const record=node as Record<string,unknown>;
     if(typeof record.type==='string'&&record.type.includes('|'))
      throw new Error('a union type leaked into a schema: '+record.type);
     for(const value of Object.values(record))walk(value);
    }
   };
   walk(schema);
  }
 });
 it('registers seventeen directions, each with a primary claim, a negative control and explicit non claims',()=>{
  const catalog=researchCatalog();
  expect(catalog).toHaveLength(17);
  expect(new Set(catalog.map((spec)=>spec.direction_id)).size).toBe(17);
  for(const spec of catalog){
   expect(spec.primary_claim_id).toBeTruthy();
   expect(spec.claims.some((claim)=>claim.claim_id===spec.primary_claim_id)).toBe(true);
   for(const claim of spec.claims){
    expect(claim.not_claimed.length).toBeGreaterThan(0);
    expect(claim.checks.some((check)=>check.role==='negative_control')).toBe(true);
    expect(claim.metrics.length).toBeGreaterThan(0);
    expect(claim.failure_condition.length).toBeGreaterThan(0);
   }
   expect(()=>validateDirectionSemantics(spec)).not.toThrow();
  }
 });
 it('rejects a specification whose primary claim is missing',()=>{
  const spec=researchDirection('D01')!;
  const broken={...spec,primary_claim_id:'D01.missing'};
  expect(()=>validateDirectionSemantics(broken)).toThrow(/primary claim/);
 });
 it('rejects a specification whose check references an undeclared evidence role',()=>{
  const spec=researchDirection('D01')!;
  const claim=spec.claims[0]!;
  const broken={...spec,claims:[{...claim,checks:claim.checks.map((check,index)=>index===0?{...check,source_roles:['not_declared']}:check)}]};
  expect(()=>validateDirectionSemantics(broken)).toThrow(/undeclared evidence role/);
 });
 it('returns null for an unknown direction',()=>{
  expect(researchDirection('D99')).toBeNull();
  expect(researchDirection('D01')).not.toBeNull();
 });
});

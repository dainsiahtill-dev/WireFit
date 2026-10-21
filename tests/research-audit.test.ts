import {describe,it,expect} from 'vitest';
import {readFile} from 'node:fs/promises';
import {execFile} from 'node:child_process';
import {promisify} from 'node:util';
import {evaluateKernel,compareObservation} from '../src/research/recipe.js';
import {researchCatalog} from '../src/research/catalog.js';

const execute=promisify(execFile);
const AUDIT=process.platform==='win32'?'python':'python3';

interface Fixture{
 documents:Record<string,unknown>;
 binaries:Record<string,string>;
 cases:{id:string;derivation:Parameters<typeof evaluateKernel>[1];expected:string|number|boolean;comparator:Parameters<typeof compareObservation>[2]}[];
}

describe('independent audit layer',()=>{
 it('produces byte identical observations in the TypeScript and the Python interpreters',async()=>{
  const fixture=JSON.parse(await readFile('tests/fixtures/research-recipe-fixture.json','utf8')) as Fixture;
  const binaries:Record<string,Buffer>={};
  for(const [role,hex] of Object.entries(fixture.binaries))binaries[role]=Buffer.from(hex,'hex');
  const context={
   document:(role:string):unknown=>{
    const value=fixture.documents[role];
    if(value===undefined)throw new Error('unknown role '+role);
    return value;
   },
   bytes:(role:string):Buffer=>{
    const value=binaries[role];
    if(value===undefined)throw new Error('unknown role '+role);
    return value;
   },
  };
  const local=fixture.cases.map((entry)=>{
   try{
    const observed=evaluateKernel(context,entry.derivation);
    return {id:entry.id,observed,passed:compareObservation(observed,entry.expected,entry.comparator),error:null};
   }catch(error){
    return {id:entry.id,observed:null,passed:null,error:(error as {code?:string}).code??'ERROR'};
   }
  });
  const executed=await execute(AUDIT,['artifacts/research/vmde/directions/audit.py','--fixture','tests/fixtures/research-recipe-fixture.json'],{cwd:process.cwd(),maxBuffer:16*1024*1024});
  const remote=JSON.parse(executed.stdout) as {results:{id:string;observed:unknown;passed:boolean|null;error:string|null}[]};
  expect(remote.results).toHaveLength(local.length);
  for(const [index,entry] of local.entries()){
   const other=remote.results[index]!;
   expect(other.id).toBe(entry.id);
   expect(other.error).toBe(entry.error);
   expect(other.observed).toEqual(entry.observed);
   expect(other.passed).toBe(entry.passed);
  }
 },120000);
 it('declares every catalog check with a derivation the audit can replay',()=>{
  for(const spec of researchCatalog())
   for(const claim of spec.claims)
    for(const check of claim.checks){
     expect(check.derivation.kernel).toBeTruthy();
     expect(check.derivation.artifact_role).toBeTruthy();
     expect(check.source_roles.length).toBeGreaterThan(0);
     expect(['eq','ne','gte','lte','gt','lt','identical_set','subset','superset']).toContain(check.comparator);
    }
 });
 it('gives every direction at least one negative control that must fail',()=>{
  for(const spec of researchCatalog())
   for(const claim of spec.claims){
    const controls=claim.checks.filter((check)=>check.role==='negative_control');
    expect(controls.length).toBeGreaterThan(0);
   }
 });
});

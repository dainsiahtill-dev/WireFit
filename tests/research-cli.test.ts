import {it,expect} from 'vitest';
import {execFile} from 'node:child_process';
import {promisify} from 'node:util';
import {mkdtemp,rm,readFile} from 'node:fs/promises';
import {existsSync} from 'node:fs';
import {tmpdir} from 'node:os';
import path from 'node:path';

const root=path.resolve('.'),
 local=path.join(root,'.tools/runtime/node_modules/node-win-x64/bin/node.exe'),
 runtime=process.platform==='win32'&&existsSync(local)?local:process.execPath,
 execute=promisify(execFile);

async function cli(...args:string[]){
 try{
  const result=await execute(runtime,['--import','tsx',path.join(root,'src/cli.ts'),...args],{cwd:root,maxBuffer:64*1024*1024});
  return {data:JSON.parse(result.stdout),stderr:result.stderr,code:0};
 }catch(error){
  const detail=error as Error&{stdout?:string;code?:number};
  const stdout=detail.stdout??'';
  let data:unknown=null;
  try{data=JSON.parse(stdout);}catch{/* a non JSON failure is reported as an exit code only. */}
  return {data,stderr:'',code:detail.code??1};
 }
}

it('lists the seventeen research directions without a case',async()=>{
 const {data,code}=await cli('research','list');
 expect(code).toBe(0);
 expect((data as {directions:unknown[]}).directions).toHaveLength(17);
},60000);

it('reads one direction specification and rejects an unknown direction with exit code two',async()=>{
 const {data,code}=await cli('research','spec','--direction','D07');
 expect(code).toBe(0);
 expect((data as {direction_id:string}).direction_id).toBe('D07');
 const unknown=await cli('research','spec','--direction','D99');
 expect(unknown.code).toBe(2);
},60000);

it('runs one research direction end to end and reports a verdict in the four value set',async()=>{
 const dir=await mkdtemp(path.join(tmpdir(),'wirefit-research-cli-')),
  caseDir=path.join(dir,'case');
 try{
  expect((await cli('case','create','--dir',caseDir)).data).toMatchObject({product:'Wirefit'});
  const run=await cli('research','run','--case',caseDir,'--direction','D01');
  expect(run.code).toBe(0);
  const result=(run.data as {result:{verdict:string;direction_id:string;claims:unknown[]}}).result;
  expect(result.direction_id).toBe('D01');
  expect(['supported','refuted','inconclusive','not_run']).toContain(result.verdict);
  expect(result.claims.length).toBeGreaterThan(0);
  const runId=(run.data as {job:{result_id:string}}).job.result_id;
  expect(runId).toBeTruthy();
  const recheck=await cli('research','recheck','--case',caseDir,'--run',runId);
  expect(recheck.code).toBe(0);
  const outcome=(recheck.data as {status:string;checked_count:number;mismatches:unknown[]});
  expect(outcome.status).toBe('agreed');
  expect(outcome.mismatches).toEqual([]);
  expect(outcome.checked_count).toBeGreaterThan(0);
 }finally{
  await rm(dir,{recursive:true,force:true});
 }
},600000);

it('rechecks a direction whose check reads a JSON Lines evidence role',async()=>{
 // D12 reads fixtures/reference_vectors.jsonl, a JSON Lines corpus. The
 // recipe addresses it as {"rows": [...]}; the corpus loader must register
 // that shape for the standalone recheck, not only for the in-run corpus.
 const dir=await mkdtemp(path.join(tmpdir(),'wirefit-research-cli-')),
  caseDir=path.join(dir,'case');
 try{
  await cli('case','create','--dir',caseDir);
  const run=await cli('research','run','--case',caseDir,'--direction','D12');
  expect(run.code).toBe(0);
  const result=(run.data as {result:{verdict:string;claims:{checks:{check_id:string}[]}[]}}).result;
  // The evidence role must be readable, otherwise the check cannot be
  // evaluated at all and the claim degrades to inconclusive.
  expect(result.verdict).toBe('supported');
  const recorded=result.claims.flatMap((claim)=>claim.checks.map((check)=>check.check_id));
  expect(recorded).toContain('D12.a.no_upstream_observation');
  const runId=(run.data as {job:{result_id:string}}).job.result_id;
  const recheck=await cli('research','recheck','--case',caseDir,'--run',runId);
  expect(recheck.code).toBe(0);
  const outcome=(recheck.data as {status:string;checked_count:number;agreed_count:number;mismatches:unknown[]});
  expect(outcome.status).toBe('agreed');
  expect(outcome.checked_count).toBe(recorded.length);
  expect(outcome.agreed_count).toBe(outcome.checked_count);
  expect(outcome.mismatches).toEqual([]);
 }finally{
  await rm(dir,{recursive:true,force:true});
 }
},600000);

it('rejects an unknown direction on the run command with exit code two',async()=>{
 const dir=await mkdtemp(path.join(tmpdir(),'wirefit-research-cli-')),
  caseDir=path.join(dir,'case');
 try{
  await cli('case','create','--dir',caseDir);
  const unknown=await cli('research','run','--case',caseDir,'--direction','D99');
  expect(unknown.code).toBe(2);
 }finally{
  await rm(dir,{recursive:true,force:true});
 }
},120000);

it('exports a research package with a plan, checks, receipt, report and manifest',async()=>{
 const dir=await mkdtemp(path.join(tmpdir(),'wirefit-research-export-')),
  caseDir=path.join(dir,'case'),
  outDir=path.join(dir,'package');
 try{
  await cli('case','create','--dir',caseDir);
  const run=await cli('research','run','--case',caseDir,'--direction','D01');
  const runId=(run.data as {job:{result_id:string}}).job.result_id;
  const exported=await cli('report','export','--case',caseDir,'--run',runId,'--out',outDir);
  expect(exported.code).toBe(0);
  const manifest=JSON.parse(await readFile(path.join(outDir,'manifest.json'),'utf8')) as {
   report_kind:string;files:{relative_path:string;sha256:string}[];product_sources:{path:string;sha256:string}[];
  };
  expect(manifest.report_kind).toBe('research');
  expect(manifest.files.map((file)=>file.relative_path)).toEqual(expect.arrayContaining(['plan.json','checks.json','receipt.json','report.md']));
  expect(manifest.product_sources.some((source)=>source.path==='src/research/recipe.ts')).toBe(true);
  for(const file of manifest.files){
   const bytes=await readFile(path.join(outDir,file.relative_path));
   const digest=(await import('node:crypto')).createHash('sha256').update(bytes).digest('hex');
   expect(digest).toBe(file.sha256);
  }
 }finally{
  await rm(dir,{recursive:true,force:true});
 }
},600000);

import {describe,it,expect} from 'vitest';
import {execFile} from 'node:child_process';
import {promisify} from 'node:util';
import {mkdtemp,readFile,readdir,rm,stat} from 'node:fs/promises';
import {existsSync} from 'node:fs';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {createHash} from 'node:crypto';

const root=path.resolve('.'),
 local=path.join(root,'.tools/runtime/node_modules/node-win-x64/bin/node.exe'),
 runtime=process.platform==='win32'&&existsSync(local)?local:process.execPath,
 execute=promisify(execFile);

async function cli(...args:string[]){
 const result=await execute(runtime,['--import','tsx',path.join(root,'src/cli.ts'),...args],{cwd:root,maxBuffer:64*1024*1024});
 return JSON.parse(result.stdout.trim().split('\n').pop());
}

describe('research export package',()=>{
 it('writes the frozen package with a plan, checks, receipt, report and manifest',async()=>{
  const dir=await mkdtemp(path.join(tmpdir(),'wirefit-research-export-')),
   caseDir=path.join(dir,'case'),
   outDir=path.join(dir,'package');
  try{
   await cli('case','create','--dir',caseDir);
   const run=await cli('research','run','--case',caseDir,'--direction','D01');
   const runId=(run as {job:{result_id:string}}).job.result_id;
   const exported=await cli('report','export','--case',caseDir,'--run',runId,'--out',outDir);
   const manifest=exported as {
    schema_version:number;product:string;report_kind:string;direction_id:string;verdict:string;
    plan_sha256:string;frozen_candidate_sha256:string;manifest_sha256:string;output_directory:string;
    files:{relative_path:string;sha256:string;size_bytes:number;media_type:string}[];
    product_sources:{path:string;sha256:string}[];
   };
   expect(manifest.schema_version).toBe(1);
   expect(manifest.product).toBe('Wirefit');
   expect(manifest.report_kind).toBe('research');
   expect(manifest.direction_id).toBe('D01');
   expect(manifest.output_directory).toBe(outDir);
   const names=manifest.files.map((file)=>file.relative_path);
   expect(names).toEqual(expect.arrayContaining(['plan.json','checks.json','receipt.json','report.md']));
   // The plan and the checks must carry the frozen pre-registration.
   const plan=JSON.parse(await readFile(path.join(outDir,'plan.json'),'utf8')) as {direction_id:string;claims:{checks:{check_id:string;role:string}[]}[]};
   expect(plan.direction_id).toBe('D01');
   expect(plan.claims[0]!.checks.some((check)=>check.role==='negative_control')).toBe(true);
   const checks=JSON.parse(await readFile(path.join(outDir,'checks.json'),'utf8')) as {checks:{check_id:string;observed:unknown;passed:boolean;derivation:unknown}[]};
   expect(checks.checks.length).toBeGreaterThan(0);
   for(const check of checks.checks){
    expect(check.derivation).toBeTruthy();
    expect(typeof check.passed).toBe('boolean');
   }
   const report=await readFile(path.join(outDir,'report.md'),'utf8');
   expect(report).toContain('研究实验报告');
   expect(report).toContain('负控检查');
  }finally{
   await rm(dir,{recursive:true,force:true});
  }
 },900000);

 it('pins every written file and the product sources it depends on',async()=>{
  const dir=await mkdtemp(path.join(tmpdir(),'wirefit-research-export-')),
   caseDir=path.join(dir,'case'),
   outDir=path.join(dir,'package');
  try{
   await cli('case','create','--dir',caseDir);
   const run=await cli('research','run','--case',caseDir,'--direction','D01');
   const runId=(run as {job:{result_id:string}}).job.result_id;
   const exported=await cli('report','export','--case',caseDir,'--run',runId,'--out',outDir);
   const manifest=exported as {files:{relative_path:string;sha256:string;size_bytes:number}[];product_sources:{path:string;sha256:string}[];manifest_sha256:string};
   for(const file of manifest.files){
    const bytes=await readFile(path.join(outDir,file.relative_path));
    expect(createHash('sha256').update(bytes).digest('hex')).toBe(file.sha256);
    expect(bytes.length).toBe(file.size_bytes);
   }
   // The product sources are pinned so that a product change invalidates the
   // package instead of silently outliving it.
   expect(manifest.product_sources.length).toBeGreaterThan(10);
   for(const source of manifest.product_sources){
    expect(existsSync(path.join(root,source.path))).toBe(true);
    const bytes=await readFile(path.join(root,source.path));
    expect(createHash('sha256').update(bytes).digest('hex')).toBe(source.sha256);
   }
   expect(manifest.product_sources.some((source)=>source.path==='src/research/recipe.ts')).toBe(true);
   expect(manifest.product_sources.some((source)=>source.path==='tools/research/audit.py')).toBe(true);
   const manifestBytes=await readFile(path.join(outDir,'manifest.json'));
   expect(createHash('sha256').update(manifestBytes).digest('hex')).toBe(manifest.manifest_sha256);
  }finally{
   await rm(dir,{recursive:true,force:true});
  }
 },900000);

 it('copies the run artifacts into the package so an auditor can replay the observations',async()=>{
  const dir=await mkdtemp(path.join(tmpdir(),'wirefit-research-export-')),
   caseDir=path.join(dir,'case'),
   outDir=path.join(dir,'package');
  try{
   await cli('case','create','--dir',caseDir);
   const run=await cli('research','run','--case',caseDir,'--direction','D01');
   const runId=(run as {job:{result_id:string}}).job.result_id;
   await cli('report','export','--case',caseDir,'--run',runId,'--out',outDir);
   const artifacts=path.join(outDir,'artifacts');
   expect(existsSync(artifacts)).toBe(true);
   const entries=await readdir(artifacts,{recursive:true,withFileTypes:true});
   const files=entries.filter((entry)=>entry.isFile());
   expect(files.length).toBeGreaterThan(0);
   // Every copied artifact must be a parseable JSON document.
   for(const entry of files){
    const full=path.join(entry.parentPath??artifacts,entry.name);
    const text=await readFile(full,'utf8');
    expect(()=>JSON.parse(text)).not.toThrow();
   }
  }finally{
   await rm(dir,{recursive:true,force:true});
  }
 },900000);

 it('refuses to write into a directory that already holds files',async()=>{
  const dir=await mkdtemp(path.join(tmpdir(),'wirefit-research-export-')),
   caseDir=path.join(dir,'case'),
   outDir=path.join(dir,'package');
  try{
   await cli('case','create','--dir',caseDir);
   const run=await cli('research','run','--case',caseDir,'--direction','D01');
   const runId=(run as {job:{result_id:string}}).job.result_id;
   await cli('report','export','--case',caseDir,'--run',runId,'--out',outDir);
   const second=await execute(runtime,['--import','tsx',path.join(root,'src/cli.ts'),'report','export','--case',caseDir,'--run',runId,'--out',outDir],{cwd:root,maxBuffer:16*1024*1024}).catch((error)=>error as {code?:number});
   expect((second as {code?:number}).code).not.toBe(0);
  }finally{
   await rm(dir,{recursive:true,force:true});
  }
 },900000);
});

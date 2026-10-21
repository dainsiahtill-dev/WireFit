import path from 'node:path';
import {mkdir,readdir,readFile,lstat,realpath,writeFile} from 'node:fs/promises';
import {assert,rootDir,sha256} from '../shared.js';
import type {CaseStore} from '../store.js';
import type {ArtifactRef} from '../types.js';
import {researchDirection} from './catalog.js';
import {renderResearchReport} from './report.js';
import type {ResearchResultView} from './report.js';

export interface ResearchExportFile{relative_path:string;sha256:string;size_bytes:number;media_type:string;}
export interface ResearchProductSource{path:string;sha256:string;}
export interface ResearchExportManifest{
 schema_version:1;
 product:'Wirefit';
 report_kind:'research';
 run_id:string;
 direction_id:string;
 verdict:string;
 plan_sha256:string;
 frozen_candidate_sha256:string;
 files:ResearchExportFile[];
 product_sources:ResearchProductSource[];
 manifest_sha256:string;
 output_directory:string;
}

const MAX_BYTES=64*1024*1024;

/** The product source files that must not change without invalidating the lane. */
const PRODUCT_SOURCE_FILES:readonly string[]=[
 'src/research/index.ts',
 'src/research/types.ts',
 'src/research/catalog.ts',
 'src/research/evidence.ts',
 'src/research/corpus.ts',
 'src/research/split.ts',
 'src/research/recipe.ts',
 'src/research/checks.ts',
 'src/research/verdict.ts',
 'src/research/runner.ts',
 'src/research/recheck.ts',
 'src/research/report.ts',
 'src/research/export.ts',
 'src/research/directions/index.ts',
 'src/research/directions/grid.ts',
 'src/research/directions/control-flow.ts',
 'src/research/directions/abi.ts',
 'src/research/directions/protocol.ts',
 'src/research/directions/geometry.ts',
 'src/research/directions/compatibility.ts',
 'docs/RESEARCH-PROTOCOL.md',
 'contracts/research-direction.schema.json',
 'contracts/research-request.schema.json',
 'contracts/research-result.schema.json',
 'tools/research/audit.py',
 'tools/research/verify-manifest.py',
];

async function noLinks(target:string):Promise<void>{
 const absolute=path.resolve(target),base=path.parse(absolute).root;
 let current=base;
 for(const part of absolute.slice(base.length).split(path.sep).filter(Boolean)){
  current=path.join(current,part);
  try{assert(!(await lstat(current)).isSymbolicLink(),'EXPORT_PATH_INVALID','Export paths must not contain links');}
  catch(error){if((error as NodeJS.ErrnoException).code!=='ENOENT')throw error;}
 }
}

/**
 * Writes the frozen research package.
 *
 * The package pins the product sources it depends on. A lane re-run that
 * changes a pinned product source invalidates the lane: the manifest digest
 * no longer matches the product it claims to come from.
 */
export async function exportResearchReport(store:CaseStore,runId:string,outDir:string):Promise<ResearchExportManifest>{
 const run=await store.getObject<{result:ResearchResultView;request:unknown}>('runs',runId);
 const result=run.result;
 assert(result?.operation==='research_experiment'&&result.result_id===runId,'EXPORT_RESEARCH_INVALID','Invalid research report identity');
 assert(typeof outDir==='string'&&outDir.length>0&&!outDir.includes('\0'),'EXPORT_PATH_INVALID','Export destination is required');
 const destination=path.resolve(outDir);
 await noLinks(destination);
 try{assert((await readdir(destination)).length===0,'EXPORT_DIRECTORY_NOT_EMPTY','Export destination must be absent or empty');}
 catch(error){if((error as NodeJS.ErrnoException).code!=='ENOENT')throw error;}
 await mkdir(destination,{recursive:true});
 await noLinks(destination);
 const resolved=await realpath(destination);
 assert((process.platform==='win32'?resolved.toLowerCase():resolved)===(process.platform==='win32'?destination.toLowerCase():destination),
  'EXPORT_PATH_INVALID','Export destination resolves through an alias');
 const files:ResearchExportFile[]=[];
 let bytesWritten=0;
 const write=async(relative:string,value:string|Uint8Array,media:string):Promise<void>=>{
  assert(relative.split('/').every((part)=>part!==''&&part!=='.'&&part!=='..'&&!part.includes('\\')&&!part.includes(':')&&!part.includes('\0')),
   'EXPORT_PATH_INVALID','Export relative path is invalid');
  const target=path.resolve(destination,...relative.split('/'));
  assert(target.startsWith(destination+path.sep),'EXPORT_PATH_INVALID','Export file escapes destination');
  await noLinks(path.dirname(target));
  await mkdir(path.dirname(target),{recursive:true});
  await noLinks(path.dirname(target));
  const bytes=typeof value==='string'?Buffer.from(value,'utf8'):Buffer.from(value);
  bytesWritten+=bytes.length;
  assert(bytesWritten<=MAX_BYTES,'EXPORT_BUDGET','Research export exceeds the byte budget');
  await writeFile(target,bytes,{flag:'wx'});
  files.push({relative_path:relative,sha256:sha256(bytes),size_bytes:bytes.length,media_type:media});
 };
 const json=async(relative:string,value:unknown):Promise<void>=>write(relative,JSON.stringify(value,null,2)+'\n','application/json');
 const spec=researchDirection(result.direction_id);
 assert(spec!==null,'EXPORT_RESEARCH_INVALID','The direction specification is no longer available.');
 const productSources:ResearchProductSource[]=[];
 for(const relative of PRODUCT_SOURCE_FILES){
  try{
   const bytes=await readFile(path.join(rootDir,...relative.split('/')));
   productSources.push({path:relative,sha256:sha256(bytes)});
  }catch{/* A missing optional source is recorded as absent rather than invented. */}
 }
 const checks=result.claims.flatMap((claim)=>claim.checks.map((check)=>{
  const registered=spec.claims.find((entry)=>entry.claim_id===claim.claim_id)?.checks.find((entry)=>entry.check_id===check.check_id);
  return {
   claim_id:claim.claim_id,
   check_id:check.check_id,
   statement:check.statement,
   role:check.role,
   derivation:registered?.derivation??null,
   comparator:check.comparator,
   expected:check.expected,
   observed:check.observed,
   passed:check.passed,
   source_roles:check.source_roles,
  };
 }));
 await json('plan.json',spec);
 await json('checks.json',{schema_version:1,direction_id:result.direction_id,plan_sha256:result.identity.plan_sha256,checks});
 await json('receipt.json',result);
 await write('report.md',renderResearchReport(result,spec),'text/markdown');
 /*
  * The run artifacts are copied into the package so that an independent
  * auditor can recompute every observation from the package alone, without
  * reading the case and without re-running the experiment.
  */
 const roles=(run as {artifact_roles?:Record<string,ArtifactRef>}).artifact_roles??{};
 for(const [role,reference] of Object.entries(roles)){
  const bytes=await store.readArtifact(reference);
  const relative='artifacts/'+role.split('/').map((part)=>part.replace(/[^A-Za-z0-9_.-]/g,'_')).join('/')+'.json';
  await write(relative,bytes,'application/json');
 }
 const payload={
  schema_version:1 as const,
  product:'Wirefit' as const,
  report_kind:'research' as const,
  run_id:runId,
  direction_id:result.direction_id,
  verdict:result.verdict,
  plan_sha256:result.identity.plan_sha256,
  frozen_candidate_sha256:result.identity.frozen_candidate_sha256,
  files,
  product_sources:productSources,
 };
 const manifestBytes=Buffer.from(JSON.stringify(payload,null,2)+'\n','utf8');
 await writeFile(path.join(destination,'manifest.json'),manifestBytes);
 const manifestDigest=sha256(manifestBytes);
 await writeFile(path.join(destination,'manifest.sha256'),manifestDigest+'  manifest.json\n',{encoding:'utf8',flag:'wx'});
 return {...payload,manifest_sha256:manifestDigest,output_directory:destination};
}

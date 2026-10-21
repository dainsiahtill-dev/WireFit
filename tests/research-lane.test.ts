import {describe,it,expect,afterEach} from 'vitest';
import {mkdtemp,mkdir,readFile,rm,writeFile} from 'node:fs/promises';
import {existsSync} from 'node:fs';
import {execFile} from 'node:child_process';
import {promisify} from 'node:util';
import {createHash} from 'node:crypto';
import {tmpdir} from 'node:os';
import path from 'node:path';

const execute=promisify(execFile);
const PYTHON=process.platform==='win32'?'python':'python3';
const AUDIT=path.resolve('tools','research','audit.py');
const VERIFY=path.resolve('tools','research','verify-manifest.py');
const roots:string[]=[];
afterEach(async()=>{for(const root of roots)await rm(root,{recursive:true,force:true});});

const sha256=(bytes:Buffer|string):string=>createHash('sha256').update(bytes).digest('hex');

/** Builds a synthetic lane package with one direction. */
async function syntheticLane(observed:number):Promise<string>{
 const root=await mkdtemp(path.join(tmpdir(),'wirefit-lane-'));
 roots.push(root);
 const direction=path.join(root,'D01');
 await mkdir(path.join(direction,'artifacts'),{recursive:true});
 const document={rows:[{id:'a',matched:true},{id:'b',matched:true}]};
 await writeFile(path.join(direction,'artifacts','evaluate.json'),JSON.stringify(document));
 const derivation={kernel:'field_count',artifact_role:'evaluate',path:'rows[*].matched',value:true};
 await writeFile(path.join(direction,'plan.json'),JSON.stringify({
  schema_version:1,
  direction_id:'D01',
  title:'synthetic',
  corpus_role:'synthetic',
  primary_claim_id:'D01.c1',
  split:{unit:'synthetic',key:'id',rule:'synthetic',seed:1,expected_counts:{train:1,validation:1,holdout:1}},
  claims:[{claim_id:'D01.c1',hypothesis:'h',control:'c',data_split:{unit:'synthetic',key:'id',rule:'synthetic',seed:1,expected_counts:{train:1,validation:1,holdout:1}},
   metrics:[{metric_id:'m',description:'d',threshold:2,comparator:'eq',source:'evaluate'}],
   failure_condition:'f',checks:[{check_id:'D01.c1.count',statement:'s',role:'primary',derivation,comparator:'eq',expected:2,source_roles:['evaluate']}],
   not_claimed:['n'],limitations:[]}],
  evidence_pins:[],
 }));
 await writeFile(path.join(direction,'checks.json'),JSON.stringify({
  schema_version:1,direction_id:'D01',plan_sha256:sha256('plan'),
  checks:[{claim_id:'D01.c1',check_id:'D01.c1.count',statement:'s',role:'primary',derivation,comparator:'eq',expected:2,observed,passed:observed===2,source_roles:['evaluate']}],
 }));
 await writeFile(path.join(direction,'receipt.json'),JSON.stringify({verdict:observed===2?'supported':'refuted'}));
 return root;
}

describe('research lane',()=>{
 it('agrees with a recorded observation and disagrees with a tampered one',async()=>{
  const root=await syntheticLane(2);
  const agreed=await execute(PYTHON,[AUDIT,'--lane',root,'--direction','D01'],{cwd:root,maxBuffer:16*1024*1024});
  expect(agreed.stdout).toContain('D01 AGREE');
  expect(agreed.stdout).toContain('1/1 directions agree');
  const tampered=await syntheticLane(5);
  const disagreed=await execute(PYTHON,[AUDIT,'--lane',tampered,'--direction','D01'],{cwd:tampered,maxBuffer:16*1024*1024}).catch((error)=>error as {stdout:string});
  expect(String((disagreed as {stdout?:string}).stdout??'')).toContain('DISAGREE');
 },120000);
 it('keeps the auditor read only and refuses to guess at a missing package',async()=>{
  const source=await readFile(AUDIT,'utf8');
  expect(source).toContain('It is strictly read only');
  expect(source).not.toMatch(/open\([^)]*['"]w['"]/);
  expect(source).not.toMatch(/open\([^)]*['"]a['"]\)/);
  const root=await mkdtemp(path.join(tmpdir(),'wirefit-lane-'));
  roots.push(root);
  const failed=await execute(PYTHON,[AUDIT,'--lane',root,'--direction','D01'],{cwd:root}).catch((error)=>error as {stdout:string});
  expect(String((failed as {stdout?:string}).stdout??'')).toMatch(/ERROR|is missing/);
 },120000);
 it('refuses to run the auditor without an explicit scope',async()=>{
  const failed=await execute(PYTHON,[AUDIT],{cwd:process.cwd()}).catch((error)=>error as {stderr:string});
  expect(String((failed as {stderr?:string}).stderr??'')).toContain('--all');
 },120000);
 it('verifies a manifest and detects a tampered file',async()=>{
  const root=await mkdtemp(path.join(tmpdir(),'wirefit-manifest-'));
  roots.push(root);
  const target=path.join(root,'file.json');
  await writeFile(target,'{"a":1}');
  await writeFile(path.join(root,'manifest.json'),JSON.stringify({
   schema_version:1,product:'Wirefit',lane:'synthetic',
   files:[{relative_path:'file.json',sha256:sha256('{"a":1}'),size_bytes:7}],
   product_sources:[],
  }));
  const verified=await execute(PYTHON,[VERIFY,'--manifest',path.join(root,'manifest.json')],{cwd:root});
  expect(verified.stdout).toContain('identities verified');
  expect(verified.stdout).not.toContain('FAIL');
  await writeFile(target,'{"a":2}');
  const failed=await execute(PYTHON,[VERIFY,'--manifest',path.join(root,'manifest.json')],{cwd:root}).catch((error)=>error as {stdout:string});
  expect(String((failed as {stdout?:string}).stdout??'')).toContain('digest mismatch');
 },120000);
 it('declares the experiment level independence deviation in the protocol',async()=>{
  const protocol=await readFile(path.join('docs','RESEARCH-PROTOCOL.md'),'utf8');
  expect(protocol).toContain('独立性声明');
  expect(protocol).toContain('实验级独立');
  expect(protocol).toContain('目录级共享');
  expect(protocol).toContain('17 个方向');
 });
 it('keeps the source controlled auditor and verifier next to the product',()=>{
  expect(existsSync(AUDIT)).toBe(true);
  expect(existsSync(VERIFY)).toBe(true);
 });
});

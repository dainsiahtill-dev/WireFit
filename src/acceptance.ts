import {readFile,writeFile,mkdir,readdir,stat,realpath,cp,rm,mkdtemp,lstat} from 'node:fs/promises';
import {existsSync,createReadStream} from 'node:fs';
import {createHash} from 'node:crypto';
import path from 'node:path';
import os from 'node:os';
import {fileURLToPath,pathToFileURL} from 'node:url';
import {rootDir,assert,canonical,errorRecord} from './shared.js';
import {runProcess,type ProcessResult} from './process.js';

type GateStatus='PASS'|'FAIL'|'NOT_RUN'|'SKIPPED'|'BLOCKED'|'INCONCLUSIVE';
export interface AcceptanceGate {id:string;title:string;criterion:string}
export interface TestEvidence {file:string;name:string;status:'passed'|'failed'|'skipped'|'pending'|'todo';failure_messages?:string[];duration_ms?:number}
interface GateOptions {benchmark?:any;rea?:any;demos?:any}
interface Rule {selectors:[string,string][];complete:boolean;scope:string;gap?:string}
const rule=(complete:boolean,scope:string,selectors:[string,string][],gap?:string):Rule=>({complete,scope,selectors,gap});
const rules:Record<string,Rule>={
 C01:rule(true,'Offline contracts, verdict injection and operation separation',[['shared.test.ts','compiles all eleven'],['shared.test.ts','rejects injected verdicts'],['shared.test.ts','rejects cross-operation']]),
 C02:rule(false,'Exact BV64 strings and FP32 zero/subnormal evaluation',[['exact-evaluator.test.ts','preserves all 64 bits'],['numeric.test.ts','preserves negative zero']],'No complete dedicated codec round-trip matrix for all required BV64 bit patterns.'),
 C03:rule(false,'DAG topology/type/attrs and direct evaluator validation',[['exact-evaluator.test.ts','rejects cycles'],['exact-operations.test.ts','rejects forged direct-evaluator']],'Dedicated duplicate-ID and invalid-extract adversarial cases are not all independently evidenced.'),
 C04:rule(false,'65,536 BV8 MBA addition input pairs',[['exact-evaluator.test.ts','evaluates MBA addition exhaustively']],'Full 65,536-pair independent enumeration for every listed binary opcode was not run.'),
 C05:rule(false,'Literal opcode boundary cases and exact BV64 arithmetic',[['exact-operations.test.ts','matches literal boundary'],['exact-evaluator.test.ts','preserves all 64 bits']],'No complete fixed-seed BV16/32/64 property campaign artifact.'),
 C06:rule(false,'Full-width large shift counts and literal signed shifts',[['exact-evaluator.test.ts','checks full wide shift'],['exact-solver.test.ts','keeps identically named']],'The complete w-1/w/w+1 matrix for every supported width is not separately evidenced.'),
 C07:rule(true,'Explicit BV/Bool bridges, extensions, concat/extract and synthetic-schema p-code byte offsets',[['exact-evaluator.test.ts','implements signed comparison'],['exact-operations.test.ts','cross-checks every operation'],['rea-pcode.test.ts','checks SUBPIECE']]),
 C08:rule(false,'Writer leases, immutable artifacts and traversal rejection',[['store.test.ts','holds one writer'],['store.test.ts','checks artifact bytes']],'No actual interrupted-write/abrupt-power-loss publication test.'),
 C09:rule(false,'Owned cancellation, late-result rejection and persisted restart state',[['jobs.test.ts','cancels active work'],['jobs.test.ts','marks abandoned jobs'],['mcp.test.ts','runs actual asynchronous']],'CLI Ctrl-C and an abrupt owning-process crash are not both independently exercised.'),
 V01:rule(true,'Real isolated Z3 UNSAT for MBA model, explicit model/domain identity',[['exact-solver.test.ts','real isolated Z3 proves MBA']]),
 V02:rule(true,'Real SAT with independent BigInt counterexample replay',[['exact-solver.test.ts','real isolated Z3 proves MBA']]),
 V03:rule(false,'Translator corruption rejection',[],'Translator-corruption fault injection was not performed.'),
 V04:rule(true,'Nonempty-domain pre-query and DOMAIN_EMPTY rejection',[['exact-solver.test.ts','checks empty domains'],['service.test.ts','persists an empty-domain failure']]),
 V05:rule(true,'Explicit domain containment and no implicit shrinking',[['exact-solver.test.ts','checks empty domains'],['verification.test.ts','checks representable FP32 domain']]),
 V06:rule(true,'Real Z3 same-named intermediates remain separate',[['exact-solver.test.ts','keeps identically named']]),
 V07:rule(false,'Real cancellation and hard-deadline paths',[['exact-solver.test.ts','kills an active worker'],['exact-solver.test.ts','reports a hard deadline']],'A genuine solver UNKNOWN and an injected UNKNOWN component campaign were not run.'),
 V08:rule(true,'Z3 child close on normal/deadline/cancel and continued MCP polling',[['exact-solver.test.ts','real isolated Z3 proves MBA'],['exact-solver.test.ts','kills an active worker'],['exact-solver.test.ts','reports a hard deadline'],['mcp.test.ts','runs actual asynchronous']]),
 V09:rule(false,'Real bounded search and explicit exhaustion',[['exact-search.test.ts','respects candidate budget'],['exact-options.test.ts','uses explicitly supplied Bool constants']],'A broad independent cold-seed expression research set is not available.'),
 V10:rule(true,'Observationally equal candidate is refuted on unseen input',[['exact-search.test.ts','refines a false observational candidate']]),
 V11:rule(false,'Real counterexample-driven candidate refinement',[['exact-search.test.ts','refines a false observational candidate']],'Separate persisted old/new application run versions are not asserted by this component test.'),
 V12:rule(true,'Fresh-process exact/FP32 code and standalone recorded-observation replay',[['exact-solver.test.ts','exports a standalone module which executes all BV8'],['numeric-process.test.ts','executes exported standalone code'],['reporting.test.ts','replays from a copied directory']]),
 V13:rule(false,'Input merge/empty-output rejection and mapping typing',[['exact-evaluator.test.ts','rejects input merging']],'All missing-input/type-difference/subset-uncompared-output reporting cases are not separately evidenced.'),
 V14:rule(false,'Imported verdict rejection and bound export semantic identity',[['exact-evaluator.test.ts','rejects cycles'],['reporting.test.ts','refuses a model whose semantics changed']],'Full cross-Oracle/source verdict-cache nonreuse campaign was not run.'),
 O01:rule(true,'Actual fresh-process independent source-owned fixture Oracle',[['oracle.test.ts','keeps exact typed observations'],['experiments.test.ts','finds boundary100']]),
 O02:rule(true,'Real JSONL protocol and typed-output failures',[['oracle.test.ts','keeps protocol failure'],['oracle.test.ts','retains multiple responses'],['oracle.test.ts','retains wrong request identity'],['oracle.test.ts','retains lossy output type']]),
 O03:rule(true,'Real timeout/crash/domain failures and unattempted collection slots',[['oracle.test.ts','retains partial stdout'],['oracle.test.ts','retains crash diagnostics'],['oracle.test.ts','counts an out-of-domain'],['dataset.test.ts','keeps failed raw calls']]),
 O04:rule(false,'Contradictory imported repeats are nondeterministic',[['dataset.test.ts','records conflicting imported repeats']],'A fresh live nondeterministic target repeat integration test was not run.'),
 O05:rule(true,'File and argv-junction identity changes plus immutable evidence',[['oracle.test.ts','invalidates changed target'],['oracle.test.ts','invalidates a retargeted argument'],['store.test.ts','checks artifact bytes']]),
 O06:rule(true,'Learner rejects holdout and service freezes before access/reuse',[['numeric-fit.test.ts','rejects a holdout split before reading'],['experiments.test.ts','freezes numeric candidate before holdout']]),
 O07:rule(true,'Boundary 100, paired real source-owned Oracle calls',[['experiments.test.ts','finds boundary100']]),
 O08:rule(true,'Zero/partial counts and retained uncompleted original observations',[['verification.test.ts','never reports matched'],['reporting.test.ts','retains uncompleted planned original observations']]),
 O09:rule(false,'Expected fixtures excluded from independent target observations',[['dataset.test.ts','rejects expected fixture rows'],['experiments.test.ts','freezes numeric candidate before holdout']],'Lifted/candidate/history/fresh source count combinations are not all separately exercised.'),
 N01:rule(true,'Independent literal FP32 rounding/zero/subnormal/knots/overflow',[['numeric.test.ts','rounds the product'],['numeric.test.ts','preserves negative zero'],['numeric.test.ts','selects the right interval'],['numeric.test.ts','rejects finite intermediate overflow']]),
 N02:rule(true,'Observation-only bounded affine least squares',[['numeric-fit.test.ts','recovers affine by centered'],['numeric-fit.test.ts','solves the bounded affine']]),
 N03:rule(true,'Real vendored pinned Circuit build/evaluation/parameter backprop',[['numeric-handwired.test.ts','builds a real parameter circuit']]),
 N04:rule(true,'Recomputed host clamp masks and actual source gradients',[['numeric-fit.test.ts','recomputes clamp masks'],['numeric-handwired.test.ts','builds a real parameter circuit']]),
 N05:rule(true,'Actual range declarations checked; adapter makes no grid/bit assumptions',[['numeric-handwired.test.ts','checks actual range contracts']]),
 N06:rule(true,'Stable copied forward and source-gradient snapshots',[['numeric-handwired.test.ts','copies forward and gradient snapshots'],['numeric-handwired.test.ts','reports signed-zero macro']]),
 N07:rule(true,'Explicit signed-zero training discrepancy and exact final export',[['numeric-handwired.test.ts','reports signed-zero macro'],['numeric-process.test.ts','executes exported standalone code'],['reporting.test.ts','exports and strictly typechecks FP32']]),
 N08:rule(false,'Frozen candidates under the fixed research holdout policy',[['numeric-fit.test.ts','fits affine_clamp'],['numeric-fit.test.ts','fits piecewise_affine']],'Full benchmark holdout outcomes determine this gate; smoke success cannot override failures.'),
 N09:rule(true,'Numeric fit dimensions stay separate from SMT model proof',[['experiments.test.ts','freezes numeric candidate before holdout']]),
 N10:rule(true,'Explicit sampled numeric comparison/policy, signed zero and failures',[['experiments.test.ts','compares numeric models only'],['numeric-fit.test.ts','uses immutable explicit policy'],['verification.test.ts','checks representable FP32 domain']]),
 R01:rule(true,'Offline authentication of captured real REA portable JavaScript Evidence',[['rea-live.test.ts','authenticates the real server-exported JavaScript Evidence offline']]),
 R02:rule(false,'Historical real public REA MCP discovery',[],'Requires authenticated captured live discovery and installed-release identity.'),
 R03:rule(true,'Actual captured portable envelope plus canonical/record/profile tampering checks',[['rea-live.test.ts','authenticates the real server-exported'],['rea.test.ts','quarantines changed record'],['rea.test.ts','quarantines noncanonical']]),
 R04:rule(false,'Historical real cross-session retained-vs-inline check',[],'Requires captured real cross-session responses.'),
 R05:rule(false,'Producer unknown/truncation semantics',[['rea.test.ts','keeps declared unknowns']],'Complete transport Evidence pagination with a truncated producer was not exercised.'),
 R06:rule(false,'Persist-before-close recovery is component-tested',[['rea-live.test.ts','persists an authenticated export before closing']],'This lifecycle test is synthetic MCP; the real native continue-from-case gate is blocked.'),
 R07:rule(true,'Captured real replies and synthetic hostile metadata/error parsing',[['rea.test.ts','retains success metadata'],['rea-live.test.ts','authenticates the real server-exported']]),
 R08:rule(false,'Real native Ghidra scalar lift',[],'Actual native provider prerequisites unavailable.'),
 R09:rule(false,'Synthetic actual-schema SSA and RETURN rejection',[['rea-pcode.test.ts','keeps same-storage SSA'],['rea-pcode.test.ts','refuses phi']],'No real native p-code fixture was produced.'),
 R10:rule(false,'Synthetic cutpoint versus producer-hole distinction',[['rea-pcode.test.ts','distinguishes a deliberate cutpoint']],'No real native cutpoint provenance fixture was produced.'),
 R11:rule(true,'Unknown-guard local slices cannot gain target fidelity',[['reporting.test.ts','keeps REA local slices with unknown guards']]),
 R12:rule(false,'Real native lift + original Oracle + exported module',[],'Actual native provider prerequisites unavailable.'),
 R13:rule(false,'Synthetic unsupported side-effect rejection',[['rea-pcode.test.ts','refuses phi']],'Real native instruction side-effect/ABI correspondence is not independently established.'),
 R14:rule(false,'Conditional CFG/phi enhancement',[],'CFG/phi capability is explicitly unsupported; no real incoming-edge-slot gate.'),
 P01:rule(false,'Real CLI import/acquire, Oracle collection/compare, simplify/fit and report export',[['cli.test.ts','runs real foreground case import'],['cli.test.ts','runs actual registered Oracle'],['cli.test.ts','exposes a proved simplified'],['cli-evidence.test.ts','runs the actual installed public REA'],['reporting.test.ts','replays from a copied directory']],'Complete CLI Oracle/REA acquire-to-fit-to-export paths are not all independently exercised.'),
 P02:rule(true,'Official MCP SDK client: schema, asynchronous jobs, cancel, counterexample retrieval',[['mcp.test.ts','advertises thirteen strict tools'],['mcp.test.ts','runs actual asynchronous']]),
 P03:rule(true,'Copied self-contained replay after original case removal',[['reporting.test.ts','replays from a copied directory']]),
 P04:rule(true,'Recorded observations stay separate from unavailable fresh target replay',[['reporting.test.ts','replays from a copied directory'],['reporting.test.ts','exports evidence without claiming candidate replay']]),
 P05:rule(true,'Explicit actual-host/backend/provider support matrix',[]),
 P06:rule(false,'Three demos A/B/C',[],'C requires unavailable real native provider prerequisites.'),
 P07:rule(true,'Single writer, cancellation, persistence recovery and no late result upgrade',[['store.test.ts','holds one writer'],['jobs.test.ts','cancels active work'],['jobs.test.ts','settles a running-state persistence failure'],['jobs.test.ts','does not resolve a queued cancellation']]),
};
export function parseAcceptanceGates(markdown:string):AcceptanceGate[] {
 const found:AcceptanceGate[]=[],ids=new Set<string>();
 for(const line of markdown.split(/\r?\n/)){const match=/^\|\s*([CVONRP]\d{2})\s*\|\s*([^|]+)\|\s*([^|]+)\|\s*$/.exec(line);if(!match)continue;assert(!ids.has(match[1]!), 'ACCEPTANCE_INVALID','Duplicate gate '+match[1]);ids.add(match[1]!);found.push({id:match[1]!,title:match[2]!.trim(),criterion:match[3]!.trim()});}
 assert(found.length>0,'ACCEPTANCE_INVALID','No normative acceptance gates found');return found;
}
export function extractVitestAssertions(report:unknown):TestEvidence[] {
 assert(report&&typeof report==='object'&&Array.isArray((report as any).testResults),'ACCEPTANCE_REPORT_INVALID','Malformed Vitest report');
 const result:TestEvidence[]=[];
 for(const suite of (report as any).testResults){assert(suite&&typeof suite.name==='string'&&Array.isArray(suite.assertionResults),'ACCEPTANCE_REPORT_INVALID','Malformed Vitest suite report');for(const test of suite.assertionResults){assert(typeof test.fullName==='string'&&['passed','failed','skipped','pending','todo'].includes(test.status),'ACCEPTANCE_REPORT_INVALID','Malformed Vitest assertion report');result.push({file:suite.name.replaceAll('\\','/'),name:test.fullName,status:test.status,failure_messages:Array.isArray(test.failureMessages)?test.failureMessages:[],...(typeof test.duration==='number'?{duration_ms:test.duration}:{})});}}
 return result;
}
export function deriveAcceptanceGate(gate:AcceptanceGate,tests:TestEvidence[],options:GateOptions={}) {
 const mapping=rules[gate.id],selectors=mapping?.selectors??[],selected=tests.filter(test=>selectors.some(([file,name])=>test.file.endsWith(file)&&test.name.includes(name)));
 const counts={selected:selected.length,passed:selected.filter(t=>t.status==='passed').length,failed:selected.filter(t=>t.status==='failed').length,skipped:selected.filter(t=>!['passed','failed'].includes(t.status)).length};
 const allSelectors=selectors.length>0&&selectors.every(([file,name])=>selected.some(test=>test.file.endsWith(file)&&test.name.includes(name)&&test.status==='passed'));
 let status:GateStatus=counts.failed?'FAIL':allSelectors?(mapping?.complete?'PASS':'INCONCLUSIVE'):selected.length?'INCONCLUSIVE':'NOT_RUN';
 let reason=counts.failed?'One or more selected real test assertions failed.':status==='PASS'?'All required assertions for the stated scope passed in the recorded run.':mapping?.gap??'Required evidence was not run or not captured.';
 if(gate.id==='N08'&&options.benchmark){const failed=Object.values(options.benchmark.counts??{}).reduce<number>((n:any,c:any)=>n+Number(c.failed??0),0);if(failed>0){status='FAIL';reason=`Preserved research benchmark contains ${failed} failed backend/task configurations under its fixed holdout policy; no retuning performed.`;}}
 if(['R08','R12','P06'].includes(gate.id)&&options.rea?.native_blockers?.length){status='BLOCKED';reason=options.rea.native_blockers.join('; ');}
 if(gate.id==='R02'&&options.rea?.resolved&&options.rea?.capabilities?.real_mcp_discovery==='PASS'){status='PASS';reason='Historical real public-entrypoint REA capture records server identity, 207 tools and target-bound capability probe; raw capture is retained.';}
 if(gate.id==='R04'&&options.rea?.evidence?.cross_session_retained_rejected&&options.rea?.evidence?.cross_session_inline_accepted){status='PASS';reason='Historical actual fresh REA connection rejected retained ID and accepted complete inline Evidence.';}
 if(gate.id==='P05'){status='PASS';reason='This report explicitly separates Windows tested, Linux/macOS not run, native blocked, optional backend outcomes and unsupported CFG/phi.';}
 return {...gate,status,scope:mapping?.scope??gate.title,reason,component_tests:selected,actual_counts:counts,coverage_complete:mapping?.complete===true&&allSelectors};
}

export function benchmarkBoundaryOverlap(benchmark:any) {
 assert(benchmark&&Array.isArray(benchmark.entries),'ACCEPTANCE_REPORT_INVALID','Malformed research benchmark entries');
 const result:{template:string;parameter_seed:number;backend:string;mode:string;planned:number;known_training_inputs:number;unseen_typed_inputs:number}[]=[];
 for(const entry of benchmark.entries){if(!Array.isArray(entry.train_observations)||!Array.isArray(entry.trials))continue;const training=new Set(entry.train_observations.map((row:any)=>canonical(row.inputs)));for(const trial of entry.trials){if(!Array.isArray(trial.holdout_observations))continue;const holdout=new Set<string>(trial.holdout_observations.map((row:any)=>canonical(row.inputs)));const known=[...holdout].filter(key=>training.has(key)).length;result.push({template:entry.template,parameter_seed:entry.parameter_seed,backend:entry.backend,mode:trial.mode,planned:trial.holdout_observations.length,known_training_inputs:known,unseen_typed_inputs:holdout.size-known});}}
 return result;
}
export function compiledEntrypointEvidence(receipt:any,catalog:any) {
 const scope='Previously recorded compiled public CLI/MCP entrypoints, official SDK client and actual isolated Z3';
 if(!receipt||!catalog)return {status:'NOT_RUN' as GateStatus,scope,reason:'No complete compiled entrypoint receipt and catalog were captured.'};
 const names=receipt.mcp?.tools,listed=catalog.tools?.map((tool:any)=>tool.name),counterexample=receipt.mcp?.counterexamples?.data?.counterexample;
 const complete=typeof receipt.node==='string'&&receipt.node.startsWith('v24.')&&receipt.cli?.doctor?.product==='Wirefit'&&receipt.cli?.doctor?.runtime?.node===receipt.node&&Array.isArray(names)&&names.length===13&&new Set(names).size===13&&names.every((name:any)=>typeof name==='string'&&name.startsWith('wirefit_'))&&Array.isArray(listed)&&canonical([...names].sort())===canonical([...listed].sort())&&receipt.mcp?.proofJob?.status==='completed'&&receipt.mcp?.proof?.data?.model_check?.status==='proved'&&receipt.mcp?.refutedJob?.status==='completed'&&receipt.mcp?.refutation?.data?.model_check?.status==='refuted'&&counterexample&&typeof counterexample.inputs==='object'&&typeof counterexample.left_outputs==='object'&&typeof counterexample.right_outputs==='object'&&receipt.mcp?.cancelled?.status==='cancelled'&&receipt.cleanup?.case_writer_released===true;
 return {status:(complete?'PASS':'INCONCLUSIVE') as GateStatus,scope,reason:complete?'Captured Node24 doctor, matching thirteen-tool catalog, completed real proof/refutation, counterexample, cancellation and released writer lease.':'The captured receipt/catalog do not establish every compiled smoke assertion.',counts:{tools:Array.isArray(names)?names.length:0}};
}
interface ArtifactEvidence {relative_path:string;sha256:string;size_bytes:number;media_type:string}
interface CheckRecord {id:string;status:'PASS'|'FAIL';command:{executable:string;args:string[];cwd:string};started_at:string;finished_at:string;exit_code:number|null;duration_ms:number;budget:{timeout_ms:number;max_stdout_bytes:number;max_stderr_bytes:number};stderr_truncated:boolean;outputs:ArtifactEvidence[];error?:unknown}
async function jsonFile<T=any>(file:string):Promise<T>{return JSON.parse(await readFile(file,'utf8')) as T;}
async function fileDigest(file:string):Promise<string>{const hash=createHash('sha256');for await(const chunk of createReadStream(file))hash.update(chunk);return hash.digest('hex');}
async function artifact(file:string,media_type='application/json'):Promise<ArtifactEvidence>{const info=await stat(file);assert(info.isFile()&&Number.isSafeInteger(info.size),'ARTIFACT_INVALID','Evidence must be a regular file with a safe byte count');return {relative_path:path.relative(rootDir,file).split(path.sep).join('/'),sha256:await fileDigest(file),size_bytes:info.size,media_type};}
async function optionalArtifact(file:string,media='application/json'):Promise<ArtifactEvidence|null>{try{return await artifact(file,media);}catch(error){if((error as NodeJS.ErrnoException).code==='ENOENT')return null;throw error;}}
async function npmCli():Promise<string> {
 const candidates=[process.env.npm_execpath,path.join(os.homedir(),'AppData','Roaming','npm','node_modules','npm','bin','npm-cli.js'),path.join(path.dirname(process.execPath),'node_modules','npm','bin','npm-cli.js'),process.platform==='win32'?'C:/Program Files/nodejs/node_modules/npm/bin/npm-cli.js':'/usr/local/lib/node_modules/npm/bin/npm-cli.js'].filter((v):v is string=>typeof v==='string');
 for(const file of candidates)if(existsSync(file))return file;
 throw Error('npm-cli.js not found; run from an installed npm environment');
}
async function packageIdentity(name:string,lock:any) {
 const file=path.join(rootDir,'node_modules',...name.split('/'),'package.json'),pkg=await jsonFile(file),record=lock.packages?.['node_modules/'+name];
 assert(record?.version===pkg.version,'DEPENDENCY_MISMATCH',`${name} installed version differs from package-lock`);
 return {name,version:pkg.version,resolved:true,resolved_url:record.resolved??null,integrity:record.integrity??null,package_json:await artifact(file),license:pkg.license??null};
}
export async function writeUpstreamLock(checks:CheckRecord[]=[],testEvidence:TestEvidence[]=[],reportRef:ArtifactEvidence|null=null) {
 const packageLock=await jsonFile(path.join(rootDir,'package-lock.json')),runtimeLockPath=path.join(rootDir,'.tools/runtime/package-lock.json'),runtimeLock=existsSync(runtimeLockPath)?await jsonFile(runtimeLockPath):null;
 const npm=await npmCli(),npmPackage=await jsonFile(path.resolve(path.dirname(npm),'../package.json'));
 const packages=await Promise.all(['typescript','vitest','tsx','ajv','canonicalize','z3-solver','@modelcontextprotocol/sdk'].map(name=>packageIdentity(name,packageLock)));
 const installed=Object.fromEntries(packages.map(pkg=>[pkg.name,pkg]));
 const handwired=await jsonFile(path.join(rootDir,'vendor/handwired/manifest.json'));
 for(const file of handwired.files){const actual=await artifact(path.join(rootDir,'vendor/handwired',file.path));assert(actual.sha256===file.sha256,'DEPENDENCY_MISMATCH','Vendored Handwired source/notice bytes changed');}
 const reaFile=path.join(rootDir,'artifacts/rea/rea-lock.json'),rea=existsSync(reaFile)?await jsonFile(reaFile):null;
 const reaArchive=rea?.npm?.archive?await optionalArtifact(path.join(rootDir,rea.npm.archive),'application/gzip'):null;
 if(reaArchive)assert(reaArchive.sha256===rea.npm.archive_sha256,'DEPENDENCY_MISMATCH','REA npm archive differs from recorded actual release');
 const passed=(fragment:string)=>testEvidence.some(test=>test.name.includes(fragment)&&test.status==='passed');
 const value={schema_version:1,kind:'wirefit-resolved-local-upstream-lock',resolved_at:new Date().toISOString(),host:{platform:process.platform,arch:process.arch,release:os.release(),tested_native_gate:'Windows x64 local developer environment; Linux native gate blocked/not run'},
  runtime:{node:{resolved:true,version:process.versions.node,executable_path:process.execPath,executable_sha256:await fileDigest(process.execPath),distribution:runtimeLock?.packages?.['node_modules/node-win-x64']??null,distribution_lock:await optionalArtifact(runtimeLockPath),note:'Exact executed image is hashed. npm distribution URL/integrity are recorded as installed, including mirror provenance; no independent Node release-signature verification claimed.'},bun:{selected_for_product_worker:false,resolved:false,reason:'Real pinned Circuit executes on native Node; no Bun compatibility workaround needed.'}},
  package_manager:{name:'npm',version:npmPackage.version,executable_path:npm,executable_sha256:await fileDigest(npm),lockfile:await artifact(path.join(rootDir,'package-lock.json'))},packages:installed,
  lanes:{core:{dependencies_resolved:true,build:checks.find(c=>c.id==='build')?.status??'NOT_RUN',typecheck:checks.find(c=>c.id==='typecheck')?.status??'NOT_RUN'},z3:{resolved:true,package:installed['z3-solver'],source_commit:null,source_commit_status:'not independently resolved from this npm release',assets:await Promise.all(['build/node.js','build/z3-built.js','build/z3-built.wasm','build/kill-threads.js'].map(file=>artifact(path.join(rootDir,'node_modules/z3-solver',file),'application/octet-stream'))),real_sat_unsat_verified:passed('real isolated Z3 proves MBA'),genuine_unknown:'NOT_RUN',worker_policy:'Fresh owned child per request; real hard timeout/cancel tests are separate from genuine UNKNOWN'},
   handwired:{resolved:true,repository:handwired.upstream,commit:handwired.commit,dependency_mode:'unmodified pinned source dependency closure',manifest:await artifact(path.join(rootDir,'vendor/handwired/manifest.json')),files:handwired.files,license:await artifact(path.join(rootDir,'vendor/handwired/LICENSE'),'text/plain'),api_map:await artifact(path.join(rootDir,'docs/handwired-api-map.md'),'text/markdown'),runtime:'Node '+process.versions.node,real_build_evaluate_backprop_verified:passed('builds a real parameter circuit'),local_patches:[],adr:'docs/adr/0002-handwired-numeric-runtime.md'},
   rea:{resolved:rea?.resolved===true,version:rea?.npm?.version??null,commit:rea?.commit??null,source_resolution:rea?.source_resolution??null,package_archive:reaArchive,lock:await optionalArtifact(reaFile),live_discovery:await optionalArtifact(path.join(rootDir,'artifacts/rea/live-discovery.json')),catalog_digest:rea?.server_identity?.catalog?.digests?.tools_sha256??null,tool_count:rea?.server_identity?.catalog?.counts?.mcp_tools??null,portable_fixture:await optionalArtifact(path.join(rootDir,'artifacts/rea/real-js-bundle.json')),capabilities:rea?.capabilities??null,native_blockers:rea?.native_blockers??['REA lane not resolved'],note:'npm provenance payload gitCommit was decoded; its attestation signature was not independently verified. Real native Ghidra lane remains blocked.'},
   mcp_sdk:{resolved:true,package:installed['@modelcontextprotocol/sdk'],actual_official_client_test_verified:passed('runs actual asynchronous Z3 jobs through the official MCP client'),codex_actual_client:'NOT_RUN'}},
  verification:{checks:checks.map(c=>({id:c.id,status:c.status,started_at:c.started_at,finished_at:c.finished_at,outputs:c.outputs})),vitest_report:reportRef,scope:'Dependency resolution and component verification are recorded separately; installed versions do not imply a native end-to-end PASS.'},unresolved:{linux_platform:'NOT_RUN',macos_platform:'NOT_RUN',ghidra_native:'BLOCKED',cfg_phi:'UNSUPPORTED',gpu:'NOT_RUN'}};
 await writeFile(path.join(rootDir,'upstream-lock.json'),JSON.stringify(value,null,2)+'\n','utf8');return value;
}
async function inputHashes():Promise<Record<string,string>> {
 const files:Record<string,string>={};
 const walk=async(relative:string)=>{const absolute=path.join(rootDir,relative);if(!existsSync(absolute))return;assert(!(await lstat(absolute)).isSymbolicLink(),'SOURCE_ALIAS_UNSUPPORTED','Source root may not be a symlink/junction: '+relative);for(const entry of await readdir(absolute,{withFileTypes:true})){const child=relative+'/'+entry.name;if(entry.name==='__pycache__'||entry.name.endsWith('.pyc'))continue;if(entry.isDirectory())await walk(child);else if(entry.isFile())files[child]=await fileDigest(path.join(rootDir,child));else assert(false,'SOURCE_ALIAS_UNSUPPORTED','Acceptance source closure contains a non-regular entry: '+child);}};
 for(const directory of ['src','vendor','contracts','tests','apps','scripts','fixtures','examples'])await walk(directory);
 for(const file of ['package.json','package-lock.json','tsconfig.json','vitest.config.ts','docs/ACCEPTANCE.md','docs/SEMANTICS.md','docs/INTERFACES.md','README.md','CODEX_START.md','wirefit.cmd','wirefit.ps1','LICENSE','NOTICE.md','THIRD_PARTY_NOTICES.md','artifacts/rea/synthetic-lifecycle-server.mjs','artifacts/rea/live-discovery.json','artifacts/rea/real-js-bundle.json','artifacts/rea/rea-lock.json','artifacts/entrypoints/compiled-smoke.mjs','artifacts/entrypoints/compiled-smoke.json','artifacts/entrypoints/mcp-tools.json'])if(existsSync(path.join(rootDir,file)))files[file]=await fileDigest(path.join(rootDir,file));
 return files;
}
async function runCheck(id:string,args:string[],folder:string,options:{cwd?:string;timeout_ms?:number;env?:NodeJS.ProcessEnv}={}):Promise<CheckRecord> {
 const started_at=new Date().toISOString(),cwd=options.cwd??rootDir,budget={timeout_ms:options.timeout_ms??180000,max_stdout_bytes:16*1024*1024,max_stderr_bytes:4*1024*1024};let execution:ProcessResult|undefined,failure:unknown;
 try{execution=await runProcess(process.execPath,args,{cwd,env:options.env,...budget});}catch(error){failure=error;}
 const finished_at=new Date().toISOString(),detail=failure&&typeof failure==='object'?(failure as any).details:undefined;
 const stdout=execution?.stdout??detail?.stdout??'',stderr=execution?.stderr??detail?.stderr??'';
 const stdoutFile=path.join(folder,id+'.stdout.log'),stderrFile=path.join(folder,id+'.stderr.log');await writeFile(stdoutFile,stdout,'utf8');await writeFile(stderrFile,stderr,'utf8');
 const record:CheckRecord={id,status:!failure&&execution?.code===0?'PASS':'FAIL',command:{executable:process.execPath,args,cwd},started_at,finished_at,exit_code:execution?.code??detail?.code??null,duration_ms:execution?.duration_ms??Date.parse(finished_at)-Date.parse(started_at),budget,stderr_truncated:execution?.stderr_truncated??detail?.stderr_truncated??false,outputs:[await artifact(stdoutFile,'text/plain'),await artifact(stderrFile,'text/plain')],...(failure?{error:errorRecord(failure,'acceptance-command')}:{})};
 const recordFile=path.join(folder,id+'.command.json');await writeFile(recordFile,JSON.stringify({...record,...(detail?{captured_failure_details:detail}:{})},null,2)+'\n','utf8');record.outputs.push(await artifact(recordFile));return record;
}
export {runCheck as runAcceptanceCheck};
async function installSmoke(folder:string):Promise<{status:GateStatus;checks:CheckRecord[];temporary_directory:string;cleanup:string}> {
 const tempRoot=path.join(rootDir,'.tmp');await mkdir(tempRoot,{recursive:true});const workspace=await realpath(rootDir),tempAbsolute=await realpath(tempRoot);assert(tempAbsolute.startsWith(workspace+path.sep)&&!(await lstat(tempRoot)).isSymbolicLink(),'INSTALL_PATH_INVALID','Install smoke temporary root must remain inside the workspace');const destination=await mkdtemp(path.join(tempAbsolute,'acceptance-install-')),checks:CheckRecord[]=[];
 let cleanup='not_attempted';
 try {
  for(const entry of ['src','vendor','contracts','apps','scripts','examples','fixtures','LICENSE','README.md','THIRD_PARTY_NOTICES.md','NOTICE.md','upstream-lock.json','package.json','package-lock.json','tsconfig.json'])if(existsSync(path.join(rootDir,entry)))await cp(path.join(rootDir,entry),path.join(destination,entry),{recursive:true,errorOnExist:true});
  const env={...process.env};const previousPath=Object.entries(env).find(([key])=>key.toLowerCase()==='path')?.[1]??'';for(const key of Object.keys(env))if(key.toLowerCase()==='path')delete env[key];env.PATH=path.dirname(process.execPath)+path.delimiter+previousPath;
  checks.push(await runCheck('install-ci',[await npmCli(),'ci','--ignore-scripts','--no-audit','--no-fund'],folder,{cwd:destination,env,timeout_ms:300000}));
  if(checks.at(-1)!.status==='PASS')checks.push(await runCheck('install-build',[await npmCli(),'run','build'],folder,{cwd:destination,env}));
  if(checks.at(-1)!.status==='PASS')checks.push(await runCheck('install-doctor',[await npmCli(),'run','doctor'],folder,{cwd:destination,env,timeout_ms:30000}));
 } finally {
  const resolved=await realpath(destination),allowed=await realpath(tempRoot);
  assert(resolved.startsWith(allowed+path.sep+'acceptance-install-'),'CLEANUP_PATH_INVALID','Install smoke cleanup escaped its unique workspace directory');
  assert(!(await lstat(destination)).isSymbolicLink(),'CLEANUP_PATH_INVALID','Install smoke cleanup target changed into a symlink');await rm(resolved,{recursive:true,force:true});cleanup='removed verified unique workspace temporary directory';
 }
 return {status:checks.length===3&&checks.every(c=>c.status==='PASS')?'PASS':'FAIL',checks,temporary_directory:destination,cleanup};
}
function markdownEscape(value:string):string{return value.replaceAll('|','\\|').replace(/[\r\n]+/g,' ');}

export async function runAcceptance(flags:string[]=[]) {
 const allowed=new Set(['--demos','--install-smoke','--help']);assert(flags.every(flag=>allowed.has(flag))&&new Set(flags).size===flags.length,'ACCEPTANCE_USAGE','Use --demos and/or --install-smoke; unknown/repeated flags rejected');
 if(flags.includes('--help')){process.stdout.write('Wirefit acceptance: npm run acceptance -- [--demos] [--install-smoke]\nRecords all normative gates, real logs and explicit missing/blocked evidence. A failed empirical recovery remains FAIL.\n');return null;}
 assert(process.versions.node.split('.')[0]==='24','RUNTIME_REQUIRED','Acceptance must execute with the pinned Node24 runtime');
 const started_at=new Date().toISOString(),acceptanceRoot=path.join(rootDir,'artifacts/acceptance');await mkdir(acceptanceRoot,{recursive:true});const folder=await mkdtemp(path.join(acceptanceRoot,'run-'+started_at.replace(/[^0-9]/g,'')+'-')),runId=path.basename(folder);
 const host={platform:process.platform,arch:process.arch,os_release:os.release(),node:process.versions.node,cpu:os.cpus()[0]?.model??null,cpu_count:os.cpus().length};
 const hashes=await inputHashes(),gateDefinitions=parseAcceptanceGates(await readFile(path.join(rootDir,'docs/ACCEPTANCE.md'),'utf8'));
 assert(gateDefinitions.length===63,'ACCEPTANCE_INVALID','Normative acceptance gate count changed; update evidence mapping explicitly');
 const sourceSnapshot=path.join(folder,'input-hashes.json');await writeFile(sourceSnapshot,JSON.stringify(hashes,null,2)+'\n','utf8');const inputRef=await artifact(sourceSnapshot);
 const checks:CheckRecord[]=[];
 checks.push(await runCheck('build',[path.join(rootDir,'node_modules/typescript/bin/tsc'),'-p','tsconfig.json'],folder));
 checks.push(await runCheck('typecheck',[path.join(rootDir,'node_modules/typescript/bin/tsc'),'-p','tsconfig.json','--noEmit'],folder));
 const vitestFile=path.join(folder,'vitest.json');checks.push(await runCheck('vitest',[path.join(rootDir,'node_modules/vitest/vitest.mjs'),'run','--reporter=json','--outputFile='+vitestFile],folder,{timeout_ms:300000}));
 let testEvidence:TestEvidence[]=[],reportError:unknown=null;const reportRef=await optionalArtifact(vitestFile);
 if(reportRef){try{testEvidence=extractVitestAssertions(await jsonFile(vitestFile));}catch(error){reportError=errorRecord(error,'acceptance-report');}}
 else reportError={code:'REPORT_MISSING',message:'Vitest did not produce a JSON report'};
 const benchmarkPath=path.join(rootDir,'artifacts/acceptance/handwired-benchmark.json'),benchmark=existsSync(benchmarkPath)?await jsonFile(benchmarkPath):null;
 const reaPath=path.join(rootDir,'artifacts/rea/rea-lock.json'),rea=existsSync(reaPath)?await jsonFile(reaPath):null;
 let demoRecord:CheckRecord|null=null,demos:any=null;
 if(flags.includes('--demos')){
  demoRecord=await runCheck('demos',[path.join(rootDir,'dist/src/demo.js')],folder,{timeout_ms:300000});checks.push(demoRecord);
  const demoFolder=path.join(rootDir,'artifacts/demo');demos={};
  for(const file of ['demo-a.json','demo-b.json','demo-c.json','summary.json']){const absolute=path.join(demoFolder,file);if(existsSync(absolute)){const info=await stat(absolute);if(info.mtimeMs>=Date.parse(demoRecord.started_at)-1000)demos[file]={data:await jsonFile(absolute),artifact:await artifact(absolute)};}}
 }
 let install:any={status:'NOT_RUN',reason:'Optional clean install smoke was not requested; no installation result is implied.'};
 if(flags.includes('--install-smoke')){try{install=await installSmoke(folder);}catch(error){install={status:'FAIL',error:errorRecord(error,'acceptance-install')};}}
 let dependencies:any,dependencyError:unknown=null;
 try{dependencies=await writeUpstreamLock(checks,testEvidence,reportRef);}catch(error){dependencyError=errorRecord(error,'acceptance-lock');dependencies={status:'FAIL',error:dependencyError};}
 const finalHashes=await inputHashes(),source_changed_during_run=JSON.stringify(Object.entries(hashes).sort())!==JSON.stringify(Object.entries(finalHashes).sort());
 const finalHashPath=path.join(folder,'final-input-hashes.json');await writeFile(finalHashPath,JSON.stringify(finalHashes,null,2)+'\n','utf8');
 const lockRef=await optionalArtifact(path.join(rootDir,'upstream-lock.json'));
 const testCheck=checks.find(check=>check.id==='vitest')!,historicalDiscovery=existsSync(path.join(rootDir,'artifacts/rea/live-discovery.json'))?await jsonFile(path.join(rootDir,'artifacts/rea/live-discovery.json')):null;
 const globalRefs=[inputRef,...checks.flatMap(check=>check.outputs),...(reportRef?[reportRef]:[]),...(lockRef?[lockRef]:[])];
 const gates=await Promise.all(gateDefinitions.map(async definition=>{
  const derived=deriveAcceptanceGate(definition,testEvidence,{benchmark,rea,demos});
  const historical=['R02','R04'].includes(definition.id)&&derived.status==='PASS';
  const refs=[...globalRefs];
  if(definition.id==='N08'&&benchmark)refs.push((await optionalArtifact(benchmarkPath))!);
  if(definition.id.startsWith('R'))for(const file of ['artifacts/rea/rea-lock.json','artifacts/rea/live-discovery.json','artifacts/rea/real-js-bundle.json']){const ref=await optionalArtifact(path.join(rootDir,file));if(ref)refs.push(ref);}
  if(definition.id==='P06'&&demos)for(const entry of Object.values(demos) as any[])refs.push(entry.artifact);
  const status=(dependencyError&&['N03','R02','R03','R04'].includes(definition.id)||source_changed_during_run&&derived.status==='PASS'&&!historical)?'INCONCLUSIVE':derived.status;
  const actuallyRun=derived.component_tests.length>0||historical||definition.id==='P05'||definition.id==='N08'&&benchmark;
  const requests:any[]=historical?[{kind:'historical_real_capture',script:'artifacts/rea/discover.mjs',capture:'artifacts/rea/live-discovery.json'}]:derived.component_tests.length?[{kind:'vitest_assertions',selected:derived.component_tests.map(test=>({file:path.relative(rootDir,test.file).replaceAll('\\','/'),name:test.name})),fault_injected:derived.component_tests.filter(test=>/persistence failure|persisting the request fails|synthetic/i.test(test.name+' '+test.file)).map(test=>test.name)}]:[];
  if(definition.id==='N08'&&benchmark)requests.push({kind:'preserved_empirical_run',artifact:'artifacts/acceptance/handwired-benchmark.json',generated_at:benchmark.generated_at??null,total_ms:benchmark.total_ms??null,scope:benchmark.scope??null});
  return {...derived,status,reason:status!==derived.status?(source_changed_during_run?'Source closure changed during verification; rerun on a stable source snapshot.':'Dependency inventory integrity failed; prior evidence cannot establish the pinned integration.'):derived.reason,command:derived.component_tests.length?testCheck.command:null,requests,started_at:historical?historicalDiscovery?.started_at??null:definition.id==='N08'&&benchmark?null:actuallyRun?testCheck.started_at:null,finished_at:historical?historicalDiscovery?.finished_at??null:definition.id==='N08'&&benchmark?benchmark.generated_at??null:actuallyRun?testCheck.finished_at:null,host,dependency_identities:lockRef,input_hashes:{normative:hashes['docs/ACCEPTANCE.md'],source_snapshot:inputRef.sha256},output_artifacts:refs,empirical_counts:definition.id==='N08'?benchmark?.counts??null:null};
 }));
 const counts=Object.fromEntries((['PASS','FAIL','NOT_RUN','SKIPPED','BLOCKED','INCONCLUSIVE'] as GateStatus[]).map(status=>[status,gates.filter(gate=>gate.status===status).length]));
  const entrypointReceiptPath=path.join(rootDir,'artifacts/entrypoints/compiled-smoke.json'),entrypointCatalogPath=path.join(rootDir,'artifacts/entrypoints/mcp-tools.json');
 const entrypointReceipt=existsSync(entrypointReceiptPath)?await jsonFile(entrypointReceiptPath):null,entrypointCatalog=existsSync(entrypointCatalogPath)?await jsonFile(entrypointCatalogPath):null;
 const entrypointArtifacts=(await Promise.all([optionalArtifact(entrypointReceiptPath),optionalArtifact(entrypointCatalogPath),optionalArtifact(path.join(rootDir,'artifacts/entrypoints/compiled-smoke.mjs'),'text/javascript')])).filter((value):value is ArtifactEvidence=>value!==null);
 const supplements=[
  {id:'P01.P02.compiled_entrypoints',...compiledEntrypointEvidence(entrypointReceipt,entrypointCatalog),recorded_at:entrypointReceipt?.recorded_at??null,artifacts:entrypointArtifacts,request:{kind:'preserved_real_compiled_smoke',script:'artifacts/entrypoints/compiled-smoke.mjs'},note:'Previously captured evidence, not rerun by this acceptance command; not an actual Codex client or native REA gate.'},
  {id:'V07.genuine_unknown',status:'NOT_RUN',scope:'Actual solver-generated UNKNOWN',reason:'No observed real UNKNOWN is claimed; real hard deadline/cancellation evidence is recorded separately.'},
  {id:'V07.injected_unknown',status:'NOT_RUN',scope:'Injected UNKNOWN handler component campaign',reason:'No dedicated UNKNOWN injection was performed.'},
  {id:'P02.codex_actual_client',status:'NOT_RUN',scope:'Actual Codex application MCP client',reason:'Official SDK client integration was run; the Codex UI/client itself was not available as a test harness.'},
  {id:'platform.windows_x64',status:process.platform==='win32'&&process.arch==='x64'&&checks.every(c=>c.status==='PASS')?'PASS':'INCONCLUSIVE',scope:'Current host only',reason:'Status derives from recorded real commands on this host.'},
  {id:'platform.linux_x64',status:'NOT_RUN',scope:'Linux runtime/native provider lane',reason:'No Linux host execution in this workspace.'},
  {id:'platform.macos',status:'NOT_RUN',scope:'macOS runtime/provider lane',reason:'No macOS host execution in this workspace.'},
  {id:'capability.cfg_phi',status:'NOT_RUN',scope:'Conditional CFG/phi enhancement',reason:'Explicitly unsupported until real incoming-edge-slot and control-flow gates can be established.'},
  {id:'install.clean',...install},
 ];
 for(const [id,file] of [['A','demo-a.json'],['B','demo-b.json'],['C','demo-c.json']] as const){const receipt=demos?.[file];supplements.push({id:'P06.demo'+id,status:receipt?.data?.status??'NOT_RUN',scope:receipt?.data?.scope??'Demo '+id,reason:receipt?.data?.reason??(receipt?'Actual fresh demo receipt retained':'--demos was not run or a fresh receipt was not produced')} as any);}
 const finished_at=new Date().toISOString(),harnessFailed=source_changed_during_run||checks.some(check=>check.status==='FAIL')||reportError!==null||dependencyError!==null||install.status==='FAIL';
 const result={schema_version:1,run_id:runId,started_at,finished_at,host,harness_status:harnessFailed?'FAIL':'PASS',release_status:gates.every(gate=>gate.status==='PASS')?'PASS':'PARTIAL',status_counts:counts,checks,vitest_report:reportRef,report_error:reportError,source_changed_during_run,final_input_hashes:await artifact(finalHashPath),dependency_error:dependencyError,dependencies:lockRef,input_hashes:inputRef,gates,supplements,demos,benchmark:await optionalArtifact(benchmarkPath),benchmark_boundary_overlap:benchmark?benchmarkBoundaryOverlap(benchmark):null,notes:['Every normative gate is retained. A component test pass is scoped and does not imply an unsupported native integration pass.','The preserved numerical benchmark has genuine recovery failures. Each 10-point holdout also contains 3 training boundary inputs; only 7 typed inputs are unseen. No holdout-driven retuning or speed advantage is claimed.','Historical real REA captures, synthetic MCP fault tests, native provider blocks and new full-suite execution are separate evidence classes.']};
 const matrixPath=path.join(folder,'matrix.json');await writeFile(matrixPath,JSON.stringify(result,null,2)+'\n','utf8');const matrixRef=await artifact(matrixPath);
 const latest={run_id:runId,matrix:matrixRef,harness_status:result.harness_status,release_status:result.release_status,status_counts:counts};await writeFile(path.join(rootDir,'artifacts/acceptance/latest.json'),JSON.stringify(latest,null,2)+'\n','utf8');
 const lines=['# Wirefit 实际验收记录','',`运行：${runId}。开始 ${started_at}，结束 ${finished_at}。`,`主机：${host.platform}/${host.arch}，Node ${host.node}。`, `命令执行状态：${result.harness_status}；完整规范交付状态：${result.release_status}。`, '',`完整机器可读证据：[matrix.json](../${matrixRef.relative_path})。依赖身份：[upstream-lock.json](../upstream-lock.json)。`, '', '门禁状态来自真实执行日志、具体断言与保留的历史捕获。INCONCLUSIVE 表示仅部分组件已覆盖；BLOCKED 和 NOT_RUN 不计入 PASS。', '', '| Gate | Status | 已验证范围 | 限制或原因 |','| --- | --- | --- | --- |',...gates.map(gate=>`| ${gate.id} | ${gate.status} | ${markdownEscape(gate.scope)} | ${markdownEscape(gate.reason)} |`),'','## 已知缺口','', '- 真实 Ghidra/Java/native decompiler 前提未满足，R08/R12 与演示 C 保持 BLOCKED。','- Linux/macOS、真实 solver UNKNOWN、实际 Codex 客户端与 CFG/phi 不冒充已运行。','- 保留的研究基准每10个 holdout 点中有3个训练边界复查点，只有7个未见 typed 输入；不把全部10点称作独立未见样本。',benchmark?('- 固定数值基准：reference '+benchmark.counts?.reference?.passed+'/'+benchmark.counts?.reference?.planned+'，Handwired '+benchmark.counts?.handwired?.passed+'/'+benchmark.counts?.handwired?.planned+'；失败记录保留，不声称速度收益。'):'- 未找到固定数值研究基准，不能声称恢复率或性能收益。',`- 干净安装 smoke：${install.status}。`, '', '每个 gate 的命令、请求、时间、主机、依赖身份、输入摘要、输出引用、计数与具体失败信息见 matrix.json；完整 Vitest JSON 与 stdout/stderr 均保留。',''];
 await writeFile(path.join(rootDir,'docs/ACCEPTANCE-RESULTS.md'),lines.join('\n'),'utf8');
 process.stdout.write(JSON.stringify(latest)+'\n');if(harnessFailed||counts.FAIL!>0)process.exitCode=1;return result;
}
const invoked=process.argv[1]&&pathToFileURL(path.resolve(process.argv[1])).href===import.meta.url;
if(invoked)runAcceptance(process.argv.slice(2)).catch(error=>{process.stderr.write(JSON.stringify({status:'FAIL',error:errorRecord(error,'acceptance')})+'\n');process.exitCode=1;});










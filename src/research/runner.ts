import {assert,errorRecord,hashObject,id,rootDir,sha256,WirefitError} from '../shared.js';
import type {CaseStore} from '../store.js';
import type {JobState} from '../jobs.js';
import type {ArtifactRef,StructuredError} from '../types.js';
import {CorpusLoader,CORPUS_UNITS} from './corpus.js';
import {selectPath} from './recipe.js';
import {EvidenceResolver} from './evidence.js';
import {evaluateChecks} from './checks.js';
import {notRunVerdict,verdictClaim,verdictDirection} from './verdict.js';
import {SplitGuard,detectHoldoutLeak} from './split.js';
import {researchDirection} from './catalog.js';
import {directionImplementation} from './directions/index.js';
import {recheckResearchRun} from './recheck.js';
import type {
 DevelopContext,
 DirectionId,
 EvaluateContext,
 EvidencePin,
 FrozenCandidate,
 ResearchCheck,
 ResearchClaim,
 ResearchDirectionSpec,
 ResearchRequest,
 ResearchVerdict,
} from './types.js';

interface PhaseRecord{
 phase:'plan'|'develop'|'freeze'|'evaluate'|'recheck';
 started_at:string;
 finished_at:string|null;
 status:'completed'|'failed'|'skipped';
}

interface ClaimOutcome{
 claim_id:string;
 verdict:ResearchVerdict;
 reason:string;
 checks:ResearchCheck[];
 errors:{code:string;message:string;check_id:string;claim_id:string}[];
}

const COMMON_NOT_CLAIMED:readonly string[]=[
 'Does not claim that the recovered behaviour equals the original implementation.',
 'Does not claim whole-program equivalence for any protected binary.',
 'Does not claim that the recovered candidate is runnable.',
 'Does not claim that a natural application input was exercised.',
];

function now():string{return new Date().toISOString();}

function blocker(code:string,message:string):{code:string;message:string;}{return {code,message};}

/**
 * Loads the row identifiers of a corpus unit.
 * The identifiers are only identifiers: no row content is read here.
 */
async function unitRowIds(corpus:CorpusLoader,unit:string):Promise<string[]>{
 const definition=CORPUS_UNITS[unit];
 assert(definition!==undefined,'SPLIT_SOURCE_UNKNOWN','Unknown corpus unit: '+unit);
 if(definition.kind==='jsonl'){
  const rows=await corpus.jsonl<Record<string,unknown>>(definition.role);
  return rows.map((row,index)=>rowIdentifier(row,definition.id_field,index));
 }
 const document=await corpus.json(definition.role);
 const selected=selectPath(document,definition.path??'');
 return selected.map((node,index)=>rowIdentifier(node,definition.id_field,index));
}

/**
 * A row identifier.
 *
 * A corpus unit whose path already selects the identifier yields strings; a
 * unit whose path selects objects uses the declared identifier field; a unit
 * without an identifier field falls back to the array index.
 */
function rowIdentifier(node:unknown,idField:string|undefined,index:number):string{
 if(typeof node==='string'){
  assert(node.length>0,'SPLIT_SOURCE_INVALID','Corpus rows must carry a nonempty identifier');
  return node;
 }
 if(node!==null&&typeof node==='object'&&!Array.isArray(node)&&idField!==undefined){
  const value=(node as Record<string,unknown>)[idField];
  assert(typeof value==='string'&&value.length>0,'SPLIT_SOURCE_INVALID','Corpus rows must carry a nonempty identifier');
  return value;
 }
 return '#'+index;
}

/**
 * Runs one research experiment.
 *
 * The five phases are plan, develop, freeze, evaluate and recheck. Their order
 * is fixed and their timestamps are recorded, so an auditor can assert that
 * the plan predates the run and that the holdout stayed out of development.
 */
export async function runResearchExperiment(
 store:CaseStore,
 request:ResearchRequest,
 job:JobState,
 signal:AbortSignal,
):Promise<{result_id:string;status:'completed'|'failed'|'cancelled';error?:StructuredError}>{
 const result_id=id('research_result');
 const phases:PhaseRecord[]=[];
 const artifacts:ArtifactRef[]=[];
 const evidencePins:EvidencePin[]=[];
 const limitations:string[]=[];
 const blockers:{code:string;message:string;}[]=[];
 const claimOutcomes:ClaimOutcome[]=[];
 let loadedSpec:ResearchDirectionSpec|null=null;
 let plan_sha256='';
 let candidate_sha256='';
 let holdout_sha256='';
 let rowCounts={train:0,validation:0,holdout:0};
 let error:StructuredError|null=null;
 let jobStatus:'completed'|'failed'|'cancelled'='completed';
 const checkCancelled=():void=>{
  if(signal.aborted)throw signal.reason instanceof WirefitError?signal.reason:new WirefitError('CANCELLED','Research experiment cancelled');
 };
 const phase=(name:PhaseRecord['phase']):PhaseRecord=>{
  const record:PhaseRecord={phase:name,started_at:now(),finished_at:null,status:'completed'};
  phases.push(record);
  return record;
 };
 const resolver=new EvidenceResolver({rootDir});
 const corpus=new CorpusLoader(resolver);
 const roleArtifacts:Record<string,ArtifactRef>={};
 const putArtifact=async(value:unknown,media='application/json'):Promise<ArtifactRef>=>{
  const reference=await store.putJson(value);
  artifacts.push(reference);
  return reference;
 };
 try{
  // ---- plan ----------------------------------------------------------
  const planPhase=phase('plan');
  const loaded=researchDirection(request.direction_id);
  assert(loaded!==null,'DIRECTION_UNKNOWN','Unknown research direction: '+request.direction_id);
  const spec:ResearchDirectionSpec=loaded;
  loadedSpec=loaded;
  validateDirectionSemantics(spec);
  for(const pin of spec.evidence_pins)corpus.declare(pin);
  plan_sha256=hashObject(spec);
  const unit=CORPUS_UNITS[spec.split.unit];
  assert(unit!==undefined,'SPLIT_SOURCE_UNKNOWN','Unknown corpus unit: '+spec.split.unit);
  assert(spec.evidence_pins.some((pin)=>pin.role===unit.role),
   'SPLIT_SOURCE_UNDECLARED','The direction does not declare the evidence role of its split unit: '+unit.role);
  const rowIds=await unitRowIds(corpus,spec.split.unit);
  const guard=new SplitGuard(spec.split.seed,rowIds);
  guard.verifyExpectedCounts(spec.split.expected_counts);
  rowCounts=guard.counts();
  holdout_sha256=guard.holdoutRowIdsSha256();
  const implementation=directionImplementation(spec.direction_id);
  assert(implementation!==null,'DIRECTION_UNKNOWN','No implementation is registered for '+spec.direction_id);
  planPhase.finished_at=now();

  // ---- develop -------------------------------------------------------
  const developPhase=phase('develop');
  const developArtifacts:{value:unknown;media:string|undefined;}[]=[];
  const developContext:DevelopContext={
   phase:'develop',
   direction_id:spec.direction_id,
   spec,
   split:guard.developView(),
   evidence:resolver,
   corpus,
   budget:request.budget,
   signal,
   putArtifact:async(value,media)=>{
    const reference=await putArtifact(value,media);
    developArtifacts.push({value,media});
    return reference;
   },
   get artifacts(){return artifacts;},
  } as DevelopContext;
  const developed=await implementation.develop(developContext,spec);
  developPhase.finished_at=now();

  // ---- freeze --------------------------------------------------------
  const freezePhase=phase('freeze');
  const frozen:FrozenCandidate={
   direction_id:spec.direction_id,
   candidate_sha256:hashObject(developed.candidate),
   candidate:developed.candidate,
   develop_notes:developed.notes,
  };
  candidate_sha256=frozen.candidate_sha256;
  await putArtifact({kind:'research_freeze',direction_id:spec.direction_id,plan_sha256,frozen_candidate_sha256:frozen.candidate_sha256,develop_notes:developed.notes});
  freezePhase.finished_at=now();

  // ---- evaluate ------------------------------------------------------
  const evaluatePhase=phase('evaluate');
  const leaked=detectHoldoutLeak(developArtifacts,guard.holdoutRows());
  if(leaked.length>0){
   blockers.push(blocker('SPLIT_LEAKAGE',
    'The develop phase artifacts contain holdout row identifiers ('+leaked.slice(0,8).join(', ')+
    (leaked.length>8?' and '+(leaked.length-8)+' more':'')+').'));
  }
  const evaluateContext:EvaluateContext={
   phase:'evaluate',
   direction_id:spec.direction_id,
   spec,
   split:guard.developView(),
   holdout:guard.holdoutRows(),
   evidence:resolver,
   corpus,
   budget:request.budget,
   signal,
   putArtifact,
   get artifacts(){return artifacts;},
  } as EvaluateContext;
  await implementation.evaluate(evaluateContext,spec,frozen);
  await corpus.primeAll();
  for(const [role,document] of corpus.registeredDocuments()){
   if(!role.startsWith('develop/')&&!role.startsWith('evaluate/'))continue;
   const digest=sha256(Buffer.from(JSON.stringify(document,null,2)+'\n','utf8'));
   const match=artifacts.find((reference)=>reference.sha256===digest);
   if(match!==undefined)roleArtifacts[role]=match;
  }
  for(const pin of corpus.observedPins()){
   const previous=evidencePins.find((entry)=>entry.role===pin.role);
   if(previous===undefined)evidencePins.push(pin);
   else Object.assign(previous,pin);
  }
  for(const claim of spec.claims){
   const templates=claim.checks.map((check)=>({
    check_id:check.check_id,
    statement:check.statement,
    role:check.role,
    derivation:check.derivation,
    comparator:check.comparator,
    expected:check.expected,
    source_roles:check.source_roles,
   }));
   const evaluated=evaluateChecks(corpus,templates,claim.claim_id);
   const decision=verdictClaim(evaluated.checks,evaluated.errors,blockers);
   claimOutcomes.push({
    claim_id:claim.claim_id,
    verdict:decision.verdict,
    reason:decision.reason,
    checks:evaluated.checks,
    errors:evaluated.errors,
   });
  }
  evaluatePhase.finished_at=now();

  // ---- recheck -------------------------------------------------------
  const recheckPhase=phase('recheck');
  const rechecked=await recheckResearchRun({corpus,claims:claimOutcomes,spec});
  recheckPhase.finished_at=now();
  if(rechecked.mismatches.length>0){
   blockers.push(blocker('AUDIT_METRIC_MISMATCH',
    'The independent product-side recomputation disagreed with the recorded observations in '+
    rechecked.mismatches.length+' check(s): '+rechecked.mismatches.map((entry)=>entry.check_id).join(', ')+'.'));
   for(const claim of claimOutcomes){
    if(claim.verdict!=='not_run')claim.verdict='inconclusive';
    claim.reason='The recorded observation could not be recomputed from the stored artifacts, so the claim cannot be decided: '+
     rechecked.mismatches.map((entry)=>entry.check_id+' ('+entry.code+')').join(', ')+'.';
   }
  }
  const directionDecision=verdictDirection(claimOutcomes,spec.primary_claim_id,blockers);
  limitations.push(...spec.claims.flatMap((claim)=>claim.limitations));
  limitations.push(...COMMON_NOT_CLAIMED);
 }catch(thrown){
  const actual=signal.aborted&&(!(thrown instanceof WirefitError)||thrown.code!=='TIMEOUT')?thrown:thrown;
  error=errorRecord(actual,'research');
  jobStatus=signal.aborted?'cancelled':'failed';
  const openPhase=phases.find((entry)=>entry.finished_at===null);
  if(openPhase!==undefined){openPhase.finished_at=now();openPhase.status='failed';}
 }
 const decision=claimOutcomes.length===0
  ? {verdict:'not_run' as ResearchVerdict,reason:notRunVerdict().reason}
  : directionVerdict(claimOutcomes,loadedSpec);
 const verdict:ResearchVerdict=decision.verdict;
 const result={
  schema_version:1 as const,
  result_id,
  research_id:request.research_id,
  operation:'research_experiment' as const,
  direction_id:request.direction_id,
  job_status:jobStatus,
  verdict:decision.verdict,
  verdict_reason:decision.reason,
  primary_claim_id:loadedSpec?.primary_claim_id??'',
  claims:(loadedSpec?.claims??[]).map((claim)=>{
   const outcome=claimOutcomes.find((entry)=>entry.claim_id===claim.claim_id);
   return {
    claim_id:claim.claim_id,
    hypothesis:claim.hypothesis,
    control:claim.control,
    data_split:claim.data_split,
    metrics:claim.metrics,
    failure_condition:claim.failure_condition,
    checks:outcome?.checks??[],
    not_claimed:claim.not_claimed,
    limitations:claim.limitations,
    verdict:outcome?.verdict??'not_run',
    verdict_reason:outcome?.reason??notRunVerdict().reason,
   };
  }),
  identity:{
   request_sha256:hashObject(request),
   plan_sha256:plan_sha256||hashObject({empty:true}),
   frozen_candidate_sha256:candidate_sha256||hashObject({empty:true}),
   corpus_row_counts:rowCounts,
   corpus_holdout_row_ids_sha256:holdout_sha256||hashObject({empty:true}),
  },
  counts:{
   planned:rowCounts.train+rowCounts.validation+rowCounts.holdout,
   attempted:claimOutcomes.reduce((total,claim)=>total+claim.checks.length,0),
   completed:claimOutcomes.reduce((total,claim)=>total+claim.checks.length,0),
   matched:claimOutcomes.reduce((total,claim)=>total+claim.checks.filter((check)=>check.role==='primary'&&check.passed).length,0),
   mismatched:claimOutcomes.reduce((total,claim)=>total+claim.checks.filter((check)=>check.role==='primary'&&!check.passed).length,0),
   failed:claimOutcomes.reduce((total,claim)=>total+claim.errors.length,0),
   out_of_domain:0,
  },
  evidence_pins:evidencePins,
  phases,
  artifacts,
  audit:{
   status:'not_run',
   recomputed_at:now(),
   checked_count:0,
   agreed_count:0,
   mismatches:[],
  },
  limitations:[...new Set(limitations)],
  error,
 };
 await store.putObject('runs',result_id,{result,request,artifact_roles:roleArtifacts});
 return {result_id,status:jobStatus==='cancelled'?'cancelled':jobStatus==='failed'?'failed':'completed',...(error?{error}:{})};
}

function directionVerdict(claims:readonly ClaimOutcome[],spec:ResearchDirectionSpec|null):{verdict:ResearchVerdict;reason:string;}{
 if(spec===null)return {verdict:'inconclusive',reason:'The direction specification could not be loaded.'};
 const decision=verdictDirection(claims,spec.primary_claim_id,[]);
 return {verdict:decision.verdict,reason:decision.reason};
}

/**
 * Semantic validation of a direction specification, beyond JSON Schema.
 * A specification that does not satisfy these rules is a specification defect,
 * not a scientific outcome.
 */
export function validateDirectionSemantics(spec:ResearchDirectionSpec):void{
 assert(spec.claims.some((claim)=>claim.claim_id===spec.primary_claim_id),
  'DIRECTION_SPEC_INVALID','The primary claim is not declared among the claims.');
 const ids=new Set<string>();
 for(const claim of spec.claims){
  assert(!ids.has(claim.claim_id),'DIRECTION_SPEC_INVALID','Duplicate claim identifier: '+claim.claim_id);
  ids.add(claim.claim_id);
  assert(claim.not_claimed.length>0||claim.limitations.length>0,
   'DIRECTION_SPEC_INVALID','A claim must declare not_claimed or limitations explicitly.');
  assert(claim.checks.some((check)=>check.role==='negative_control'),
   'DIRECTION_SPEC_INVALID','Every claim must declare at least one negative control check: '+claim.claim_id);
  for(const check of claim.checks){
   assert(check.source_roles.length>0,'DIRECTION_SPEC_INVALID','A check must declare its source roles: '+check.check_id);
   for(const role of check.source_roles)
    assert(spec.evidence_pins.some((pin)=>pin.role===role),
     'DIRECTION_SPEC_INVALID','Check '+check.check_id+' references an undeclared evidence role: '+role);
  }
 }
 const roles=new Set(spec.evidence_pins.map((pin)=>pin.role));
 assert(roles.size===spec.evidence_pins.length,'DIRECTION_SPEC_INVALID','Duplicate evidence role in the direction specification.');
}

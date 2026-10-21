import {WirefitError,assert,rootDir} from '../shared.js';
import type {CaseStore} from '../store.js';
import type {ArtifactRef} from '../types.js';
import {compareObservation,evaluateKernel} from './recipe.js';
import type {RecipeContext} from './recipe.js';
import {CorpusLoader} from './corpus.js';
import {EvidenceResolver} from './evidence.js';
import {researchDirection} from './catalog.js';
import type {ResearchCheck,ResearchDirectionSpec} from './types.js';

export interface RecheckMismatch{
 check_id:string;
 claim_id:string;
 code:string;
 recorded_observed:string;
 recomputed_observed:string;
}

export interface RecheckOutcome{
 checked_count:number;
 agreed_count:number;
 mismatches:RecheckMismatch[];
}

export interface RecheckInput{
 corpus:RecipeContext;
 claims:{claim_id:string;checks:ResearchCheck[]}[];
 spec:ResearchDirectionSpec;
}

/**
 * Recomputes every recorded observation from the registered corpus.
 *
 * This is the convenience layer of the audit: it detects tampering inside one
 * case. The authoritative layer is the independent Python auditor in the
 * research lane, which re-derives the same values from the raw artifacts
 * without sharing any code with this module.
 */
export function recheckResearchRun(input:RecheckInput):RecheckOutcome{
 const mismatches:RecheckMismatch[]=[];
 let checked=0,agreed=0;
 for(const claim of input.claims){
  for(const check of claim.checks){
   checked++;
   let recomputed:string|number|boolean;
   try{
    recomputed=evaluateKernel(input.corpus,check.derivation);
   }catch(error){
    mismatches.push({
     check_id:check.check_id,
     claim_id:claim.claim_id,
     code:error instanceof WirefitError?error.code:'RECIPE_EVALUATION_FAILED',
     recorded_observed:JSON.stringify(check.observed),
     recomputed_observed:'ERROR: '+(error instanceof Error?error.message:String(error)),
    });
    continue;
   }
   if(sameObservation(recomputed,check.observed))agreed++;
   else mismatches.push({
    check_id:check.check_id,
    claim_id:claim.claim_id,
    code:'AUDIT_METRIC_MISMATCH',
    recorded_observed:JSON.stringify(check.observed),
    recomputed_observed:JSON.stringify(recomputed),
   });
  }
 }
 return {checked_count:checked,agreed_count:agreed,mismatches};
}

/** Compares a recomputed observation with a recorded one. */
export function sameObservation(left:string|number|boolean,right:string|number|boolean):boolean{
 if(typeof left==='number'&&typeof right==='number')return left===right;
 if(typeof left!==typeof right)return false;
 return left===right;
}

/**
 * Compares a recomputed observation with the pre-registered expectation.
 * Used by the lane auditor to decide whether a check would still pass.
 */
export function checkWouldPass(
 observed:string|number|boolean,
 expected:string|number|boolean,
 comparator:Parameters<typeof compareObservation>[2],
):boolean{
 return compareObservation(observed,expected,comparator);
}

/** The stored run record of a research experiment. */
export interface StoredResearchRun{
 result:{
  direction_id:string;
  claims:{claim_id:string;checks:ResearchCheck[]}[];
  artifacts:ArtifactRef[];
 };
 request:unknown;
 artifact_roles?:Record<string,ArtifactRef>;
}

/**
 * Recomputes a stored research run from the case.
 *
 * The recomputation reads the run artifacts and the pinned evidence back from
 * the case and the repository, then re-derives every recorded observation.
 * It never re-runs the experiment.
 */
export async function recheckResearchRunFromStore(store:CaseStore,runId:string):Promise<RecheckOutcome>{
 const record=await store.getObject<StoredResearchRun>('runs',runId);
 const spec=researchDirection(record.result.direction_id);
 assert(spec!==null,'DIRECTION_UNKNOWN','Unknown research direction: '+record.result.direction_id);
 const resolver=new EvidenceResolver({rootDir});
 const corpus=new CorpusLoader(resolver);
 for(const pin of spec.evidence_pins)corpus.declare(pin);
 const roles=record.artifact_roles??{};
 for(const [role,reference] of Object.entries(roles)){
  const bytes=await store.readArtifact(reference);
  corpus.registerBinary(role,bytes);
  try{
   corpus.registerDocument(role,JSON.parse(bytes.toString('utf8')) as unknown);
  }catch{/* A non JSON artifact stays binary; the file kernels can still use it. */}
 }
 await corpus.primeAll();
 return recheckResearchRun({corpus,claims:record.result.claims,spec});
}

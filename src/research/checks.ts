import {WirefitError} from '../shared.js';
import {compareObservation,evaluateKernel} from './recipe.js';
import type {RecipeContext} from './recipe.js';
import type {CheckDerivation,CheckComparator,CheckRole,ResearchCheck} from './types.js';

export interface CheckTemplate{
 check_id:string;
 statement:string;
 role:CheckRole;
 derivation:CheckDerivation;
 comparator:CheckComparator;
 expected:string|number|boolean;
 source_roles:string[];
}

export interface EvaluatedCheck{
 check:ResearchCheck;
 error:null;
}

export interface FailedCheck{
 check:null;
 error:{code:string;message:string;check_id:string;claim_id:string};
}

/**
 * Evaluates one pre-registered check against the registered corpus.
 *
 * A check that cannot be evaluated is never silently dropped: the failure is
 * returned so the claim can be downgraded to inconclusive with a concrete
 * blocking code.
 */
export function evaluateCheck(
 ctx:RecipeContext,
 template:CheckTemplate,
 claimId:string,
):EvaluatedCheck|FailedCheck{
 try{
  const observed=evaluateKernel(ctx,template.derivation);
  const passed=compareObservation(observed,template.expected,template.comparator);
  return {
   error:null,
   check:{
    check_id:template.check_id,
    statement:template.statement,
    role:template.role,
    derivation:template.derivation,
    comparator:template.comparator,
    expected:template.expected,
    observed,
    passed,
    source_roles:template.source_roles,
   },
  };
 }catch(error){
  const code=error instanceof WirefitError?error.code:'RECIPE_EVALUATION_FAILED';
  const message=error instanceof Error?error.message:String(error);
  return {check:null,error:{code,message,check_id:template.check_id,claim_id:claimId}};
 }
}

/** Evaluates a claim's whole check list, preserving declaration order. */
export function evaluateChecks(
 ctx:RecipeContext,
 templates:readonly CheckTemplate[],
 claimId:string,
):{checks:ResearchCheck[];errors:FailedCheck['error'][]}{
 const checks:ResearchCheck[]=[];
 const errors:FailedCheck['error'][]=[];
 for(const template of templates){
  const outcome=evaluateCheck(ctx,template,claimId);
  if(outcome.check!==null)checks.push(outcome.check);
  else errors.push(outcome.error);
 }
 return {checks,errors};
}

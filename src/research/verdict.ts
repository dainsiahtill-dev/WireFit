import type {ResearchCheck,ResearchVerdict} from './types.js';

/** An external condition that prevents a claim from being decided. */
export interface VerdictBlocker{code:string;message:string;}

export interface ClaimVerdict{verdict:ResearchVerdict;reason:string;}

const NOT_RUN_REASON='The decision phase did not run, so no claim was evaluated.';

/**
 * Decides one claim from its evaluated checks.
 *
 * The algebra is deliberately asymmetric:
 *
 * - A primary check that does not pass refutes the claim. The expectation was
 *   not observed, so the hypothesis is disproved.
 * - A negative control that *passes* is not a refutation but an
 *   inconclusive: the metric accepted an artifact it was supposed to reject,
 *   so it has no discriminating power.
 * - A negative control that fails is the expected outcome and does not refute
 *   anything. Negative controls are therefore excluded from the refutation
 *   rule, which is the only way "all primary checks pass and the negative
 *   control fails as expected" can be a consistent state.
 */
export function verdictClaim(
 checks:readonly ResearchCheck[],
 errors:readonly {code:string;message:string}[],
 blockers:readonly VerdictBlocker[],
):ClaimVerdict{
 if(blockers.length>0)
  return {verdict:'inconclusive',reason:blockers.map((blocker)=>blocker.code+': '+blocker.message).join('; ')};
 if(errors.length>0)
  return {
   verdict:'inconclusive',
   reason:'A pre-registered check could not be evaluated, so the claim cannot be decided: '+
    errors.map((error)=>error.code+' ('+error.message+')').join('; '),
  };
 const primary=checks.filter((check)=>check.role==='primary');
 const negative=checks.filter((check)=>check.role==='negative_control');
 if(primary.length===0)
  return {verdict:'inconclusive',reason:'The claim declares no primary check, so nothing can refute or support it.'};
 const failed=primary.filter((check)=>!check.passed);
 if(failed.length>0){
  const first=failed[0]!;
  return {
   verdict:'refuted',
   reason:'Pre-registered check '+first.check_id+' failed: observed '+JSON.stringify(first.observed)+
    ' does not satisfy '+first.comparator+' '+JSON.stringify(first.expected)+'.',
  };
 }
 if(negative.length===0)
  return {verdict:'inconclusive',reason:'NO_NEGATIVE_CONTROL: the claim declares no negative control, so the metric has no demonstrated discriminating power.'};
 const passedControl=negative.filter((check)=>check.passed);
 if(passedControl.length>0){
  const first=passedControl[0]!;
  return {
   verdict:'inconclusive',
   reason:'NEGATIVE_CONTROL_DID_NOT_FAIL: negative control '+first.check_id+
    ' passed, so the metric accepted an artifact it was required to reject and has no discriminating power.',
  };
 }
 return {
  verdict:'supported',
  reason:'All '+primary.length+' primary checks passed and '+negative.length+
   ' negative control(s) failed as required.',
 };
}

/** The verdict of a claim that was never evaluated. */
export function notRunVerdict():ClaimVerdict{return {verdict:'not_run',reason:NOT_RUN_REASON};}

/**
 * The direction verdict is the verdict of the primary claim.
 *
 * Secondary claims do not drag the direction verdict down: a direction whose
 * primary claim is supported may still carry a refuted auxiliary claim, and
 * the auxiliary verdict is reported next to it rather than hidden.
 */
export function verdictDirection(
 claims:readonly {claim_id:string;verdict:ResearchVerdict;reason:string}[],
 primaryClaimId:string,
 blockers:readonly VerdictBlocker[],
):ClaimVerdict{
 if(blockers.length>0)
  return {verdict:'inconclusive',reason:blockers.map((blocker)=>blocker.code+': '+blocker.message).join('; ')};
 const primary=claims.find((claim)=>claim.claim_id===primaryClaimId);
 if(!primary)return {verdict:'inconclusive',reason:'The primary claim '+primaryClaimId+' is missing from the result.'};
 return {verdict:primary.verdict,reason:primary.reason};
}

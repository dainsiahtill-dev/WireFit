import type {ArtifactRef,Budget,StructuredError} from './types.js';
import type {Counts} from './verification.js';
export interface ExperimentRequest extends Record<string,unknown>{schema_version:1;experiment_id:string;operation:'simplify'|'compare_models'|'compare_oracles'|'verify_candidate'|'fit_numeric'|'suggest_inputs';budget:Budget}
export interface Dimension<S extends string>{status:S;reason:string;artifacts:ArtifactRef[]}
export interface ExperimentResult {
 schema_version:1;result_id:string;experiment_id:string;operation:ExperimentRequest['operation'];job_status:'completed'|'failed'|'cancelled'|'interrupted';
 identity:{request_sha256:string;model_semantic_hashes:string[];source_envelope_hashes:string[];oracle_binding_hashes:string[];input_plan_sha256:string|null;policy_sha256:string|null;observation_binding_sha256:string|null};
 model_check:Dimension<'proved'|'refuted'|'inconclusive'|'not_run'>&{solver_record:ArtifactRef|null};
 target_validation:Dimension<'matched'|'mismatch'|'partial'|'unavailable'|'not_run'>&{mode:'recorded'|'live'|'mixed'|'none';counts:Counts;source_counts:{kind:string;mode:'recorded'|'live';count:number}[]};
 fit:Dimension<'fitted'|'failed'|'not_run'>&{candidate_model_id:string|null;backend:'analytic_baseline'|'reference'|'handwired'|null;train_counts:Counts;validation_counts:Counts;holdout_counts:Counts};
 sample_comparison:Dimension<'matched'|'mismatch'|'partial'|'not_run'>&{counts:Counts};
 fidelity:Dimension<'unvalidated'|'sampled_match'|'sampled_mismatch'|'unavailable'|'not_applicable'>&{binding_identity_sha256:string|null};
 dependencies:ArtifactRef[];artifacts:ArtifactRef[];limitations:string[];error:StructuredError|null;
}
export interface StoredRun {
 result:ExperimentResult;request:ExperimentRequest;model_ids:string[];candidate_model_id:string|null;dataset_id:string|null;
 observations_artifact:ArtifactRef|null;comparison_artifact:ArtifactRef|null;test_inputs_artifact:ArtifactRef|null;
}

import type {ArtifactRef,Budget} from '../types.js';

/** Direction identifiers of the seventeen pre-registered research directions. */
export type DirectionId =
 | 'D01'|'D02'|'D03'|'D04'|'D05'|'D06'|'D07'|'D08'|'D09'|'D10'|'D11'|'D12'|'D13'|'D14'|'D15'|'D16'|'D17';

export const DIRECTION_IDS:readonly DirectionId[]=[
 'D01','D02','D03','D04','D05','D06','D07','D08','D09','D10','D11','D12','D13','D14','D15','D16','D17'];

/**
 * A research verdict is a completed analysis, not a process state.
 * `refuted` means the pre-registered claim was disproved by the evidence; it is
 * a legitimate scientific outcome and never a process failure.
 */
export type ResearchVerdict='supported'|'refuted'|'inconclusive'|'not_run';

export type EvidenceKind='stable_corpus'|'lane_artifact';

/**
 * A pre-registered evidence pin.
 * `expected_sha256` is mandatory for stable corpora (write-once inputs) and
 * `null` for lane artifacts, which a lane re-run may legitimately overwrite.
 */
export interface EvidencePinSpec{
 role:string;
 path:string;
 expected_sha256:string|null;
 size_bytes:number|null;
 kind:EvidenceKind;
}

/** An evidence pin after resolution: what was actually observed on disk. */
export interface EvidencePin extends EvidencePinSpec{
 observed_sha256_before:string|null;
 observed_sha256_after:string|null;
 verified:boolean;
}

export type CheckKernel=
 | 'row_count'|'distinct_count'|'field_count'|'field_sum'|'field_min'|'field_max'
 | 'all_equal'|'any_equal'|'set_equality'|'file_sha256'|'byte_pattern_count';

export const CHECK_KERNELS:readonly CheckKernel[]=[
 'row_count','distinct_count','field_count','field_sum','field_min','field_max',
 'all_equal','any_equal','set_equality','file_sha256','byte_pattern_count'];

export type CheckComparator=
 'eq'|'ne'|'gte'|'lte'|'gt'|'lt'|'identical_set'|'subset'|'superset';

export const CHECK_COMPARATORS:readonly CheckComparator[]=[
 'eq','ne','gte','lte','gt','lt','identical_set','subset','superset'];

export type CheckRole='primary'|'negative_control';

/**
 * How an auditor re-derives a check value from raw artifacts.
 * Directions provide data only; the recipe kernel provides the algorithm.
 */
export interface CheckDerivation{
 kernel:CheckKernel;
 artifact_role:string;
 path?:string;
 field?:string;
 value?:string|number|boolean;
 second_artifact_role?:string;
 second_path?:string;
 pattern_hex?:string;
}

export interface ResearchCheckTemplate{
 check_id:string;
 statement:string;
 role:CheckRole;
 derivation:CheckDerivation;
 comparator:CheckComparator;
 expected:string|number|boolean;
 source_roles:string[];
}

export interface ResearchCheck extends ResearchCheckTemplate{
 observed:string|number|boolean;
 passed:boolean;
}

/** A metric threshold, fixed before the experiment runs. */
export interface ResearchMetric{
 metric_id:string;
 description:string;
 threshold:string|number|boolean;
 comparator:'eq'|'ne'|'gte'|'lte'|'gt'|'lt';
 source:string;
}

/** Machine-computable data split. The rule and seed belong to the specification. */
export interface ResearchSplit{
 unit:string;
 key:string;
 rule:string;
 seed:number;
 expected_counts:{train:number;validation:number;holdout:number};
}

export interface ResearchClaim{
 claim_id:string;
 hypothesis:string;
 control:string;
 data_split:ResearchSplit;
 metrics:ResearchMetric[];
 failure_condition:string;
 checks:ResearchCheckTemplate[];
 not_claimed:string[];
 limitations:string[];
}

/** The research request: one direction identifier plus a resolved budget. */
export interface ResearchRequest{
 schema_version:1;
 research_id:string;
 direction_id:DirectionId;
 budget:Budget;
}

export interface ResearchDirectionSpec{
 schema_version:1;
 direction_id:DirectionId;
 title:string;
 corpus_role:string;
 primary_claim_id:string;
 split:ResearchSplit;
 claims:ResearchClaim[];
 evidence_pins:EvidencePinSpec[];
}

/**
 * The develop phase sees only train and validation rows.
 * There is deliberately no `holdout` property: an implementation cannot read
 * holdout identifiers through this type even by accident.
 */
export interface SplitView{
 readonly train:readonly string[];
 readonly validation:readonly string[];
}

export type SplitName='train'|'validation'|'holdout';

/** Fields shared by both experiment phases. */
export interface ResearchPhaseContext{
 readonly direction_id:DirectionId;
 readonly spec:ResearchDirectionSpec;
 /** Train and validation row identifiers. Holdout is not reachable here. */
 readonly split:SplitView;
 readonly evidence:import('./evidence.js').EvidenceResolver;
 readonly corpus:import('./corpus.js').CorpusLoader;
 readonly budget:Budget;
 readonly signal:AbortSignal;
 /** Persists a run artifact and returns its immutable reference. */
 putArtifact(value:unknown,media?:string):Promise<ArtifactRef>;
 readonly artifacts:ArtifactRef[];
}

/**
 * The develop context. It has no holdout accessor at all: the holdout row
 * identifiers are only reachable from the evaluate context.
 */
export interface DevelopContext extends ResearchPhaseContext{
 readonly phase:'develop';
}

/** The evaluate context. Only this one carries the holdout identifiers. */
export interface EvaluateContext extends ResearchPhaseContext{
 readonly phase:'evaluate';
 readonly holdout:readonly string[];
}

/** What the develop phase produced: a candidate that will be frozen. */
export interface DevelopOutcome{
 candidate:unknown;
 notes:string[];
}

export interface EvaluateOutcome{
 notes:string[];
}

export interface DirectionImplementation{
 direction_id:DirectionId;
 develop(ctx:DevelopContext,spec:ResearchDirectionSpec):Promise<DevelopOutcome>;
 evaluate(ctx:EvaluateContext,spec:ResearchDirectionSpec,frozen:FrozenCandidate):Promise<EvaluateOutcome>;
}

/** A develop candidate plus its immutable identity, written by the freeze phase. */
export interface FrozenCandidate{
 direction_id:DirectionId;
 candidate_sha256:string;
 candidate:unknown;
 develop_notes:string[];
}

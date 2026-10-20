export type Width = 8 | 16 | 32 | 64;
export type BVType = { kind: 'bv'; width: Width };
export type BoolType = { kind: 'bool' };
export type FP32Type = { kind: 'fp32' };
export type CoreType = BVType | BoolType;
export type ValueType = CoreType | FP32Type;
export type BVValue = BVType & { bits: string };
export type BoolValue = BoolType & { value: boolean };
export type FP32Value = FP32Type & { bits: string };
export type TypedValue = BVValue | BoolValue | FP32Value;
export type CoreValue = BVValue | BoolValue;
export type ValueMap = Record<string, TypedValue>;
export interface Port {
  id: string;
  type: ValueType;
}
export interface Signature {
  inputs: Port[];
  outputs: Port[];
}
export interface Domain {
  constraints: {
    input: string;
    op: 'eq' | 'ne' | 'ule' | 'uge' | 'sle' | 'sge' | 'le' | 'ge';
    value: TypedValue;
  }[];
}
export interface Mapping {
  inputs: { left: string; right: string }[];
  outputs: { left: string; right: string }[];
}
export interface ArtifactRef {
  sha256: string;
  relative_path: string;
  media_type: string;
  size_bytes: number;
}
export interface Scope {
  kind: 'expression' | 'exported_model' | 'trace_slice' | 'behavior_model';
  observation: 'declared_outputs';
  source_completeness: 'complete' | 'partial' | 'unknown' | 'not_applicable';
  execution_guard:
    | { kind: 'all_inputs' }
    | { kind: 'model_bool'; node_id: string }
    | { kind: 'unknown' };
  observation_point: {
    kind: 'expression_output' | 'function_return' | 'local_value';
    source_location: string | null;
  };
}
export interface Provenance {
  source_kind: 'manual' | 'rea_portable' | 'rea_live' | 'oracle_fit';
  source_ref: null | {
    bundle_sha256: string;
    evidence_id: string;
    provider_id: string | null;
    analysis_profile_digest: string | null;
    target_sha256: string | null;
    location: string | null;
  };
  source_artifacts: ArtifactRef[];
  notes: string;
}
export type BvOp =
  | 'const'
  | 'copy'
  | 'bv_add'
  | 'bv_sub'
  | 'bv_mul'
  | 'bv_neg'
  | 'bv_and'
  | 'bv_or'
  | 'bv_xor'
  | 'bv_not'
  | 'bv_eq'
  | 'bv_ne'
  | 'bv_ult'
  | 'bv_ule'
  | 'bv_slt'
  | 'bv_sle'
  | 'bool_and'
  | 'bool_or'
  | 'bool_not'
  | 'bv_nonzero'
  | 'bool_to_bv'
  | 'select'
  | 'bv_shl'
  | 'bv_lshr'
  | 'bv_ashr'
  | 'bv_zext'
  | 'bv_sext'
  | 'bv_extract'
  | 'bv_concat';
export interface BvNode {
  id: string;
  op: BvOp;
  type: CoreType;
  args: string[];
  attrs: { value?: CoreValue; low?: number };
}
interface ModelBase {
  schema_version: 1;
  model_id: string;
  title: string;
  scope: Scope;
  provenance: Provenance;
  domain: Domain;
}
export interface BvModel extends ModelBase {
  kind: 'bv_dag';
  semantics_profile: 'wirefix.bv.total.v1';
  inputs: { id: string; type: CoreType }[];
  nodes: BvNode[];
  outputs: { id: string; type: CoreType; ref: string }[];
}
export interface NumericModel extends ModelBase {
  kind: 'numeric_template';
  semantics_profile: 'wirefix.fp32.templates.v1';
  inputs: { id: string; type: FP32Type }[];
  outputs: { id: string; type: FP32Type }[];
  definition: {
    template: 'affine' | 'affine_clamp' | 'piecewise_affine';
    parameters: Record<string, FP32Value>;
    fixed: { lo?: FP32Value; hi?: FP32Value; knots?: FP32Value[] };
    parameter_bounds: Record<string, { lower: FP32Value; upper: FP32Value }>;
  };
}
export type Model = BvModel | NumericModel;
export interface Budget {
  wall_time_ms: number;
  solver_soft_time_ms: number;
  solver_hard_time_ms: number;
  max_candidates: number;
  max_ast_nodes: number;
  max_oracle_calls: number;
  max_iterations: number;
  seed: number;
}
export type ComparisonPolicy =
  | { kind: 'exact-bv' }
  | { kind: 'bitwise-fp32'; nonfinite: 'reject' }
  | { kind: 'tolerance-fp32'; atol: string; rtol: string; nonfinite: 'reject' };
export interface StructuredError {
  code: string;
  message: string;
  scope: string;
  retryable: boolean;
  artifacts: ArtifactRef[];
}
export interface Observation {
  schema_version: 1;
  observation_id: string;
  sample_id: string;
  request_id: string;
  record_kind: 'observed' | 'expected_fixture';
  source_kind: 'original_target' | 'reference_fixture' | 'lifted_model' | 'candidate_model';
  source_id: string;
  source_identity_sha256: string;
  split: 'train' | 'validation' | 'holdout';
  inputs: ValueMap;
  observed_at: string | null;
  duration_ms: number | null;
  raw_artifacts: ArtifactRef[];
  status:
    | 'ok'
    | 'target_error'
    | 'timeout'
    | 'crash'
    | 'protocol_error'
    | 'out_of_domain'
    | 'nonfinite'
    | 'cancelled';
  outputs: ValueMap;
  error: StructuredError | null;
}

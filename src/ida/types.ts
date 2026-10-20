import type { ArtifactRef, StructuredError } from '../types.js';
import type { BinarySource } from '../binary-files.js';

export type IdaQuery =
  | { kind: 'overview' }
  | { kind: 'functions' | 'strings' | 'types'; pattern?: string; offset?: number; limit?: number }
  | { kind: 'function' | 'xrefs'; address: string }
  | { kind: 'bytes'; address: string; size: number };
export interface IdaAnalysisRequest {
  file: string;
  queries: IdaQuery[];
  timeout_ms?: number;
}
export interface IdaProvider {
  id: 'ida';
  version: string;
  server: string;
  revision: string;
}
export interface IdaConfiguration {
  schema_version: 1;
  command: string;
  args: string[];
  env?: Record<string, string>;
  provider: { version: string; server: string; revision: string };
  lifecycle: 'owned-stdio';
  probe_receipt?: string;
}
export interface IdaSample {
  id: string;
  label: string;
  file: string;
  sha256: string;
  description: string;
  address?: string;
  scope_kind?: 'reference_fixture' | 'derived_window';
  provenance?: { file: string; sha256: string };
}
export interface IdaSourceScope {
  kind: 'reference_fixture' | 'derived_window' | 'unclassified';
  label: string;
  description: string;
  provenance_artifact?: ArtifactRef;
}
export interface IdaCapabilities {
  configured: boolean;
  installed: boolean;
  status: 'not_configured' | 'invalid_configuration' | 'not_probed' | 'verified' | 'probe_failed';
  provider: IdaProvider | null;
  configuration_path: string;
  probe: unknown;
  error?: StructuredError;
  samples: IdaSample[];
  queries: readonly IdaQuery['kind'][];
  read_only: true;
  native_execution: false;
}
export interface IdaQueryResult {
  query: IdaQuery;
  status: 'completed' | 'partial' | 'failed' | 'cancelled';
  data?: Record<string, unknown>;
  error?: StructuredError;
  artifact?: ArtifactRef;
  artifacts: ArtifactRef[];
}
export interface IdaAnalysisResult {
  result_id: string;
  supersedes_result_id?: string;
  operation: 'analyze_ida';
  status: 'completed' | 'partial' | 'failed' | 'cancelled';
  source: BinarySource;
  source_scope?: IdaSourceScope;
  provider: IdaProvider;
  database: {
    input_path: string | null;
    path: string | null;
    source_sha256: string | null;
    identity_verified: boolean;
    imagebase?: string;
    version?: string;
    analysis_completed?: boolean;
  };
  queries: IdaQueryResult[];
  artifacts: ArtifactRef[];
  tool_catalog_artifact?: ArtifactRef;
  error: StructuredError | null;
  limitations: string[];
  validation: { source_unchanged: boolean; runnable_verified: false; whole_program_equivalence: false };
  cleanup: {
    owned: true;
    idb_closed: boolean;
    process_closed: boolean;
    forced: boolean;
    pid: number | null;
    error?: StructuredError;
  };
}

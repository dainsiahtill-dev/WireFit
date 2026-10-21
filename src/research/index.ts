/**
 * The research subsystem.
 *
 * This module is the experiment engine. It is **not** related to
 * `src/web/research.ts`, which is a read-only projection of an earlier
 * research lane onto the web surface. The two live at different layers:
 *
 * - `src/web/research.ts` presents a lane's frozen artifacts.
 * - `src/research/**` runs, audits and reports research experiments.
 *
 * CLI and MCP import from here only.
 */
export * from './types.js';
export {RESEARCH_DIRECTIONS,researchCatalog,researchDirection,LANE_PATHS,STABLE_DIGESTS,STABLE_SIZES} from './catalog.js';
export {RESEARCH_SPLIT_RULE,RESEARCH_SPLIT_SEED,assignSplit,detectHoldoutLeak,splitBucket,SplitGuard} from './split.js';
export {EvidenceResolver,DEFAULT_ALLOWED_ROOTS,MAX_EVIDENCE_BYTES} from './evidence.js';
export {CorpusLoader,CORPUS_UNITS} from './corpus.js';
export {
 compareObservation,
 compareCodePoints,
 encodeScalar,
 evaluateKernel,
 normalizeScalar,
 parsePath,
 selectPath,
 selectValues,
} from './recipe.js';
export {evaluateCheck,evaluateChecks} from './checks.js';
export {verdictClaim,verdictDirection,notRunVerdict} from './verdict.js';
export {runResearchExperiment,validateDirectionSemantics} from './runner.js';
export {recheckResearchRun,sameObservation} from './recheck.js';
export {renderResearchReport} from './report.js';
export {exportResearchReport} from './export.js';
export {directionImplementation,registeredDirectionIds} from './directions/index.js';

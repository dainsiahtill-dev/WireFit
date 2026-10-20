import type {Model,ValueMap,FP32Value} from '../types.js';
import type {JobState} from '../jobs.js';

export interface WebCase {id:string;label:string;path:string;case_id:string;kind:'managed'|'research';writable:boolean;created_at:string|null}
export interface WebProfile {id:string;label:string;kind:'inspect'|'trace'|'unpack';available:boolean}
export interface WebPreset {id:string;label:string;description:string;request:unknown}
export interface WebRun {id:string;operation:string;status:string;created_at?:string|null;result:unknown}
export interface WebCollectionSummary {total:number;shown:number;truncated:boolean}
export interface WebCaseData {case:WebCase;models:Model[];jobs:(JobState&{owned?:boolean})[];runs:WebRun[];datasets:unknown[];oracles:unknown[];collections?:Record<'models'|'jobs'|'runs'|'datasets'|'oracles',WebCollectionSummary>}
export interface LabRequest {inputs:ValueMap;parameters?:Record<string,FP32Value>;sweep?:{input:string;from:number;to:number;steps:number}}
export interface LabResult {outputs:ValueMap;trace:{id:string;value:unknown;op?:string}[];curve:{x:number;y:number|null;error?:string}[];preview:boolean;scope:string}
export type WebTaskRequest = {kind:'experiment';request:unknown}|{kind:'inspect'|'trace'|'unpack';file:string;profileId:string;plan?:unknown}|{kind:'ida';file:string;queries:import('../ida/index.js').IdaQuery[];timeout_ms?:number};
export interface WebExport {id:string;path:string;files:{name:string;size_bytes:number}[];report_url:string}
export interface WebEvidence {id:string;label:string;path:string;sha256:string;size_bytes:number;format:'text'|'hex'|'json';text:string;truncated:boolean}
export interface ResearchFunction {id:string;name:string;address:string;status:string;scope:string;description:string;counts?:Record<string,number>}
export interface ResearchFunctionDetail extends ResearchFunction {sources:WebEvidence[];instructions:{address:string;bytes?:string;text:string}[];graph:{nodes:{id:string;label:string;address?:string;status?:string}[];edges:{from:string;to:string;label?:string}[]};evidence:WebEvidence[];limitations:string[]}
export interface ResearchTrace {id:string;label:string;status:string;pid:number|null;job_id:string|null;event_count:number;source:string;started_at?:string|null}
export interface ResearchEvent {index:number;type:string;label:string;address:string|null;thread_id:number|null;time:string|null;context:Record<string,unknown>|null;stack:unknown;code:unknown;details:unknown;evidence_id?:string}
export interface ResearchValidation {id:string;label:string;kind:string;status:string;scope:string;counts:Record<string,number>;limitations:string[]}
export interface ResearchOverview {title:string;target:{name:string;path:string;sha256:string};status:string;summary:string;metrics:{label:string;value:string;detail:string;tone?:string}[];milestones:{label:string;status:string;detail:string}[];functions:ResearchFunction[];traces:ResearchTrace[];validations:ResearchValidation[];evidence:WebEvidence[];limitations:string[]}
export interface PageQuery {offset?:number;limit?:number;type?:string;q?:string;status?:string}
export interface Page<T> {items:T[];total:number;offset:number;limit:number}
export interface ValidationPage extends Page<Record<string,unknown>> {validation:ResearchValidation}

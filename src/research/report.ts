import type {ResearchDirectionSpec,ResearchVerdict} from './types.js';

/** The result shape produced by the research runner and stored in the case. */
export interface ResearchResultView{
 schema_version:1;
 result_id:string;
 research_id:string;
 operation:'research_experiment';
 direction_id:string;
 job_status:'completed'|'failed'|'cancelled'|'interrupted';
 verdict:ResearchVerdict;
 verdict_reason:string;
 primary_claim_id:string;
 claims:{
  claim_id:string;
  hypothesis:string;
  control:string;
  data_split:{unit:string;key:string;rule:string;seed:number;expected_counts:{train:number;validation:number;holdout:number}};
  metrics:{metric_id:string;description:string;threshold:string|number|boolean;comparator:string;source:string}[];
  failure_condition:string;
  checks:{check_id:string;statement:string;role:'primary'|'negative_control';comparator:string;expected:string|number|boolean;observed:string|number|boolean;passed:boolean;source_roles:string[]}[];
  not_claimed:string[];
  limitations:string[];
  verdict:ResearchVerdict;
  verdict_reason:string;
 }[];
 identity:{
  request_sha256:string;
  plan_sha256:string;
  frozen_candidate_sha256:string;
  corpus_row_counts:{train:number;validation:number;holdout:number};
  corpus_holdout_row_ids_sha256:string;
 };
 counts:{planned:number;attempted:number;completed:number;matched:number;mismatched:number;failed:number;out_of_domain:number};
 evidence_pins:{role:string;path:string;kind:string;expected_sha256:string|null;observed_sha256_before:string|null;observed_sha256_after:string|null;verified:boolean}[];
 phases:{phase:string;started_at:string;finished_at:string|null;status:string}[];
 artifacts:{sha256:string;relative_path:string;media_type:string;size_bytes:number}[];
 audit:{status:string;recomputed_at:string;checked_count:number;agreed_count:number;mismatches:{check_id:string;claim_id:string;code:string}[]};
 limitations:string[];
 error:{code:string;message:string;scope:string;retryable:boolean;artifacts:never[]} | null;
}

const VERDICT_LABELS:Record<ResearchVerdict,string>={
 supported:'支撑（supported）',
 refuted:'证伪（refuted）',
 inconclusive:'不可判定（inconclusive）',
 not_run:'未执行（not_run）',
};

function cell(value:string|number|boolean):string{
 return typeof value==='string'?'`'+value.replaceAll('|','\\|')+'`':String(value);
}

/**
 * Renders the research result as a Chinese Markdown report.
 *
 * The report states the verdict first, then the evidence. Primary checks and
 * negative controls are rendered in separate tables because they have
 * opposite pass semantics: a primary check must pass, a negative control
 * must fail.
 */
export function renderResearchReport(result:ResearchResultView,spec:ResearchDirectionSpec|null):string{
 const lines:string[]=[];
 lines.push('# 研究实验报告');
 lines.push('');
 lines.push('| 项 | 值 |');
 lines.push('| --- | --- |');
 lines.push('| 方向 | '+result.direction_id+(spec===null?'':' '+spec.title)+' |');
 lines.push('| 运行 id | `'+result.result_id+'` |');
 lines.push('| 判定 | **'+VERDICT_LABELS[result.verdict]+'** |');
 lines.push('| 主主张 | `'+result.primary_claim_id+'` |');
 lines.push('| 计划摘要 | `'+result.identity.plan_sha256+'` |');
 lines.push('| 冻结候选摘要 | `'+result.identity.frozen_candidate_sha256+'` |');
 lines.push('| 划分计数 | train '+String(result.identity.corpus_row_counts.train)+
  ' / validation '+String(result.identity.corpus_row_counts.validation)+
  ' / holdout '+String(result.identity.corpus_row_counts.holdout)+' |');
 lines.push('| holdout 行标识摘要 | `'+result.identity.corpus_holdout_row_ids_sha256+'` |');
 lines.push('| 审计状态 | '+result.audit.status+'（复算 '+String(result.audit.agreed_count)+
  ' / '+String(result.audit.checked_count)+' 一致） |');
 lines.push('');
 lines.push('## 判定理由');
 lines.push('');
 lines.push(result.verdict_reason);
 lines.push('');
 lines.push('> `refuted` 是完成的分析结论，不是进程失败。被证伪的主张仍然是有效的科学产出。');
 lines.push('');
 lines.push('## 主张');
 lines.push('');
 for(const claim of result.claims){
  lines.push('### '+claim.claim_id+' — '+VERDICT_LABELS[claim.verdict]);
  lines.push('');
  lines.push('- **假设**：'+claim.hypothesis);
  lines.push('- **对照**：'+claim.control);
  lines.push('- **失败条件**：'+claim.failure_condition);
  lines.push('- **划分**：`'+claim.data_split.unit+'`，种子 '+String(claim.data_split.seed)+
   '，预注册计数 '+String(claim.data_split.expected_counts.train)+'/'+
   String(claim.data_split.expected_counts.validation)+'/'+String(claim.data_split.expected_counts.holdout));
  lines.push('- **判定理由**：'+claim.verdict_reason);
  lines.push('');
  lines.push('预注册度量：');
  lines.push('');
  lines.push('| 度量 | 阈值 | 比较 | 来源 |');
  lines.push('| --- | --- | --- | --- |');
  for(const metric of claim.metrics)
   lines.push('| '+metric.description+' | '+cell(metric.threshold)+' | `'+metric.comparator+'` | `'+metric.source+'` |');
  lines.push('');
  const primary=claim.checks.filter((check)=>check.role==='primary');
  const negative=claim.checks.filter((check)=>check.role==='negative_control');
  if(primary.length>0){
   lines.push('主要检查（必须通过）：');
   lines.push('');
   lines.push('| 检查 | 断言 | 期望 | 观测 | 通过 |');
   lines.push('| --- | --- | --- | --- | --- |');
   for(const check of primary)
    lines.push('| `'+check.check_id+'` | '+check.statement+' | '+cell(check.expected)+' | '+cell(check.observed)+
     ' | '+(check.passed?'是':'否')+' |');
   lines.push('');
  }
  if(negative.length>0){
   lines.push('负控检查（**必须未通过**；通过说明度量没有判别力，判为不可判定）：');
   lines.push('');
   lines.push('| 检查 | 断言 | 期望 | 观测 | 未通过 |');
   lines.push('| --- | --- | --- | --- | --- |');
   for(const check of negative)
    lines.push('| `'+check.check_id+'` | '+check.statement+' | '+cell(check.expected)+' | '+cell(check.observed)+
     ' | '+(check.passed?'否（不成立）':'是')+' |');
   lines.push('');
  }
  if(claim.not_claimed.length>0){
   lines.push('明确不主张：');
   lines.push('');
   for(const text of claim.not_claimed)lines.push('- '+text);
   lines.push('');
  }
  if(claim.limitations.length>0){
   lines.push('限制：');
   lines.push('');
   for(const text of claim.limitations)lines.push('- '+text);
   lines.push('');
  }
 }
 lines.push('## 阶段');
 lines.push('');
 lines.push('| 阶段 | 开始 | 结束 | 状态 |');
 lines.push('| --- | --- | --- | --- |');
 for(const phase of result.phases)
  lines.push('| '+phase.phase+' | '+phase.started_at+' | '+(phase.finished_at??'—')+' | '+phase.status+' |');
 lines.push('');
 lines.push('## 证据钉');
 lines.push('');
 lines.push('| 角色 | 类别 | 路径 | 期望摘要 | 实测摘要（前） | 实测摘要（后） | 已核实 |');
 lines.push('| --- | --- | --- | --- | --- | --- | --- |');
 for(const pin of result.evidence_pins)
  lines.push('| `'+pin.role+'` | '+pin.kind+' | `'+pin.path+'` | '+
   (pin.expected_sha256===null?'—':'`'+pin.expected_sha256+'`')+' | '+
   (pin.observed_sha256_before===null?'—':'`'+pin.observed_sha256_before+'`')+' | '+
   (pin.observed_sha256_after===null?'—':'`'+pin.observed_sha256_after+'`')+' | '+(pin.verified?'是':'否')+' |');
 lines.push('');
 if(result.audit.mismatches.length>0){
  lines.push('## 复算不一致');
  lines.push('');
  lines.push('| 检查 | 主张 | 阻塞码 |');
  lines.push('| --- | --- | --- |');
  for(const mismatch of result.audit.mismatches)
   lines.push('| `'+mismatch.check_id+'` | `'+mismatch.claim_id+'` | `'+mismatch.code+'` |');
  lines.push('');
 }
 if(result.limitations.length>0){
  lines.push('## 全局限制');
  lines.push('');
  for(const text of result.limitations)lines.push('- '+text);
  lines.push('');
 }
 if(result.error!==null){
  lines.push('## 错误');
  lines.push('');
  lines.push('- `'+result.error.code+'`：'+result.error.message);
  lines.push('');
 }
 lines.push('---');
 lines.push('');
 lines.push('本报告由 Wirefit 研究实验引擎生成；判定只由 verifier 产生，工具参数无法设置判定。');
 lines.push('');
 return lines.join('\n');
}

import type {
 EvidencePinSpec,
 ResearchCheckTemplate,
 ResearchClaim,
 ResearchDirectionSpec,
 ResearchMetric,
 ResearchSplit,
} from './types.js';
import {RESEARCH_SPLIT_RULE,RESEARCH_SPLIT_SEED} from './split.js';

/** Repository-relative paths of the frozen research lane evidence. */
export const LANE_PATHS={
 gridObservations:'artifacts/research/vmde/kernel-replay/run-t48nkuwa/observations.jsonl',
 nativeObservations:'artifacts/research/vmde/native-kernel/observations-legacy896.json',
 kernelReturnReview:'artifacts/research/vmde/caller-layout/kernel-return-review.json',
 recoveredGridComparison:'artifacts/research/vmde/caller-layout/recovered-grid-comparison.json',
 referenceVectors:'fixtures/reference_vectors.jsonl',
 businessAudit:'artifacts/research/vmde/business-functions/audit.json',
 algorithmAudit:'artifacts/research/vmde/algorithm-candidates/audit.json',
 gridAudit:'artifacts/research/vmde/grid-kernel-analysis/audit.json',
 gridFacts:'artifacts/research/vmde/grid-kernel-analysis/facts.json',
 inputContract:'artifacts/research/vmde/grid-kernel-analysis/input-contract-candidate.json',
 algorithmFacts:'artifacts/research/vmde/algorithm-candidates/facts.json',
 privateClosureEvidence:'artifacts/research/vmde/private-closure/analysis/evidence.json',
 privateClosureSlices:'artifacts/research/vmde/private-closure/analysis/static-slices.json',
 privateClosureCallpop:'artifacts/research/vmde/private-closure/analysis/062d0356.callpop.json',
 moduleSlotsReceipt:'artifacts/research/vmde/module-slots/run-ezesyU/receipt.json',
 protectedTransitionReview:'artifacts/research/vmde/startup-compat/protected-transition-review.json',
 moduleImageJson:'artifacts/research/vmde/module-image/vmde-main-v2-20261020.json',
 moduleImageBin:'artifacts/research/vmde/module-image/vmde-main-v2-20261020.bin',
 segmentationResult:'artifacts/research/vmde/segmentation-results/run-label-replay-20261020/result.json',
 freshBusinessCode:'artifacts/research/vmde/module-slots/fresh-business-code.json',
 startupCompatReceipt:'artifacts/research/vmde/startup-compat/build/receipt.json',
 startupReview:'artifacts/research/vmde/startup-compat/initial-startup-observation-review.json',
 dumpStartup:'exports/vmde-20261020/dump-startup.json',
 dumpCrash:'exports/vmde-20261020/dump-crash-event.json',
 unpackedVmde:'exports/vmde-20261020/unpacked_vmde.exe',
 candidateExe:'artifacts/research/vmde/startup-compat/build/candidate.exe',
 comparisonLegacy896:'artifacts/research/vmde/native-kernel/comparison-legacy896.json',
 comparisonPositiveControl:'artifacts/research/vmde/native-kernel/comparison-positive-control.json',
 nativeSummary:'artifacts/research/vmde/native-kernel/native-summary.json',
 laneTreeAnchor:'artifacts/research/vmde/module-slots/audit/manifest.json',
} as const;

/** Digests of the write-once stable corpus, verified against the files on disk. */
export const STABLE_DIGESTS={
 unpackedVmde:'50b6bb68637b23d14ee1886ca1e84d944fade255204e70a831f27a3ef4fd6992',
 moduleImageBin:'4933d735ecbb9cb6b070b814518ae982066a5b98dd8394a6bafa1591a153cb20',
 candidateExe:'6fb89bd01d8dfaaba8bd1924393548431b001d3a5c0cdb3f78d0cb1dd6e12169',
} as const;

export const STABLE_SIZES={
 unpackedVmde:14454272,
 moduleImageBin:14561280,
 candidateExe:14454272,
} as const;

function stable(role:string,path:string,key:keyof typeof STABLE_DIGESTS):EvidencePinSpec{
 return {role,path,expected_sha256:STABLE_DIGESTS[key],size_bytes:STABLE_SIZES[key],kind:'stable_corpus'};
}
function lane(role:string,path:string):EvidencePinSpec{
 return {role,path,expected_sha256:null,size_bytes:null,kind:'lane_artifact'};
}
function split(unit:string,counts:{train:number;validation:number;holdout:number}):ResearchSplit{
 return {unit,key:'row_id',rule:RESEARCH_SPLIT_RULE,seed:RESEARCH_SPLIT_SEED,expected_counts:counts};
}
function metric(metric_id:string,description:string,threshold:number,comparator:ResearchMetric['comparator'],source:string):ResearchMetric{
 return {metric_id,description,threshold,comparator,source};
}
function check(
 check_id:string,
 statement:string,
 role:ResearchCheckTemplate['role'],
 derivation:ResearchCheckTemplate['derivation'],
 comparator:ResearchCheckTemplate['comparator'],
 expected:string|number|boolean,
 source_roles:string[],
):ResearchCheckTemplate{
 return {check_id,statement,role,derivation,comparator,expected,source_roles};
}
function claim(
 claim_id:string,
 hypothesis:string,
 control:string,
 data_split:ResearchSplit,
 metrics:ResearchMetric[],
 failure_condition:string,
 checks:ResearchCheckTemplate[],
 limitations:string[],
):ResearchClaim{
 return {claim_id,hypothesis,control,data_split,metrics,failure_condition,checks,not_claimed:[],limitations};
}

const GRID_SPLIT=split('grid',{train:332,validation:177,holdout:387});
const FUNCTION_SPLIT=split('accepted_functions',{train:4,validation:4,holdout:6});
const SCENARIO_SPLIT=split('segmentation_scenarios',{train:4,validation:4,holdout:4});
const LAYOUT_SPLIT=split('kernel_layout_offsets',{train:4,validation:5,holdout:6});
const INTERVAL_SPLIT=split('module_image_intervals',{train:79,validation:50,holdout:94});
const INSTRUCTION_SPLIT=split('private_closure_instructions',{train:128,validation:73,holdout:107});
const EVENT_SPLIT=split('module_slot_events',{train:7,validation:2,holdout:6});

const NOT_CLAIMED_COMMON:readonly string[]=[
 '不主张自然应用输入被复现。',
 '不主张整程序等价。',
 '不主张 runnable_verified。',
 '不主张原实现被复原：等价重构不等于实现复原。',
];

/**
 * The seventeen pre-registered research directions.
 *
 * Every threshold, every split expectation and every negative control is
 * written here, before any experiment runs. The runner freezes this document
 * and records its digest as `plan_sha256`; the auditor recomputes every
 * observation from the same derivation and expectation.
 */
export const RESEARCH_DIRECTIONS:ResearchDirectionSpec[]=[
 {
  schema_version:1,
  direction_id:'D01',
  title:'数值参数恢复：节点计数公式',
  corpus_role:'vmde 0x498a50 网格内核的 896 条稠密标签观测',
  primary_claim_id:'D01.c1',
  split:GRID_SPLIT,
  evidence_pins:[
   lane('grid_observations',LANE_PATHS.gridObservations),
   lane('native_observations',LANE_PATHS.nativeObservations),
   lane('kernel_return_review',LANE_PATHS.kernelReturnReview),
   lane('recovered_grid_comparison',LANE_PATHS.recoveredGridComparison),
  ],
  claims:[
   claim('D01.c1',
    '节点计数可由 计数 = a*(w+h) + b + c*离散特征 精确刻画，且该模型在 holdout 的 387 行上逐行精确复现原生返回计数。',
    '仅使用 (w,h) 的全局仿射基线（不引入任何离散特征）。',
    GRID_SPLIT,
    [
     metric('D01.m1','holdout 精确复现行数',387,'eq','evaluate/d01_holdout'),
     metric('D01.m2','train+validation 精确复现行数',509,'eq','develop/d01_model_search'),
     metric('D01.m3','仿射基线在 holdout 的精确复现行数',0,'lte','evaluate/d01_holdout'),
    ],
    '任一 holdout 行未被精确复现即证伪；若仿射基线在 holdout 上同样达到 387/387，则该度量无判别力，判为 inconclusive。',
    [
     check('D01.c1.holdout_exact','holdout 387 行全部被冻结模型逐行精确复现',
      'primary',{kernel:'field_count',artifact_role:'evaluate/d01_holdout',path:'rows[*].exact',value:true},'eq',387,['grid_observations']),
     check('D01.c1.train_validation_exact','train 与 validation 共 509 行全部被精确复现',
      'primary',{kernel:'field_count',artifact_role:'develop/d01_model_search',path:'fit_rows[*].exact',value:true},'eq',509,['grid_observations']),
     check('D01.c1.lane_corroboration','研究道已记录的 904 条计数复核全部匹配',
      'primary',{kernel:'field_count',artifact_role:'kernel_return_review',path:'groups[*].cases[*].status',value:'matched'},'eq',904,['kernel_return_review']),
     check('D01.c1.affine_baseline_rejected','负控：仅 (w,h) 的仿射基线不得在 holdout 达到 387/387',
      'negative_control',{kernel:'field_count',artifact_role:'evaluate/d01_holdout',path:'rows[*].affine_exact',value:true},'eq',387,['grid_observations']),
    ],
    [
     '计数公式只覆盖 2..16 的合成稠密标签域，不覆盖真实对象的分配、对齐与别名行为。',
     '节点 id 的逐点编号仍依赖前缀顺序，不在本主张范围内。',
    ]),
  ],
 },
 {
  schema_version:1,
  direction_id:'D02',
  title:'未知公式发现：受限文法内的网格程序',
  corpus_role:'vmde 0x498a50 网格内核的 896 条机器输出',
  primary_claim_id:'D02.c1',
  split:GRID_SPLIT,
  evidence_pins:[
   lane('grid_observations',LANE_PATHS.gridObservations),
   lane('kernel_replay_candidate','artifacts/research/vmde/kernel-replay/candidate.py'),
  ],
  claims:[
   claim('D02.c1',
    '在受限文法（≤16 条规则、每条规则一个二项算术表达式）内自动发现的网格程序，可在 holdout 的 387 行上逐字节复现 machine_output。',
    '同预算下的种子化随机搜索。',
    GRID_SPLIT,
    [
     metric('D02.m1','holdout 逐字节精确复现行数',387,'eq','evaluate/d02_holdout'),
     metric('D02.m2','发现程序使用的规则条数',16,'lte','develop/d02_search'),
    ],
    '发现程序在 holdout 上不能逐字节复现 387/387 即证伪；若搜索空间内不存在可复现程序，则该主张被证伪——这是一个关于发现过程的完整分析，不是过程失败。',
    [
     check('D02.c1.holdout_byte_exact','holdout 387 行的 machine_output 被发现程序逐字节复现',
      'primary',{kernel:'field_count',artifact_role:'evaluate/d02_holdout',path:'rows[*].exact',value:true},'eq',387,['grid_observations']),
     check('D02.c1.rule_budget','发现程序的规则条数不超过 16',
      'primary',{kernel:'field_max',artifact_role:'develop/d02_search',path:'rule_count'},'lte',16,['grid_observations']),
     check('D02.c1.random_search_rejected','负控：同预算随机搜索不得产生 387/387 的逐字节复现',
      'negative_control',{kernel:'field_count',artifact_role:'evaluate/d02_holdout',path:'rows[*].random_exact',value:true},'eq',387,['grid_observations']),
    ],
    [
     '受限文法的表达能力由本实验定义；更宽的文法可能找到可复现程序。',
     '搜索预算由请求预算决定，预算变化会改变结论。',
    ]),
  ],
 },
 {
  schema_version:1,
  direction_id:'D03',
  title:'分段规则恢复：(w,h) 上的分段仿射',
  corpus_role:'vmde 0x498a50 网格内核的 896 条稠密标签观测',
  primary_claim_id:'D03.c1',
  split:GRID_SPLIT,
  evidence_pins:[
   lane('grid_observations',LANE_PATHS.gridObservations),
  ],
  claims:[
   claim('D03.c1',
    '节点计数可由 (w,h) 上的分段仿射函数（断点 ≤8）精确刻画，即计数只是 (w,h) 的函数。',
    'D01 的全局仿射基线（单段）。',
    GRID_SPLIT,
    [
     metric('D03.m1','holdout 精确复现行数',387,'eq','evaluate/d03_holdout'),
     metric('D03.m2','使用的断点数',8,'lte','develop/d03_model'),
    ],
    '分段仿射在 holdout 上不能逐行精确复现即证伪。',
    [
     check('D03.c1.holdout_exact','holdout 387 行全部被分段仿射模型精确复现',
      'primary',{kernel:'field_count',artifact_role:'evaluate/d03_holdout',path:'rows[*].exact',value:true},'eq',387,['grid_observations']),
     check('D03.c1.breakpoint_budget','分段仿射使用的断点数不超过 8',
      'primary',{kernel:'field_max',artifact_role:'develop/d03_model',path:'breakpoint_count'},'lte',8,['grid_observations']),
     check('D03.c1.affine_baseline_rejected','负控：单段全局仿射不得在 holdout 达到 387/387',
      'negative_control',{kernel:'field_count',artifact_role:'evaluate/d03_holdout',path:'rows[*].affine_exact',value:true},'eq',387,['grid_observations']),
    ],
    [
     '本主张只检验"计数是否只是 (w,h) 的函数"，不检验节点 id 的逐点编号。',
     '分段仿射的断点由训练集取值选择，不覆盖训练集之外的连续区间。',
    ]),
  ],
 },
 {
  schema_version:1,
  direction_id:'D04',
  title:'查表与插值恢复：邻域等价类查表',
  corpus_role:'vmde 0x498a50 网格内核的 896 条稠密标签观测',
  primary_claim_id:'D04.c1',
  split:GRID_SPLIT,
  evidence_pins:[
   lane('grid_observations',LANE_PATHS.gridObservations),
  ],
  claims:[
   claim('D04.c1',
    '内部交叉点的"是否非均匀"判定可由一张 ≤256 项、以四邻域等价类为键的查表精确表达，配合 (w,h) 的仿射项后，节点计数在 holdout 的 387 行上逐行精确。',
    '不使用查表的纯仿射基线。',
    GRID_SPLIT,
    [
     metric('D04.m1','holdout 精确复现行数',387,'eq','evaluate/d04_holdout'),
     metric('D04.m2','查表项数',256,'lte','develop/d04_model'),
    ],
    '查表+仿射模型在 holdout 上不能逐行精确复现，或查表项数超过 256，即证伪。',
    [
     check('D04.c1.holdout_exact','holdout 387 行全部被查表模型精确复现',
      'primary',{kernel:'field_count',artifact_role:'evaluate/d04_holdout',path:'rows[*].exact',value:true},'eq',387,['grid_observations']),
     check('D04.c1.table_budget','查表项数不超过 256',
      'primary',{kernel:'row_count',artifact_role:'develop/d04_model',path:'table'},'lte',256,['grid_observations']),
     check('D04.c1.affine_baseline_rejected','负控：不含查表的仿射基线不得在 holdout 达到 387/387',
      'negative_control',{kernel:'field_count',artifact_role:'evaluate/d04_holdout',path:'rows[*].affine_exact',value:true},'eq',387,['grid_observations']),
    ],
    [
     '查表键是四邻域的等价类划分，不是标签的原始取值；标签取值本身不参与查表。',
     '仿射项 (w,h) 的系数由训练集拟合，不证明其在其它尺寸上成立。',
    ]),
  ],
 },
 {
  schema_version:1,
  direction_id:'D05',
  title:'整数与 MBA 去混淆：≤8 操作的整数程序',
  corpus_role:'vmde 0x498a50 网格内核的 896 条稠密标签观测与 bv8 MBA 参考向量',
  primary_claim_id:'D05.c1',
  split:GRID_SPLIT,
  evidence_pins:[
   lane('grid_observations',LANE_PATHS.gridObservations),
   lane('reference_vectors',LANE_PATHS.referenceVectors),
   lane('kernel_return_review',LANE_PATHS.kernelReturnReview),
  ],
  claims:[
   claim('D05.c1',
    '计数路径不含超出简单整数仿射加离散查表的 MBA 混淆：存在一个 ≤8 个整数操作的程序，在 holdout 的 387 行上逐行精确复现计数，且对 MBA 编码变体具有判别力。',
    '已存在的未混淆公式（kernel_return_review 的 independent_formula）与 MBA 负控语料。',
    GRID_SPLIT,
    [
     metric('D05.m1','holdout 精确复现行数',387,'eq','evaluate/d05_holdout'),
     metric('D05.m2','整数程序的操作数',8,'lte','develop/d05_program'),
     metric('D05.m3','参考向量中 is_upstream_observation 为真的条数',0,'eq','reference_vectors'),
    ],
    '整数程序在 holdout 上不能逐行精确复现，或操作数超过 8，即证伪。',
    [
     check('D05.c1.holdout_exact','holdout 387 行全部被 ≤8 操作整数程序精确复现',
      'primary',{kernel:'field_count',artifact_role:'evaluate/d05_holdout',path:'rows[*].exact',value:true},'eq',387,['grid_observations']),
     check('D05.c1.operation_budget','整数程序的操作数不超过 8',
      'primary',{kernel:'field_max',artifact_role:'develop/d05_program',path:'op_count'},'lte',8,['grid_observations']),
     check('D05.c1.mba_variant_rejected','负控：MBA 编码变体语料不得被该整数程序复现',
      'negative_control',{kernel:'field_count',artifact_role:'evaluate/d05_holdout',path:'rows[*].mba_exact',value:true},'eq',387,['grid_observations']),
    ],
    [
     'MBA 变体只检验"简单程序不会误接受混淆编码"，不证明混淆本身可被自动还原。',
     '参考向量组 bv8_mba 只有 10 条（5 组参数对），不构成统计意义上的混淆覆盖。',
    ]),
  ],
 },
 {
  schema_version:1,
  direction_id:'D06',
  title:'分支与控制流恢复：已接受函数的高层 pcode 作用域',
  corpus_role:'14 个已接受函数与 1 个被拒函数的 pcode 作用域审计',
  primary_claim_id:'D06.c1',
  split:FUNCTION_SPLIT,
  evidence_pins:[
   lane('business_audit',LANE_PATHS.businessAudit),
   lane('algorithm_audit',LANE_PATHS.algorithmAudit),
   lane('grid_audit',LANE_PATHS.gridAudit),
   lane('fresh_business_code',LANE_PATHS.freshBusinessCode),
  ],
  claims:[
   claim('D06.c1',
    '由已接受函数的高层 pcode 推导的控制流图不逃出函数体：holdout 中的每个函数 outside_body_count==0 且 outside_guard_count==0，且原始 pcode 的 PC 全部落在 listing 内。',
    '被拒的 0x0042ce10（DECOMPILER_SCOPE_ESCAPE）：它必须仍然逃逸。',
    FUNCTION_SPLIT,
    [
     metric('D06.m1','holdout 中无作用域逃逸的函数数',6,'eq','evaluate/d06_functions'),
     metric('D06.m2','被拒函数逃逸的 PC 数',731,'gte','evaluate/d06_negative_control'),
    ],
    '任一 holdout 函数出现作用域逃逸即证伪；若被拒函数被接受（即逃逸计数为 0），说明作用域判定失去判别力，判为 inconclusive。',
    [
     check('D06.c1.holdout_no_body_escape','holdout 的 6 个函数 outside_body_count 全为 0',
      'primary',{kernel:'field_count',artifact_role:'evaluate/d06_functions',path:'functions[*].outside_body_count',value:0},'eq',6,['business_audit','algorithm_audit','grid_audit']),
     check('D06.c1.holdout_no_guard_escape','holdout 的 6 个函数 outside_guard_count 全为 0',
      'primary',{kernel:'field_count',artifact_role:'evaluate/d06_functions',path:'functions[*].outside_guard_count',value:0},'eq',6,['business_audit','algorithm_audit','grid_audit']),
     check('D06.c1.raw_pcode_in_listing','holdout 的 6 个函数的原始 pcode PC 全部落在 listing 内',
      'primary',{kernel:'field_count',artifact_role:'evaluate/d06_functions',path:'functions[*].raw_pcode_pcs_in_listing',value:true},'eq',6,['business_audit','algorithm_audit','grid_audit']),
     check('D06.c1.rejected_scope_still_escapes','负控：被拒函数 0x0042ce10 不得变成零逃逸',
      'negative_control',{kernel:'field_count',artifact_role:'evaluate/d06_negative_control',path:'functions[*].outside_body_count',value:0},'eq',1,['business_audit']),
    ],
    [
     '作用域判定基于静态 PC 归属，不证明反编译出的 C 语义正确。',
     '逃逸计数为 0 不等于函数完整，只等于该 pcode 作用域未越出函数体。',
    ]),
  ],
 },
 {
  schema_version:1,
  direction_id:'D07',
  title:'虚拟机指令语义恢复：私有执行页的独立解码',
  corpus_role:'私有执行页 0x62d0356 的 308 条指令窗口与守卫关系',
  primary_claim_id:'D07.c1',
  split:INSTRUCTION_SPLIT,
  evidence_pins:[
   lane('private_closure_callpop',LANE_PATHS.privateClosureCallpop),
   lane('private_closure_evidence',LANE_PATHS.privateClosureEvidence),
   lane('private_closure_slices',LANE_PATHS.privateClosureSlices),
  ],
  claims:[
   claim('D07.c1',
    '私有执行页中可判定指令子集的语义可由一个独立解码器复现：独立解码器在 holdout 的 107 个指令窗口上复现出与记录一致的字节序列，且分支结果未知的守卫被如实登记为未知而不是被猜测。',
    '负控：分支结果未知的守卫 DWORD 记录不得被当作已知值参与推断。',
    INSTRUCTION_SPLIT,
    [
     metric('D07.m1','holdout 中被独立解码器复现的指令窗口数',107,'eq','evaluate/d07_instructions'),
     metric('D07.m2','登记为未知的分支数',2,'eq','evaluate/d07_summary'),
    ],
    '独立解码器在 holdout 上不能复现 107/107 的字节序列即证伪；未知分支被静默当作已知即证伪。',
    [
     check('D07.c1.holdout_bytes_reproduced','holdout 的 107 个指令窗口的字节前缀被独立解码器复现',
      'primary',{kernel:'field_count',artifact_role:'evaluate/d07_instructions',path:'instructions[*].bytes_reproduced',value:true},'eq',107,['private_closure_callpop']),
     check('D07.c1.unknown_branches_registered','登记为未知的分支数等于 2',
      'primary',{kernel:'field_max',artifact_role:'evaluate/d07_summary',path:'unknown_branch_count'},'eq',2,['private_closure_callpop','private_closure_slices']),
     check('D07.c1.unknown_guard_not_asserted','负控：守卫 DWORD 未捕获时不得被断言为已知分支结果',
      'negative_control',{kernel:'field_count',artifact_role:'evaluate/d07_summary',path:'guards[*].outcome_asserted',value:true},'eq',1,['private_closure_slices']),
    ],
    [
     '独立解码器只覆盖该窗口实际出现的指令助记符子集，不覆盖整个 x86 指令集。',
     '守卫 DWORD 的真实取值从未被捕获，因此守卫分支结果在原则上不可知。',
    ]),
  ],
 },
 {
  schema_version:1,
  direction_id:'D08',
  title:'结构体与 ABI 恢复：内核对象布局声明的证实',
  corpus_role:'grid-kernel-analysis 记录的 15 条内核对象偏移与 24 条初始化器 store',
  primary_claim_id:'D08.c1',
  split:LAYOUT_SPLIT,
  evidence_pins:[
   lane('grid_kernel_facts',LANE_PATHS.gridFacts),
   lane('grid_audit',LANE_PATHS.gridAudit),
   lane('business_audit',LANE_PATHS.businessAudit),
   lane('algorithm_audit',LANE_PATHS.algorithmAudit),
  ],
  claims:[
   claim('D08.c1',
    'kernel_layout 声明的 15 个内核对象偏移，其证据地址确实落在已接受函数的代码范围内；holdout 中的 6 个偏移无一例外，且初始化器的 24 条 store 与声明的偏移表一致。',
    '被拒的 0x0042ce10 不得被当作可接受的证据来源。',
    LAYOUT_SPLIT,
    [
     metric('D08.m1','holdout 中证据地址落在已接受代码内的偏移数',6,'eq','evaluate/d08_offsets'),
     metric('D08.m2','初始化器 store 条数',24,'eq','develop/d08_initializer'),
    ],
    '任一 holdout 偏移的证据地址落在已接受代码之外，或初始化器 store 与声明表不一致，即证伪。',
    [
     check('D08.c1.holdout_offsets_confirmed','holdout 的 6 个偏移的证据地址全部落在已接受代码内',
      'primary',{kernel:'field_count',artifact_role:'evaluate/d08_offsets',path:'offsets[*].evidence_inside_accepted_code',value:true},'eq',6,['grid_kernel_facts','grid_audit']),
     check('D08.c1.initializer_consistent','初始化器的 24 条 store 与声明的 3 张偏移表一致',
      'primary',{kernel:'field_count',artifact_role:'develop/d08_initializer',path:'tables[*].consistent',value:true},'eq',3,['grid_kernel_facts']),
     check('D08.c1.rejected_scope_not_used','负控：作为证据来源的已接受函数数不得包含被拒的 0x0042ce10',
      'negative_control',{kernel:'field_max',artifact_role:'develop/d08_initializer',path:'accepted_function_count'},'eq',15,['grid_audit','business_audit']),
    ],
    [
     '偏移角色是静态声明的候选，不是运行时观测到的对象字段。',
     '证据地址落在代码内只说明该地址被访问过，不证明访问宽度与声明的类型一致。',
    ]),
  ],
 },
 {
  schema_version:1,
  direction_id:'D09',
  title:'循环与容器算法恢复：带路径压缩的并查集',
  corpus_role:'分割状态重放的 12 个场景、26 次调用',
  primary_claim_id:'D09.c1',
  split:SCENARIO_SPLIT,
  evidence_pins:[
   lane('segmentation_result',LANE_PATHS.segmentationResult),
  ],
  claims:[
   claim('D09.c1',
    '三种操作实现的是带路径压缩的并查集：一个独立重实现在 holdout 的 7 次调用上逐字节复现 labels/parents/components/dirty 四项完整状态，且去掉路径压缩的消融版本严格更差。',
    '既有 model.py（研究道手写模型）与去掉路径压缩的消融版本。',
    SCENARIO_SPLIT,
    [
     metric('D09.m1','holdout 中四项状态全部相等的调用数',7,'eq','evaluate/d09_calls'),
     metric('D09.m2','消融版本（无路径压缩）在 holdout 上不相等的调用数',1,'gte','evaluate/d09_calls'),
    ],
    '任一 holdout 调用的四项状态不全等即证伪；若消融版本同样全等，说明该度量无法区分路径压缩的作用，判为 inconclusive。',
    [
     check('D09.c1.holdout_state_equal','holdout 的 7 次调用的四项状态全部相等',
      'primary',{kernel:'field_count',artifact_role:'evaluate/d09_calls',path:'calls[*].state_equal',value:true},'eq',7,['segmentation_result']),
     check('D09.c1.ablation_strictly_worse','消融版本（无路径压缩）在 holdout 上至少有一次不相等',
      'primary',{kernel:'field_count',artifact_role:'evaluate/d09_calls',path:'calls[*].ablation_equal',value:false},'gte',1,['segmentation_result']),
     check('D09.c1.ablation_not_equivalent','负控：消融版本不得与带压缩版本在 holdout 上全等',
      'negative_control',{kernel:'field_count',artifact_role:'evaluate/d09_calls',path:'calls[*].ablation_equal',value:true},'eq',7,['segmentation_result']),
    ],
    [
     '重放是受控 CPU 仿真，不是原进程调用。',
     '场景是人工构造的，labels/parents/components/dirty 的初始取值不来自真实应用。',
    ]),
  ],
 },
 {
  schema_version:1,
  direction_id:'D10',
  title:'状态机与协议逆向：模块槽采集到保护转移',
  corpus_role:'模块槽运行收据的 15 条事件与受保护转移复核',
  primary_claim_id:'D10.c1',
  split:EVENT_SPLIT,
  evidence_pins:[
   lane('module_slots_receipt',LANE_PATHS.moduleSlotsReceipt),
   lane('protected_transition_review',LANE_PATHS.protectedTransitionReview),
  ],
  claims:[
   claim('D10.c1',
    '把"模块槽采集→保护转移→应用主函数"抽象成状态机后，每条 holdout 事件转移都满足声明的转移关系；并且剩余的受保护转移 0x42474f→0xd2ed39→0xaa35de 被显式登记为未闭合。',
    '显式反例：剩余保护转移必须登记为未闭合，不得被当作已闭合。',
    EVENT_SPLIT,
    [
     metric('D10.m1','holdout 中满足声明转移关系的事件数',6,'eq','evaluate/d10_events'),
     metric('D10.m2','登记为未闭合的转移数',1,'gte','evaluate/d10_events'),
    ],
    '任一 holdout 事件违反声明的转移关系即证伪；未闭合转移未被登记即属过度声明，判为 inconclusive。',
    [
     check('D10.c1.holdout_transitions_hold','holdout 的 6 条事件全部满足声明的转移关系',
      'primary',{kernel:'field_count',artifact_role:'evaluate/d10_events',path:'events[*].relation_holds',value:true},'eq',6,['module_slots_receipt']),
     check('D10.c1.unclosed_declared','剩余受保护转移被登记为未闭合',
      'primary',{kernel:'field_max',artifact_role:'evaluate/d10_events',path:'unclosed_transition_count'},'gte',1,['protected_transition_review']),
     check('D10.c1.no_undeclared_unclosed','负控：不得存在未被登记为未闭合的剩余转移',
      'negative_control',{kernel:'field_max',artifact_role:'evaluate/d10_events',path:'undeclared_unclosed_count'},'eq',1,['protected_transition_review']),
    ],
    [
     '状态机是从已记录事件抽象出来的，不是原程序的显式状态机。',
     '未闭合转移的根因仍未确定，只登记了"未闭合"这一事实。',
    ]),
  ],
 },
 {
  schema_version:1,
  direction_id:'D11',
  title:'文件格式与序列化恢复：主模块镜像的区间记录',
  corpus_role:'主模块活体镜像的 223 条覆盖区间',
  primary_claim_id:'D11.c1',
  split:INTERVAL_SPLIT,
  evidence_pins:[
   lane('module_image_json',LANE_PATHS.moduleImageJson),
   stable('module_image_bin',LANE_PATHS.moduleImageBin,'moduleImageBin'),
  ],
  claims:[
   claim('D11.c1',
    '主模块镜像的区间记录格式可被一个长度前缀解析器完整 round-trip：holdout 的 94 条区间的实测 sha256 与镜像中对应字节完全一致，且这些区间恰好一次覆盖整幅镜像。',
    '固定长度解析器基线（按固定 4096 字节切分），它必须无法复现记录的区间边界。',
    INTERVAL_SPLIT,
    [
     metric('D11.m1','holdout 中摘要一致的区间数',94,'eq','evaluate/d11_intervals'),
     metric('D11.m2','覆盖镜像字节数',14561280,'eq','evaluate/d11_intervals'),
    ],
    '任一 holdout 区间摘要不一致，或区间不能恰好一次覆盖镜像，即证伪。',
    [
     check('D11.c1.holdout_hashes_match','holdout 的 94 条区间的实测摘要与记录一致',
      'primary',{kernel:'field_count',artifact_role:'evaluate/d11_intervals',path:'intervals[*].sha256_matches',value:true},'eq',94,['module_image_json','module_image_bin']),
     check('D11.c1.full_coverage','区间恰好一次覆盖 14561280 字节的镜像',
      'primary',{kernel:'field_max',artifact_role:'evaluate/d11_intervals',path:'covered_bytes'},'eq',14561280,['module_image_json','module_image_bin']),
     check('D11.c1.fixed_length_parser_rejected','负控：固定长度解析器不得复现出记录的区间边界',
      'negative_control',{kernel:'field_count',artifact_role:'evaluate/d11_intervals',path:'intervals[*].fixed_length_boundary_matches',value:true},'eq',94,['module_image_json','module_image_bin']),
    ],
    [
     '镜像是非原子外部读取的产物，其自身带有 unobserved zero fill 的声明。',
     'round-trip 只覆盖区间边界与字节摘要，不覆盖任何更高层的结构语义。',
    ]),
  ],
 },
 {
  schema_version:1,
  direction_id:'D12',
  title:'图像/音频/几何算法恢复：几何算子契约与自然图像否证',
  corpus_role:'网格内核几何算子契约与全树否定扫描',
  primary_claim_id:'D12.a',
  split:GRID_SPLIT,
  evidence_pins:[
   lane('grid_observations',LANE_PATHS.gridObservations),
   lane('input_contract',LANE_PATHS.inputContract),
   lane('reference_vectors',LANE_PATHS.referenceVectors),
   lane('lane_tree_anchor',LANE_PATHS.laneTreeAnchor),
  ],
  claims:[
   claim('D12.a',
    '几何算子契约在合成域被完整刻画：契约文档的 15 条叶级声明可被枚举，且由此得到的几何算子在 holdout 的 387 行上逐行精确复现。',
    'fixtures/reference_vectors.jsonl 中 is_upstream_observation 为真的样本（必须为 0 条）。',
    GRID_SPLIT,
    [
     metric('D12.a.m1','holdout 精确复现行数',387,'eq','evaluate/d12_geometry'),
     metric('D12.a.m2','契约叶级声明数',15,'eq','develop/d12_contract'),
     metric('D12.a.m3','参考向量中上游观测条数',0,'eq','reference_vectors'),
    ],
    '几何算子在 holdout 上不能逐行精确复现，或契约声明数与预注册不符，即证伪。',
    [
     check('D12.a.holdout_exact','holdout 387 行全部被几何算子精确复现',
      'primary',{kernel:'field_count',artifact_role:'evaluate/d12_geometry',path:'rows[*].exact',value:true},'eq',387,['grid_observations','input_contract']),
     check('D12.a.contract_field_count','契约文档的叶级声明数为 15',
      'primary',{kernel:'field_max',artifact_role:'develop/d12_contract',path:'leaf_declaration_count'},'eq',15,['input_contract']),
     check('D12.a.no_upstream_observation','负控：参考向量中不得存在上游观测样本',
      'negative_control',{kernel:'field_count',artifact_role:'reference_vectors',path:'rows[*].is_upstream_observation',value:true},'eq',1,['reference_vectors']),
    ],
    [
     '契约是静态候选输入契约，不是从真实调用点恢复的原始 ABI。',
     '几何算子只在合成的 2..16 稠密标签域上被验证。',
    ]),
   claim('D12.b',
    '否定命题：仓库中不存在"自然图像→矢量"的已验证输出对；全树扫描必须枚举 artifacts/research/vmde 下的全部 JSON，且其中 runnable_verified、whole_program_equivalence、natural_image_to_vector_verified 为真的条目数为 0。',
    '全树否定扫描本身即对照：任何一条为真的条目都是反例。',
    GRID_SPLIT,
    [
     metric('D12.b.m1','runnable_verified 为真的条目数',0,'eq','evaluate/d12_negative_scan'),
     metric('D12.b.m2','whole_program_equivalence 为真的条目数',0,'eq','evaluate/d12_negative_scan'),
     metric('D12.b.m3','natural_image_to_vector_verified 为真的条目数',0,'eq','evaluate/d12_negative_scan'),
    ],
    '扫描发现任一为真的条目即证伪否定命题；正向命题因无上游图像观测而判为 inconclusive（NO_UPSTREAM_IMAGE_OBSERVATION）。',
    [
     check('D12.b.no_runnable_verified','全树扫描中 runnable_verified 为真的条目数为 0',
      'primary',{kernel:'field_max',artifact_role:'evaluate/d12_negative_scan',path:'runnable_verified_true_count'},'eq',0,['lane_tree_anchor']),
     check('D12.b.no_whole_program_equivalence','全树扫描中 whole_program_equivalence 为真的条目数为 0',
      'primary',{kernel:'field_max',artifact_role:'evaluate/d12_negative_scan',path:'whole_program_equivalence_true_count'},'eq',0,['lane_tree_anchor']),
     check('D12.b.scan_completeness','负控：扫描不得漏掉任何 JSON 文件',
      'negative_control',{kernel:'field_max',artifact_role:'evaluate/d12_negative_scan',path:'unscanned_file_count'},'eq',1,['lane_tree_anchor']),
    ],
    [
     '否定扫描只覆盖 artifacts/research/vmde 下的 JSON 文件，不覆盖二进制内容。',
     '正向命题因缺少上游图像观测而不可判定。',
    ]),
  ],
 },
 {
  schema_version:1,
  direction_id:'D13',
  title:'跨版本语义比较：分析转储与活体镜像',
  corpus_role:'14 个已接受函数在分析转储与活体镜像之间的 1906 指令窗口',
  primary_claim_id:'D13.c1',
  split:FUNCTION_SPLIT,
  evidence_pins:[
   lane('fresh_business_code',LANE_PATHS.freshBusinessCode),
   stable('unpacked_vmde',LANE_PATHS.unpackedVmde,'unpackedVmde'),
   stable('module_image_bin',LANE_PATHS.moduleImageBin,'moduleImageBin'),
  ],
  claims:[
   claim('D13.c1',
    '14 个已接受函数在分析转储与活体镜像之间语义一致，全部 22 处差异都落在旧 listing 的 FF 15 导入调用点上；holdout 中每个函数的变化条数与记录完全一致。',
    '被拒的 0x0042ce10：它必须仍然被拒绝，不得被纳入比较。',
    FUNCTION_SPLIT,
    [
     metric('D13.m1','可归因到 FF 15 的变化数',22,'eq','evaluate/d13_changes'),
     metric('D13.m2','holdout 中变化条数与记录一致的函数数',6,'eq','evaluate/d13_functions'),
     metric('D13.m3','内核 637 字节与保留重放一致',1,'eq','evaluate/d13_functions'),
    ],
    '任一变化不可归因到 FF 15 导入调用点即证伪；任一函数的变化条数与记录不符即证伪。',
    [
     check('D13.c1.all_changes_attributable','全部 22 处变化都可归因到 FF 15 导入调用点',
      'primary',{kernel:'field_count',artifact_role:'evaluate/d13_changes',path:'changes[*].attributable',value:true},'eq',22,['fresh_business_code']),
     check('D13.c1.holdout_change_counts_match','holdout 的 6 个函数的变化条数与记录一致',
      'primary',{kernel:'field_count',artifact_role:'evaluate/d13_functions',path:'functions[*].change_count_matches',value:true},'eq',6,['fresh_business_code']),
     check('D13.c1.kernel_bytes_retained','内核 637 字节与保留重放保持一致',
      'primary',{kernel:'field_max',artifact_role:'evaluate/d13_functions',path:'kernel_637_bytes_match_retained_replay'},'eq',1,['fresh_business_code']),
     check('D13.c1.rejected_scope_rejected','负控：被拒的 0x0042ce10 不得被纳入比较集合',
      'negative_control',{kernel:'field_max',artifact_role:'evaluate/d13_functions',path:'rejected_scope_included_count'},'eq',1,['fresh_business_code']),
    ],
    [
     '跨版本比较只覆盖 14 个已接受函数，不覆盖其余模块代码。',
     '活体镜像是一次非原子读取的产物，其字节可能在采集期间变化。',
     '指令字节相等只建立"在一次非原子镜像观测中存在"，不建立执行或 ABI 正确性。',
     'FF 15 归因只覆盖字节形态，不证明两处调用在语义上等价。',
    ]),
  ],
 },
 {
  schema_version:1,
  direction_id:'D14',
  title:'组件与算法指纹：内容派生的稳定签名',
  corpus_role:'14 个已接受函数引用的浮点常量与两幅镜像',
  primary_claim_id:'D14.c1',
  split:FUNCTION_SPLIT,
  evidence_pins:[
   lane('algorithm_facts',LANE_PATHS.algorithmFacts),
   stable('module_image_bin',LANE_PATHS.moduleImageBin,'moduleImageBin'),
   stable('unpacked_vmde',LANE_PATHS.unpackedVmde,'unpackedVmde'),
   lane('fresh_business_code',LANE_PATHS.freshBusinessCode),
  ],
  claims:[
   claim('D14.c1',
    '每个已恢复组件可由内容派生的稳定指纹刻画：指纹由函数引用的浮点常量位型导出，在分析转储与活体镜像之间不变，且能区分已接受函数与无关窗口。',
    '负控：从活体镜像随机抽取的 637 字节窗口（必须零碰撞）与被拒的 0x0042ce10。',
    FUNCTION_SPLIT,
    [
     metric('D14.m1','holdout 中跨镜像指纹稳定的函数数',6,'eq','evaluate/d14_fingerprints'),
     metric('D14.m2','负控窗口与指纹的碰撞数',0,'eq','evaluate/d14_fingerprints'),
    ],
    '任一 holdout 函数的指纹在两幅镜像之间不稳定即证伪；负控发生碰撞说明指纹无判别力，判为 inconclusive。',
    [
     check('D14.c1.fingerprint_stable','holdout 的 6 个函数的指纹在两幅镜像之间保持不变',
      'primary',{kernel:'field_count',artifact_role:'evaluate/d14_fingerprints',path:'functions[*].fingerprint_stable',value:true},'eq',6,['algorithm_facts','module_image_bin']),
     check('D14.c1.negative_control_no_collision','负控：随机 637 字节窗口与任一指纹都不碰撞',
      'negative_control',{kernel:'field_max',artifact_role:'evaluate/d14_fingerprints',path:'negative_control_collision_count'},'eq',1,['module_image_bin']),
    ],
    [
     '浮点常量只覆盖 analysis-candidates 记录的 7 个常量，不是全部函数特征的完备指纹。',
     '指纹只覆盖引用了浮点常量的函数。',
     '随机窗口的位置由请求预算的种子决定，跨运行可能不同。',
    ]),
  ],
 },
 {
  schema_version:1,
  direction_id:'D15',
  title:'安全分析与补丁验证：兼容性候选的差异审计',
  corpus_role:'兼容性候选与启动观测收据',
  primary_claim_id:'D15.c1',
  split:FUNCTION_SPLIT,
  evidence_pins:[
   stable('candidate_exe',LANE_PATHS.candidateExe,'candidateExe'),
   stable('unpacked_vmde',LANE_PATHS.unpackedVmde,'unpackedVmde'),
   lane('startup_compat_receipt',LANE_PATHS.startupCompatReceipt),
   lane('dump_startup',LANE_PATHS.dumpStartup),
   lane('dump_crash',LANE_PATHS.dumpCrash),
   lane('fresh_business_code',LANE_PATHS.freshBusinessCode),
  ],
  claims:[
   claim('D15.c1',
    '兼容性候选相对分析转储的差异恰好是 2 处共 52 字节（entry_point 字段 4 字节 @320 中变化 2 字节；compatibility_prefix 50 字节 @721764），没有第三处差异；且补丁在已记录的启动观测集上语义中性——补丁后的候选推进到了已记录的检查点，而未打补丁的分析转储受控启动时触发 0xC0000005。',
    '负控：未打补丁的分析转储（它必须崩溃而不是推进到检查点）。',
    FUNCTION_SPLIT,
    [
     metric('D15.m1','差异处数',2,'eq','evaluate/d15_diff'),
     metric('D15.m2','差异字节总数',52,'eq','evaluate/d15_diff'),
     metric('D15.m3','entry_point 处变化字节数',2,'eq','evaluate/d15_diff'),
     metric('D15.m4','compatibility_prefix 处变化字节数',50,'eq','evaluate/d15_diff'),
    ],
    '出现第 3 处差异，或差异字节数不等于 52，即证伪；候选未推进到已记录检查点即证伪。',
    [
     check('D15.c1.patch_count','候选与分析转储的差异恰好是 2 处',
      'primary',{kernel:'field_max',artifact_role:'evaluate/d15_diff',path:'region_count'},'eq',2,['candidate_exe','unpacked_vmde']),
     check('D15.c1.total_changed_bytes','差异字节总数为 52',
      'primary',{kernel:'field_max',artifact_role:'evaluate/d15_diff',path:'total_changed_bytes'},'eq',52,['candidate_exe','unpacked_vmde']),
     check('D15.c1.entry_point_bytes','entry_point 处（@320 的 4 字节字段）变化 2 字节',
      'primary',{kernel:'field_max',artifact_role:'evaluate/d15_diff',path:'entry_point_changed_bytes'},'eq',2,['candidate_exe','unpacked_vmde','startup_compat_receipt']),
     check('D15.c1.compatibility_prefix_bytes','compatibility_prefix 处（@721764 的 50 字节）变化 50 字节',
      'primary',{kernel:'field_max',artifact_role:'evaluate/d15_diff',path:'compatibility_prefix_changed_bytes'},'eq',50,['candidate_exe','unpacked_vmde','startup_compat_receipt']),
     check('D15.c1.unpatched_dump_crashes','未打补丁的分析转储受控启动时触发 0xC0000005',
      'primary',{kernel:'field_max',artifact_role:'evaluate/d15_diff',path:'unpatched_crashed'},'eq',1,['dump_crash','dump_startup']),
     check('D15.c1.unpatched_dump_rejected','负控：未打补丁的分析转储不得被判定为推进到已记录检查点',
      'negative_control',{kernel:'field_max',artifact_role:'evaluate/d15_diff',path:'unpatched_reached_checkpoints_count'},'eq',1,['dump_startup','dump_crash']),
    ],
    [
     'entry_point 的 4 字节字段中只有 2 字节发生变化，另 2 字节相同。',
     '差异审计只覆盖文件字节，不覆盖补丁语义之外的运行时行为。',
     '补丁的中立性只在已记录的启动观测集上成立。',
     '崩溃事件来自受控启动，不是原始用户场景。',
    ]),
  ],
 },
 {
  schema_version:1,
  direction_id:'D16',
  title:'兼容替代与软件迁移：三方一致的独立实现',
  corpus_role:'原生内进程执行、Python 候选与 C++ 对照的 896 条语料',
  primary_claim_id:'D16.c1',
  split:GRID_SPLIT,
  evidence_pins:[
   lane('grid_observations',LANE_PATHS.gridObservations),
   lane('comparison_legacy896',LANE_PATHS.comparisonLegacy896),
   lane('comparison_positive_control',LANE_PATHS.comparisonPositiveControl),
   lane('native_summary',LANE_PATHS.nativeSummary),
  ],
  claims:[
   claim('D16.c1',
    '三个相互独立的实现在声明契约上与原生一致：本仓库的 TypeScript 重实现在 holdout 的 387 行上逐字节复现原生输出，研究道记录的 Python 比较 896/896 匹配，原生内进程执行 904/904 匹配。',
    '正对照语料的全零突变体（它必须被每一个实现拒绝）。',
    GRID_SPLIT,
    [
     metric('D16.m1','holdout 三方一致的行数',387,'eq','evaluate/d16_agreement'),
     metric('D16.m2','研究道 Python 比较的匹配数',896,'eq','comparison_legacy896'),
     metric('D16.m3','原生内进程执行的匹配数',904,'eq','native_summary'),
    ],
    '任一 holdout 行三方不一致即证伪；负控突变体被接受即属度量无判别力，判为 inconclusive。',
    [
     check('D16.c1.holdout_three_way','holdout 的 387 行上原生输出、Python 记录与本仓库实现三方一致',
      'primary',{kernel:'field_count',artifact_role:'evaluate/d16_agreement',path:'rows[*].three_way_equal',value:true},'eq',387,['grid_observations','comparison_legacy896']),
     check('D16.c1.python_comparison_complete','研究道记录的 Python 与原生比较 896 条全部匹配',
      'primary',{kernel:'field_count',artifact_role:'comparison_legacy896',path:'comparisons[*].status',value:'matched'},'eq',896,['comparison_legacy896']),
     check('D16.c1.native_in_process_complete','原生内进程执行 904 条全部匹配',
      'primary',{kernel:'field_max',artifact_role:'native_summary',path:'original_matched'},'eq',904,['native_summary']),
     check('D16.c1.mutant_rejected','负控：全零突变体语料不得被接受',
      'negative_control',{kernel:'field_max',artifact_role:'comparison_positive_control',path:'negative_control.accepted'},'eq',1,['comparison_positive_control']),
    ],
    [
     '三方一致只覆盖合成网格契约，不覆盖任何自然应用输入。',
     '原生侧是内进程执行，不是原程序的真实调用路径。',
     'C++ 对照只跑了 8 条正对照用例，不构成与 387 行同规模的第三方比较。',
    ]),
  ],
 },
 {
  schema_version:1,
  direction_id:'D17',
  title:'脱壳后的可运行重建：可启动且完成声明业务操作',
  corpus_role:'兼容性候选的启动观测、崩溃事件与受保护转移复核',
  primary_claim_id:'D17.c1',
  split:FUNCTION_SPLIT,
  evidence_pins:[
   lane('startup_review',LANE_PATHS.startupReview),
   lane('dump_startup',LANE_PATHS.dumpStartup),
   lane('dump_crash',LANE_PATHS.dumpCrash),
   lane('protected_transition_review',LANE_PATHS.protectedTransitionReview),
   stable('candidate_exe',LANE_PATHS.candidateExe,'candidateExe'),
   lane('fresh_business_code',LANE_PATHS.freshBusinessCode),
  ],
  claims:[
   claim('D17.c1',
    '存在一个从脱壳产物出发、可独立启动并完成一项声明业务操作（进入 0x5b85e0）的重建程序：谓词为 候选已启动 ∧ 已完成声明业务操作 ∧ 无访问违例。',
    '被保护的原件 vmde.exe（9a0fa724…）作为"应当可运行"的基线。',
    FUNCTION_SPLIT,
    [
     metric('D17.m1','候选是否独立启动',1,'eq','evaluate/d17_rebuild'),
     metric('D17.m2','是否完成声明业务操作',1,'eq','evaluate/d17_rebuild'),
     metric('D17.m3','是否无访问违例',1,'eq','evaluate/d17_rebuild'),
    ],
    '候选启动但未完成声明业务操作（或出现访问违例），即证伪该主张；这是一个完成的分析结论，不是过程失败。',
    [
     check('D17.c1.candidate_starts','兼容性候选可独立启动并进入 CRT 初始化',
      'primary',{kernel:'field_max',artifact_role:'evaluate/d17_rebuild',path:'candidate_started'},'eq',1,['startup_review','candidate_exe']),
     check('D17.c1.declared_operation_completed','候选完成了声明的业务操作（进入 0x5b85e0）',
      'primary',{kernel:'field_max',artifact_role:'evaluate/d17_rebuild',path:'declared_operation_completed'},'eq',1,['startup_review']),
     check('D17.c1.no_access_violation','候选运行期间没有访问违例',
      'primary',{kernel:'field_max',artifact_role:'evaluate/d17_rebuild',path:'access_violation_free'},'eq',1,['dump_crash','dump_startup']),
     check('D17.c1.unclosed_transition_declared','负控：未闭合的受保护转移必须被登记为未闭合',
      'negative_control',{kernel:'field_max',artifact_role:'evaluate/d17_rebuild',path:'undeclared_unclosed_transition_count'},'eq',1,['protected_transition_review']),
    ],
    [
     '受控启动不是用户的真实运行场景。',
     '进程在最终捕获前终止，终止机制未被识别。',
    ]),
  ],
 },
];

export function researchCatalog():ResearchDirectionSpec[]{
 return RESEARCH_DIRECTIONS.map((spec)=>structuredClone(spec));
}
export function researchDirection(directionId:string):ResearchDirectionSpec|null{
 const found=RESEARCH_DIRECTIONS.find((spec)=>spec.direction_id===directionId);
 return found===undefined?null:structuredClone(found);
}

/** The claim identifiers and the shared non-claims applied to every direction. */
export function applyCommonNotClaimed(specs:ResearchDirectionSpec[]):ResearchDirectionSpec[]{
 for(const spec of specs)
  for(const claim of spec.claims)
   for(const text of NOT_CLAIMED_COMMON)
    if(!claim.not_claimed.includes(text))claim.not_claimed.push(text);
 return specs;
}

applyCommonNotClaimed(RESEARCH_DIRECTIONS);

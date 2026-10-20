import type {ResearchFunction} from './types.js';
export const VMDE='artifacts/research/vmde/';
export const LIMITATIONS=[
  '原生观测仅覆盖声明的合成对象契约；没有观察到自然应用的网格调用。',
  'CPU 回放、模型证明、静态 listing 与原生观测是独立证据范围，不能互相替代。',
  '自然图像标签生成、完整矢量输出、保护初始化与真实 OEP 仍未恢复；没有已验证可运行的 vmde 重建。',
  '图为局部已记录依赖，不是全程序调用图；不建立模型节点与机器地址的虚构映射。',
];
export interface FunctionEntry {record:ResearchFunction;listing:string;sources:string[];evidence:string[]}
export const FUNCTIONS:FunctionEntry[]=[
  {record:{id:'grid-498a50',name:'网格节点编号',address:'0x00498a50',status:'native-observed',scope:'native synthetic-contract observation',description:'637 字节网格核；904 次原始机器码原生调用在合成、互不重叠对象契约下匹配。自然应用调用未观察到。'},listing:'grid-kernel-analysis/run-ayl3ui/00498a50.json',sources:['grid-kernel-analysis/run-ayl3ui/00498a50.c','kernel-replay/candidate.py','grid-kernel-analysis/candidate-model.json'],evidence:['native-kernel/native-summary.json','native-kernel/comparison-edges8.json','native-kernel/comparison-legacy896.json','grid-kernel-analysis/input-contract-candidate.json']},
  {record:{id:'node-record-480230',name:'40 字节节点记录写入',address:'0x00480230',status:'cpu-replay',scope:'bounded CPU replay; no new native calls',description:'保留未知字节的局部记录写入；31 个合成 CPU 仿真案例。对象构造和自然 FPU 状态未证明。'},listing:'grid-kernel-analysis/run-ayl3ui/00480230.json',sources:['grid-kernel-analysis/run-ayl3ui/00480230.c','node-records/run-cpu-writer-20261020/model.py'],evidence:['node-records/cpu-observation-review.json','node-records/static-abi.json','node-records/layout-review.json']},
  {record:{id:'label-lookup',name:'标签代表查找',address:'0x0047e8e0',status:'cpu-replay',scope:'bounded CPU replay / synthetic acyclic label forest',description:'仅压缩初始标签父项与选定像素；EAX 代表值有局部语义检查。'},listing:'segmentation-results/run-label-lookup-20261020/analysis/0047e8e0.json',sources:['segmentation-results/run-label-lookup-20261020/analysis/0047e8e0.c','segmentation-results/run-label-replay-20261020/model.py'],evidence:['segmentation-results/lookup-abi-review.json','segmentation-results/label-cpu-observation-review.json']},
  {record:{id:'label-relabel',name:'标签根合并',address:'0x0047e1b0',status:'cpu-replay',scope:'bounded CPU replay / synthetic acyclic label forest',description:'合并两个不同根，置脏并减少计数；没有自然图像标签来源证明。'},listing:'segmentation-results/run-label-lookup-20261020/analysis/0047e1b0.json',sources:['segmentation-results/run-label-lookup-20261020/analysis/0047e1b0.c','segmentation-results/run-label-replay-20261020/model.py'],evidence:['segmentation-results/relabel-store-review.json','segmentation-results/label-cpu-observation-review.json']},
  {record:{id:'label-normalize',name:'标签状态规范化',address:'0x0047fcb0',status:'cpu-replay',scope:'bounded CPU replay / synthetic acyclic label forest',description:'脏时规范所有像素并清父项；保留原根索引，不是稠密重编号。'},listing:'segmentation-results/run-label-normalize-20261020/analysis/0047fcb0.json',sources:['segmentation-results/run-label-normalize-20261020/analysis/0047fcb0.c','segmentation-results/run-label-replay-20261020/model.py'],evidence:['segmentation-results/label-model-review.json','segmentation-results/label-cpu-observation-review.json']},
  {record:{id:'startup-transition',name:'启动与受保护调度转移',address:'0x0042474f → 0x00d2ed39',status:'partial',scope:'same-run v7 compatibility observation; VM semantics unknown',description:'同一兼容候选进程的四个检查点与可变状态；不表示真实 OEP、自然保护初始化或运行成功。'},listing:'runtime-export-observer/protected-continuation-static.json',sources:['startup-compat/qmain-static/analysis/00424650.scope-rejected.c','startup-compat/qmain-static/analysis/00465cd0.c','runtime-export-observer/protected-continuation-static.json'],evidence:['startup-compat/protected-dispatch-v7-review.json','startup-compat/protected-transition-review.json']},
];
export const TRACE_DEFINITIONS=[
  {id:'startup-exit-v7',label:'兼容候选 · 受保护调度 v7',folder:'startup-compat/exit-probe-v7'},
  {id:'startup-compat',label:'兼容候选 · 初始启动',folder:'startup-compat'},
  {id:'startup-original-qsettings',label:'原程序 · QSettings 失败对照',folder:'startup-original-qsettings'},
  {id:'startup-context',label:'原程序 · CRT API 栈帧',folder:'startup-context'},
] as const;
export const OBSERVER_FOLDER='runtime-export-observer/export-observations-20261020-a/';

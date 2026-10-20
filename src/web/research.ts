import type {Page,PageQuery,ResearchEvent,ResearchFunction,ResearchFunctionDetail,ResearchOverview,ResearchTrace,ResearchValidation,ValidationPage,WebEvidence} from './types.js';
import {ResearchFiles,failure,integer,list,object,reason,string,type JsonObject} from './research-files.js';
import {FUNCTIONS,LIMITATIONS,OBSERVER_FOLDER,TRACE_DEFINITIONS,VMDE} from './research-catalog.js';

interface TraceData {trace:ResearchTrace;events:ResearchEvent[]}
interface ValidationData {validation:ResearchValidation;rows:JsonObject[]}
interface MaybeJson {value:JsonObject|null;id:string;error:string|null}
function functionRecord(source:ResearchFunction,hasListing:boolean,validation?:ResearchValidation):ResearchFunction{
  const record={...source};if(!hasListing)record.status='unavailable';
  if(validation){
    record.counts=validation.counts;
    if(validation.status==='unavailable'){
      record.status=hasListing?'static-only':'unavailable';record.description='当前未能加载对应验证证据；仅展示可读取的静态材料，不报告已验证调用数量。';
    }else if(source.id==='grid-498a50')record.description=`已加载原生合成契约观测：${validation.counts.original_calls??'未记录'} 次调用，记录匹配 ${validation.counts.original_matched??'未记录'}。自然应用调用与整程序等价未验证。`;
    else if(source.id==='node-record-480230')record.description=`节点写入器 CPU 回放：已完成 ${validation.counts.completed??'未记录'} 例；未新增原生业务调用。`;
    else record.description=`标签状态操作组 CPU 回放：整组已完成 ${validation.counts.completed??'未记录'} 次调用；不代表当前单个操作或自然应用调用数量。`;
    if(hasListing&&validation.status==='partial')record.status='partial';
  }
  return record;
}
const shaPattern=/^[a-f0-9]{64}$/;
const sourceFormat=(relative:string):WebEvidence['format']=>relative.endsWith('.json')?'json':relative.endsWith('.bin')?'hex':'text';
function counts(value:unknown):Record<string,number>{return Object.fromEntries(Object.entries(object(value)).filter((entry):entry is [string,number]=>integer(entry[1])!==null));}
function bounded(value:unknown,depth=0):unknown{
  if(depth>5)return '[展开原始证据查看更深字段]';
  if(typeof value==='string')return value.length>8192?value.slice(0,8192)+'… [字段已截断]':value;
  if(Array.isArray(value))return value.length>128?{items:value.slice(0,128).map(v=>bounded(v,depth+1)),total:value.length,truncated:true}:value.map(v=>bounded(v,depth+1));
  if(value&&typeof value==='object')return Object.fromEntries(Object.entries(value).slice(0,48).map(([key,v])=>[key,bounded(v,depth+1)]));
  return value??null;
}
function queryPage(query:PageQuery):Required<Pick<PageQuery,'offset'|'limit'>>&PageQuery{
  if(!query||typeof query!=='object'||Array.isArray(query))throw failure('INVALID_QUERY','Invalid research query');
  const offset=query.offset??0,limit=query.limit??50;
  if(integer(offset)===null||offset>100_000_000||integer(limit)===null||limit<1||limit>500)throw failure('INVALID_QUERY','offset must be nonnegative and limit must be between 1 and 500');
  for(const [key,max] of [['q',256],['type',64],['status',64]] as const){const value=query[key];if(value!==undefined&&(typeof value!=='string'||value.length>max||/[\u0000-\u001f]/.test(value)))throw failure('INVALID_QUERY','Invalid research filter');}
  return {...query,offset,limit};
}
function page<T>(rows:T[],query:ReturnType<typeof queryPage>):Page<T>{return {items:rows.slice(query.offset,query.offset+query.limit),total:rows.length,offset:query.offset,limit:query.limit};}
function uniqueRows(value:unknown,key='id'):Map<string,JsonObject>{
  if(!Array.isArray(value)||value.length>10000)throw failure('EVIDENCE_UNAVAILABLE','Invalid or excessive saved rows');
  const result=new Map<string,JsonObject>();for(const item of value){const row=object(item),id=string(row[key]);if(!id||result.has(id))throw failure('EVIDENCE_UNAVAILABLE','Missing or duplicate saved row identity');result.set(id,row);}return result;
}

/** Readonly projection of a fixed research archive. No scripts, interpreters, native tools,
 * PE images or browser-selected filesystem paths are executed by this adapter. */
export class ResearchArchive {
  private readonly files:ResearchFiles;
  private nativePromise:Promise<ValidationData>|undefined;
  private readonly traces=new Map<string,Promise<TraceData>>();
  private readonly validations=new Map<string,Promise<ValidationData>>();
  constructor(root:string){
    this.files=new ResearchFiles(root);
    for(const entry of FUNCTIONS)for(const relative of [entry.listing,...entry.sources,...entry.evidence])this.register(relative);
    for(const definition of TRACE_DEFINITIONS)this.register(definition.folder+'/process-receipt.json');
    for(const relative of ['native-kernel/native-summary.json','node-records/cpu-observation-review.json','segmentation-results/label-cpu-observation-review.json','runtime-export-observer/process-receipt.json',OBSERVER_FOLDER+'result.json'])this.register(relative);
  }
  private register(relative:string,label=relative):string{return this.files.register(VMDE+relative,label,sourceFormat(relative));}
  private async json(relative:string):Promise<MaybeJson>{
    const id=this.register(relative);try{return {value:await this.files.json(VMDE+relative),id,error:null};}catch(error){return {value:null,id,error:reason(error)};}
  }
  async evidence(id:string):Promise<WebEvidence>{
    // Dynamic case snapshots are registered only through their fixed trace definitions.
    if(!/^ev_[a-f0-9]{24}$/.test(id))throw failure('NOT_FOUND','Unknown evidence ID');
    return this.files.evidence(id);
  }
  async overview():Promise<ResearchOverview>{
    const [native,node,label,traces,receipt]=await Promise.all([
      this.native(),this.cpu('node-record-cpu'),this.cpu('label-state-cpu'),
      Promise.all([...TRACE_DEFINITIONS.map(d=>this.traceData(d.id)),this.traceData('runtime-exports')]),
      this.json('startup-original-qsettings/process-receipt.json'),
    ]);
    const original=object(receipt.value?.source);
    const functions=await Promise.all(FUNCTIONS.map(async entry=>{
      const listing=await this.json(entry.listing),validation=entry.record.id==='grid-498a50'?native:entry.record.id==='node-record-480230'?node:label;
      return functionRecord(entry.record,!!listing.value,entry.record.id==='startup-transition'?undefined:validation.validation);
    }));
    const evidence:WebEvidence[]=[];
    for(const relative of ['native-kernel/native-summary.json','node-records/cpu-observation-review.json','segmentation-results/label-cpu-observation-review.json','startup-compat/protected-dispatch-v7-review.json'])try{evidence.push(await this.evidence(this.register(relative)));}catch{/* Missing sources remain explicit in the catalogs below. */}
    const nativeCount=native.validation.counts.original_calls;
    return {
      title:'vmde 还原研究档案',
      target:{name:'vmde.exe',path:string(original.path)??'原文件路径未读取；参见原始收据',sha256:string(original.sha256)??''},
      status:'partial-recovery',summary:'局部原生观测、CPU 回放与启动证据已归档；完整应用行为和可运行重建仍未验证。',
      metrics:[
        {label:'原生网格核调用',value:nativeCount===undefined?'不可用':String(nativeCount),detail:'声明的 synthetic disjoint-object contract；不含编译正对照',tone:nativeCount===undefined?'muted':'teal'},
        {label:'节点记录 CPU 回放',value:node.validation.counts.completed===undefined?'不可用':String(node.validation.counts.completed),detail:'CPU 仿真，未新增原生业务调用'},
        {label:'标签状态 CPU 调用',value:label.validation.counts.completed===undefined?'不可用':String(label.validation.counts.completed),detail:'合成无环标签森林；不是自然图像标签来源'},
        {label:'完整可运行重建',value:'未验证',detail:'真实 OEP、保护初始化与正常矢量输出仍有缺口',tone:'warning'},
      ],
      milestones:[
        {label:'网格核与编号',status:native.validation.status,detail:native.validation.scope},
        {label:'40 字节节点记录',status:node.validation.status,detail:node.validation.scope},
        {label:'三项标签森林操作',status:label.validation.status,detail:label.validation.scope},
        {label:'兼容启动与受保护调度',status:traces[0]?.trace.status??'unavailable',detail:'只解释同一运行的观测；终止根因与 VM 语义仍未知'},
        {label:'完整 vmde',status:'unverified',detail:'未证明自然图像到矢量输出，未交付已验证可运行重建'},
      ],functions,traces:traces.map(t=>t.trace),validations:[native.validation,node.validation,label.validation],evidence,limitations:[...LIMITATIONS],
    };
  }
  async function(id:string):Promise<ResearchFunctionDetail>{
    const entry=FUNCTIONS.find(e=>e.record.id===id);if(!entry)throw failure('NOT_FOUND','Unknown research function');
    const sources:WebEvidence[]=[],evidence:WebEvidence[]=[],limitations=[...LIMITATIONS];
    const listing=await this.json(entry.listing);
    for(const [relatives,target] of [[entry.sources,sources],[entry.evidence,evidence]] as const)for(const relative of relatives)try{target.push(await this.evidence(this.register(relative)));}catch{limitations.push('证据不可用 / unavailable: '+relative);}
    if(!listing.value)limitations.push('指令 listing 不可用 / unavailable: '+entry.listing);
    const rawInstructions=id==='startup-transition'?object(listing.value?.dispatcher_listing).instructions??listing.value?.dispatcher_listing:listing.value?.listing;
    const instructions=list(rawInstructions).slice(0,2048).flatMap(value=>{
      const row=object(value),address=string(row.va)??string(row.address),text=string(row.text)??string(row.instruction)??(string(row.mnemonic)?[row.mnemonic,row.operands].filter(Boolean).join(' '):null);
      return address&&text?[{address,text,...(string(row.bytes)?{bytes:string(row.bytes)!}:{})}]:[];
    });
    const graph:ResearchFunctionDetail['graph']={nodes:[{id,label:entry.record.name,address:entry.record.address,status:entry.record.status}],edges:[]};
    let graphTruncated=false;
    const addNode=(node:ResearchFunctionDetail['graph']['nodes'][number])=>{if(graph.nodes.some(item=>item.id===node.id))return true;if(graph.nodes.length>=32){graphTruncated=true;return false;}graph.nodes.push(node);return true;};
    const addEdge=(edge:ResearchFunctionDetail['graph']['edges'][number])=>{if(!graph.nodes.some(n=>n.id===edge.from)||!graph.nodes.some(n=>n.id===edge.to)||graph.edges.length>=32){graphTruncated=true;return;}if(!graph.edges.some(e=>e.from===edge.from&&e.to===edge.to&&e.label===edge.label))graph.edges.push(edge);};
    // Targets are reported by the bounded static listing; this is not executed call coverage.
    const seen=new Set<string>();
    for(const instruction of list(listing.value?.listing)){
      const row=object(instruction);if(!String(row.flow_type??'').includes('CALL'))continue;
      const directTarget=/^CALL (0x[\da-f]{1,8})$/i.exec(string(row.text)??'')?.[1];
      for(const target of directTarget?[directTarget]:list(row.flows??row.targets)){
        const address=string(target)??string(object(target).address);if(!address||!/^0x[\da-f]{1,8}$/i.test(address))continue;
        const nodeId='callee-'+address.toLowerCase();if(!seen.has(nodeId)){seen.add(nodeId);if(!addNode({id:nodeId,label:address,address,status:'static-call-target'}))break;}
        addEdge({from:id,to:nodeId,label:'bounded listing CALL'});
      }
      if(graph.nodes.length>=32)break;
    }
    if(id==='grid-498a50'||id==='node-record-480230'){
      const callerRelative='algorithm-candidates/run-1QAnNQ/00499eb0.json',caller=await this.json(callerRelative);
      const allowed=new Map([['00498a50','grid-498a50'],['00480230','node-record-480230']]);
      for(const value of list(caller.value?.listing)){
        const row=object(value),target=/^CALL 0x([\da-f]{8})$/i.exec(string(row.text)??'')?.[1]?.toLowerCase();
        const to=target?allowed.get(target):undefined;if(!to||!String(row.flow_type??'').includes('CALL'))continue;
        if(!addNode({id:'caller-499eb0',label:'局部调用者 499eb0',address:'0x00499eb0',status:'static-listing'}))break;
        const known=FUNCTIONS.find(e=>e.record.id===to)!.record;if(!addNode({id:to,label:known.name,address:known.address,status:'static-call-target'}))break;
        addEdge({from:'caller-499eb0',to,label:'static CALL @ '+String(row.va)});if(graph.edges.length>=32){graphTruncated=true;break;}
      }
      if(caller.value)try{evidence.push(await this.evidence(caller.id));}catch{limitations.push('局部调用者 listing 预览不可用。');}
    }
    if(id==='startup-transition'){
      limitations.push('指令文本来自独立冻结的静态 Capstone listing；不是 v7 每条指令的动态执行记录。');
      const trace=await this.traceData('startup-exit-v7'),checkpoints=trace.events.filter(e=>e.type==='breakpoint');
      const nodes=new Map<number,string>();
      for(const checkpoint of checkpoints){if(!checkpoint.address)continue;const nodeId='v7-checkpoint-'+checkpoint.index;if(!addNode({id:nodeId,label:'v7 '+checkpoint.address,address:checkpoint.address,status:'same-run-breakpoint'}))break;nodes.set(checkpoint.index,nodeId);}
      const retained=checkpoints.filter(checkpoint=>nodes.has(checkpoint.index));
      for(const checkpoint of retained){
        const code=object(checkpoint.code),hex=string(code.hex);if(!hex||!/^68[\da-f]{8}e9[\da-f]{8}/i.test(hex)||!checkpoint.address)continue;
        const bytes=Buffer.from(hex.slice(0,20),'hex'),source=Number.parseInt(checkpoint.address,16),target=source+10+bytes.readInt32LE(6);
        const next=retained.find(e=>e.index>checkpoint.index&&e.thread_id===checkpoint.thread_id&&e.address!==null&&Number.parseInt(e.address,16)===target);
        if(next)addEdge({from:nodes.get(checkpoint.index)!,to:nodes.get(next.index)!,label:'v7 实测 PUSH token / JMP rel32'});
      }
      limitations.push('未用相邻检查点推断中间控制流；图中只有代码字节可确定的转移边。');
    }
    if(graph.edges.length===0)limitations.push('此 listing 未提供已解析外部 CALL 边；单节点图不表示全程序无依赖。');
    if(graphTruncated)limitations.push('图达到 32 个节点 / 32 条边的显示预算；其余依赖已截断，请查看原始证据。');
    const validation=id==='startup-transition'?undefined:id==='grid-498a50'?(await this.native()).validation:(await this.cpu(id==='node-record-480230'?'node-record-cpu':'label-state-cpu')).validation;
    const record=functionRecord(entry.record,!!listing.value,validation);
    graph.nodes[0]!.status=record.status;
    if(id.startsWith('label-'))record.counts=(await this.cpu('label-state-cpu')).validation.counts;
    return {...record,sources,instructions,graph,evidence,limitations};
  }
  async trace(id:string,query:PageQuery):Promise<Page<ResearchEvent>&{trace:ResearchTrace}>{
    const normalized=queryPage(query),data=await this.traceData(id),needle=normalized.q?.toLocaleLowerCase();
    const rows=data.events.filter(event=>(!normalized.type||normalized.type==='all'||event.type===normalized.type||(normalized.type==='api'&&event.type.startsWith('api_'))||(normalized.type==='module'&&event.type.startsWith('module')))&&(!needle||JSON.stringify(event).toLocaleLowerCase().includes(needle)));
    return {...page(rows,normalized),trace:data.trace};
  }
  private traceData(id:string):Promise<TraceData>{
    const definition=TRACE_DEFINITIONS.find(d=>d.id===id);
    if(!definition&&id!=='runtime-exports')throw failure('NOT_FOUND','Unknown research trace');
    let promise=this.traces.get(id);if(!promise){promise=id==='runtime-exports'?this.observer():this.loadTrace(definition!);this.traces.set(id,promise);}return promise;
  }
  private async loadTrace(definition:typeof TRACE_DEFINITIONS[number]):Promise<TraceData>{
    const receipt=await this.json(definition.folder+'/process-receipt.json');
    const trace:ResearchTrace={id:definition.id,label:definition.label,status:'unavailable',pid:null,job_id:null,event_count:0,source:VMDE+definition.folder+'/process-receipt.json',started_at:string(receipt.value?.started_at)};
    if(!receipt.value)return {trace,events:[]};
    const cli=this.cliResult(receipt.value),result=object(cli.result),job=object(cli.job),ref=object(result.trace_artifact);
    trace.job_id=string(job.job_id);trace.started_at=string(job.started_at)??trace.started_at;
    try{
      const expected=this.reference(ref),relative=VMDE+definition.folder+'/case/artifacts/'+expected.sha256;
      const evidenceId=this.files.register(relative,definition.label+' · 原始 trace','json',expected);
      const raw=await this.files.json(relative,definition.label+' · 原始 trace',expected);
      if(!Array.isArray(raw.events)||raw.events.length>10000)throw failure('EVIDENCE_UNAVAILABLE','Invalid trace events');
      const statuses=[string(result.status),string(job.status),string(raw.status)].filter((s):s is string=>s!==null);
      trace.pid=integer(raw.pid);
      trace.status=statuses.includes('failed')||raw.error!=null||result.error!=null?'failed':new Set(statuses).size>1||object(result.trace_recovery).is_checkpoint===true?'partial':statuses[0]??'unknown';
      trace.event_count=raw.events.length;trace.source=relative;
      const snapshots=list(result.snapshots).slice(0,128).flatMap(value=>{
        const snapshot=object(value);try{const identity=this.reference(object(snapshot.artifact));const id=this.files.register(VMDE+definition.folder+'/case/artifacts/'+identity.sha256,'快照 '+String(snapshot.phase??'')+' '+String(snapshot.rva??''),'hex',identity);return [{rva:snapshot.rva,phase:snapshot.phase,size_bytes:identity.size_bytes,evidence_id:id}];}catch{return [];}
      });
      return {trace,events:raw.events.map((value,index)=>{
        const row=object(value),context=object(row.context),pc=object(row.pc);
        return {index,type:string(row.type)??'unknown',label:[string(row.type),string(row.module),string(row.symbol),string(row.breakpoint_rva)].filter(Boolean).join(' · '),address:string(pc.address)??string(context.pc)??string(context.eip)??string(row.address),thread_id:integer(row.thread_id),time:string(row.time)??string(row.observed_at)??string(row.timestamp),context:Object.keys(context).length?object(bounded(context)):null,stack:bounded(row.stack),code:bounded(row.pc_code??row.code),details:bounded({...row,snapshots:snapshots.filter(s=>!row.breakpoint_rva||s.phase==='breakpoint-'+String(row.breakpoint_rva).replace(/^0x/,'')),trace_error:raw.error,omitted_events:raw.omitted_events}),evidence_id:evidenceId};
      })};
    }catch(error){return {trace:{...trace,status:'unavailable'},events:[]};}
  }
  private cliResult(receipt:JsonObject):JsonObject{
    if(Object.keys(object(receipt.cli_result)).length)return object(receipt.cli_result);
    // The original QSettings failed control retained its public CLI envelope on the
    // process row, not at the top level. Inspect data only; never follow args or paths.
    for(const value of [...list(receipt.processes)].reverse()){const row=object(value),result=object(row.result);if(Object.keys(object(result.result)).length)return result;const stdout=string(object(row.execution).stdout);if(stdout&&Buffer.byteLength(stdout,'utf8')<=1024*1024)try{const decoded=object(JSON.parse(stdout));if(Object.keys(object(decoded.result)).length)return decoded;}catch{/* Not a JSON CLI receipt. */}}
    return {};
  }
  private reference(ref:JsonObject):{sha256:string;size_bytes:number}{
    const sha256=string(ref.sha256),size=integer(ref.size_bytes);
    if(!sha256||!shaPattern.test(sha256)||size===null||ref.relative_path!=='artifacts/'+sha256)throw failure('EVIDENCE_UNAVAILABLE','Invalid local artifact reference');return {sha256,size_bytes:size};
  }
  private async observer():Promise<TraceData>{
    const result=await this.json(OBSERVER_FOLDER+'result.json'),raw=result.value;
    const trace:ResearchTrace={id:'runtime-exports',label:'原程序 · QtCore 导出 8 时点观察',status:'unavailable',pid:null,job_id:null,event_count:0,source:VMDE+OBSERVER_FOLDER+'result.json',started_at:string(raw?.started_utc)};
    if(!raw||!Array.isArray(raw.samples)||raw.samples.length>8)return {trace,events:[]};
    const identity=object(raw.identity);trace.pid=integer(object(identity.start).pid)??integer(object(raw.request).pid);trace.status=string(raw.status)??'unknown';
    const events:ResearchEvent[]=[];
    for(let index=0;index<raw.samples.length;index++){
      const summary=object(raw.samples[index]),expectedFile='sample-'+index.toString().padStart(3,'0')+'.json';let details:JsonObject,evidenceId=result.id;
      try{
        if(summary.file!==expectedFile||summary.index!==index)throw failure('EVIDENCE_UNAVAILABLE','Unexpected observer sample identity');
        const expected=typeof summary.sha256==='string'&&shaPattern.test(summary.sha256)&&integer(summary.size_bytes)!==null?{sha256:summary.sha256,size_bytes:summary.size_bytes as number}:undefined;
        const relative=VMDE+OBSERVER_FOLDER+expectedFile;evidenceId=this.files.register(relative,'QtCore 导出时点 '+index,'json',expected);
        const sample=await this.files.json(relative,'QtCore 导出时点 '+index,expected);
        if(sample.index!==index)throw failure('EVIDENCE_UNAVAILABLE','Observer sample index mismatch');
        const sampleIdentity=object(sample.identity),start=object(sampleIdentity.start),end=object(sampleIdentity.end),expectedIdentity=object(identity.start);
        for(const observed of [sampleIdentity,start,end]){
          const samplePid=integer(observed.pid);if(samplePid!==null&&trace.pid!==null&&samplePid!==trace.pid)throw failure('EVIDENCE_UNAVAILABLE','Observer sample belongs to a different PID');
          for(const key of ['creation_filetime','executable'])if(expectedIdentity[key]!==undefined&&observed[key]!==undefined&&expectedIdentity[key]!==observed[key])throw failure('EVIDENCE_UNAVAILABLE','Observer sample process identity changed');
        }
        const inspection=object(sample.inspection);
        details={...summary,status:summary.status??'unknown',identity:sample.identity,module:sample.module,error:sample.error,atomic:sample.atomic,inspection:{status:inspection.status,frida_export_type:inspection.frida_export_type??null,os_resolution_verified:inspection.os_resolution_verified??null,exports:inspection.exports,errors:inspection.errors},scope:'Readonly export metadata; execute permission does not prove hook success, function/data type or function invocation.'};
      }catch(error){details={...summary,status:'unavailable',error:reason(error)};trace.status='partial';}
      const module=object(details.module);events.push({index,type:'export_sample',label:`QtCore 导出采样 ${index} · ${String(summary.requested_offset_ms??'?')} ms`,address:typeof module.base==='number'?'0x'+module.base.toString(16):null,thread_id:null,time:string(summary.started_utc),context:null,stack:null,code:null,details:bounded(details),evidence_id:evidenceId});
    }
    trace.event_count=events.length;return {trace,events};
  }
  async validation(id:string,query:PageQuery):Promise<ValidationPage>{
    const normalized=queryPage(query);let data:ValidationData;
    if(id==='native-grid')data=await this.native();else if(id==='node-record-cpu'||id==='label-state-cpu')data=await this.cpu(id);else throw failure('NOT_FOUND','Unknown research validation');
    const needle=normalized.q?.toLocaleLowerCase();const rows=data.rows.filter(row=>(!normalized.status||normalized.status==='all'||row.status===normalized.status)&&(!needle||JSON.stringify(row).toLocaleLowerCase().includes(needle)));
    return {...page(rows,normalized),validation:data.validation};
  }
  private native():Promise<ValidationData>{return this.nativePromise??=this.loadNative();}
  private async loadNative():Promise<ValidationData>{
    const summary=await this.json('native-kernel/native-summary.json');
    const validation:ResearchValidation={id:'native-grid',label:'原生网格核 · 合成契约',kind:'native-observation',status:'unavailable',scope:'native synthetic disjoint-object contract; 637-byte grid kernel only; compiled positive control excluded from original calls',counts:{},limitations:[LIMITATIONS[0]!,LIMITATIONS[2]!,'候选输出数组没有保存在比较报告中；展示原生实测输出与已保存比较结论，candidate_output 明确为 null。']};
    if(!summary.value||integer(summary.value.original_calls)===null)return {validation,rows:[]};
    validation.counts=Object.fromEntries(['original_calls','original_matched','original_failed','original_unattempted','compiled_control_calls'].flatMap(key=>integer(summary.value![key])===null?[]:[[key,summary.value![key] as number]]));
    validation.status=string(summary.value.status)??'unknown';const rows:JsonObject[]=[];
    for(const profile of ['edges8','legacy896']){
      const [comparison,corpus]=await Promise.all([this.json(`native-kernel/comparison-${profile}.json`),this.json(`native-kernel/${profile}.json`)]);
      const nativeRelative=`native-kernel/release-files/runs/${profile}/native-result.json`,nativeId=this.register(nativeRelative);
      let actual:JsonObject|null=null;
      try{
        const summaryRun=list(summary.value.runs).map(object).find(run=>run.profile===profile),identity=object(summaryRun?.native);
        const expected=string(identity.sha256)&&shaPattern.test(String(identity.sha256))&&integer(identity.size_bytes)!==null?{sha256:String(identity.sha256),size_bytes:identity.size_bytes as number}:undefined;
        actual=await this.files.json(VMDE+nativeRelative,profile+' · 保存原生输出',expected);
      }catch{validation.status='partial';validation.limitations.push('原生输出不可用: '+profile);}
      if(!comparison.value){validation.status='partial';validation.limitations.push('比较结论不可用: '+profile);continue;}
      try{
        const observed=actual?uniqueRows(actual.rows):new Map<string,JsonObject>(),inputs=corpus.value?uniqueRows(corpus.value.cases):new Map<string,JsonObject>();
        for(const [id,compared] of uniqueRows(comparison.value.comparisons)){
          const original=observed.get(id),status=string(compared.status)??'unknown';
          const hasOutput=Array.isArray(original?.output)&&original.output.every(value=>typeof value==='number'&&Number.isInteger(value)&&value>=-2147483648&&value<=2147483647);
          const originalStatus=string(original?.status),rowStatus=originalStatus==='failed'?'failed':originalStatus==='unattempted'?'unattempted':originalStatus==='completed'&&hasOutput?status:'unavailable';
          rows.push({id,profile,status:rowStatus,comparison_status:status,scope:validation.scope,input:bounded(inputs.get(id)??null),original_output:hasOutput?bounded(original?.output):null,candidate_output:null,candidate_output_status:'not_retained_in_comparison_report',original_status:originalStatus??'unavailable',native_evidence:bounded(original?.evidence),original_error:bounded(original?.error),comparison:bounded(compared),evidence_id:nativeId,comparison_evidence_id:comparison.id});
          if(rowStatus==='unavailable'||rowStatus!==status||actual?.status==='failed')validation.status='partial';
        }
      }catch(error){validation.status='partial';validation.limitations.push(reason(error)+' · '+profile);}
    }
    if(rows.length!==validation.counts.original_calls){validation.status='partial';validation.limitations.push('可读取比较行数与原生总计不同；总计保持原收据值。');}
    return {validation,rows};
  }
  private cpu(id:'node-record-cpu'|'label-state-cpu'):Promise<ValidationData>{let promise=this.validations.get(id);if(!promise){promise=this.loadCpu(id);this.validations.set(id,promise);}return promise;}
  private async loadCpu(id:'node-record-cpu'|'label-state-cpu'):Promise<ValidationData>{
    const node=id==='node-record-cpu',relative=node?'node-records/run-cpu-writer-20261020/result.json':'segmentation-results/run-label-replay-20261020/result.json',saved=await this.json(relative),raw=saved.value;
    const validation:ResearchValidation={id,label:node?'节点记录 · CPU 回放':'标签森林三项操作 · CPU 回放',kind:'cpu-replay',status:'unavailable',scope:node?'31-case bounded CPU replay under synthetic record/stack/FPU contract; no native target execution':'26-call / 12-scenario bounded CPU replay of synthetic acyclic label forests; no natural image labels',counts:{},limitations:[LIMITATIONS[1]!,LIMITATIONS[2]!,'保存的 expected_state/expected_sha256 是候选模型预期；不构成全输入域证明。']};
    if(!raw||!Array.isArray(raw.rows)||raw.rows.length>10000||raw.native_call!==false||raw.observation_kind!=='bounded_cpu_emulation')return {validation,rows:[]};
    validation.status=string(raw.status)??'unknown';validation.counts=counts(raw.counts);
    if(!node&&Array.isArray(raw.scenarios))validation.counts.scenarios=raw.scenarios.length;
    const rows=raw.rows.map((value,index)=>{
      const row=object(value),comparison=object(row.comparison),status=string(row.status)??'unknown';
      return {id:string(row.id)??`${string(row.scenario_id)??'scenario'}:${integer(row.call_index)??index}`,status:status==='completed'?(comparison.matched===true?'matched':comparison.matched===false?'mismatched':'unknown'):status,method:row.method??'write-record',scenario_id:row.scenario_id??null,call_index:row.call_index??null,scope:validation.scope,input:bounded(row.case??object(row.actual_before).state),original_output:bounded(node?row.actual_after_hex:object(row.actual_after).state),candidate_output:bounded(node?{expected_sha256:row.expected_sha256}:row.expected_state),comparison:bounded(comparison),registers:bounded(row.registers_after),checks:bounded(row.checks),steps:row.steps??null,negative_controls:bounded(row.negative_controls),error:row.error??null,evidence_id:saved.id};
    });return {validation,rows};
  }
}

import {el,heading,panel,badge,button,field,select,loading,errorBox,empty,kv,json,notice,table,showEvidence,collectionNotice} from '../components.js';
import {isTerminal,dateLabel,createGeneration,pretty} from '../view-model.js';
import {buildIdaQueries,idaReadCase,idaCapabilityLabel,idaReportSummary,idaCodeText,createIdaSelection} from '../ida-view-model.js';
import {graphView} from './code.js';
function replaceContent(node,...children){node.replaceChildren(...children.flat(Infinity).filter(value=>value!==null&&value!==undefined&&value!==false));}

/** IDA is a static evidence provider. Every submission uses the normal owned job API. */
export async function renderIda(ctx) {
  const writeCaseId=ctx.managedCaseId;
  let readCaseId=idaReadCase(ctx.selected,ctx.caseId,writeCaseId);
  let data=await ctx.api(`/api/cases/${encodeURIComponent(readCaseId)}`);
  let selectedJobId,selectedRunId,pollTimer,polling=false,renderedSelectionState;
  const selection=createIdaSelection(),refreshGeneration=createGeneration();
  const capabilityBox=el('div',{class:'ida-capability'}),history=el('div',{}),monitor=el('div',{class:'ida-monitor'}),results=el('div',{}),submitStatus=el('div',{'aria-live':'polite'}),exports=el('div',{'aria-live':'polite'});
  const capability=await ctx.api('/api/ida/status');
  function showCapability(value) {
    replaceContent(capabilityBox,el('div',{class:'row'},badge(value.status,idaCapabilityLabel(value)),el('span',{class:'tag mono'},value.provider?.version??'IDA 版本未验证')),
      kv([['MCP 后端',value.provider?.server??'未配置'],['源码版本',value.provider?.revision??'未记录'],['配置文件',value.configuration_path??'未记录']]),
      value.error?errorBox(value.error):null,
      notice('本页执行静态分析并保存原始证据。反编译结果不授予行为等价或整程序还原结论。','neutral'),
      value.probe?el('details',{},el('summary',{},'本机能力实测记录'),json(value.probe)):null);
  }
  showCapability(capability);
  const samples=Array.isArray(capability.samples)?capability.samples:[];
  const file=el('input',{type:'text',required:true,placeholder:'服务器上的绝对文件路径','aria-label':'IDA 目标文件'});
  const preset=select([{value:'function',label:'函数分析与交叉引用'},{value:'overview',label:'元数据、函数与字符串概览'},{value:'functions',label:'函数列表 / 搜索'},{value:'strings',label:'字符串列表 / 搜索'},{value:'types',label:'类型列表 / 搜索'},{value:'bytes',label:'读取指定地址字节'},{value:'json',label:'高级查询 JSON'}],{'aria-label':'IDA 查询预设'});
  const address=el('input',{value:'0x498a50',placeholder:'0x401000','aria-label':'IDA 函数或字节地址'});
  const pattern=el('input',{placeholder:'可选：名字或字符串条件','aria-label':'IDA 搜索条件'});
  const offset=el('input',{type:'number',min:0,max:1000000,value:'0','aria-label':'IDA 列表偏移'});
  const limit=el('input',{type:'number',min:1,max:200,value:'50','aria-label':'IDA 列表条数'});
  const size=el('input',{type:'number',min:1,max:4096,value:'64','aria-label':'IDA 字节数'});
  const timeout=el('input',{type:'number',min:1,max:600000,value:'120000','aria-label':'IDA 超时毫秒'});
  const editor=el('textarea',{class:'json-editor',rows:9,spellcheck:false,'aria-label':'IDA 查询 JSON',value:'[\n  {"kind":"overview"},\n  {"kind":"function","address":"0x498a50"}\n]'});
  const addressField=field('地址 / EA',address,'使用当前输入数据库的绝对地址；保留完整 64 位。');
  const searchFields=el('div',{},field('筛选条件',pattern),el('div',{class:'ida-field-row'},field('偏移',offset),field('条数',limit)));
  const sizeField=field('读取字节数',size),jsonField=field('查询 JSON',editor,'仅允许静态查询，最多 16 个；不接受任意工具名或 Python。');
  function updateFields() {
    addressField.hidden=!['function','bytes'].includes(preset.value);
    sizeField.hidden=preset.value!=='bytes';
    searchFields.hidden=!['functions','strings','types'].includes(preset.value);
    jsonField.hidden=preset.value!=='json';
  }
  preset.addEventListener('change',updateFields);updateFields();
  const sampleNotice=el('div',{}),sampleSelect=select([{value:'',label:'选择已核对身份的本机样例'},...samples.map(sample=>({value:sample.id,label:sample.label}))],{'aria-label':'IDA 本机样例',onchange:()=>{
    const sample=samples.find(item=>item.id===sampleSelect.value);
    if(!sample){sampleNotice.replaceChildren();return;}
    file.value=sample.file;
    if(sample.address){address.value=sample.address;preset.value='function';}else preset.value='overview';
    updateFields();sampleNotice.replaceChildren(notice(sample.description,'neutral'),el('code',{class:'small'},sample.sha256));
  }});
  const target=ctx.bootstrap.research?.target?.path;
  const targetButton=target?button('使用 vmde 原文件路径',()=>{file.value=target;},'text'):null;
  const destination=ctx.bootstrap.cases.find(item=>item.id===writeCaseId);
  const submit=el('button',{type:'submit',class:'button primary','data-testid':'submit-ida'},'提交 IDA 分析');
  const form=el('form',{class:'ida-form'},notice(`新任务保存到：${destination?.label??writeCaseId}。原文件保留，分析使用独立副本。`,'neutral'),samples.length?field('已验证输入样例',sampleSelect):null,sampleNotice,field('目标文件',file),targetButton,
    field('查询预设',preset),addressField,searchFields,sizeField,jsonField,field('任务超时（毫秒）',timeout),submit,submitStatus);
  form.addEventListener('submit',async event=>{
    event.preventDefault();if(form.dataset.busy)return;form.dataset.busy='true';submit.disabled=true;
    submitStatus.replaceChildren(loading('正在提交分析任务…'));
    try {
      const queries=buildIdaQueries({preset:preset.value,address:address.value,pattern:pattern.value,offset:offset.value,limit:limit.value,size:size.value,json:editor.value});
      const milliseconds=Number(timeout.value);
      if(!Number.isSafeInteger(milliseconds)||milliseconds<1||milliseconds>600000)throw new Error('超时须为 1–600000 毫秒');
      const job=await ctx.api(`/api/cases/${encodeURIComponent(writeCaseId)}/tasks`,{method:'POST',body:{kind:'ida',file:file.value.trim(),queries,timeout_ms:milliseconds}});
      if(!ctx.isCurrent())return;
      readCaseId=writeCaseId;selectedJobId=job.job_id;selectedRunId=undefined;
      await refresh();
      submitStatus.replaceChildren(notice(`已提交 ${job.job_id}。查询进度见右侧。`,'success'));schedule();
    } catch(error) {if(error.name!=='AbortError'&&ctx.isCurrent())submitStatus.replaceChildren(errorBox(error));}
    finally {delete form.dataset.busy;if(ctx.isCurrent())submit.disabled=false;}
  });
  ctx.signal.addEventListener('abort',()=>clearTimeout(pollTimer),{once:true});
  const idaJobs=()=>data.jobs.filter(job=>job.operation==='analyze_ida');
  const idaRuns=()=>data.runs.filter(run=>run.operation==='analyze_ida');
  async function refresh() {
    const requestedCase=readCaseId,refreshTicket=refreshGeneration.next();
    const next=await ctx.api(`/api/cases/${encodeURIComponent(requestedCase)}`);
    if(!ctx.isCurrent()||requestedCase!==readCaseId||!refreshGeneration.isCurrent(refreshTicket))return;
    data=next;const jobs=idaJobs();
    if(!selectedJobId&&!selectedRunId)selectedJobId=jobs[0]?.job_id;
    renderHistory();renderSelection();
  }
  function renderHistory() {
    const runs=idaRuns();
    replaceContent(history,notice(`正在查看案例：${data.case?.label??readCaseId}`,'neutral'),collectionNotice(data,'jobs','任务'),collectionNotice(data,'runs','运行'),
      idaJobs().length?el('div',{class:'job-list'},idaJobs().map(job=>button(el('span',{class:'job-content'},el('span',{class:'job-heading'},el('strong',{},'IDA 分析'),badge(job.status)),el('small',{class:'mono'},job.job_id),el('span',{class:'small muted'},dateLabel(job.created_at))),()=>{
        selectedJobId=job.job_id;selectedRunId=undefined;renderHistory();renderSelection();
      },`job-row${selectedJobId===job.job_id?' selected':''}`,{'data-ida-job-id':job.job_id}))):empty('还没有 IDA 任务','填写目标与查询后提交；既有分析结果会保存在案例中。'),
      runs.length?el('details',{},el('summary',{},`全部已保存 IDA 结果（${runs.length}）`),table([{label:'运行',render:run=>button(run.id,()=>{selectedRunId=run.id;selectedJobId=undefined;renderHistory();renderSelection();},'text')},{label:'结果',render:run=>badge(run.status)}],runs)):null);
  }
  function renderSelection() {
    const job=data.jobs.find(item=>item.job_id===selectedJobId);
    const run=data.runs.find(item=>item.id===(selectedRunId??job?.result_id));
    const {ticket,changed}=selection.select(readCaseId,selectedJobId,run?.id);
    const state=JSON.stringify([readCaseId,selectedJobId??null,run?.id??null,job?.status,job?.owned,job?.started_at,job?.finished_at,job?.error,run?.status]);
    if(state===renderedSelectionState)return;
    renderedSelectionState=state;
    if(changed)exports.replaceChildren();
    const controls=[];
    if(job)controls.push(button('取消此 IDA 任务',async event=>{
      event.currentTarget.disabled=true;
      try {
        await ctx.api(`/api/cases/${encodeURIComponent(readCaseId)}/jobs/${encodeURIComponent(job.job_id)}/cancel`,{method:'POST',body:{}});
        if(!ctx.isCurrent()||!selection.isCurrent(ticket))return;
        await refresh();schedule();
      }catch(error){if(error.name!=='AbortError'&&ctx.isCurrent()&&selection.isCurrent(ticket))exports.replaceChildren(errorBox(error));}
    },'danger-outline',{disabled:!job.owned||isTerminal(job.status)||job.status==='cancelling','data-testid':'cancel-ida'}));
    if(run)controls.push(button('导出 IDA 证据报告',()=>exportRun(run.id,ticket),'primary',{'data-testid':'export-ida'}));
    replaceContent(monitor,el('div',{class:'row'},job?badge(job.status):null,run?badge(run.status):null,...controls),
      job?kv([['任务 ID',job.job_id],['开始时间',dateLabel(job.started_at)],['结束时间',dateLabel(job.finished_at)],['归属',job.owned?'当前服务会话':'历史任务 / 不可取消']]):null,
      job?.error?errorBox(job.error):null,exports);
    if(run)showResult(run.result,ticket);
    else results.replaceChildren(empty(job&&!isTerminal(job.status)?'IDA 正在分析':'等待分析结果',job?'分析完成后展示逐项查询、源文件身份和证据。':'提交新任务或选择历史记录。'));
  }
  async function exportRun(runId,ticket) {
    exports.replaceChildren(loading('正在导出可独立校验的证据包…'));
    try {
      const value=await ctx.api(`/api/cases/${encodeURIComponent(readCaseId)}/exports`,{method:'POST',body:{runId}});
      if(!ctx.isCurrent()||!selection.isCurrent(ticket))return;
      exports.replaceChildren(notice('证据报告已导出。','success'),kv([['导出目录',value.path]]),el('div',{class:'download-files'},value.files.map(item=>el('a',{class:'download-link',href:`/api/exports/${encodeURIComponent(value.id)}/file?path=${encodeURIComponent(item.name)}`,download:item.name},item.name))));
    }catch(error){if(error.name!=='AbortError'&&ctx.isCurrent()&&selection.isCurrent(ticket))exports.replaceChildren(errorBox(error));}
  }
  function artifactButton(ref,ticket) {
    return button(`证据 ${ref.sha256.slice(0,16)}…`,async()=>{
      try {
        const value=await ctx.api(`/api/cases/${encodeURIComponent(readCaseId)}/artifacts/${ref.sha256}`);
        if(ctx.isCurrent()&&selection.isCurrent(ticket))showEvidence(value,ctx);
      }catch(error){if(error.name!=='AbortError'&&ctx.isCurrent()&&selection.isCurrent(ticket))exports.replaceChildren(errorBox(error));}
    },'text');
  }
  function showResult(result,ticket) {
    const summary=idaReportSummary(result);
    const scope=result.source_scope??samples.find(item=>item.sha256===result.source?.sha256);
    const root=el('div',{class:'ida-result','data-testid':'ida-result'},el('div',{class:'row'},el('h3',{},summary.label),badge(result.status)),scope?notice(scope.description,'neutral'):null,
      kv([['源文件',result.source?.path],['SHA-256',result.source?.sha256],['数据库',result.database?.path],['Image base',result.database?.imagebase],['输入身份',result.database?.identity_verified?'已核对':'未核对'],['查询结果',`${summary.completed} 完成 / ${summary.failed} 失败 / ${summary.other} 部分或未完成`]]),
      result.error?errorBox(result.error):null,...(result.limitations??[]).filter(text=>text!==scope?.description).map(text=>notice(text,'neutral')));
    for(const [index,item] of (result.queries??[]).entries()) {
      const text=idaCodeText(item.data),body=el('div',{class:'ida-query-body'},el('div',{class:'row'},badge(item.status),el('code',{},pretty(item.query))),item.error?errorBox(item.error):null);
      if(text!==null)body.append(el('h4',{},'IDA 保留的代码文本'),el('pre',{class:'ida-code'},text));
      if(Array.isArray(item.data?.disassembly)&&item.data.disassembly.length)body.append(panel('反汇编','仅展示已返回的指令',json(item.data.disassembly)));
      const graph=item.data?.basic_blocks;
      if(Array.isArray(graph?.nodes)&&Array.isArray(graph?.edges)) {
        const nodes=graph.nodes.filter(node=>typeof node?.id==='string').slice(0,60).map(node=>({...node,label:node.label??node.address??node.start??node.id}));
        const ids=new Set(nodes.map(node=>node.id));
        const edges=graph.edges.map(edge=>({from:edge.from??edge.source,to:edge.to??edge.target})).filter(edge=>ids.has(edge.from)&&ids.has(edge.to)).slice(0,200);
        body.append(graphView({nodes,edges},node=>nodeInfo.replaceChildren(kv([['基本块',node.id],['地址',node.address??node.start]]))));
        const nodeInfo=el('div',{});body.append(nodeInfo);
        if(graph.nodes.length>60||graph.edges.length>200)body.append(notice('图显示最多 60 个节点和 200 条边；完整返回值见下方 JSON。','neutral'));
      }
      body.append(el('details',{open:text===null},el('summary',{},'完整结构化查询结果'),json(item.data??null)));
      root.append(panel(`查询 ${index+1} · ${item.query?.kind??'未记录'}`,item.query?.address??'静态分析',body));
    }
    root.append(el('details',{},el('summary',{},'进程与数据库清理'),json(result.cleanup)));
    const refs=(result.artifacts??[]).filter(ref=>typeof ref?.sha256==='string'&&/^[0-9a-f]{64}$/.test(ref.sha256));
    root.append(panel('原始证据','SHA-256 工件 · 文本安全预览',el('div',{class:'artifact-buttons'},refs.slice(0,48).map(ref=>artifactButton(ref,ticket)))));
    if(refs.length>48)root.append(notice(`仅展示前 48 个证据入口，共 ${refs.length} 个；导出包保留全部登记工件。`,'neutral'));
    results.replaceChildren(root);
  }
  function schedule() {
    clearTimeout(pollTimer);
    if(!ctx.isCurrent()||!idaJobs().some(job=>job.owned&&!isTerminal(job.status)))return;
    pollTimer=setTimeout(async()=>{
      if(polling||!ctx.isCurrent())return;polling=true;
      try{await refresh();}catch(error){if(error.name!=='AbortError'&&ctx.isCurrent())submitStatus.replaceChildren(errorBox(error));}
      finally{polling=false;schedule();}
    },1000);
  }
  renderHistory();
  if(idaJobs().length)selectedJobId=idaJobs()[0].job_id;
  else selectedRunId=idaRuns()[0]?.id;
  renderSelection();schedule();
  return el('div',{class:'view'},heading('IDA ANALYSIS','IDA 分析','通过独立 MCP 后端查询本机 IDA，保留每项成功、部分结果和失败。'),
    panel('本机能力','安装状态与实测状态分别记录',capabilityBox),el('div',{class:'ida-layout'},el('div',{class:'ida-controls'},panel('新建静态分析','Read-only queries / 独立输入副本',form),panel('分析历史','Jobs / 当前案例内的 IDA 任务',history)),el('div',{class:'ida-main'},panel('任务与结果','IDA 证据不等于行为验证',el('div',{},monitor,results)))));
}

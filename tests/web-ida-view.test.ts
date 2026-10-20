import {describe,it,expect} from 'vitest';
// @ts-expect-error Browser ES module is tested directly.
import {buildIdaQueries,idaReadCase,idaCapabilityLabel,idaReportSummary,idaCodeText,createIdaSelection} from '../apps/web/public/ida-view-model.js';

describe('IDA workbench data and evidence boundaries',()=>{
 it('builds explicit read-only queries while preserving 64-bit addresses',()=>{
  expect(buildIdaQueries({preset:'function',address:'0x123456789abcdef0'})).toEqual([{kind:'function',address:'0x123456789abcdef0'},{kind:'xrefs',address:'0x123456789abcdef0'}]);
  expect(buildIdaQueries({preset:'overview'})).toEqual([{kind:'overview'},{kind:'functions',offset:0,limit:50},{kind:'strings',offset:0,limit:50}]);
  expect(buildIdaQueries({preset:'bytes',address:'0x401000',size:'32'})).toEqual([{kind:'bytes',address:'0x401000',size:32}]);
 });
 it('rejects browser-supplied executable tools, malformed addresses and excessive budgets',()=>{
  for(const json of ['[{"kind":"py_eval","code":"bad"}]','[{"kind":"overview","command":"bad"}]','[]',JSON.stringify(Array.from({length:17},()=>({kind:'overview'})))])expect(()=>buildIdaQueries({preset:'json',json})).toThrow();
  expect(()=>buildIdaQueries({preset:'function',address:'401000'})).toThrow();
  expect(()=>buildIdaQueries({preset:'bytes',address:'0x401000',size:'4097'})).toThrow();
 });
 it('preserves historical result case identity while separating the writable destination',()=>{
  expect(idaReadCase({kind:'managed',writable:false},'history','workbench')).toBe('history');
  expect(idaReadCase({kind:'research'},'vmde','workbench')).toBe('workbench');
 });
 it('does not turn an installed runtime or a completed partial query into proof',()=>{
  expect(idaCapabilityLabel({installed:true,status:'not_probed'})).toContain('未验证');
  expect(idaCapabilityLabel({status:'verified'})).toContain('已实测');
  expect(idaReportSummary({status:'partial',queries:[{status:'completed'},{status:'failed'}]})).toEqual({completed:1,failed:1,other:0,total:2,label:'部分查询完成'});
  expect(idaReportSummary({status:'failed',queries:[]}).label).toBe('分析失败');
 });
 it('extracts retained code text without inventing a decompilation for missing fields',()=>{
  expect(idaCodeText({pseudocode:'int f(){return 1;}'})).toBe('int f(){return 1;}');
  expect(idaCodeText({code:'<script>bad()</script>'})).toBe('<script>bad()</script>');
  expect(idaCodeText({decompile_error:'No decompiler'})).toBe(null);
 });
 it('keeps a pending export current across polls and invalidates only actual selection changes',()=>{
  const selection=createIdaSelection();const first=selection.select('case','job','run');
  expect(selection.select('case','job','run')).toEqual({ticket:first.ticket,changed:false});expect(selection.isCurrent(first.ticket)).toBe(true);
  selection.select('case','job_other','run_other');expect(selection.isCurrent(first.ticket)).toBe(false);
 });
});

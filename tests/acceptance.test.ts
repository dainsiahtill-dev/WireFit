import {it,expect} from 'vitest';
import {readFileSync} from 'node:fs';
const api:any=await import('../src/acceptance.js');
const normative=readFileSync(new URL('../docs/ACCEPTANCE.md',import.meta.url),'utf8');
it('retains all 63 normative gates and rejects duplicate gate identities',()=>{
 expect(api.parseAcceptanceGates?.(normative)).toHaveLength(63);
 expect(()=>api.parseAcceptanceGates?.('| C01 | first | criterion |\n| C01 | duplicate | criterion |')).toThrow(/duplicate/i);
});
it('does not upgrade partial component coverage or absent evidence to a full gate pass',()=>{
 const partial=api.deriveAcceptanceGate?.({id:'C04',title:'BV8',criterion:'every core op'},[{file:'tests/exact-evaluator.test.ts',name:'exact independent evaluator evaluates MBA addition exhaustively over BV8 input pairs',status:'passed'}],{});
 expect(partial?.status).toBe('INCONCLUSIVE');
 expect(api.deriveAcceptanceGate?.({id:'V03',title:'translator corruption',criterion:'reject false counterexample'},[],{})?.status).toBe('NOT_RUN');
});
it('keeps empirical recovery failures and blocked native gates visible',()=>{
 const options={benchmark:{counts:{handwired:{failed:1,passed:8,planned:9}},entries:[{template:'piecewise_affine',parameter_seed:1,backend:'handwired',status:'FAIL'}]},rea:{native_blockers:['Ghidra unavailable']}};
 expect(api.deriveAcceptanceGate?.({id:'N08',title:'holdout',criterion:'fixed tolerance'},[],options)?.status).toBe('FAIL');
 expect(api.deriveAcceptanceGate?.({id:'R08',title:'native',criterion:'real native gate'},[],options)?.status).toBe('BLOCKED');
});
it('uses actual reporter failures and preserves test identities while rejecting malformed reporter data',()=>{
 const report={testResults:[{name:'E:/wirefit/tests/shared.test.ts',assertionResults:[{fullName:'canonical contracts compiles all eleven JSON Schema 2020-12 contracts offline',status:'failed',failureMessages:['actual regression']}]}]};
 const tests=api.extractVitestAssertions?.(report);
 expect(tests?.[0]).toMatchObject({status:'failed',name:'canonical contracts compiles all eleven JSON Schema 2020-12 contracts offline'});
 expect(api.deriveAcceptanceGate?.({id:'C01',title:'contracts',criterion:'all schemas'},tests??[],{})?.status).toBe('FAIL');
 expect(()=>api.extractVitestAssertions?.({testResults:'not an array'})).toThrow(/report/i);
});


it('counts known training inputs separately from unseen research holdout points',()=>{
 const benchmark={entries:[{template:'affine',parameter_seed:0,backend:'reference',train_observations:[{inputs:{x:{kind:'fp32',bits:'0x00000000'}}}],trials:[{mode:'cold',holdout_observations:[{inputs:{x:{kind:'fp32',bits:'0x00000000'}}},{inputs:{x:{kind:'fp32',bits:'0x80000000'}}}]}]}]};
 expect(api.benchmarkBoundaryOverlap?.(benchmark)).toEqual([{template:'affine',parameter_seed:0,backend:'reference',mode:'cold',planned:2,known_training_inputs:1,unseen_typed_inputs:1}]);
});
it('keeps compiled entrypoint receipts separate and refuses incomplete or inconsistent success evidence',()=>{
 const tools=Array.from({length:13},(_,i)=>'wirefit_tool_'+i);
 const receipt={node:'v24.22.0',cli:{doctor:{product:'Wirefit',runtime:{node:'v24.22.0'}}},mcp:{tools,proofJob:{status:'completed'},proof:{data:{model_check:{status:'proved'}}},refutedJob:{status:'completed'},refutation:{data:{model_check:{status:'refuted'}}},counterexamples:{data:{counterexample:{inputs:{},left_outputs:{},right_outputs:{}}}},cancelled:{status:'cancelled'}},cleanup:{case_writer_released:true}};
 const catalog={tools:tools.map(name=>({name}))};
 expect(api.compiledEntrypointEvidence?.(null,null)?.status).toBe('NOT_RUN');
 expect(api.compiledEntrypointEvidence?.(receipt,catalog)?.status).toBe('PASS');
 expect(api.compiledEntrypointEvidence?.({...receipt,cleanup:{case_writer_released:false}},catalog)?.status).toBe('INCONCLUSIVE');
 expect(api.compiledEntrypointEvidence?.(receipt,{tools:[...catalog.tools.slice(1)]})?.status).toBe('INCONCLUSIVE');
});
it('preserves the real reporter bytes when a command receipt shares its check ID',async()=>{
 const {mkdtemp,readFile,rm,mkdir}=await import('node:fs/promises');
 const path=await import('node:path');
 const root=path.resolve('.tmp');await mkdir(root,{recursive:true});const folder=await mkdtemp(path.join(root,'acceptance-path-test-'));
 try {
  const report=path.join(folder,'vitest.json'),payload={testResults:[]};
  const check=await api.runAcceptanceCheck('vitest',['-e',"require('node:fs').writeFileSync(process.argv[1],JSON.stringify({testResults:[]}),'utf8')",report],folder);
  expect(check.status).toBe('PASS');
  expect(JSON.parse(await readFile(report,'utf8'))).toEqual(payload);
  expect(check.outputs.some((output:any)=>output.relative_path.endsWith('vitest.command.json'))).toBe(true);
 } finally {
  expect(path.resolve(folder).startsWith(root+path.sep+'acceptance-path-test-')).toBe(true);
  await rm(folder,{recursive:true,force:true});
 }
});

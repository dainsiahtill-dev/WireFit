import {describe,it,expect} from 'vitest';
import {readFile} from 'node:fs/promises';
import {assignSplit,detectHoldoutLeak,RESEARCH_SPLIT_RULE,RESEARCH_SPLIT_SEED,splitBucket,SplitGuard} from '../src/research/split.js';

describe('research split',()=>{
 it('reproduces the pre-registered grid counts 332/177/387 from the fixed corpus',async()=>{
  const rows=await readFile('artifacts/research/vmde/kernel-replay/run-t48nkuwa/observations.jsonl','utf8');
  const ids=rows.split(/\r?\n/).filter((line)=>line!=='').map((line)=>JSON.parse(line) as {id:string}).map((row)=>row.id);
  expect(ids).toHaveLength(896);
  expect(new Set(ids).size).toBe(896);
  const guard=new SplitGuard(RESEARCH_SPLIT_SEED,ids);
  expect(guard.counts()).toEqual({train:332,validation:177,holdout:387});
 });
 it('reproduces the pre-registered function counts 4/4/6 and scenario counts 4/4/4',async()=>{
  const business=JSON.parse(await readFile('artifacts/research/vmde/module-slots/fresh-business-code.json','utf8')) as {candidates:{entry_va:string}[]};
  const functions=new SplitGuard(RESEARCH_SPLIT_SEED,business.candidates.map((entry)=>entry.entry_va));
  expect(functions.counts()).toEqual({train:4,validation:4,holdout:6});
  const segmentation=JSON.parse(await readFile('artifacts/research/vmde/segmentation-results/run-label-replay-20261020/result.json','utf8')) as {scenarios:{id:string}[]};
  const scenarios=new SplitGuard(RESEARCH_SPLIT_SEED,segmentation.scenarios.map((entry)=>entry.id));
  expect(scenarios.counts()).toEqual({train:4,validation:4,holdout:4});
 });
 it('keeps the train, validation and holdout identifiers disjoint',async()=>{
  const rows=await readFile('artifacts/research/vmde/kernel-replay/run-t48nkuwa/observations.jsonl','utf8');
  const ids=rows.split(/\r?\n/).filter((line)=>line!=='').map((line)=>JSON.parse(line) as {id:string}).map((row)=>row.id);
  const guard=new SplitGuard(RESEARCH_SPLIT_SEED,ids);
  const train=new Set(guard.developView().train),validation=new Set(guard.developView().validation);
  expect(train.size).toBe(332);
  expect(validation.size).toBe(177);
  expect([...train].some((id)=>validation.has(id))).toBe(false);
  expect([...train].some((id)=>guard.isHoldout(id))).toBe(false);
  expect([...validation].some((id)=>guard.isHoldout(id))).toBe(false);
 });
 it('exposes no holdout property on the develop view',()=>{
  const guard=new SplitGuard(RESEARCH_SPLIT_SEED,['a','b','c','d','e']);
  const view=guard.developView();
  expect(Object.hasOwn(view,'holdout')).toBe(false);
  expect('holdout' in view).toBe(false);
 });
 it('changes the assignment when the seed changes',()=>{
  const ids=['four-cell-0','four-cell-1','four-cell-2','four-cell-3','four-cell-4','four-cell-5'];
  const first=ids.map((id)=>assignSplit(RESEARCH_SPLIT_SEED,id));
  const second=ids.map((id)=>assignSplit(RESEARCH_SPLIT_SEED+1,id));
  expect(first).not.toEqual(second);
  expect(splitBucket(RESEARCH_SPLIT_SEED,'four-cell-0')).toBeLessThan(5);
 });
 it('records the split rule verbatim in the specification',()=>{
  expect(RESEARCH_SPLIT_RULE).toContain('sha256(seed + "\\0" + row_id)');
  expect(RESEARCH_SPLIT_RULE).toContain('mod 5');
  expect(RESEARCH_SPLIT_SEED).toBe(20261019);
 });
 it('fails loudly when the observed counts differ from the pre-registered counts',()=>{
  const guard=new SplitGuard(RESEARCH_SPLIT_SEED,['a','b','c','d','e']);
  const observed=guard.counts();
  expect(()=>guard.verifyExpectedCounts(observed)).not.toThrow();
  expect(()=>guard.verifyExpectedCounts({train:2,validation:2,holdout:1})).toThrow(/do not match/);
 });
 it('detects holdout row identifiers in develop artifacts',()=>{
  const holdout=['four-cell-77','four-cell-78'];
  expect(detectHoldoutLeak([{value:{rows:[{id:'four-cell-1'}]}}],holdout)).toEqual([]);
  expect(detectHoldoutLeak([{value:{rows:[{id:'four-cell-77'}]}}],holdout)).toEqual(['four-cell-77']);
  expect(detectHoldoutLeak([{value:{note:'contains four-cell-78 inside'}}],holdout)).toEqual(['four-cell-78']);
 });
});

import {describe,it,expect} from 'vitest';
import {readFile} from 'node:fs/promises';
import path from 'node:path';
import {rootDir} from '../src/shared.js';
import {fp32Bits,fp32Number} from '../src/values.js';
import type {Model} from '../src/types.js';
import {evaluateLab} from '../src/web/lab.js';

const example=async(name:string):Promise<Model>=>JSON.parse(await readFile(path.join(rootDir,'examples',name),'utf8'));
describe('typed model laboratory',()=>{
 it('uses the BV evaluator for node traces including modular overflow',async()=>{
  const model=await example('model.mba-u8.json');
  const result=evaluateLab(model,{inputs:{a:{kind:'bv',width:8,bits:'0xff'},b:{kind:'bv',width:8,bits:'0x02'}}});
  expect(result.outputs.result).toEqual({kind:'bv',width:8,bits:'0x01'});
  expect(result.trace.length).toBeGreaterThan(2);
  expect(result.trace.at(-1)?.value).toEqual(result.outputs.result);
 });
 it('previews validated parameters and computes bounded real curves without modifying the saved model',async()=>{
  const model=await example('model.affine-clamp-initial.json');const original=JSON.stringify(model);
  const result=evaluateLab(model,{inputs:{x:fp32Bits(1)},parameters:{a:fp32Bits(2)},sweep:{input:'x',from:-4,to:4,steps:9}});
  expect(fp32Number(result.outputs.result as any)).toBe(2);expect(result.preview).toBe(true);
  expect(result.curve).toHaveLength(9);expect(result.curve[0]?.y).toBe(-2);expect(JSON.stringify(model)).toBe(original);
 });
 it('preserves domain errors and rejects unbounded, mistyped and unexpected requests',async()=>{
  const model=await example('model.affine-clamp-initial.json');
  expect(()=>evaluateLab(model,{inputs:{x:fp32Bits(5)}})).toThrow(/domain/i);
  expect(()=>evaluateLab(model,{inputs:{x:fp32Bits(0)},sweep:{input:'x',from:0,to:1,steps:129}})).toThrow();
  expect(()=>evaluateLab(model,{inputs:{x:fp32Bits(0)},parameters:{unknown:fp32Bits(1)}})).toThrow();
  expect(()=>evaluateLab(model,{inputs:{x:fp32Bits(0)},parameters:{a:fp32Bits(8)}})).toThrow();
  expect(()=>evaluateLab(model,{inputs:{x:fp32Bits(0)},extra:true} as any)).toThrow();
 });
 it('keeps sweep errors per point explicit',async()=>{
  const model=await example('model.affine-clamp-initial.json');
  const result=evaluateLab(model,{inputs:{x:fp32Bits(0)},sweep:{input:'x',from:-5,to:5,steps:3}});
  expect(result.curve[0]).toMatchObject({x:-5,y:null});expect(result.curve[0]?.error).toMatch(/domain/i);
  expect(result.curve[1]?.y).toBe(0);
 });
});

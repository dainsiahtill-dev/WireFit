import {describe,it,expect} from 'vitest';
const api:any=await import('../src/handwired.js');

describe('real Handwired adapter',()=>{
  it('builds a real parameter circuit and backpropagates x and one',()=>{
    const result=api.handwiredAffine?.(2,0.25,3,1,{a:[-4,4],b:[-2,2],x:[-8,8]});
    expect(result?.output).toBe(6.25);
    expect(result?.gradients).toEqual({a:3,b:1});
    expect(result?.operations).toBeGreaterThan(1);
  });
  it('copies forward and gradient snapshots before subsequent calls',()=>{
    const compiled=api.createHandwiredAffine?.({a:[-4,4],b:[-2,2],x:[-8,8]});
    const first=compiled?.evaluate(2,0.25,3,2);
    compiled?.evaluate(-1,1,-2,5);
    expect(first?.output).toBe(6.25);
    expect(first?.gradients).toEqual({a:6,b:2});
    expect(first?.values instanceof Float32Array).toBe(true);
  });
  it('checks actual range contracts and rejects nonfinite inputs',()=>{
    const compiled=api.createHandwiredAffine?.({a:[-4,4],b:[-2,2],x:[-8,8]});
    expect(()=>compiled?.evaluate(5,0,1,1)).toThrow(/range/i);
    expect(()=>compiled?.evaluate(1,0,NaN,1)).toThrow(/finite/i);
  });
});

it('reports signed-zero macro incompatibility without relaxing final FP32 semantics',()=>{
  const snapshot=api.handwiredAffine?.(0,-0,-1,1,{a:[-4,4],b:[-2,2],x:[-8,8]});
  expect(snapshot?.bitwise_compatible).toBe(false);
  const compiled=api.createHandwiredAffine?.({a:[-4,4],b:[-2,2],x:[-8,8]});
  const first=compiled?.evaluate(2,0.25,3,2);compiled?.evaluate(-1,1,-2,5);
  expect(Array.from(first?.values.slice(0,3)??[])).toEqual([2,0.25,3]);
  expect(Array.from(first?.source_gradients??[])).toEqual([6,2,4]);
});


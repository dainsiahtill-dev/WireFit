import {describe,it,expect} from 'vitest';
import {readFileSync} from 'node:fs';
const api:any = await import('../src/numeric.js');
const affine:any = JSON.parse(readFileSync(new URL('../examples/model.affine-initial.json',import.meta.url),'utf8'));
const clamp:any = JSON.parse(readFileSync(new URL('../examples/model.affine-clamp-initial.json',import.meta.url),'utf8'));
const piecewise:any = JSON.parse(readFileSync(new URL('../examples/model.piecewise-initial.json',import.meta.url),'utf8'));
const f = (bits:string)=>({kind:'fp32',bits});
const run=(m:any,bits:string)=>api.evaluateNumeric?.(m,{x:f(bits)});

describe('FP32 template contract',()=>{
  it('rounds the product before addition, rather than computing a fused result',()=>{
    const m=structuredClone(affine); m.domain.constraints=[];
    m.definition.parameters={a:f('0x3f800001'),b:f('0xbf800002')};
    expect(run(m,'0x3f800001')).toEqual({result:f('0x00000000')});
  });
  it('preserves negative zero at a clamp boundary and gradual underflow',()=>{
    const m=structuredClone(clamp); m.definition.parameters={a:f('0x00000000'),b:f('0x80000000')};
    m.definition.fixed={lo:f('0x00000000'),hi:f('0x40000000')};
    expect(run(m,'0xbf800000')).toEqual({result:f('0x80000000')});
    m.definition.parameters={a:f('0x00000001'),b:f('0x00000000')};
    expect(run(m,'0x3f800000')).toEqual({result:f('0x00000001')});
  });
  it('selects the right interval at a knot and extends end intervals',()=>{
    const m=structuredClone(piecewise);m.domain.constraints=[];
    expect(run(m,'0x80000000')).toEqual({result:f('0x3e800000')});
    expect(run(m,'0xc1200000')).toEqual({result:f('0xc1200000')});
    expect(run(m,'0x41200000')).toEqual({result:f('0x40a80000')});
  });
  it('rejects finite intermediate overflow even when clamp would hide it',()=>{
    const m=structuredClone(clamp);m.domain.constraints=[];
    m.definition.parameter_bounds.a.upper=f('0x7f7fffff');m.definition.parameters.a=f('0x7f7fffff');
    expect(()=>api.evaluateNumeric?.(m,{x:f('0x40000000')})).toThrow(/finite|overflow/i);
  });
  it('rejects malformed parameter sets, bounds, knots and out of domain inputs',()=>{
    const bad=structuredClone(piecewise);bad.definition.parameters.a2=f('0x3f800000');
    expect(()=>api.validateNumericModel?.(bad)).toThrow();
    const reversed=structuredClone(affine);reversed.definition.parameter_bounds.a.lower=f('0x40800000');reversed.definition.parameter_bounds.a.upper=f('0xc0800000');
    expect(()=>api.validateNumericModel?.(reversed)).toThrow();
    const nonfinite=structuredClone(affine);nonfinite.definition.parameters.a=f('0x7fc00001');
    expect(()=>api.validateNumericModel?.(nonfinite)).toThrow();
    const duplicate=structuredClone(piecewise);duplicate.definition.fixed.knots.push(f('0x80000000'));
    expect(()=>api.validateNumericModel?.(duplicate)).toThrow();
    expect(()=>api.evaluateNumeric?.(affine,{x:f('0x40a00000')})).toThrow(/domain/i);
  });
});


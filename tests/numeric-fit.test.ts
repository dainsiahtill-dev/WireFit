import {describe,it,expect} from 'vitest';
import {readFileSync} from 'node:fs';
const api:any=await import('../src/numeric.js');
const affine:any=JSON.parse(readFileSync(new URL('../examples/model.affine-initial.json',import.meta.url),'utf8'));
const clamp:any=JSON.parse(readFileSync(new URL('../examples/model.affine-clamp-initial.json',import.meta.url),'utf8'));
const piecewise:any=JSON.parse(readFileSync(new URL('../examples/model.piecewise-initial.json',import.meta.url),'utf8'));
function fp(x:number){const v=new DataView(new ArrayBuffer(4));v.setFloat32(0,x);return {kind:'fp32',bits:'0x'+v.getUint32(0).toString(16).padStart(8,'0')};}
function rows(split:string,points:number[],fn:(x:number)=>number){return points.map((x,i)=>({schema_version:1,observation_id:`${split}_${i}`,sample_id:`${split}_${i}`,request_id:`q_${split}_${i}`,record_kind:'expected_fixture',source_kind:'reference_fixture',source_id:'test_fixture',source_identity_sha256:'0'.repeat(64),split,inputs:{x:fp(x)},status:'ok',outputs:{result:fp(fn(x))},error:null,observed_at:null,duration_ms:null,raw_artifacts:[]}));}
const budget={wall_time_ms:30000,solver_soft_time_ms:1000,solver_hard_time_ms:2000,max_candidates:500,max_ast_nodes:9,max_oracle_calls:0,max_iterations:1800,seed:42};
const policy={kind:'tolerance-fp32',atol:'0.00002',rtol:'0.00002',nonfinite:'reject'};
const settings={optimizer:'adam',learning_rate:'0.03',loss:'mse',batch_size:32,restarts:1,validation_interval:20};

describe('numeric fitting isolation and backends',()=>{
  it('recovers affine by centered least squares from observations and freezes the candidate',()=>{
    const train=rows('train',[-4,-2,0,2,4],x=>Math.fround(1.5*x-0.5));const validation=rows('validation',[-3,-1,1,3],x=>Math.fround(1.5*x-0.5));
    const fit=api.fitNumeric?.(affine,train,validation,{backend:'analytic_baseline',training:{...settings,optimizer:'closed_form'},budget,comparison_policy:{kind:'bitwise-fp32',nonfinite:'reject'}});
    expect(fit?.candidate.definition.parameters).toEqual({a:fp(1.5),b:fp(-0.5)});
    expect(fit?.validation_metrics.matched).toBe(4);
    expect(Object.isFrozen(fit?.candidate.definition.parameters)).toBe(true);
    expect(fit?.frozen_sha256).toMatch(/^[a-f0-9]{64}$/);
  });
  for(const backend of ['reference','handwired'])for(const [template,fn] of [[clamp,(x:number)=>Math.max(-2,Math.min(2,1.25*x-0.5))],[piecewise,(x:number)=>x<0?0.75*x-0.25:1.5*x+0.5]] as const){
    it(`${backend} fits ${template.definition.template} using fixed host gates`,()=>{
      const xs=Array.from({length:33},(_,i)=>(i-16)/4),validation=rows('validation',[-3.875,-1.125,-0.125,0,0.125,1.125,3.875],fn);
      const fit=api.fitNumeric?.(template,rows('train',xs,fn),validation,{backend,training:settings,budget,comparison_policy:policy});
      expect(fit?.validation_metrics.mismatched).toBe(0);
      expect(fit?.backend_semantics.boolean_gradient).toBe('reject');
      if(backend==='handwired')expect(fit?.backend_identity.commit).toBe('257856e3b221140acb4cc4460626b850c0bd4ff1');
    });
  }
  it('recomputes clamp masks at each parameter state and has zero derivative at equality',()=>{
    const m=structuredClone(clamp);
    expect(api.numericGradient?.(m,{x:fp(2)})).toEqual({a:0,b:0});
    m.definition.parameters.a=fp(0.5);
    expect(api.numericGradient?.(m,{x:fp(2)})).toEqual({a:2,b:1});
  });
  it('rejects holdout leakage, failed rows, zero samples and unsupported baseline combinations',()=>{
    const opts={backend:'analytic_baseline',training:{...settings,optimizer:'closed_form'},budget,comparison_policy:policy};
    expect(()=>api.fitNumeric?.(affine,rows('holdout',[0,1],x=>x),rows('validation',[2],x=>x),opts)).toThrow(/holdout|split/i);
    expect(()=>api.fitNumeric?.(affine,[],rows('validation',[2],x=>x),opts)).toThrow(/empty|sample/i);
    const failed=rows('train',[0,1],x=>x);failed[0].status='timeout';
    expect(()=>api.fitNumeric?.(affine,failed,rows('validation',[2],x=>x),opts)).toThrow(/observation|status/i);
    expect(()=>api.fitNumeric?.(clamp,rows('train',[0,1],x=>x),rows('validation',[2],x=>x),opts)).toThrow(/affine|unsupported/i);
  });
  it('uses immutable explicit policy and counts signed-zero discrepancy',()=>{
    expect(api.compareNumericOutputs?.({y:fp(-0)},{y:fp(0)},{kind:'bitwise-fp32',nonfinite:'reject'}).matched).toBe(false);
    expect(api.compareNumericOutputs?.({y:fp(-0)},{y:fp(0)},policy).matched).toBe(true);
    expect(()=>api.compareNumericOutputs?.({y:fp(0)},{y:fp(Infinity)},policy)).toThrow(/finite/i);
    expect(()=>api.compareNumericOutputs?.({},{},policy)).toThrow(/nonempty/i);
  });
});

it('solves the bounded affine least-squares problem after slope hits a constraint',()=>{
  const template=structuredClone(affine);template.definition.parameter_bounds.a={lower:fp(0),upper:fp(1)};
  const fit=api.fitNumeric?.(template,rows('train',[0,2],x=>2*x),rows('validation',[1],x=>2*x),{backend:'analytic_baseline',training:{...settings,optimizer:'closed_form'},budget,comparison_policy:policy});
  expect(fit?.candidate.definition.parameters).toEqual({a:fp(1),b:fp(1)});
});

it('rejects a holdout split before reading its outputs',()=>{
  const row=rows('holdout',[0],x=>x)[0]!;
  Object.defineProperty(row,'outputs',{get(){throw Error('holdout outputs were accessed');},enumerable:true});
  const opts={backend:'reference',training:settings,budget,comparison_policy:policy};
  expect(()=>api.fitNumeric?.(affine,[row],rows('validation',[2],x=>x),opts)).toThrow(/split|holdout is never accepted/i);
});


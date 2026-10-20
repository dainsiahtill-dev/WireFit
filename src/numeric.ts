import type {NumericModel,FP32Value,ValueMap,ComparisonPolicy,Observation,Budget} from './types.js';
import {assert,validateSchema,WirefitError,hashObject,semanticHash} from './shared.js';
import {fp32Number,fp32Bits,validateTypedValue} from './values.js';
import {validateDomain,validateInputs,domainContainsPoint} from './model.js';
import {createHandwiredAffine,HANDWIRED_IDENTITY} from './handwired.js';

function finite(value:number,context:string):number {assert(Number.isFinite(value),'NONFINITE',`${context} is nonfinite or overflowed`);return value;}
function decode(value:FP32Value,context:string):number {validateTypedValue(value,{kind:'fp32'});return finite(fp32Number(value),context);}
function sameKeys(value:object,keys:string[]):boolean {return Object.keys(value).sort().join(',')===[...keys].sort().join(',');}
export function parameterNames(model:NumericModel):string[] {
  return model.definition.template==='piecewise_affine'?Array.from({length:model.definition.fixed.knots!.length+1},(_,i)=>[`a${i}`,`b${i}`]).flat():['a','b'];
}
export function validateNumericModel(value:unknown):NumericModel {
  validateSchema('model',value);const model=value as NumericModel;
  assert(model.kind==='numeric_template','UNSUPPORTED_MODEL','Expected numeric template');
  assert(model.scope.execution_guard.kind!=='model_bool','INVALID_GUARD','Numeric templates cannot reference a Bool node');
  validateDomain(model.domain,model.inputs);
  const {definition:d}=model;
  if(d.template==='affine_clamp') assert(decode(d.fixed.lo!,'lo')<=decode(d.fixed.hi!,'hi'),'INVALID_RANGE','Clamp bounds are inverted');
  if(d.template==='piecewise_affine') {let previous=-Infinity;for(const knot of d.fixed.knots!){const x=decode(knot,'knot');assert(x>previous,'INVALID_KNOTS','Knots must be strictly increasing');previous=x;}}
  const names=parameterNames(model);
  assert(sameKeys(d.parameters,names)&&sameKeys(d.parameter_bounds,names),'INVALID_PARAMETERS','Parameters and parameter bounds must exactly match the template');
  for(const name of names){const p=decode(d.parameters[name]!,name),bound=d.parameter_bounds[name]!;const lo=decode(bound.lower,`${name} lower`),hi=decode(bound.upper,`${name} upper`);assert(lo<=hi&&p>=lo&&p<=hi,'INVALID_RANGE',`${name} parameter or bounds outside declared range`);}
  return model;
}
function intervalIndex(model:NumericModel,x:number):number {let index=0;if(model.definition.template==='piecewise_affine')for(const knot of model.definition.fixed.knots!) {if(x<fp32Number(knot))break;index++;}return index;}
function affineState(model:NumericModel,x:number) {
  const index=intervalIndex(model,x),suffix=model.definition.template==='piecewise_affine'?String(index):'';
  const a=decode(model.definition.parameters[`a${suffix}`]!,`a${suffix}`),b=decode(model.definition.parameters[`b${suffix}`]!,`b${suffix}`);
  const product=finite(Math.fround(a*x),'affine product');const t=finite(Math.fround(product+b),'affine sum');
  let output=t,mask=1;
  if(model.definition.template==='affine_clamp') {const lo=decode(model.definition.fixed.lo!,'lo'),hi=decode(model.definition.fixed.hi!,'hi');output=t<lo?lo:t>hi?hi:t;mask=lo<t&&t<hi?1:0;}
  return {index,suffix,a,b,t,output,mask};
}
function evaluateValidated(model:NumericModel,inputs:unknown):ValueMap {
  const values=validateInputs(model.inputs,inputs);const x=decode(values[model.inputs[0]!.id] as FP32Value,'input');
  assert(domainContainsPoint(model.domain,values),'OUT_OF_DOMAIN','Input outside model domain');
  return {[model.outputs[0]!.id]:fp32Bits(affineState(model,x).output)};
}
export function evaluateNumeric(model:NumericModel,inputs:unknown):ValueMap {return evaluateValidated(validateNumericModel(model),inputs);}
/** Real arithmetic intent derivative, with host clamp and piecewise choices fixed. */
export function numericGradient(model:NumericModel,inputs:unknown,upstream=1):Record<string,number> {
  validateNumericModel(model);const values=validateInputs(model.inputs,inputs),x=decode(values[model.inputs[0]!.id] as FP32Value,'input');
  assert(domainContainsPoint(model.domain,values),'OUT_OF_DOMAIN','Input outside model domain');finite(upstream,'gradient');
  const state=affineState(model,x),gradient=Object.fromEntries(parameterNames(model).map(k=>[k,0]));
  gradient[`a${state.suffix}`]=finite(upstream*state.mask*x,'a gradient');gradient[`b${state.suffix}`]=upstream*state.mask;return gradient;
}
export function validateNumericPolicy(policy:ComparisonPolicy):asserts policy is Exclude<ComparisonPolicy,{kind:'exact-bv'}> {
  assert(!!policy&&typeof policy==='object'&&(policy.kind==='bitwise-fp32'||policy.kind==='tolerance-fp32')&&policy.nonfinite==='reject','INVALID_POLICY','Numeric comparison requires an explicit FP32 policy');
  assert(sameKeys(policy,policy.kind==='bitwise-fp32'?['kind','nonfinite']:['kind','nonfinite','atol','rtol']),'INVALID_POLICY','Unexpected numeric policy properties');
  if(policy.kind==='tolerance-fp32')for(const name of ['atol','rtol'] as const){assert(typeof policy[name]==='string'&&/^(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?$/.test(policy[name])&&Number.isFinite(Number(policy[name]))&&Number(policy[name])>=0,'INVALID_POLICY','Tolerances must be finite nonnegative decimal strings');}
}
export function compareNumericOutputs(left:ValueMap,right:ValueMap,policy:ComparisonPolicy) {
  validateNumericPolicy(policy);assert(!!left&&!!right&&typeof left==='object'&&typeof right==='object'&&!Array.isArray(left)&&!Array.isArray(right),'INVALID_OUTPUT','Outputs must be maps');
  const keys=Object.keys(left);assert(keys.length>0&&sameKeys(right,keys),'INVALID_OUTPUT','Output maps must match and be nonempty');
  let matched=true,max_absolute_error=0,max_relative_error=0;
  for(const key of keys){const a=decode(left[key] as FP32Value,'left output'),b=decode(right[key] as FP32Value,'right output'),absolute=Math.abs(a-b),scale=Math.max(Math.abs(a),Math.abs(b));
    max_absolute_error=Math.max(max_absolute_error,absolute);max_relative_error=Math.max(max_relative_error,scale===0?0:absolute/scale);
    matched&&=policy.kind==='bitwise-fp32'?(left[key] as FP32Value).bits===(right[key] as FP32Value).bits:absolute<=Number(policy.atol)+Number(policy.rtol)*scale;
  }
  return {matched,max_absolute_error,max_relative_error};
}

export function exportNumericModelSource(model:NumericModel,language:'js'|'ts'='js'):string {
  validateNumericModel(model);assert(language==='js'||language==='ts','UNSUPPORTED_LANGUAGE','Numeric export supports js or ts');
  const typed=language==='ts';
  const declarations=typed?`export interface FP32Value {kind:'fp32';bits:string}\nexport type FP32Inputs=Record<string,FP32Value>;\ninterface ExportModel {[key:string]:unknown;inputs:[{id:string;type:{kind:'fp32'}}];outputs:[{id:string;type:{kind:'fp32'}}];domain:{constraints:{input:string;op:'eq'|'ne'|'le'|'ge';value:FP32Value}[]};definition:{template:'affine'|'affine_clamp'|'piecewise_affine';parameters:Record<string,FP32Value>;parameter_bounds:Record<string,{lower:FP32Value;upper:FP32Value}>;fixed:{lo?:FP32Value;hi?:FP32Value;knots?:FP32Value[]}}}\n`:'';
  return `// Wirefit FP32 template profile; each fround is a separate rounding point.\n${declarations}const model${typed?':ExportModel':''}=${JSON.stringify(model)};\nconst view=new DataView(new ArrayBuffer(4));\nfunction number(v${typed?':FP32Value|undefined':''})${typed?':number':''}{if(!v||v.kind!=='fp32'||Object.keys(v).sort().join(',')!=='bits,kind'||!/^0x[0-9a-f]{8}$/.test(v.bits))throw Error('Invalid FP32');view.setUint32(0,parseInt(v.bits.slice(2),16));const n=view.getFloat32(0);if(!Number.isFinite(n))throw Error('Nonfinite');return n;}\nfunction bits(n${typed?':number':''})${typed?':FP32Value':''}{if(!Number.isFinite(n))throw Error('Nonfinite intermediate');view.setFloat32(0,n);return {kind:'fp32',bits:'0x'+view.getUint32(0).toString(16).padStart(8,'0')};}\nexport function evaluate(inputs${typed?':FP32Inputs':''})${typed?':FP32Inputs':''}{if(!inputs||typeof inputs!=='object'||Array.isArray(inputs)||Object.keys(inputs).length!==1||!Object.hasOwn(inputs,model.inputs[0].id))throw Error('Invalid inputs');const x=number(inputs[model.inputs[0].id]);for(const c of model.domain.constraints){const v=number(c.value);if(!(c.op==='eq'?x===v:c.op==='ne'?x!==v:c.op==='le'?x<=v:x>=v))throw Error('Out of domain');}const d=model.definition;let i=0;if(d.template==='piecewise_affine')for(const k of d.fixed.knots??[]){if(x<number(k))break;i++;}const suffix=d.template==='piecewise_affine'?String(i):'';const product=Math.fround(number(d.parameters['a'+suffix])*x);if(!Number.isFinite(product))throw Error('Nonfinite product');let y=Math.fround(product+number(d.parameters['b'+suffix]));if(!Number.isFinite(y))throw Error('Nonfinite sum');if(d.template==='affine_clamp'){const lo=number(d.fixed.lo),hi=number(d.fixed.hi);y=y<lo?lo:y>hi?hi:y;}return {[model.outputs[0].id]:bits(y)};}\nexport default evaluate;\n`;
}
export interface NumericTraining {optimizer:'adam'|'sgd'|'closed_form';learning_rate:string;loss:'mse';batch_size:number;restarts:number;validation_interval:number}
export interface FitOptions {backend:'analytic_baseline'|'reference'|'handwired';training:NumericTraining;budget:Budget;comparison_policy:ComparisonPolicy;signal?:AbortSignal}
export interface NumericMetrics {planned:number;attempted:number;completed:number;matched:number;mismatched:number;failed:number;out_of_domain:number;mse:number;max_absolute_error:number;max_relative_error:number}
interface Point {x:number;y:number;row:Observation}
function checkedPoints(model:NumericModel,rows:Observation[],split:'train'|'validation'):Point[] {
  assert(Array.isArray(rows)&&rows.length>0,'EMPTY_DATASET',`${split} samples must not be empty`);
  const seen=new Set<string>();
  return rows.map(row=>{
    assert(!!row&&typeof row==='object'&&!Array.isArray(row),'INVALID_OBSERVATION','Expected observation record');
    assert(row.split===split,'SPLIT_LEAKAGE',`Expected ${split} split; holdout is never accepted by the learner`);
    validateSchema('observation',row);
    assert(row.status==='ok','FAILED_OBSERVATION',`${row.sample_id} observation status ${row.status} cannot be dropped`);
    assert(row.source_kind!=='candidate_model','SELF_GENERATED_EXPECTATION','Candidate output cannot supply its own expected observation');
    assert(!seen.has(row.sample_id),'DUPLICATE_SAMPLE',`Duplicate ${split} sample`);seen.add(row.sample_id);
    const input=validateInputs(model.inputs,row.inputs),outputs=validateInputs(model.outputs,row.outputs);
    assert(domainContainsPoint(model.domain,input),'OUT_OF_DOMAIN',`${row.sample_id} outside model domain`);
    return {x:decode(input[model.inputs[0]!.id] as FP32Value,'training input'),y:decode(outputs[model.outputs[0]!.id] as FP32Value,'observed output'),row};
  });
}
function validateTraining(options:FitOptions,model:NumericModel) {
  assert(!!options&&typeof options==='object','INVALID_TRAINING','Training options required');
  validateSchema('budget',options.budget);validateNumericPolicy(options.comparison_policy);
  assert(['analytic_baseline','reference','handwired'].includes(options.backend),'INVALID_BACKEND','Unknown backend');
  const t=options.training;
  assert(!!t&&typeof t==='object'&&sameKeys(t,['optimizer','learning_rate','loss','batch_size','restarts','validation_interval']),'INVALID_TRAINING','Invalid training options');
  assert(t.loss==='mse'&&['adam','sgd','closed_form'].includes(t.optimizer),'INVALID_TRAINING','Unsupported loss or optimizer');
  assert(typeof t.learning_rate==='string'&&/^(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?$/.test(t.learning_rate)&&Number.isFinite(Number(t.learning_rate)),'INVALID_TRAINING','Learning rate must be a finite nonnegative decimal string');
  for(const [name,maximum] of [['batch_size',1000000],['restarts',128],['validation_interval',1000000]] as const)assert(Number.isInteger(t[name])&&t[name]>=1&&t[name]<=maximum,'INVALID_TRAINING',`Invalid ${name}`);
  if(options.backend==='analytic_baseline')assert(t.optimizer==='closed_form'&&model.definition.template==='affine','UNSUPPORTED_BASELINE','Analytic baseline supports affine with closed_form only');
  else assert(t.optimizer==='adam'||t.optimizer==='sgd','UNSUPPORTED_OPTIMIZER','Gradient backends require adam or sgd');
}
function metrics(model:NumericModel,points:Point[],policy:ComparisonPolicy):NumericMetrics {
  let sum=0,matched=0,max_absolute_error=0,max_relative_error=0;
  for(const point of points){const result=evaluateValidated(model,point.row.inputs),comparison=compareNumericOutputs(result,point.row.outputs,policy);matched+=Number(comparison.matched);max_absolute_error=Math.max(max_absolute_error,comparison.max_absolute_error);max_relative_error=Math.max(max_relative_error,comparison.max_relative_error);const error=decode(result[model.outputs[0]!.id] as FP32Value,'candidate output')-point.y;sum+=error*error;}
  return {planned:points.length,attempted:points.length,completed:points.length,matched,mismatched:points.length-matched,failed:0,out_of_domain:0,mse:finite(sum/points.length,'MSE'),max_absolute_error,max_relative_error};
}
function deepFreeze<T>(value:T):T {if(value&&typeof value==='object'){for(const item of Object.values(value))deepFreeze(item);Object.freeze(value);}return value;}
function randomGenerator(seed:number):()=>number {let state=seed>>>0;return()=>{state=(state+0x6d2b79f5)>>>0;let t=Math.imul(state^(state>>>15),1|state);t^=t+Math.imul(t^(t>>>7),61|t);return((t^(t>>>14))>>>0)/4294967296;};}
function setParameters(model:NumericModel,parameters:Record<string,number>):void {for(const name of parameterNames(model)){const bounds=model.definition.parameter_bounds[name]!,lo=fp32Number(bounds.lower),hi=fp32Number(bounds.upper);model.definition.parameters[name]=fp32Bits(finite(Math.fround(Math.min(hi,Math.max(lo,parameters[name]!))),`parameter ${name}`));}}

/** The learner receives train and validation only. Holdout access belongs to the parent verifier. */
export function fitNumeric(template:NumericModel,trainingRows:Observation[],validationRows:Observation[],options:FitOptions) {
  const start=performance.now();validateNumericModel(template);validateTraining(options,template);
  const train=checkedPoints(template,trainingRows,'train'),validation=checkedPoints(template,validationRows,'validation');
  const trainIDs=new Set(train.map(p=>p.row.sample_id));assert(!validation.some(p=>trainIDs.has(p.row.sample_id)),'SPLIT_LEAKAGE','A sample belongs to multiple splits');
  const optionsSnapshot={...options,training:structuredClone(options.training),budget:structuredClone(options.budget),comparison_policy:structuredClone(options.comparison_policy)};
  const {backend,training:t,budget,comparison_policy:policy}=optionsSnapshot;
  const names=parameterNames(template),rng=randomGenerator(budget.seed),logs:{iteration:number;restart:number;train_mse:number;validation_mse:number}[]=[];
  let iterations=0,candidates=0,gradient_calls=0,bitwise_discrepancies=0,best=structuredClone(template),bestValidation=Infinity,termination='iteration_budget';
  const checkBudget=()=>{
    if(options.signal?.aborted)throw new WirefitError('CANCELLED','Numeric fit cancelled');
    if(performance.now()-start>=budget.wall_time_ms){termination='wall_time_budget';return false;}
    if(candidates>=budget.max_candidates){termination='candidate_budget';return false;}return true;
  };
  const consider=(model:NumericModel,restart:number)=>{
    if(!checkBudget())return false;
    const tm=metrics(model,train,policy),vm=metrics(model,validation,policy);candidates++;
    if(logs.length<1000)logs.push({iteration:iterations,restart,train_mse:tm.mse,validation_mse:vm.mse});
    if(vm.mse<bestValidation){bestValidation=vm.mse;best=structuredClone(model);}
    return true;
  };
  const buildStart=performance.now();
  const circuits:ReturnType<typeof createHandwiredAffine>[]=[];
  if(backend==='handwired') {
    let minX=Infinity,maxX=-Infinity;for(const p of train){minX=Math.min(minX,p.x);maxX=Math.max(maxX,p.x);}const xRange:[number,number]=[minX,maxX];
    for(let i=0;i<names.length/2;i++) {const suffix=template.definition.template==='piecewise_affine'?String(i):'',a=template.definition.parameter_bounds[`a${suffix}`]!,b=template.definition.parameter_bounds[`b${suffix}`]!;
      circuits.push(createHandwiredAffine({a:[fp32Number(a.lower),fp32Number(a.upper)],b:[fp32Number(b.lower),fp32Number(b.upper)],x:xRange}));
    }
  }
  const build_ms=performance.now()-buildStart;
  if(backend==='analytic_baseline') {
    assert(checkBudget(),'BUDGET_EXHAUSTED','Budget exhausted before baseline');
    // Centering avoids the cancellation in n*sum(x*x)-sum(x)^2.
    const meanX=train.reduce((s,p)=>s+p.x,0)/train.length,meanY=train.reduce((s,p)=>s+p.y,0)/train.length;
    let xx=0,xy=0;for(const p of train){xx+=(p.x-meanX)**2;xy+=(p.x-meanX)*(p.y-meanY);}
    assert(xx>0&&Number.isFinite(xx)&&Number.isFinite(xy),'UNIDENTIFIABLE_PARAMETERS','Affine least squares requires distinct input values');
    const candidate=structuredClone(template),unconstrainedA=xy/xx;
    const ab=template.definition.parameter_bounds.a!,bb=template.definition.parameter_bounds.b!;
    const alo=fp32Number(ab.lower),ahi=fp32Number(ab.upper),blo=fp32Number(bb.lower),bhi=fp32Number(bb.upper);
    const clamp=(x:number,lo:number,hi:number)=>Math.min(hi,Math.max(lo,x));
    const choices:{a:number;b:number}[]=[{a:clamp(unconstrainedA,alo,ahi),b:clamp(meanY-unconstrainedA*meanX,blo,bhi)}];
    for(const a of [alo,ahi])choices.push({a,b:clamp(meanY-a*meanX,blo,bhi)});
    const sumXX=train.reduce((s,p)=>s+p.x*p.x,0);
    for(const b of [blo,bhi])choices.push({a:clamp(train.reduce((s,p)=>s+p.x*(p.y-b),0)/sumXX,alo,ahi),b});
    let least=Infinity,chosen=choices[0]!;
    for(const p of choices){const loss=train.reduce((s,point)=>s+(p.a*point.x+p.b-point.y)**2,0);if(loss<least){least=loss;chosen=p;}}
    setParameters(candidate,chosen);iterations=1;consider(candidate,0);termination='closed_form';
  } else {
    let stop=false;
    const perRestart=Math.max(1,Math.ceil(budget.max_iterations/t.restarts));
    for(let restart=0;restart<t.restarts&&!stop&&iterations<budget.max_iterations;restart++) {
      const model=structuredClone(template),parameters:Record<string,number>={},moment:Record<string,number>={},variance:Record<string,number>={};
      for(const name of names){const bound=model.definition.parameter_bounds[name]!,lo=fp32Number(bound.lower),hi=fp32Number(bound.upper);parameters[name]=restart===0?fp32Number(model.definition.parameters[name]!):lo+rng()*(hi-lo);moment[name]=0;variance[name]=0;}
      setParameters(model,parameters);consider(model,restart);
      const order=Array.from({length:train.length},(_,i)=>i);let cursor=train.length;
      for(let step=1;step<=perRestart&&iterations<budget.max_iterations;step++) {
        if(!checkBudget()){stop=true;break;}
        const gradient=Object.fromEntries(names.map(n=>[n,0])),batchCount=Math.min(t.batch_size,train.length);
        for(let j=0;j<batchCount;j++) {
          if(options.signal?.aborted)throw new WirefitError('CANCELLED','Numeric fit cancelled');
          if(cursor>=order.length){for(let k=order.length-1;k>0;k--){const r=Math.floor(rng()*(k+1));[order[k],order[r]]=[order[r]!,order[k]!];}cursor=0;}
          const point=train[order[cursor++]!]!,state=affineState(model,point.x),upstream=2*(state.output-point.y)*state.mask/batchCount;
          if(backend==='handwired') {
            const snapshot=circuits[state.index]!.evaluate(state.a,state.b,point.x,upstream);gradient_calls++;bitwise_discrepancies+=Number(!snapshot.bitwise_compatible);
            gradient[`a${state.suffix}`]!+=snapshot.gradients.a;gradient[`b${state.suffix}`]!+=snapshot.gradients.b;
          } else {gradient[`a${state.suffix}`]!+=upstream*point.x;gradient[`b${state.suffix}`]!+=upstream;}
        }
        for(const name of names){const g=finite(gradient[name]!,`${name} gradient`),rate=Number(t.learning_rate);
          if(t.optimizer==='adam'){moment[name]=0.9*moment[name]!+0.1*g;variance[name]=0.999*variance[name]!+0.001*g*g;parameters[name]=fp32Number(model.definition.parameters[name]!)-rate*(moment[name]!/(1-0.9**step))/(Math.sqrt(variance[name]!/(1-0.999**step))+1e-8);}
          else parameters[name]=fp32Number(model.definition.parameters[name]!)-rate*g;
        }
        setParameters(model,parameters);iterations++;
        if(step%t.validation_interval===0||step===perRestart||iterations===budget.max_iterations) {
          if(!consider(model,restart)){stop=true;break;}
          if(bestValidation===0){termination='zero_validation_loss';stop=true;break;}
        }
      }
    }
  }
  assert(Number.isFinite(bestValidation),'NO_CANDIDATE','No valid candidate was frozen within budget');
  const freezeStart=performance.now();
  best.model_id=`${template.model_id.slice(0,95)}_fit_${hashObject({parameters:best.definition.parameters,backend,seed:budget.seed}).slice(0,12)}`;
  best.title=`Fitted ${template.title}`.slice(0,256);
  best.provenance={source_kind:'oracle_fit',source_ref:null,source_artifacts:[],notes:`Fitted from ${train.length} train and ${validation.length} validation observations; backend=${backend}; no holdout received.`};
  validateNumericModel(best);const frozen_sha256=semanticHash(best);
  const candidate=deepFreeze(best),train_metrics=metrics(candidate,train,policy),validation_metrics=metrics(candidate,validation,policy);
  return {candidate,frozen_sha256,backend_identity:backend==='handwired'?{...HANDWIRED_IDENTITY}:{name:backend,runtime:`node ${process.versions.node}`,algorithm:backend==='analytic_baseline'?'centered_affine_least_squares':t.optimizer},backend_semantics:{forward:backend==='handwired'?'host-gated FP32 template; real Handwired affine graph checked numerically':'independent host FP32 two-rounding template',gradient:'real arithmetic intent; host clamp mask strict interior; fixed knots left-closed',boolean_gradient:'reject',index_gradient:'reject',training_comparison:'numeric FP32; signed-zero discrepancies counted',bitwise_discrepancies,final_semantics:'wirefix.fp32.templates.v1'},iterations,candidates,gradient_calls,termination,logs,train_metrics,validation_metrics,timing:{build_ms,fit_ms:freezeStart-start-build_ms,validation_ms:performance.now()-freezeStart,total_ms:performance.now()-start},training_identity_sha256:hashObject({train:trainingRows.map(r=>({sample_id:r.sample_id,inputs:r.inputs,outputs:r.outputs})),validation:validationRows.map(r=>({sample_id:r.sample_id,inputs:r.inputs,outputs:r.outputs})),training:t,budget,policy,backend})};
}






import {assert} from '../shared.js';
import {evaluateModel} from '../verification.js';
import {evaluateNode} from '../bv.js';
import {validateModel} from '../repository.js';
import {fp32Bits,fp32Number,bv} from '../values.js';
import type {Model,TypedValue,ValueMap} from '../types.js';
import type {LabRequest,LabResult} from './types.js';

/** Preview uses the same validated concrete interpreters as experiments. */
export function evaluateLab(saved:Model,request:LabRequest):LabResult {
 assert(request!==null&&typeof request==='object'&&!Array.isArray(request)&&Object.keys(request).every(key=>['inputs','parameters','sweep'].includes(key)),'LAB_REQUEST_INVALID','Laboratory request has invalid fields');
 const model=structuredClone(saved);
 if(request.parameters!==undefined){
  assert(model.kind==='numeric_template','LAB_PARAMETERS_INVALID','Parameter previews require a numeric model');
  assert(request.parameters!==null&&typeof request.parameters==='object'&&!Array.isArray(request.parameters),'LAB_PARAMETERS_INVALID','Parameters must be a typed map');
  for(const [key,value] of Object.entries(request.parameters)){
   assert(Object.hasOwn(model.definition.parameters,key),'LAB_PARAMETERS_INVALID','Unknown parameter: '+key);
   model.definition.parameters[key]=structuredClone(value);
  }
 }
 validateModel(model);
 assert(model.kind!=='bv_dag'||model.nodes.length<=4096,'RESOURCE_LIMIT','Laboratory evaluation supports at most 4096 nodes');
 const outputs=evaluateModel(model,request.inputs);
 const trace:LabResult['trace']=Object.entries(request.inputs).map(([id,value])=>({id,value:structuredClone(value),op:'input'}));
 if(model.kind==='bv_dag'){
  const values=new Map<string,TypedValue>(Object.entries(request.inputs));
  for(const node of model.nodes){
   const value=evaluateNode(node.op,node.type,node.args.map(id=>values.get(id)!),node.attrs);values.set(node.id,value);
   if(trace.length<255)trace.push({id:node.id,value,op:node.op});
  }
 }else for(const [id,value] of Object.entries(model.definition.parameters))trace.push({id,value,op:'parameter'});
 for(const [id,value] of Object.entries(outputs))trace.push({id,value,op:'output'});
 const curve:LabResult['curve']=[];
 if(request.sweep!==undefined){
  const sweep=request.sweep;
  assert(sweep!==null&&typeof sweep==='object'&&!Array.isArray(sweep)&&Object.keys(sweep).sort().join(',')==='from,input,steps,to','LAB_SWEEP_INVALID','Sweep requires input, from, to and steps');
  assert(Number.isFinite(sweep.from)&&Number.isFinite(sweep.to)&&Number.isFinite(sweep.to-sweep.from)&&sweep.from<=sweep.to&&Number.isSafeInteger(sweep.steps)&&sweep.steps>=2&&sweep.steps<=128,'LAB_SWEEP_INVALID','Sweep must have finite ascending bounds and 2..128 points');
  const input=model.inputs.find(input=>input.id===sweep.input);
  assert(input&&input.type.kind!=='bool','LAB_SWEEP_INVALID','Sweep requires a declared numeric or bit-vector input');
  const outputId=model.outputs[0]!.id;
  for(let index=0;index<sweep.steps;index++){
   const x=index===sweep.steps-1?sweep.to:sweep.from+(sweep.to-sweep.from)*index/(sweep.steps-1);
   try{
    let typed:TypedValue;
    if(input.type.kind==='fp32')typed=fp32Bits(x);
    else {assert(Number.isSafeInteger(x)&&x>=0&&BigInt(x)<(1n<<BigInt(input.type.width)),'LAB_SWEEP_INVALID','BV sweep values must be integers within their width');typed=bv(BigInt(x),input.type.width);}
    const inputs:ValueMap={...request.inputs,[input.id]:typed};const value=evaluateModel(model,inputs)[outputId]!;
    const y=value.kind==='fp32'?fp32Number(value):value.kind==='bool'?Number(value.value):Number(BigInt(value.bits));
    assert(Number.isFinite(y)&&(value.kind!=='bv'||Number.isSafeInteger(y)),'LAB_SWEEP_INVALID','Output cannot be represented exactly on a numeric chart');
    curve.push({x,y});
   }catch(error){curve.push({x,y:null,error:error instanceof Error?error.message:String(error)});}
  }
 }
 return {outputs,trace,curve,preview:request.parameters!==undefined,scope:`${request.parameters===undefined?'已存模型解释执行':'参数预览（未保存）'}；${model.scope.kind} / ${model.scope.source_completeness}；仅声明输出，不表示原程序等价`};
}

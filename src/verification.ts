import {assert,WirefitError,hashObject} from './shared.js';
import {validateDomain,validateMapping,validateInputs,domainContainsPoint} from './model.js';
import {evaluateBv} from './bv.js';
import {evaluateNumeric,compareNumericOutputs} from './numeric.js';
import {fp32Bits,fp32Number,valueEquals} from './values.js';
import type {Model,NumericModel,Domain,Mapping,ValueMap,ComparisonPolicy,Observation} from './types.js';
export interface Counts {planned:number;attempted:number;completed:number;matched:number;mismatched:number;failed:number;out_of_domain:number}
export function emptyCounts(planned=0):Counts{return {planned,attempted:0,completed:0,matched:0,mismatched:0,failed:0,out_of_domain:0};}
export function onlyCounts(value:Counts):Counts{return {planned:value.planned,attempted:value.attempted,completed:value.completed,matched:value.matched,mismatched:value.mismatched,failed:value.failed,out_of_domain:value.out_of_domain};}
export function deriveStatus(counts:Counts,available=true):'matched'|'mismatch'|'partial'|'unavailable'{
 assert(Object.values(counts).every(n=>Number.isSafeInteger(n)&&n>=0),'COUNTS_INVALID','Invalid comparison counts');
 assert(counts.matched+counts.mismatched===counts.completed&&counts.completed+counts.failed+counts.out_of_domain===counts.attempted&&counts.attempted<=counts.planned,'COUNTS_INVALID','Comparison denominator is inconsistent');
 if(!available||counts.planned===0)return 'unavailable';
 if(counts.mismatched>0)return 'mismatch';
 return counts.completed===counts.planned?'matched':'partial';
}
export function evaluateModel(model:Model,inputs:unknown):ValueMap{return model.kind==='bv_dag'?evaluateBv(model,inputs as ValueMap):evaluateNumeric(model,inputs);}
export function compareOutputs(left:ValueMap,right:ValueMap,policy:ComparisonPolicy):boolean{
 const leftKeys=Object.keys(left).sort(),rightKeys=Object.keys(right).sort();
 assert(leftKeys.length>0&&leftKeys.join('\0')===rightKeys.join('\0'),'OUTPUT_INVALID','Output sets must match and be nonempty');
 if(policy.kind!=='exact-bv')return compareNumericOutputs(left,right,policy).matched;
 assert([...Object.values(left),...Object.values(right)].every(v=>v.kind!=='fp32'),'POLICY_INVALID','exact-bv does not compare floats');
 return leftKeys.every(key=>valueEquals(left[key]!,right[key]!));
}
export function mappedInputs(mapping:Mapping,rightInputs:ValueMap):ValueMap{return Object.fromEntries(mapping.inputs.map(pair=>[pair.left,rightInputs[pair.right]!])) as ValueMap;}
export function mappedOutputs(mapping:Mapping,left:ValueMap,right:ValueMap):[ValueMap,ValueMap]{
 return [Object.fromEntries(mapping.outputs.map(pair=>[pair.left,left[pair.left]!])),Object.fromEntries(mapping.outputs.map(pair=>[pair.left,right[pair.right]!]))];
}
export function verifyRows(model:Model,rows:Observation[],policy:ComparisonPolicy,mapping:Mapping){
 const counts=emptyCounts(rows.length);
 const isTarget=(row:Observation)=>row.record_kind==='observed'&&['original_target','reference_fixture'].includes(row.source_kind);const targetRows=rows.filter(isTarget);
 const target_counts=emptyCounts(targetRows.length);
 const source_counts: {kind:Observation['source_kind'];mode:'recorded'|'live';count:number}[]=[];
 const details:unknown[]=[];
 for(const row of rows){
  const target=isTarget(row);counts.attempted++;if(target)target_counts.attempted++;
  const fail=(kind:'failed'|'out_of_domain')=>{counts[kind]++;if(target)target_counts[kind]++;};
  if(row.status!=='ok'){fail(row.status==='out_of_domain'?'out_of_domain':'failed');details.push({sample_id:row.sample_id,status:row.status,error:row.error});continue;}
  try{
   const inputs=mappedInputs(mapping,row.inputs);
   validateInputs(model.inputs,inputs);
   if(!domainContainsPoint(model.domain,inputs)){fail('out_of_domain');details.push({sample_id:row.sample_id,status:'out_of_domain'});continue;}
   const outputs=evaluateModel(model,inputs);
   const [left,right]=mappedOutputs(mapping,outputs,row.outputs);
   const matched=compareOutputs(left,right,policy);
   counts.completed++;counts[matched?'matched':'mismatched']++;
   if(target){target_counts.completed++;target_counts[matched?'matched':'mismatched']++;const existing=source_counts.find(entry=>entry.kind===row.source_kind);if(existing)existing.count++;else source_counts.push({kind:row.source_kind,mode:'recorded',count:1});}
   details.push({sample_id:row.sample_id,inputs,candidate_outputs:outputs,observed_outputs:row.outputs,matched,record_kind:row.record_kind,source_kind:row.source_kind});
  }catch(error){fail('failed');details.push({sample_id:row.sample_id,status:'failed',error:error instanceof Error?error.message:String(error)});}
 }
 deriveStatus(counts);deriveStatus(target_counts);
 return {counts,target_counts,source_counts,details,status:deriveStatus(counts),target_status:deriveStatus(target_counts)};
}
function next(value:number,direction:1|-1):number{
 if(value===0)return direction>0?2**-149:-(2**-149);
 const bits=BigInt(fp32Bits(value).bits)+(value>0?BigInt(direction):-BigInt(direction));
 return fp32Number({kind:'fp32',bits:'0x'+bits.toString(16).padStart(8,'0')});
}
function numericWitness(domain:Domain,input:string):number|null{
 let lo=-3.4028234663852886e38,hi=3.4028234663852886e38;const excluded:number[]=[];
 for(const c of domain.constraints){
  assert(c.input===input&&c.value.kind==='fp32','DOMAIN_INVALID','Numeric comparison domain has incompatible input');
  const v=fp32Number(c.value);
  if(c.op==='eq'){lo=Math.max(lo,v);hi=Math.min(hi,v);}
  else if(c.op==='ne')excluded.push(v);
  else if(c.op==='le')hi=Math.min(hi,v);
  else if(c.op==='ge')lo=Math.max(lo,v);
  else throw new WirefitError('DOMAIN_INVALID','Invalid FP32 domain operator');
 }
 let point=lo;let count=0;
 while(point<=hi&&count++<=excluded.length){
  if(!excluded.some(v=>v===point))return point;
  point=next(point,1);
 }
 return null;
}
export function checkNumericComparisonDomain(left:NumericModel,right:NumericModel,domain:Domain,mapping:Mapping):void{
 validateMapping(left,right,mapping);validateDomain(domain,left.inputs);
 const input=left.inputs[0]!.id;
 assert(numericWitness(domain,input)!==null,'DOMAIN_EMPTY','Numeric comparison domain is empty');
 for(const side of [left,right]){
  for(const constraint of side.domain.constraints){
   const point=side===right?mapping.inputs.find(pair=>pair.right===constraint.input)?.left:constraint.input;
   assert(point===input&&constraint.value.kind==='fp32','DOMAIN_INVALID','Domain input mapping invalid');
   let inverse:Domain['constraints'][number];
   if(constraint.op==='eq'||constraint.op==='ne')inverse={...constraint,input,op:constraint.op==='eq'?'ne':'eq'};
   else {
    const v=fp32Number(constraint.value);
    const boundary=next(v,constraint.op==='le'?1:-1);
    if(!Number.isFinite(boundary))continue;
    inverse={input,op:constraint.op==='le'?'ge':'le',value:fp32Bits(boundary)};
   }
   assert(numericWitness({constraints:[...domain.constraints,inverse]},input)===null,'DOMAIN_MISMATCH','Requested comparison domain exceeds model domain');
  }
 }
}
export function verificationBinding(model:Model,oracleHash:string,planHash:string,policy:ComparisonPolicy,sourceHash:string,mapping:Mapping):string{
 return hashObject({model_semantics:hashObject({schema_version:model.schema_version,kind:model.kind,semantics_profile:model.semantics_profile,inputs:model.inputs,outputs:model.outputs,domain:model.domain,...(model.kind==='bv_dag'?{nodes:model.nodes}:{definition:model.definition})}),source:sourceHash,oracle:oracleHash,input_plan:planHash,policy:hashObject(policy),scope:model.scope,mapping});
}

/** Check domains independently of any claimed relationship between target implementations. */
export async function checkOracleDomains(left:{signature:import('./types.js').Signature;domain:Domain},right:{signature:import('./types.js').Signature;domain:Domain},domain:Domain,mapping:Mapping,budget:import('./types.js').Budget,signal?:AbortSignal){
 validateDomain(domain,left.signature.inputs);
 validateMapping(left.signature,right.signature,mapping);
 const allCore=[...left.signature.inputs,...right.signature.inputs].every(port=>port.type.kind!=='fp32');
 if(allCore){
  const make=(source:typeof left):import('./types.js').BvModel=>{
   const node='domain_constant_'+Math.random().toString(16).slice(2);
   return {schema_version:1,model_id:node,title:'Input-domain checker only',kind:'bv_dag',semantics_profile:'wirefix.bv.total.v1',inputs:source.signature.inputs as import('./types.js').BvModel['inputs'],outputs:[{id:'domain_result',type:{kind:'bool'},ref:node}],nodes:[{id:node,op:'const',type:{kind:'bool'},args:[],attrs:{value:{kind:'bool',value:true}}}],domain:source.domain,scope:{kind:'expression',observation:'declared_outputs',source_completeness:'not_applicable',execution_guard:{kind:'all_inputs'},observation_point:{kind:'expression_output',source_location:null}},provenance:{source_kind:'manual',source_ref:null,source_artifacts:[],notes:'Synthetic constant outputs are used only to check input-domain nonemptiness and containment, not target behavior.'}};
  };
  const {compareBv}=await import('./solver.js');
  const check=await compareBv(make(left),make(right),domain,{inputs:mapping.inputs,outputs:[{left:'domain_result',right:'domain_result'}]},budget,signal);
  assert(check.status==='proved','DOMAIN_INCONCLUSIVE','Could not establish Oracle comparison input domain');
  return {purpose:'input_domain_only',...check};
 }
 assert(left.signature.inputs.length===1&&right.signature.inputs.length===1&&left.signature.inputs[0]!.type.kind==='fp32'&&right.signature.inputs[0]!.type.kind==='fp32','UNSUPPORTED_DOMAIN_PROFILE','Oracle domain checking currently supports BV/Bool or one FP32 input');
 const make=(source:typeof left):NumericModel=>({schema_version:1,model_id:'domain_numeric',title:'FP32 input-domain checker only',kind:'numeric_template',semantics_profile:'wirefix.fp32.templates.v1',inputs:source.signature.inputs as NumericModel['inputs'],outputs:[{id:'domain_result',type:{kind:'fp32'}}],definition:{template:'affine',parameters:{a:fp32Bits(0),b:fp32Bits(0)},fixed:{},parameter_bounds:{a:{lower:fp32Bits(0),upper:fp32Bits(0)},b:{lower:fp32Bits(0),upper:fp32Bits(0)}}},domain:source.domain,scope:{kind:'expression',observation:'declared_outputs',source_completeness:'not_applicable',execution_guard:{kind:'all_inputs'},observation_point:{kind:'expression_output',source_location:null}},provenance:{source_kind:'manual',source_ref:null,source_artifacts:[],notes:'Domain checker only.'}});
 checkNumericComparisonDomain(make(left),make(right),domain,{inputs:mapping.inputs,outputs:[{left:'domain_result',right:'domain_result'}]});
 return {purpose:'input_domain_only',status:'validated_finite_fp32_domain'};
}

"""Compare provided observations with the frozen independent candidate.

Native origin, byte identity, ownership and guards must be validated by the host.
Neither absent outputs nor failed calls are populated using candidate values.
"""
from pathlib import Path
import argparse,json,sys
sys.dont_write_bytecode=True
sys.path.insert(0,str(Path(__file__).resolve().parent))
from corpus import CANDIDATE_PATH,CANDIDATE_SHA256,candidate_bytes,need,parse_json,stable_bytes,validate_corpus,write_new_json

def _error(value):
 need(type(value) is dict and set(value)=={'code','message'} and type(value['code']) is str and 0<len(value['code'])<=128 and type(value['message']) is str and len(value['message'])<=4096 and '\0' not in value['code']+value['message'],'Invalid observation error')
 return value.copy()

def _observations(rows,cases):
 need(type(rows) is list and len(rows)<=len(cases),'Observation list is outside its bound')
 indexed={};by_id={row['id']:row for row in cases}
 for row in rows:
  need(type(row) is dict and {'id','status'}<=set(row)<= {'id','status','output','error'},'Observation must contain only id/status/output/error')
  name=row['id'];need(type(name) is str and name in by_id and name not in indexed,'Unknown or duplicate observation ID')
  status=row['status'];need(type(status) is str and status in {'completed','failed','unattempted'},'Invalid native observation status')
  selected={'id':name,'status':status}
  if 'error' in row:selected['error']=_error(row['error'])
  if status=='completed':need('output' in row and 'error' not in row,'Completed observation requires actual output and no error')
  if status=='failed':need('error' in row,'Failed native call requires an error')
  if status=='unattempted':need('output' not in row,'Unattempted native call cannot have output')
  if 'output' in row:
   output=row['output'];size=by_id[name]['node_stride']*(by_id[name]['height']+1)
   need(type(output) is list and all(type(item) is int and -(1<<31)<=item<(1<<31) for item in output),'Observed output must be signed int32 values')
   need(len(output)==size if status=='completed' else len(output)<=size,'Observed output length differs from native buffer contract')
   selected['output']=output.copy()
  indexed[name]=selected
 return indexed

def compare_observations(corpus,observations,*,candidate_path=CANDIDATE_PATH):
 corpus=validate_corpus(corpus);rows=_observations(observations,corpus['cases'])
 source=candidate_bytes(candidate_path);need(len(source)==corpus['candidate']['size_bytes'],'Corpus candidate size differs from frozen source')
 namespace={'__name__':'wirefit_frozen_grid_candidate','__file__':str(candidate_path),'__package__':None}
 exec(compile(source,str(candidate_path),'exec'),namespace)
 candidate=namespace.get('recover_grid');need(callable(candidate),'Frozen candidate entry is missing')
 counts={'declared':len(corpus['cases']),'attempted':0,'completed':0,'matched':0,'mismatched':0,'failed':0,'unattempted':0}
 comparisons=[];counterexamples=[];negative_rejected=0
 for case in corpus['cases']:
  row=rows.get(case['id'])
  if row is None or row['status']=='unattempted':
   counts['unattempted']+=1;comparison={'id':case['id'],'status':'unattempted','observation_returned':row is not None}
   if row is not None and 'error' in row:comparison['error']=row['error']
   comparisons.append(comparison);continue
  counts['attempted']+=1
  if row['status']=='failed':
   counts['failed']+=1;comparison={'id':case['id'],'status':'failed','error':row['error']}
   if 'output' in row:comparison['observed_output']=row['output']
   comparisons.append(comparison);continue
  counts['completed']+=1;observed=row['output']
  expected=candidate(case['labels'],case['width'],case['height'],case['node_stride'])
  need(type(expected) is list and len(expected)==len(observed) and all(type(item) is int and -(1<<31)<=item<(1<<31) for item in expected),'Frozen candidate returned invalid output')
  matched=observed==expected;counts['matched' if matched else 'mismatched']+=1
  comparisons.append({'id':case['id'],'status':'matched' if matched else 'mismatch','observed_values':len(observed)})
  if observed!=[0]*len(observed):negative_rejected+=1
  if not matched and len(counterexamples)<8:
   index=next(index for index,(left,right) in enumerate(zip(observed,expected)) if left!=right)
   counterexamples.append({'id':case['id'],'case':case,'first_difference':{'index':index,'observed':observed[index],'candidate':expected[index]},'observed_output':observed,'candidate_output':expected})
 need(candidate_bytes(candidate_path)==source,'Candidate changed during comparison')
 negative={'mutant':'all_zero_output','attempted':counts['completed'],'rejected':negative_rejected,'accepted':counts['completed']-negative_rejected,'status':'unattempted' if counts['completed']==0 else 'rejected' if negative_rejected==counts['completed'] else 'accepted_for_some_observations'}
 status='counterexample' if counts['mismatched'] else 'native_failures' if counts['failed'] else 'incomplete' if counts['unattempted'] else 'negative_control_failed' if negative_rejected!=counts['completed'] or counts['completed']==0 else 'sampled_contract_matched'
 return {'schema_version':1,'status':status,'scope':'provided_outputs_under_declared_synthetic_grid_contract','cases_sha256':corpus['cases_sha256'],'candidate':{'path':str(candidate_path),'before_sha256':CANDIDATE_SHA256,'after_sha256':CANDIDATE_SHA256,'unchanged':True},'counts':counts,'comparisons':comparisons,'counterexamples':counterexamples,'counterexamples_truncated':max(0,counts['mismatched']-len(counterexamples)),'negative_control':negative,'native_origin_verified':False,'comparison_executes_native_code':False,'natural_application_call_observed':False,'whole_program_equivalence':False,'runnable_verified':False,'requires_host_validation':['owned_process_identity','kernel_body_identity_before_after','positive_control','input_immutability','canaries','cleanup']}

def main():
 parser=argparse.ArgumentParser(allow_abbrev=False);parser.add_argument('--corpus',required=True);parser.add_argument('--observations',required=True);parser.add_argument('--out',required=True);parser.add_argument('--candidate');args=parser.parse_args()
 try:
  corpus=parse_json(stable_bytes(Path(args.corpus)));rows=parse_json(stable_bytes(Path(args.observations)))
  if type(rows) is dict:need(set(rows)=={'rows'},'Observation envelope must contain only rows');rows=rows['rows']
  result=compare_observations(corpus,rows,**({'candidate_path':Path(args.candidate)} if args.candidate else {}));output=write_new_json(args.out,result)
 except Exception as error:print(json.dumps({'status':'failed','error':{'code':'NATIVE_KERNEL_COMPARISON_INVALID','message':str(error)},'comparison_executes_native_code':False}));return 1
 print(json.dumps({'status':result['status'],'counts':result['counts'],'output':output,'comparison_executes_native_code':False}));return 0 if result['status']=='sampled_contract_matched' else 2

if __name__=='__main__':raise SystemExit(main())
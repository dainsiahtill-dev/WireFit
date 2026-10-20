"""Offline validation of a copied, pinned native-kernel evidence release.

Only registered root/name files are read. Original paths are provenance metadata.
Only the exact reviewed worker and candidate code identities execute, as pure
validators/calculation in non-main namespaces. Frida and target code never run.
"""
from pathlib import Path
import argparse,hashlib,json,math,ntpath,os,re,stat,sys
MAX_FILE=16*1024*1024
MAX_TOTAL=128*1024*1024
PINS={
 'tools/native-kernel/worker.py':('f485c06c0d548ba7b85eb1f12d48d1aaadc32a904ca74300237600b23752db31',47023),
 'tools/native-kernel/agent.js':('6c628d6d74ce44138e635c478b6896cfbee6cb5ff69e25932f276f3093b53581',13983),
 'tools/native-kernel/corpus.py':('8dbd041b4b4be0c34484bd7651e75f66797aa495f340a84f85339919db168d89',10017),
 'tools/native-kernel/compare.py':('11391bd5ce9f9192167e0758833f2111e7e8136af0fb77d014e0e6b29882e05a',7032),
 'candidate/candidate.py':('00d212c77b5d4a62566820306ebbb0828d95cafe8301ee6ae77e0e94aabc95e5',1714),
}
ROLES={'raw_receipt','memory','analysis','audit','source_code','release_manifest','disk_reference'}
MEDIA={'application/octet-stream','application/vnd.wirefit.evidence-file+json','text/plain; charset=utf-8','text/markdown; charset=utf-8'}
HASH=re.compile(r'[a-f0-9]{64}\Z')
NATIVE_KEYS={'schema_version','kind','profile','status','is_checkpoint','source_sha256','corpus','candidate','corpus_input','identities','setup','identity_initial','identity_final','in_flight_id','rows','cleanup','error','source_unchanged','scope','runnable_verified','finish','inputs_unchanged','journal'}

def need(ok,message):
 if not ok:raise ValueError(message)

def sha(data):return hashlib.sha256(data).hexdigest()
def integer(value,low,high):return type(value) is int and low<=value<=high

def parse(data):
 def pairs(rows):
  result={}
  for key,value in rows:need(key not in result,'Duplicate JSON key');result[key]=value
  return result
 value=json.loads(data.decode('utf-8',errors='strict'),object_pairs_hook=pairs,parse_constant=lambda _:(_ for _ in ()).throw(ValueError('Nonfinite JSON')))
 pending=[value];count=0
 while pending:
  item=pending.pop();count+=1;need(count<=500000,'JSON node budget exceeded')
  if type(item) is dict:pending.extend(item.values())
  elif type(item) is list:pending.extend(item)
  elif type(item) is float:need(math.isfinite(item),'Nonfinite JSON number')
 return value

def safe_name(value):
 need(type(value) is str and 0<len(value)<=4096 and not re.search(r'[\\:\x00]',value),'Invalid logical name/path')
 parts=value.split('/');need(len(parts)<=64 and all(part and part not in {'.','..'} and not re.search(r'[<>"|?*\x00-\x1f]',part) and not part.endswith(('.',' ')) and not re.match(r'(?i)^(con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\.|$)',part) for part in parts),'Unsafe logical namespace component')
 return parts

def ordinary(value):
 file=Path(value);need(file.is_absolute() and '\0' not in str(file),'Expected absolute ordinary path')
 if os.name=='nt':
  need(re.match(r'^[A-Za-z]:[\\/]',str(file)) is not None and ':' not in str(file)[2:],'Path contains an ADS or drive alias')
  for part in file.parts[1:]:need(part not in {'.','..'} and not part.endswith(('.',' ')) and not re.search(r'[<>:"|?*\x00-\x1f]',part) and not re.match(r'(?i)^(con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\.|$)',part),'Path contains an aliased component')
 for part in [file,*file.parents]:need(not part.is_symlink() and not part.is_junction(),'Path contains a symlink or junction')
 selected=str(file);resolved=str(file.resolve(strict=True))
 need(selected.casefold()==resolved.casefold() if os.name=='nt' else selected==resolved,'Path resolves through an alias')
 return file

def stable_read(file,limit=MAX_FILE):
 file=ordinary(file);entry=file.stat()
 with file.open('rb') as handle:
  before=os.fstat(handle.fileno());need(stat.S_ISREG(before.st_mode) and before.st_nlink==1 and 0<=before.st_size<=limit,'File link or size bound is invalid')
  data=handle.read(limit+1);after=os.fstat(handle.fileno());current=file.stat()
  identity=lambda row:(row.st_dev,row.st_ino,row.st_size,row.st_mtime_ns,row.st_nlink)
  metadata=lambda row:(*identity(row),row.st_ctime_ns)
  need(metadata(entry)==metadata(current) and metadata(before)==metadata(after) and identity(entry)==identity(before)==identity(current) and len(data)==before.st_size,'File identity changed during retained-HANDLE read')
 ordinary(file);return data

def metadata_path(value):
 need(type(value) is str and 0<len(value)<=32767 and '\0' not in value,'Invalid original-path metadata')
 need(bool(re.match(r'^[A-Za-z]:[\\/]',value)) or value.startswith('/'),'Original-path metadata is not absolute')
 need(not any(part in {'.','..'} for part in re.split(r'[\\/]',value)),'Original-path metadata contains traversal')
 return value

def metadata_key(value):
 metadata_path(value)
 return ntpath.normcase(ntpath.normpath(value)) if re.match(r'^[A-Za-z]:',value) else value

def inventory(root):
 files=set();seen=set();count=0
 def walk(directory,prefix=''):
  nonlocal count
  for child in directory.iterdir():
   count+=1;need(count<=4096,'Root inventory entry budget exceeded')
   name=prefix+child.name;safe_name(name);key=name.casefold();need(key not in seen,'Root inventory has a case alias');seen.add(key)
   need(not child.is_symlink() and not child.is_junction(),'Root inventory contains a link or junction')
   info=child.lstat()
   if stat.S_ISDIR(info.st_mode):walk(child,name+'/')
   else:need(stat.S_ISREG(info.st_mode),'Unsupported root inventory entry');files.add(name)
 walk(root);return files

class Package:
 def __init__(self,root,release,pin):
  self.root=ordinary(root);need(self.root.is_dir(),'Logical root must be a directory');self.release=ordinary(release)
  need(type(pin) is str and HASH.fullmatch(pin),'Invalid explicit release SHA pin')
  self.release_bytes=stable_read(self.release,4*1024*1024);need(sha(self.release_bytes)==pin,'Release differs from explicit SHA pin');self.pin=pin
  value=parse(self.release_bytes);required={'schema_version','kind','parent','source','entries'}
  need(type(value) is dict and required<=set(value)<=required|{'external_dependencies'} and type(value['schema_version']) is int and value['schema_version']==1 and value['kind']=='managed_file_attachment','Invalid release schema')
  parent=value['parent'];need(type(parent) is dict and set(parent)=={'result_id','sha256'} and type(parent['result_id']) is str and re.fullmatch(r'[A-Za-z][A-Za-z0-9_.:-]{0,127}',parent['result_id']) and type(parent['sha256']) is str and HASH.fullmatch(parent['sha256']),'Invalid release parent metadata')
  need(value['source']=={'sha256':'9a0fa724e4a2f189da4cafdd700842d5b6c7aa6c571269500e5eb56cc3fa9a5d','size_bytes':6516736},'Release source anchor differs')
  need(type(value['entries']) is list and 1<=len(value['entries'])<=512,'Invalid release file count')
  self.rows={};keys=set();total=0
  for row in value['entries']:
   expected={'name','path','size_bytes','sha256','role','media_type'}
   need(type(row) is dict and expected<=set(row)<=expected|{'link_policy'},'Invalid release entry fields');safe_name(row['name']);metadata_path(row['path'])
   need(row['name'].casefold() not in keys and row['name'].casefold()!='release.json','Duplicate or reserved release logical name');keys.add(row['name'].casefold())
   need(integer(row['size_bytes'],0,MAX_FILE) and type(row['sha256']) is str and HASH.fullmatch(row['sha256']),'Entry size/hash is outside its bound')
   need(row['role'] in ROLES and row['media_type'] in MEDIA and row.get('link_policy','single') in {'single','readonly_external'} and (row.get('link_policy')!='readonly_external' or row['role']=='disk_reference'),'Invalid release role/media/link policy')
   total+=row['size_bytes'];self.rows[row['name']]=row
  need(total<=MAX_TOTAL,'Total release byte budget exceeded')
  for name in self.rows:
   parts=name.split('/')
   need(all('/'.join(parts[:n]).casefold() not in keys for n in range(1,len(parts))),'Logical namespace file/directory conflict')
  dependencies=value.get('external_dependencies',[]);need(type(dependencies) is list and len(dependencies)<=128,'External metadata count exceeds bound')
  for row in dependencies:
   expected={'kind','path','size_bytes','sha256'};need(type(row) is dict and expected<=set(row)<=expected|{'version'},'Invalid external metadata fields');metadata_path(row['path'])
   need(row['kind'] in {'runtime','system_library','analysis_tool'} and integer(row['size_bytes'],0,1<<30) and type(row['sha256']) is str and HASH.fullmatch(row['sha256']),'Invalid external metadata identity')
   if 'version' in row:need(type(row['version']) is str and 0<len(row['version'])<=256,'Invalid external version metadata')
  self.allowed=set(self.rows)
  if self.release.parent==self.root:need(self.release.name=='release.json','In-root release must be root/release.json');self.allowed.add('release.json')
  need(inventory(self.root)==self.allowed,'Unregistered or missing root inventory file')
  self.data={}
  for name,row in self.rows.items():
   data=stable_read(self.root.joinpath(*safe_name(name)));need(len(data)==row['size_bytes'] and sha(data)==row['sha256'],'Registered file identity differs: '+name);self.data[name]=data
  self.total=total
 def get(self,name):need(name in self.data,'Required logical file is missing: '+name);return self.data[name]
 def json(self,name):return parse(self.get(name))
 def final(self):
  need(stable_read(self.release,4*1024*1024)==self.release_bytes,'Release identity changed after validation')
  for name,data in self.data.items():need(stable_read(self.root.joinpath(*safe_name(name)))==data,'Registered file changed after validation: '+name)
  need(inventory(self.root)==self.allowed,'Root inventory changed after validation')

def binding(identity,data,label):
 need(type(identity) is dict and type(identity.get('sha256')) is str and HASH.fullmatch(identity['sha256']) and integer(identity.get('size_bytes'),0,MAX_FILE) and identity['sha256']==sha(data) and identity['size_bytes']==len(data),label+' byte identity differs')

def artifact(ref,data,label):
 need(type(ref) is dict and set(ref)=={'sha256','relative_path','media_type','size_bytes'},label+' artifact fields differ');binding(ref,data,label)
 need(ref['relative_path']=='artifacts/'+ref['sha256'] and type(ref['media_type']) is str and 0<len(ref['media_type'])<=256,label+' artifact path/media differs')

def clean(value):
 need(type(value) is dict and all(value.get(name) is True for name in ['owned_pid_terminated','session_detached','windows_job_assigned','windows_job_closed']) and value.get('errors',[])==[],'Cleanup was not fully confirmed')

def corpus_document(value,profile,worker):
 expected={'schema_version','kind','profile','candidate','kernel','cases_sha256','cases'}|({'legacy_inputs'} if profile=='legacy896' else set())
 need(type(value) is dict and set(value)==expected and type(value['schema_version']) is int and value['schema_version']==1 and value['kind']=='native_kernel_corpus' and value['profile']==profile,'Corpus schema differs')
 candidate=value['candidate'];need(type(candidate) is dict and set(candidate)=={'path','size_bytes','sha256','frozen_before_cases'} and candidate['sha256']==PINS['candidate/candidate.py'][0] and type(candidate['size_bytes']) is int and candidate['size_bytes']==1714 and candidate['frozen_before_cases'] is True,'Candidate was not the frozen source');metadata_path(candidate['path'])
 need(value['kernel']=={'rva':'0x98a50','size_bytes':637,'sha256':worker['PROFILES']['vmde-grid']['body_sha256']},'Corpus kernel differs')
 count=8 if profile=='edges8' else 896;need(type(value['cases']) is list and len(value['cases'])==count,'Corpus denominator differs')
 for case in value['cases']:worker['validate_case'](case)
 need(len({case['id'] for case in value['cases']})==count and value['cases_sha256']==worker['CASES_HASHES'][profile]==worker['cases_hash'](value['cases']),'Corpus fixed input hash differs')
 if profile=='legacy896':
  legacy=value['legacy_inputs'];need(type(legacy) is dict and set(legacy)=={'path','size_bytes','sha256','cases'} and legacy['sha256']==worker['LEGACY_SHA'] and type(legacy['cases']) is int and legacy['cases']==896 and integer(legacy['size_bytes'],1,MAX_FILE),'Legacy input metadata differs');metadata_path(legacy['path'])
 return value

def validate_journal(data,identity,rows):
 need(type(identity) is dict and set(identity)=={'file','size_bytes','sha256','records'} and identity['file']=='native-calls.jsonl' and type(identity['records']) is int and identity['records']==2*len(rows),'Journal identity/record count differs');binding(identity,data,'journal')
 need(data.endswith(b'\n'),'Journal does not end in a complete record');lines=data.splitlines();need(len(lines)==2*len(rows),'Journal denominator differs')
 for index,row in enumerate(rows):
  start,end=parse(lines[2*index]),parse(lines[2*index+1])
  need(start=={'sequence':2*index+1,'phase':'started','index':index,'id':row['id']},'Journal started sequence differs')
  need(end=={'sequence':2*index+2,'phase':'returned','index':index,'id':row['id'],'row':row},'Journal actual returned row differs')

def staged_path(case,result_id,basename):
 metadata_path(case)
 return ntpath.join(case,'.binary-work',result_id,basename) if re.match(r'^[A-Za-z]:',case) else str(Path(case)/'.binary-work'/result_id/basename)

def validate_run(package,label,corpus,worker,candidate):
 profile='positive-control' if label=='positive-control' else 'vmde-grid';fixed=worker['PROFILES'][profile];count=len(corpus['cases']);prefix='runs/'+label+'/'
 native_data=package.get(prefix+'native-result.json');native=parse(native_data);public=package.json(prefix+'public-run.json');raw_data=package.get(prefix+'raw-trace.json');raw=parse(raw_data)
 need(type(native) is dict and set(native)==NATIVE_KEYS and type(native['schema_version']) is int and native['schema_version']==1 and native['kind']=='native_inprocess_kernel' and native['profile']==profile and native['status']=='completed' and native['is_checkpoint'] is False and native['error'] is None and native['source_unchanged'] is True and native['inputs_unchanged'] is True and native['runnable_verified'] is False and native['in_flight_id'] is None,'Native receipt is incomplete or failed')
 clean(native['cleanup']);need(native['source_sha256']==fixed['source_sha256'] and native['candidate']==corpus['candidate'] and native['corpus_input']==corpus,'Native source/corpus identity differs');corpus_document(native['corpus_input'],corpus['profile'],worker)
 need(type(native['rows']) is list and len(native['rows'])==count and all(row.get('status')=='completed' for row in native['rows']) and native['finish']=={'completed_calls':count,'halted':False},'Native denominator or finish differs')
 need(type(public) is dict and type(public.get('schema_version')) is int and public['schema_version']==1 and public.get('profile')==label and public.get('source_unchanged') is True,'Public run scope differs')
 envelope=public['result'];job=envelope['job'];result=envelope['result']
 need(job['status']=='completed' and job['error'] is None and job['operation']=='trace_binary' and result['status']=='completed' and result['error'] is None and result['operation']=='trace_binary' and result['backend']=='frida' and job['result_id']==result['result_id'] and result['outputs']==[] and result['validation']=={'source_unchanged':True,'runnable_verified':False},'Public job/result is not a completed observation')
 need(result['trace_recovery']['is_checkpoint'] is False,'Public trace was recovered from an incomplete checkpoint')
 source_name='source/wirefit-kernel-control.exe' if profile=='positive-control' else 'source/vmde.exe';source=package.get(source_name)
 need(sha(source)==fixed['source_sha256'] and result['source']['sha256']==fixed['source_sha256'] and public['source']['sha256']==fixed['source_sha256'] and result['source']['size_bytes']==public['source']['size_bytes']==len(source),'Public source bytes differ');artifact(result['source']['artifact'],source,'source')
 corpus_name='corpus/'+corpus['profile']+'.json';corpus_bytes=package.get(corpus_name);binding(native['corpus'],corpus_bytes,'corpus');need(native['corpus']['case_count']==count and native['corpus']['cases_sha256']==corpus['cases_sha256'] and public['corpus']['sha256']==sha(corpus_bytes) and metadata_key(public['corpus']['path'])==metadata_key(native['corpus']['path']),'Public corpus identity differs')
 first,last=native['identity_initial'],native['identity_final'];pid=first['pid'];need(integer(pid,1,0xffffffff),'Invalid recorded native PID')
 basename='wirefit-kernel-control.exe' if profile=='positive-control' else 'vmde.exe';target=staged_path(public['case'],result['result_id'],basename)
 need(metadata_key(first['main']['path'])==metadata_key(target),'Recorded staged target path differs')
 worker['validate_identity'](first,profile,pid,first['main']['path']);worker['validate_identity'](last,profile,pid,first['main']['path'],first['main']);worker['validate_setup'](native['setup'],profile);need(native['setup']['main']==first['main'],'Setup main differs')
 for role,name in [('worker','tools/native-kernel/worker.py'),('agent','tools/native-kernel/agent.js')]:binding(native['identities'][role],package.get(name),'native '+role)
 need(native['identities']['support']['sha256']==worker['SUPPORT_SHA'],'Support source identity differs')
 matched=0
 for case,row in zip(corpus['cases'],native['rows']):
  worker['validate_row'](row,case,profile,first['main']);expected=candidate(case['labels'],case['width'],case['height'],case['node_stride'])
  need(row['output']==expected,'Observed output disagrees with frozen candidate');need(row['output']!=[0]*len(expected),'Zero negative control was not rejected');matched+=1
 validate_journal(package.get(prefix+'native-calls.jsonl'),native['journal'],native['rows'])
 artifact(result['trace_artifact'],raw_data,'raw trace')
 need(type(raw.get('schema_version')) is int and raw['schema_version']==1 and raw['status']=='completed' and raw['error'] is None and type(raw['pid']) is int and raw['pid']==pid and type(raw['omitted_events']) is int and raw['omitted_events']==0 and raw['omitted_events_complete'] is True and raw['hook_states_complete'] is True and raw['hook_states']=={'initial':[],'current':[],'final':[]},'Raw trace is incomplete')
 clean(raw['cleanup']);need(raw['cleanup']==native['cleanup'],'Native/raw cleanup differs')
 for role in ['worker','agent']:need(raw['identities'][role]==native['identities'][role],'Raw code identity differs')
 code_refs=result['trace_code_artifacts'];need(type(code_refs) is list and len(code_refs)==2 and {row['role'] for row in code_refs}=={'worker','agent'},'Public code references differ')
 for row in code_refs:artifact(row['artifact'],package.get('tools/native-kernel/'+('worker.py' if row['role']=='worker' else 'agent.js')),'public '+row['role'])
 summary=raw['native_kernel'];binding(summary,native_data,'raw native receipt');need(summary['profile']==profile and summary['source_sha256']==fixed['source_sha256'] and summary['in_flight_id'] is None and summary['corpus']==native['corpus'] and summary['identities']==native['identities'] and summary['journal']==native['journal'],'Raw native summary binding differs')
 need(type(summary['counts']) is dict and set(summary['counts'])=={'completed','failed','unattempted'} and all(type(value) is int for value in summary['counts'].values()) and summary['counts']=={'completed':count,'failed':0,'unattempted':0},'Raw denominator differs')
 need(type(raw['snapshots']) is list and len(raw['snapshots'])==2 and type(result['snapshots']) is list and len(result['snapshots'])==2,'Snapshot denominator differs')
 for phase,identity in [('initial',first),('final',last)]:
  snapshot=package.get(prefix+'snapshot-'+phase+'.bin');need(len(snapshot)==fixed['size_bytes'] and sha(snapshot)==fixed['body_sha256'] and snapshot.hex()==identity['body_hex'],'Snapshot body bytes differ')
  rows=[row for row in raw['snapshots'] if row.get('phase')==phase];need(len(rows)==1 and rows[0]=={'rva':fixed['rva'],'size_bytes':len(snapshot),'phase':phase,'file':'memory-'+phase+'-00.bin','sha256':sha(snapshot)},'Raw snapshot binding differs')
  rows=[row for row in result['snapshots'] if row.get('phase')==phase];need(len(rows)==1 and set(rows[0])=={'rva','size_bytes','phase','artifact'} and rows[0]['rva']==fixed['rva'] and rows[0]['size_bytes']==len(snapshot),'Public snapshot binding differs');artifact(rows[0]['artifact'],snapshot,'public snapshot')
 events=raw['events'];need(type(events) is list and len(events)<=512 and all(type(row) is dict for row in events),'Raw event bound differs')
 ready=[row for row in events if row.get('type')=='agent_ready'];need(len(ready)==1 and ready[0]['arch']=='ia32' and ready[0]['pointer_size']==4 and ready[0]['image_base']==first['main']['base'] and ready[0]['image_size']==first['main']['size'] and type(ready[0]['hardware_breakpoints']) is int and ready[0]['hardware_breakpoints']==0 and type(ready[0]['installed_api_hooks']) is int and ready[0]['installed_api_hooks']==0,'Agent-ready binding differs')
 setup=[row for row in events if row.get('type')=='native_kernel_setup'];need(len(setup)==1 and setup[0]['profile']==profile and setup[0]['setup']==native['setup'],'Raw setup differs')
 observed=[]
 for event in events:
  if event.get('type')=='native_kernel_cases':need(type(event.get('rows')) is list,'Raw case event rows differ');observed.extend(event['rows'])
 projected=[{key:row[key] for key in ['id','status','output','error'] if key in row} for row in native['rows']]
 need(observed==projected,'Raw event outputs differ from actual rows')
 return {'profile':profile,'declared':count,'completed':matched,'matched':matched,'failed':0,'unattempted':0,'negative_control_rejected':matched,'journal_records':2*count,'recorded_pid':pid,'recorded_main_base':first['main']['base'],'public_job_id':job['job_id'],'public_result_id':result['result_id']}

def audit_release(root,release,release_sha256):
 previous=sys.dont_write_bytecode;sys.dont_write_bytecode=True
 try:
  package=Package(root,release,release_sha256)
  for name,(pin,size) in PINS.items():data=package.get(name);need(sha(data)==pin and len(data)==size,'Reviewed code identity differs: '+name)
  namespace={'__name__':'wirefit_offline_reviewed_worker','__file__':str(package.root/'tools/native-kernel/worker.py'),'__package__':None}
  exec(compile(package.get('tools/native-kernel/worker.py'),namespace['__file__'],'exec'),namespace)
  def forbidden(*_args,**_kwargs):raise ValueError('Original-path worker I/O is forbidden during offline validation')
  namespace['stable_bytes']=forbidden;namespace['load_support']=forbidden
  candidate_namespace={'__name__':'wirefit_offline_frozen_candidate','__file__':str(package.root/'candidate/candidate.py'),'__package__':None};exec(compile(package.get('candidate/candidate.py'),candidate_namespace['__file__'],'exec'),candidate_namespace)
  candidate=candidate_namespace['recover_grid'];corpora={profile:corpus_document(package.json('corpus/'+profile+'.json'),profile,namespace) for profile in ['edges8','legacy896']}
  runs={label:validate_run(package,label,corpora['legacy896' if label=='legacy896' else 'edges8'],namespace,candidate) for label in ['positive-control','edges8','legacy896']}
  package.final();total=sum(run['completed'] for run in runs.values());original=runs['edges8']['completed']+runs['legacy896']['completed']
  return {'schema_version':1,'status':'verified_native_evidence','scope':'offline_validation_of_recorded_native_evidence','release_sha256':package.pin,'files_verified':len(package.data),'registered_bytes':package.total,'runs':runs,'total_completed':total,'original_kernel_completed':original,'negative_control':{'attempted':total,'rejected':total},'original_paths_opened':0,'native_reexecution':False,'auditor_target_execution':False,'natural_application_call_observed':False,'whole_program_equivalence':False,'runnable_verified':False,'external_runtime_metadata':'recorded_only_not_opened'}
 except ValueError:raise
 except Exception as error:raise ValueError('Native evidence validation failed: '+str(error)) from error
 finally:sys.dont_write_bytecode=previous

def output_path(value,root):
 file=Path(value);need(file.is_absolute() and file.name not in {'','.', '..'},'Output must be a new absolute path');safe_name(file.name);parent=ordinary(file.parent);root=ordinary(root)
 need(not file.is_relative_to(root),'Audit output must be outside the logical root');need(not os.path.lexists(file),'Audit output already exists');return file

def main():
 parser=argparse.ArgumentParser(allow_abbrev=False)
 for flag in ['root','release','release-sha256','out']:parser.add_argument('--'+flag,required=True)
 args=parser.parse_args()
 try:
  output=output_path(args.out,args.root);result=audit_release(args.root,args.release,args.release_sha256);text=json.dumps(result,ensure_ascii=False,allow_nan=False,indent=2)+'\n'
  with output.open('x',encoding='utf-8',newline='\n') as handle:handle.write(text);handle.flush();os.fsync(handle.fileno())
 except Exception as error:print(json.dumps({'status':'failed','error':{'code':'NATIVE_KERNEL_RELEASE_INVALID','message':str(error)},'native_reexecution':False},ensure_ascii=False));return 1
 print(json.dumps(result,ensure_ascii=False,allow_nan=False));return 0

if __name__=='__main__':raise SystemExit(main())
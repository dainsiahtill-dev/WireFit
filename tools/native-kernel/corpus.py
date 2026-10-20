"""Bounded grid inputs. Historical replay is read as data and never imported."""
from pathlib import Path
import argparse,hashlib,json,os,re,stat,sys
HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[1]
CANDIDATE_PATH=ROOT/'artifacts/research/vmde/kernel-replay/candidate.py'
LEGACY_PATH=ROOT/'artifacts/research/vmde/kernel-replay/run-t48nkuwa/observations.jsonl'
CANDIDATE_SHA256='00d212c77b5d4a62566820306ebbb0828d95cafe8301ee6ae77e0e94aabc95e5'
LEGACY_SHA256='98d0609048c7898575241918935670e3333233a70e9b6dc0d96dc8e814efac24'
KERNEL={'rva':'0x98a50','size_bytes':637,'sha256':'65d46a13deb731ea75b91fd29baf96dc614da6ad8bfcf48805aba748a139f70c'}
CASE_KEYS={'id','width','height','node_stride','source_stride','labels'}
PROFILES={'edges8':8,'legacy896':896,'all904':904}

def need(condition,message):
 if not condition:raise ValueError(message)

def sha(data):return hashlib.sha256(data).hexdigest()

def stable_bytes(value,limit=16777216):
 file=Path(value);need(file.is_absolute() and '\0' not in str(file),'Expected an absolute input path')
 if os.name=='nt':need(bool(re.match(r'^[A-Za-z]:[\\/]',str(file))) and ':' not in str(file)[2:],'Input path contains a stream or non-drive alias')
 for part in [file,*file.parents]:need(not part.is_symlink() and not part.is_junction(),'Input path contains a link or junction')
 selected=str(file.absolute());resolved=str(file.resolve(strict=True))
 need(selected.casefold()==resolved.casefold() if os.name=='nt' else selected==resolved,'Input path resolves through an alias')
 entry=file.stat()
 with file.open('rb') as handle:
  before=os.fstat(handle.fileno());need(stat.S_ISREG(before.st_mode) and 0<=before.st_size<=limit,'Input file exceeds its byte bound')
  data=handle.read(limit+1);after=os.fstat(handle.fileno());current=file.stat()
  meta=lambda row:(row.st_dev,row.st_ino,row.st_size,row.st_mtime_ns,row.st_ctime_ns)
  ident=lambda row:(row.st_dev,row.st_ino,row.st_size,row.st_mtime_ns)
  need(meta(before)==meta(after) and meta(entry)==meta(current) and ident(entry)==ident(before)==ident(current) and len(data)==before.st_size,'Input file changed during read')
 for part in [file,*file.parents]:need(not part.is_symlink() and not part.is_junction(),'Input path changed into a link or junction')
 return data

def parse_json(data):
 def pairs(rows):
  value={}
  for key,item in rows:need(key not in value,'Duplicate JSON field');value[key]=item
  return value
 return json.loads(data.decode('utf-8',errors='strict'),object_pairs_hook=pairs,parse_constant=lambda _:(_ for _ in ()).throw(ValueError('Nonfinite JSON value')))

def candidate_bytes(path=CANDIDATE_PATH):
 data=stable_bytes(Path(path),1048576);need(sha(data)==CANDIDATE_SHA256,'Frozen candidate source identity changed');return data

def validate_case(value):
 need(type(value) is dict and set(value)==CASE_KEYS,'A case requires exactly the six declared fields')
 need(isinstance(value['id'],str) and bool(re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,63}',value['id'])),'Invalid bounded case ID')
 width,height=value['width'],value['height'];node,source=value['node_stride'],value['source_stride']
 need(type(width) is int and type(height) is int and 2<=width<=16 and 2<=height<=16,'Dimensions must be integers from 2 through 16')
 need(type(node) is int and width+1<=node<=width+8 and type(source) is int and width<=source<=width+8,'Stride is outside the declared contract')
 labels=value['labels'];need(type(labels) is list and len(labels)==width*height and all(type(item) is int and -(1<<31)<=item<(1<<31) for item in labels),'Labels must be a dense signed-int32 W*H list')
 return {'id':value['id'],'width':width,'height':height,'node_stride':node,'source_stride':source,'labels':labels.copy()}

def cases_sha256(cases):return sha(json.dumps(cases,sort_keys=True,separators=(',',':'),ensure_ascii=True,allow_nan=False).encode('utf-8'))

def _edges():
 low,high=-(1<<31),(1<<31)-1
 return [
 {'id':'edge-00-uniform-2x2','width':2,'height':2,'node_stride':3,'source_stride':2,'labels':[0,0,0,0]},
 {'id':'edge-01-extreme-checker','width':2,'height':2,'node_stride':10,'source_stride':10,'labels':[low,high,high,low]},
 {'id':'edge-02-bottom-right','width':2,'height':2,'node_stride':3,'source_stride':2,'labels':[0,0,0,1]},
 {'id':'edge-03-wide','width':16,'height':2,'node_stride':17,'source_stride':16,'labels':[x%2 for y in range(2) for x in range(16)]},
 {'id':'edge-04-tall','width':2,'height':16,'node_stride':10,'source_stride':10,'labels':[y%2 for y in range(16) for x in range(2)]},
 {'id':'edge-05-max-uniform-padding','width':16,'height':16,'node_stride':24,'source_stride':24,'labels':[low]*256},
 {'id':'edge-06-max-checker','width':16,'height':16,'node_stride':17,'source_stride':16,'labels':[low if (x+y)%2==0 else high for y in range(16) for x in range(16)]},
 {'id':'edge-07-center','width':3,'height':3,'node_stride':11,'source_stride':11,'labels':[-1,-1,-1,-1,0,-1,-1,-1,-1]},
 ]

def build_corpus(profile='edges8',*,candidate_path=CANDIDATE_PATH,legacy_path=LEGACY_PATH):
 need(profile in PROFILES,'Unknown corpus profile')
 frozen=candidate_bytes(candidate_path) # Must precede construction of fresh cases.
 cases=_edges() if profile in {'edges8','all904'} else []
 legacy=None
 if profile in {'legacy896','all904'}:
  data=stable_bytes(Path(legacy_path));need(sha(data)==LEGACY_SHA256,'Historical legacy observation identity changed')
  rows=[parse_json(line) for line in data.splitlines()];need(len(rows)==896,'Historical legacy input count changed')
  cases.extend({key:row[key] for key in ['id','width','height','node_stride','source_stride','labels']} for row in rows)
  legacy={'path':str(Path(legacy_path)),'size_bytes':len(data),'sha256':sha(data),'cases':896}
 cases=[validate_case(row) for row in cases];need(len({row['id'] for row in cases})==len(cases),'Duplicate generated case ID')
 need(candidate_bytes(candidate_path)==frozen,'Candidate changed while constructing corpus')
 value={'schema_version':1,'kind':'native_kernel_corpus','profile':profile,'candidate':{'path':str(Path(candidate_path)),'size_bytes':len(frozen),'sha256':sha(frozen),'frozen_before_cases':True},'kernel':dict(KERNEL),'cases_sha256':cases_sha256(cases),'cases':cases}
 if legacy is not None:value['legacy_inputs']=legacy
 return validate_corpus(value)

def validate_corpus(value):
 need(type(value) is dict and set(value) in ({'schema_version','kind','profile','candidate','kernel','cases_sha256','cases'},{'schema_version','kind','profile','candidate','kernel','cases_sha256','cases','legacy_inputs'}),'Unexpected corpus fields')
 need(type(value['schema_version']) is int and value['schema_version']==1 and value['kind']=='native_kernel_corpus' and value['profile'] in PROFILES,'Invalid corpus schema/profile')
 candidate=value['candidate'];need(type(candidate) is dict and set(candidate)=={'path','size_bytes','sha256','frozen_before_cases'} and type(candidate['path']) is str and Path(candidate['path']).is_absolute() and '\0' not in candidate['path'] and type(candidate['size_bytes']) is int and 0<candidate['size_bytes']<=1048576 and candidate['sha256']==CANDIDATE_SHA256 and candidate['frozen_before_cases'] is True,'Corpus candidate is not the frozen identity')
 need(type(value['kernel']) is dict and value['kernel']==KERNEL,'Corpus kernel identity differs')
 need(type(value['cases']) is list and len(value['cases'])==PROFILES[value['profile']],'Corpus profile case count differs')
 cases=[validate_case(row) for row in value['cases']];need(len({row['id'] for row in cases})==len(cases),'Duplicate corpus case ID')
 need(type(value['cases_sha256']) is str and value['cases_sha256']==cases_sha256(cases),'Corpus input digest differs')
 if 'legacy_inputs' in value:
  legacy=value['legacy_inputs'];need(value['profile']!='edges8' and type(legacy) is dict and set(legacy)=={'path','size_bytes','sha256','cases'} and type(legacy['path']) is str and Path(legacy['path']).is_absolute() and '\0' not in legacy['path'] and type(legacy['size_bytes']) is int and legacy['size_bytes']>0 and legacy['sha256']==LEGACY_SHA256 and type(legacy['cases']) is int and legacy['cases']==896,'Invalid historical input identity')
 else:need(value['profile']=='edges8','Legacy profile lacks source identity')
 return {**value,'candidate':candidate.copy(),'kernel':dict(KERNEL),'cases':cases,**({'legacy_inputs':value['legacy_inputs'].copy()} if 'legacy_inputs' in value else {})}

def write_new_json(path,value):
 file=Path(path);need(file.is_absolute() and '\0' not in str(file),'Output must be absolute')
 name=file.name;need(name and not re.search(r'[<>:"/\\|?*\x00-\x1f]',name) and not name.endswith(('.', ' ')) and not re.match(r'(?i)^(con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\.|$)',name),'Invalid new output name')
 for part in [file.parent,*file.parent.parents]:need(not part.is_symlink() and not part.is_junction(),'Output has a linked ancestor')
 selected=str(file.parent.absolute());resolved=str(file.parent.resolve(strict=True));need(selected.casefold()==resolved.casefold() if os.name=='nt' else selected==resolved,'Output parent resolves through an alias')
 data=json.dumps(value,ensure_ascii=False,allow_nan=False,indent=2)+'\n'
 with file.open('x',encoding='utf-8',newline='\n') as handle:handle.write(data);handle.flush();os.fsync(handle.fileno())
 return {'path':str(file),'size_bytes':len(data.encode('utf-8')),'sha256':sha(data.encode('utf-8'))}

def main():
 parser=argparse.ArgumentParser(allow_abbrev=False);parser.add_argument('--profile',required=True,choices=PROFILES);parser.add_argument('--out',required=True);args=parser.parse_args()
 try:
  corpus=build_corpus(args.profile);output=write_new_json(args.out,corpus)
 except Exception as error:print(json.dumps({'status':'failed','error':{'code':'NATIVE_KERNEL_CORPUS_INVALID','message':str(error)}}));return 1
 print(json.dumps({'status':'created','cases':len(corpus['cases']),'cases_sha256':corpus['cases_sha256'],'output':output,'native_code_executed':False}));return 0

if __name__=='__main__':raise SystemExit(main())
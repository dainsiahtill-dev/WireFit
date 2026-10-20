"""Offline copied-evidence tests. All PE inputs are read as bytes, never run."""
from pathlib import Path
import contextlib,copy,hashlib,importlib.util,io,json,os,struct,subprocess,sys,tempfile,unittest
from unittest.mock import patch
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[1]
ENTRY=HERE/'audit-release.py'
sha=lambda value:hashlib.sha256(value).hexdigest()
encode=lambda value:(json.dumps(value,ensure_ascii=False,indent=2,allow_nan=False)+'\n').encode('utf-8')

class AuditReleaseTests(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  cls.files={}
  for name in ['worker.py','agent.js','corpus.py','compare.py']:
   cls.files['tools/native-kernel/'+name]=(HERE/name).read_bytes()
  cls.files['candidate/candidate.py']=(ROOT/'artifacts/research/vmde/kernel-replay/candidate.py').read_bytes()
  base=ROOT/'artifacts/research/vmde/native-kernel'
  for name in ['edges8','legacy896']:cls.files['corpus/'+name+'.json']=(base/(name+'.json')).read_bytes()
  for label in ['positive-control','edges8','legacy896']:
   folder=base/('run-'+label);public=json.loads((folder/'public-run.json').read_text(encoding='utf-8'))
   result=public['result']['result'];work=folder/'case'/'.binary-work'/result['result_id'];prefix='runs/'+label+'/'
   for name in ['native-result.json','native-calls.jsonl']:cls.files[prefix+name]=(work/name).read_bytes()
   cls.files[prefix+'public-run.json']=(folder/'public-run.json').read_bytes()
   cls.files[prefix+'raw-trace.json']=(folder/'case'/result['trace_artifact']['relative_path']).read_bytes()
   for snapshot in result['snapshots']:cls.files[prefix+'snapshot-'+snapshot['phase']+'.bin']=(folder/'case'/snapshot['artifact']['relative_path']).read_bytes()
   source='source/wirefit-kernel-control.exe' if label=='positive-control' else 'source/vmde.exe'
   cls.files[source]=(folder/'case'/result['source']['artifact']['relative_path']).read_bytes()
 def setUp(self):
  self.assertTrue(ENTRY.is_file(),'offline audit implementation is missing')
  spec=importlib.util.spec_from_file_location('wirefit_audit_tested',ENTRY);self.module=importlib.util.module_from_spec(spec);spec.loader.exec_module(self.module)
  self.temp=tempfile.TemporaryDirectory(prefix='wirefit-kernel-audit-');self.addCleanup(self.temp.cleanup)
  self.outer=Path(self.temp.name);self.root=self.outer/'logical';self.root.mkdir()
  for name,data in self.files.items():
   file=self.root/name;file.parent.mkdir(parents=True,exist_ok=True);file.write_bytes(data)
  self.release=self.root/'release.json'
  self.manifest={'schema_version':1,'kind':'managed_file_attachment','parent':{'result_id':'binary_trace_evidence_test','sha256':'0'*64},'source':{'sha256':'9a0fa724e4a2f189da4cafdd700842d5b6c7aa6c571269500e5eb56cc3fa9a5d','size_bytes':6516736},'entries':[{'name':name,'path':'Z:\\removed-workspace\\file-'+str(index),'size_bytes':len(data),'sha256':sha(data),'role':'source_code' if name.endswith(('.py','.js')) else 'analysis','media_type':'application/octet-stream'} for index,(name,data) in enumerate(self.files.items())],'external_dependencies':[{'kind':'runtime','path':'Z:\\deleted-runtime\\python.exe','size_bytes':1,'sha256':'0'*64}]}
  self.repin()
 def repin(self):self.release.write_bytes(encode(self.manifest));self.pin=sha(self.release.read_bytes())
 def rewrite(self,name,value):
  data=value if type(value) is bytes else encode(value);(self.root/name).write_bytes(data)
  row=next(row for row in self.manifest['entries'] if row['name']==name);row.update(size_bytes=len(data),sha256=sha(data));self.repin()
 def read_json(self,name):return json.loads((self.root/name).read_text(encoding='utf-8'))
 def audit(self):return self.module.audit_release(self.root,self.release,self.pin)
 def test_real_copied_912_rows_verify_without_opening_original_paths(self):
  original=Path.open;opened=[]
  def guarded(file,*args,**kwargs):
   self.assertTrue(file.absolute().is_relative_to(self.outer),'opened a path outside the copied package: '+str(file));opened.append(str(file));return original(file,*args,**kwargs)
  with patch.object(Path,'open',guarded):result=self.audit()
  self.assertEqual(result['status'],'verified_native_evidence');self.assertEqual(result['total_completed'],912);self.assertEqual(result['original_kernel_completed'],904)
  self.assertEqual(result['negative_control'],{'attempted':912,'rejected':912});self.assertFalse(result['native_reexecution']);self.assertFalse(result['runnable_verified']);self.assertTrue(opened)
 def test_explicit_release_pin_is_checked_before_any_proof_execution(self):
  with self.assertRaisesRegex(ValueError,'pin|SHA|identity'):self.module.audit_release(self.root,self.release,'0'*64)
 def test_unknown_worker_code_never_executes_even_with_recomputed_release_pin(self):
  name='tools/native-kernel/worker.py';self.rewrite(name,(self.root/name).read_bytes()+b'\nprint("UNTRUSTED_EXECUTED")\n')
  output=io.StringIO()
  with contextlib.redirect_stdout(output),self.assertRaises(ValueError):self.audit()
  self.assertEqual(output.getvalue(),'')
 def test_namespace_rejects_traversal_ads_backslash_absolute_reserved_and_case_aliases(self):
  names=['../escape','bad:stream','bad\\file','/absolute','CON.txt','trailing.','double//part']
  for name in names:
   original=copy.deepcopy(self.manifest);self.manifest['entries'][0]['name']=name;self.repin()
   with self.subTest(name=name),self.assertRaisesRegex(ValueError,'name|path|namespace|component'):self.audit()
   self.manifest=original;self.repin()
  self.manifest['entries'].append({**self.manifest['entries'][0],'name':self.manifest['entries'][0]['name'].upper()});self.repin()
  with self.assertRaisesRegex(ValueError,'Duplicate|duplicate|case'):self.audit()
 def test_exact_inventory_rejects_unregistered_file(self):
  (self.root/'unexpected.txt').write_text('unregistered',encoding='utf-8')
  with self.assertRaisesRegex(ValueError,'inventory|Unregistered|unregistered'):self.audit()
 def test_hardlinked_input_is_rejected(self):
  os.link(self.root/'candidate/candidate.py',self.outer/'alias.py')
  with self.assertRaisesRegex(ValueError,'link|identity'):self.audit()
 def test_real_junction_or_symlink_is_rejected(self):
  linked=self.root/'linked'
  if os.name=='nt':
   node=ROOT/'.tools/runtime/node_modules/node-win-x64/bin/node.exe'
   subprocess.run([str(node),'-e','require("node:fs").symlinkSync(process.argv[1],process.argv[2],"junction")',str(self.outer),str(linked)],check=True,capture_output=True)
  else:os.symlink(self.outer,linked,target_is_directory=True)
  with self.assertRaisesRegex(ValueError,'link|junction'):self.audit()
 def test_terminal_cleanup_and_denominator_cannot_be_promoted(self):
  name='runs/edges8/native-result.json';original=self.read_json(name)
  for mutate in [lambda d:d.update(status='failed'),lambda d:d['cleanup'].update(owned_pid_terminated=False),lambda d:d['rows'][0].update(status='unattempted'),lambda d:d['finish'].update(completed_calls=7)]:
   value=copy.deepcopy(original);mutate(value);self.rewrite(name,value)
   with self.assertRaises(ValueError):self.audit()
 def test_registered_repin_does_not_hide_wrong_registers_or_page_bytes(self):
  name='runs/edges8/native-result.json';original=self.read_json(name)
  for mutate in [lambda d:d['rows'][0]['evidence']['registers'].update(esp_after=1),lambda d:d['rows'][0]['evidence']['buffer_after_sha256'].update(nodes='0'*64)]:
   value=copy.deepcopy(original);mutate(value);self.rewrite(name,value)
   with self.assertRaises(ValueError):self.audit()
 def test_journal_sequence_and_returned_row_must_match_actual_receipt(self):
  name='runs/positive-control/native-calls.jsonl';lines=[json.loads(line) for line in (self.root/name).read_text(encoding='utf-8').splitlines()];lines[1]['row']['output'][0]=42
  self.rewrite(name,b''.join((json.dumps(row)+'\n').encode('utf-8') for row in lines))
  with self.assertRaises(ValueError):self.audit()
 def test_public_trace_and_snapshot_byte_refs_are_bound(self):
  name='runs/edges8/public-run.json';value=self.read_json(name);value['result']['result']['trace_artifact']['sha256']='0'*64;self.rewrite(name,value)
  with self.assertRaises(ValueError):self.audit()
 def test_snapshot_repin_does_not_change_allowed_body_identity(self):
  name='runs/edges8/snapshot-final.bin';self.rewrite(name,b'\x90'*637)
  with self.assertRaises(ValueError):self.audit()
 def test_file_and_total_declared_budgets_reject_before_content_read(self):
  original=copy.deepcopy(self.manifest)
  self.manifest['entries'][0]['size_bytes']=16*1024*1024+1;self.repin()
  with self.assertRaisesRegex(ValueError,'budget|bound|size'):self.audit()
  self.manifest=original
  for row in self.manifest['entries']:row['size_bytes']=16*1024*1024
  self.repin()
  with self.assertRaisesRegex(ValueError,'budget|bound|size'):self.audit()
 def test_cli_creates_only_new_external_receipt(self):
  output=self.outer/'audit.json';args=[sys.executable,'-X','utf8','-I','-S',str(ENTRY),'--root',str(self.root),'--release',str(self.release),'--release-sha256',self.pin,'--out',str(output)]
  first=subprocess.run(args,capture_output=True,text=True,encoding='utf-8',timeout=30);self.assertEqual(first.returncode,0,first.stdout+first.stderr);saved=output.read_bytes()
  second=subprocess.run(args,capture_output=True,text=True,encoding='utf-8',timeout=30);self.assertNotEqual(second.returncode,0);self.assertEqual(output.read_bytes(),saved)
  inside=args.copy();inside[-1]=str(self.root/'audit.json');blocked=subprocess.run(inside,capture_output=True,text=True,encoding='utf-8',timeout=30);self.assertNotEqual(blocked.returncode,0);self.assertFalse((self.root/'audit.json').exists())

 def test_nonfinite_exponent_json_is_rejected_even_outside_proof_fields(self):
  with self.assertRaises(ValueError):self.module.parse(b'{"metadata":1e500}')
 def test_self_consistent_wrong_output_is_rejected_by_candidate_comparison(self):
  prefix='runs/edges8/';native=self.read_json(prefix+'native-result.json');row=native['rows'][0]
  row['output'][4]=42;raw_output=struct.pack('<'+'i'*len(row['output']),*row['output'])
  row['evidence']['output_hex']=raw_output.hex();row['evidence']['output_sha256']=sha(raw_output)
  buffer=next(b for b in row['evidence']['buffers'] if b['name']=='nodes')
  row['evidence']['buffer_after_sha256']['nodes']=sha(b'\xa5'*(buffer['page_size']-buffer['size_bytes'])+raw_output)
  journal=[json.loads(line) for line in (self.root/(prefix+'native-calls.jsonl')).read_text(encoding='utf-8').splitlines()]
  journal[1]['row']=row;journal_bytes=b''.join((json.dumps(event,separators=(',',':'))+'\n').encode('utf-8') for event in journal)
  native['journal'].update(size_bytes=len(journal_bytes),sha256=sha(journal_bytes));native_bytes=encode(native)
  raw=self.read_json(prefix+'raw-trace.json');raw['native_kernel'].update(size_bytes=len(native_bytes),sha256=sha(native_bytes),journal=native['journal'])
  for event in raw['events']:
   if event.get('type')=='native_kernel_cases':
    for observed in event['rows']:
     if observed['id']==row['id']:observed['output']=row['output'].copy()
  raw_bytes=encode(raw);public=self.read_json(prefix+'public-run.json');public['result']['result']['trace_artifact'].update(size_bytes=len(raw_bytes),sha256=sha(raw_bytes),relative_path='artifacts/'+sha(raw_bytes))
  for name,data in [('native-calls.jsonl',journal_bytes),('native-result.json',native_bytes),('raw-trace.json',raw_bytes),('public-run.json',encode(public))]:self.rewrite(prefix+name,data)
  with self.assertRaisesRegex(ValueError,'candidate|Candidate'):self.audit()
 def test_file_changed_after_all_proofs_is_rejected_before_verified_result(self):
  original=self.module.validate_run
  def changing(*args,**kwargs):
   result=original(*args,**kwargs)
   if args[1]=='legacy896':
    file=self.root/'tools/native-kernel/agent.js';file.write_bytes(file.read_bytes()+b'\n')
   return result
  with patch.object(self.module,'validate_run',changing),self.assertRaisesRegex(ValueError,'changed|identity'):self.audit()
if __name__=='__main__':unittest.main(verbosity=2)
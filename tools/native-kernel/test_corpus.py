"""Pure corpus tests. Read frozen evidence as data; never load a PE or replay main."""
from pathlib import Path
import hashlib,importlib.util,json,subprocess,sys,tempfile,unittest
sys.dont_write_bytecode=True
HERE=Path(__file__).parent

class CorpusTests(unittest.TestCase):
 def setUp(self):
  entry=HERE/'corpus.py';self.assertTrue(entry.is_file(),'corpus implementation is missing')
  spec=importlib.util.spec_from_file_location('native_kernel_corpus_tested',entry);self.module=importlib.util.module_from_spec(spec);spec.loader.exec_module(self.module)
 def test_eight_edges_include_padding_extremes_and_dimension_boundaries(self):
  corpus=self.module.build_corpus('edges8')
  self.assertEqual(corpus['candidate']['sha256'],'00d212c77b5d4a62566820306ebbb0828d95cafe8301ee6ae77e0e94aabc95e5')
  self.assertEqual(len(corpus['cases']),8);self.assertEqual(len({row['id'] for row in corpus['cases']}),8)
  self.assertEqual(corpus['cases'][0],{'id':'edge-00-uniform-2x2','width':2,'height':2,'node_stride':3,'source_stride':2,'labels':[0,0,0,0]})
  self.assertEqual(corpus['cases'][1]['labels'],[-2147483648,2147483647,2147483647,-2147483648])
  self.assertEqual((corpus['cases'][3]['width'],corpus['cases'][3]['height']),(16,2))
  self.assertEqual((corpus['cases'][4]['width'],corpus['cases'][4]['height']),(2,16))
  self.assertEqual((corpus['cases'][5]['width'],corpus['cases'][5]['height'],corpus['cases'][5]['node_stride'],corpus['cases'][5]['source_stride']),(16,16,24,24))
 def test_legacy_cases_come_from_896_pinned_historical_inputs(self):
  corpus=self.module.build_corpus('legacy896');cases=corpus['cases']
  self.assertEqual(len(cases),896)
  self.assertEqual(cases[0],{'id':'four-cell-0','width':2,'height':2,'node_stride':3,'source_stride':2,'labels':[-2147483648]*4})
  self.assertEqual(cases[255]['labels'],[2147483647]*4)
  self.assertEqual(cases[256]['labels'],[0]*9)
  self.assertTrue(all(set(row)=={'id','width','height','node_stride','source_stride','labels'} for row in cases))
  self.assertEqual(corpus['legacy_inputs']['sha256'],'98d0609048c7898575241918935670e3333233a70e9b6dc0d96dc8e814efac24')
 def test_all_profile_has_904_unique_cases_and_is_deterministic(self):
  first=self.module.build_corpus('all904');second=self.module.build_corpus('all904')
  self.assertEqual(first,second);self.assertEqual(len(first['cases']),904);self.assertEqual(len({row['id'] for row in first['cases']}),904)
 def test_case_validation_rejects_unknown_fields_bool_values_and_out_of_domain(self):
  base={'id':'sample','width':2,'height':2,'node_stride':3,'source_stride':2,'labels':[0,0,0,0]}
  mutations=[{'width':True},{'height':1},{'node_stride':2},{'source_stride':11},{'labels':[0,0,0,2147483648]},{'labels':[0,0,0,True]},{'id':'../escape'},{'extra':0}]
  for mutation in mutations:
   with self.subTest(mutation=mutation),self.assertRaises(ValueError):self.module.validate_case({**base,**mutation})
 def test_changed_candidate_is_rejected_before_constructing_corpus(self):
  with tempfile.TemporaryDirectory(prefix='wirefit-kernel-candidate-') as folder:
   copy=Path(folder)/'candidate.py';copy.write_bytes(self.module.CANDIDATE_PATH.read_bytes()+b'\n# changed\n')
   with self.assertRaisesRegex(ValueError,'candidate|Candidate'):self.module.build_corpus('edges8',candidate_path=copy)
 def test_legacy_file_hash_is_checked_before_extracting_cases(self):
  with tempfile.TemporaryDirectory(prefix='wirefit-kernel-legacy-') as folder:
   copy=Path(folder)/'observations.jsonl';copy.write_text('{}\n',encoding='utf-8')
   with self.assertRaisesRegex(ValueError,'legacy|Legacy|historical|Historical'):self.module.build_corpus('legacy896',legacy_path=copy)
 def test_cli_creates_utf8_corpus_once_and_preserves_existing_output(self):
  with tempfile.TemporaryDirectory(prefix='wirefit-kernel-corpus-') as folder:
   output=Path(folder)/'corpus.json';args=[sys.executable,'-X','utf8','-I','-S',str(HERE/'corpus.py'),'--profile','edges8','--out',str(output)]
   first=subprocess.run(args,capture_output=True,text=True,encoding='utf-8',timeout=10);self.assertEqual(first.returncode,0,first.stderr)
   saved=output.read_bytes();self.assertEqual(len(json.loads(saved.decode('utf-8'))['cases']),8)
   second=subprocess.run(args,capture_output=True,text=True,encoding='utf-8',timeout=10);self.assertNotEqual(second.returncode,0);self.assertEqual(output.read_bytes(),saved)

if __name__=='__main__':unittest.main(verbosity=2)
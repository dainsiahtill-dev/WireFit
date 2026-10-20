"""Compare actual frozen CPU observations as data; this test never executes native code."""
from pathlib import Path
import importlib.util,json,sys,tempfile,unittest
sys.dont_write_bytecode=True
HERE=Path(__file__).parent

class CompareTests(unittest.TestCase):
 def setUp(self):
  self.assertTrue((HERE/'compare.py').is_file(),'comparison implementation is missing')
  sys.path.insert(0,str(HERE));self.addCleanup(lambda:sys.path.remove(str(HERE)))
  import corpus
  spec=importlib.util.spec_from_file_location('native_kernel_compare_tested',HERE/'compare.py');self.module=importlib.util.module_from_spec(spec);spec.loader.exec_module(self.module)
  self.corpus=corpus.build_corpus('legacy896')
  raw=[json.loads(line) for line in corpus.LEGACY_PATH.read_text(encoding='utf-8').splitlines()]
  self.rows=[{'id':row['id'],'status':'completed','output':row['machine_output']} for row in raw]
 def test_actual_frozen_observations_match_896_and_reject_zero_mutant(self):
  result=self.module.compare_observations(self.corpus,self.rows)
  self.assertEqual(result['status'],'sampled_contract_matched');self.assertEqual(result['counts'],{'declared':896,'attempted':896,'completed':896,'matched':896,'mismatched':0,'failed':0,'unattempted':0})
  self.assertEqual(result['negative_control']['rejected'],896);self.assertEqual(result['negative_control']['status'],'rejected')
  self.assertFalse(result['native_origin_verified']);self.assertFalse(result['comparison_executes_native_code'])
  self.assertEqual(result['candidate']['before_sha256'],result['candidate']['after_sha256'])
 def test_concrete_disagreement_retains_both_actual_and_candidate_values(self):
  self.rows[0]['output']=self.rows[0]['output'].copy();self.rows[0]['output'][4]=42
  result=self.module.compare_observations(self.corpus,self.rows)
  self.assertEqual(result['status'],'counterexample');self.assertEqual(result['counts']['mismatched'],1)
  example=result['counterexamples'][0];self.assertEqual(example['id'],'four-cell-0');self.assertEqual(example['first_difference'],{'index':4,'observed':42,'candidate':-1})
  self.assertEqual(example['observed_output'][4],42);self.assertEqual(example['candidate_output'][4],-1)
 def test_absent_observation_is_unattempted_without_filled_output(self):
  result=self.module.compare_observations(self.corpus,self.rows[1:])
  self.assertEqual(result['status'],'incomplete');self.assertEqual(result['counts']['unattempted'],1)
  row=next(row for row in result['comparisons'] if row['id']=='four-cell-0')
  self.assertEqual(row['status'],'unattempted');self.assertNotIn('candidate_output',row);self.assertNotIn('output',row)
 def test_failed_and_explicitly_unattempted_are_counted_separately(self):
  self.rows[0]={'id':'four-cell-0','status':'failed','error':{'code':'NATIVE_CALL_FAILED','message':'synthetic observed error'}}
  self.rows[1]={'id':'four-cell-1','status':'unattempted','error':{'code':'STOPPED','message':'not called'}}
  result=self.module.compare_observations(self.corpus,self.rows)
  self.assertEqual(result['status'],'native_failures');self.assertEqual(result['counts']['failed'],1);self.assertEqual(result['counts']['unattempted'],1);self.assertEqual(result['counts']['attempted'],895)
  self.assertNotIn('candidate_output',result['comparisons'][0]);self.assertNotIn('output',result['comparisons'][0])
 def test_missing_completed_output_is_rejected_instead_of_using_candidate(self):
  self.rows[0]={'id':'four-cell-0','status':'completed'}
  with self.assertRaises(ValueError):self.module.compare_observations(self.corpus,self.rows)
 def test_duplicate_unknown_id_or_non_int32_observation_is_rejected(self):
  variants=[[self.rows[0],self.rows[0]],[{'id':'unknown','status':'completed','output':[0]}],[{**self.rows[0],'output':[True]*9}],[{**self.rows[0],'output':[0]*8}]]
  for rows in variants:
   with self.subTest(rows=rows),self.assertRaises(ValueError):self.module.compare_observations(self.corpus,rows)
 def test_no_observation_cannot_pass_or_run_negative_control(self):
  result=self.module.compare_observations(self.corpus,[])
  self.assertEqual(result['status'],'incomplete');self.assertEqual(result['counts']['attempted'],0);self.assertEqual(result['counts']['unattempted'],896);self.assertEqual(result['negative_control']['status'],'unattempted')
 def test_changed_candidate_never_replaces_frozen_candidate(self):
  import corpus
  with tempfile.TemporaryDirectory(prefix='wirefit-kernel-compare-') as folder:
   copy=Path(folder)/'candidate.py';copy.write_bytes(corpus.CANDIDATE_PATH.read_bytes()+b'\n# changed\n')
   with self.assertRaisesRegex(ValueError,'candidate|Candidate'):self.module.compare_observations(self.corpus,self.rows,candidate_path=copy)

 def test_declared_candidate_size_must_match_the_actual_frozen_source(self):
  self.corpus['candidate']['size_bytes']=1
  with self.assertRaisesRegex(ValueError,'candidate|Candidate'):self.module.compare_observations(self.corpus,self.rows)
 def test_injected_verdict_or_evidence_is_not_a_basic_observation(self):
  with self.assertRaises(ValueError):self.module.compare_observations(self.corpus,[{**self.rows[0],'matched':True}])
 def test_counterexample_retention_is_bounded_without_hiding_total_mismatches(self):
  for row in self.rows[:10]:row['output']=row['output'].copy();row['output'][0]=42
  result=self.module.compare_observations(self.corpus,self.rows)
  self.assertEqual(result['counts']['mismatched'],10);self.assertEqual(len(result['counterexamples']),8);self.assertEqual(result['counterexamples_truncated'],2)
if __name__=='__main__':unittest.main(verbosity=2)
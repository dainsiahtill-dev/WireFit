"""Pure flat-memory PE fixtures; no Windows helper, target or emulator imports."""
import importlib.util
from pathlib import Path
import struct
import sys
import unittest

HERE = Path(__file__).absolute().parent
BASE = 0x67000000


class FlatPe:
    def __init__(self, names=('CtorA','CtorB'), size=0x8000):
        self.data=bytearray(size);self.calls=[];self.queries=[];self.read_overrides={};self.query_overrides={}
        self.data[:2]=b'MZ';struct.pack_into('<I',self.data,60,0x80)
        self.data[0x80:0x84]=b'PE\0\0';struct.pack_into('<HH',self.data,0x84,0x14c,1);struct.pack_into('<H',self.data,0x94,0xe0)
        optional=0x98;struct.pack_into('<H',self.data,optional,0x10b);struct.pack_into('<I',self.data,optional+28,0x10000000)
        struct.pack_into('<II',self.data,optional+56,size,0x1000);struct.pack_into('<I',self.data,optional+92,16)
        struct.pack_into('<II',self.data,optional+96,0x1000,0x800)
        self.data[0x178:0x180]=b'.text\0\0\0'
        struct.pack_into('<IIII',self.data,0x180,size-0x1000,0x1000,size-0x1000,0x700000)
        struct.pack_into('<I',self.data,0x178+36,0x60000020)
        self.setup(names)
    def setup(self,names,functions=None,name_rvas=None,eat=0x1100,ent=0x1200,eot=0x1300):
        functions=functions if functions is not None else [0x4000+0x20*i for i in range(max(1,len(names)))]
        struct.pack_into('<IIIIII',self.data,0x1010,1,len(functions),len(names),eat,ent,eot)
        for i,target in enumerate(functions):struct.pack_into('<I',self.data,eat+i*4,target)
        for i,name in enumerate(names):
            rva=name_rvas[i] if name_rvas else 0x2000+i*0x100
            struct.pack_into('<I',self.data,ent+i*4,rva);struct.pack_into('<H',self.data,eot+i*2,min(i,len(functions)-1))
            raw=name.encode('ascii')+b'\0';self.data[rva:rva+len(raw)]=raw
        for i,target in enumerate(functions):
            if 0x4000<=target<len(self.data)-16:self.data[target:target+16]=bytes([0x40+i])*16
    def read(self,rva,length):
        self.calls.append((rva,length))
        if (rva,length) in self.read_overrides:return self.read_overrides[(rva,length)]
        if rva in self.read_overrides:
            value=self.read_overrides[rva]
            if isinstance(value,BaseException):raise value
            return value
        b=bytes(self.data[rva:rva+length])
        return {'data':b,'transferred_bytes':len(b),'success':len(b)==length,'winerror':0 if len(b)==length else 299}
    def query(self,va):
        self.queries.append(va)
        if va in self.query_overrides:
            value=self.query_overrides[va]
            if isinstance(value,BaseException):raise value
            return value
        return {'base_address':BASE,'allocation_base':BASE,'allocation_protect':0x20,
                'region_size':len(self.data),'state':0x1000,'protect':0x20,'type':0x1000000,'returned_size':48}


class ExportModelTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        p=HERE/'model.py'
        if p.is_file():
            spec=importlib.util.spec_from_file_location('runtime_export_pure_model',p)
            cls.module=importlib.util.module_from_spec(spec);spec.loader.exec_module(cls.module)
        else:cls.module=None
    def run_model(self,fixture=None,names=('CtorA',),**kwargs):
        self.assertIsNotNone(self.module,'Pure export model is not implemented')
        fixture=fixture or FlatPe()
        return self.module.inspect_exports(fixture.read,fixture.query,BASE,len(fixture.data),names,query_struct_size=48,**kwargs)
    def row(self,result,name='CtorA'):
        return next(x for x in result['exports'] if x['name']==name)
    def test_direct_export_uses_flat_rva_and_actual_base_not_disk_offsets(self):
        f=FlatPe();r=self.run_model(f)
        self.assertEqual(r['status'],'completed')
        row=self.row(r);self.assertEqual(row['lookup_status'],'resolved')
        m=row['matches'][0];self.assertEqual((m['target_rva'],m['target_va']),(0x4000,hex(BASE+0x4000)))
        self.assertEqual(m['target_bytes']['hex'],'40'*16)
        self.assertEqual(m['section_characteristics'],0x60000020)
        self.assertTrue(m['runtime_executable']);self.assertIsNone(m['frida_export_type'])
        self.assertEqual(m['export_kind'],'direct');self.assertFalse(r['atomic'])
    def test_alias_names_can_share_one_ordinal_and_target(self):
        f=FlatPe();struct.pack_into('<H',f.data,0x1302,0)
        r=self.run_model(f,('CtorA','CtorB'))
        self.assertEqual([x['lookup_status'] for x in r['exports']],['resolved','resolved'])
        self.assertEqual([x['matches'][0]['target_rva'] for x in r['exports']],[0x4000,0x4000])
    def test_forwarder_is_raw_string_and_never_resolves_another_module(self):
        f=FlatPe();struct.pack_into('<I',f.data,0x1100,0x1400);f.data[0x1400:0x1400+len(b'OTHER.#17\0')]=b'OTHER.#17\0'
        r=self.run_model(f);m=self.row(r)['matches'][0]
        self.assertEqual(m['export_kind'],'forwarder');self.assertEqual(m['forwarder'],'OTHER.#17')
        self.assertIsNone(m['target_bytes']);self.assertIsNone(m['runtime_executable'])
        self.assertTrue(all(BASE<=x<BASE+len(f.data) for x in f.queries))
    def test_zero_eat_is_unassigned_and_not_a_callable_module_base(self):
        f=FlatPe();struct.pack_into('<I',f.data,0x1100,0)
        m=self.row(self.run_model(f))['matches'][0]
        self.assertEqual(m['export_kind'],'unassigned');self.assertIsNone(m['target_va']);self.assertIsNone(m['target_bytes'])
    def test_out_of_module_eat_is_invalid_and_never_read(self):
        f=FlatPe();struct.pack_into('<I',f.data,0x1100,0x9000)
        r=self.run_model(f);m=self.row(r)['matches'][0]
        self.assertEqual(m['export_kind'],'invalid');self.assertEqual(r['status'],'partial')
        self.assertTrue(all(a+n<=len(f.data) for a,n in f.calls))
    def test_duplicate_exact_name_is_ambiguous_and_both_matches_retained(self):
        f=FlatPe(('CtorA','CtorA'));row=self.row(self.run_model(f))
        self.assertEqual(row['lookup_status'],'ambiguous');self.assertEqual(len(row['matches']),2)
    def test_unreadable_other_name_prevents_unique_found_result(self):
        f=FlatPe();struct.pack_into('<I',f.data,0x1204,0x3000);f.read_overrides[0x3000]=OSError('unreadable name page')
        r=self.run_model(f);row=self.row(r)
        self.assertEqual(row['lookup_status'],'indeterminate');self.assertEqual(len(row['matches']),1);self.assertEqual(r['status'],'partial')
    def test_unreadable_name_prevents_not_found_claim(self):
        f=FlatPe();f.read_overrides[0x2000]=OSError('unreadable names')
        r=self.run_model(f,('Absent',))
        self.assertEqual(self.row(r,'Absent')['lookup_status'],'indeterminate')
    def test_non_target_long_name_needs_only_requested_length_prefix(self):
        f=FlatPe(('A'*900,),size=0x8000);r=self.run_model(f,('No',))
        self.assertEqual(self.row(r,'No')['lookup_status'],'not_found')
        self.assertFalse(any(a==0x3000 for a,n in f.calls))
        self.assertLessEqual(sum(n for a,n in f.calls),4*4096)
    def test_matching_name_bad_ordinal_is_partial_not_resolved(self):
        f=FlatPe();struct.pack_into('<H',f.data,0x1300,2)
        r=self.run_model(f);self.assertEqual(self.row(r)['lookup_status'],'indeterminate');self.assertEqual(r['status'],'partial')
    def test_decorated_ascii_names_are_exact_and_case_sensitive(self):
        name='??0QCoreApplication@@QAE@AAHPAPAD@Z'
        f=FlatPe((name,));r=self.run_model(f,(name,name.lower()))
        self.assertEqual(self.row(r,name)['lookup_status'],'resolved')
        self.assertEqual(self.row(r,name.lower())['lookup_status'],'not_found')
    def test_invalid_request_scalars_names_and_bounds_do_not_touch_callbacks(self):
        f=FlatPe();self.assertIsNotNone(self.module,'Pure export model is not implemented')
        for base,size,names,qsize in [(True,0x8000,('CtorA',),48),(BASE,False,('CtorA',),48),
             (BASE+1,0x8000,('CtorA',),48),(BASE,0x8001,('CtorA',),48),(0xfffff000,0x2000,('CtorA',),48),
             (BASE,0x4001000,('CtorA',),48),(BASE,0x8000,('CtorA','CtorA'),48),(BASE,0x8000,(),48),
             (BASE,0x8000,('x'*257,),48),(BASE,0x8000,('x\0y',),48),(BASE,0x8000,('中文',),48),(BASE,0x8000,('CtorA',),True),(1<<80,0x8000,('CtorA',),48)]:
            with self.subTest(values=(base,size,names,qsize)):
                r=self.module.inspect_exports(f.read,f.query,base,size,names,query_struct_size=qsize)
                self.assertEqual(r['status'],'failed')
                if type(base) is int and base>=1<<32:self.assertIsNone(r['module']['base'])
        self.assertEqual(f.calls,[]);self.assertEqual(f.queries,[])
    def test_read_record_schema_rejects_bool_count_and_nonbytes(self):
        for value in [{'data':b'x','transferred_bytes':True,'success':False,'winerror':299},
                      {'data':'x','transferred_bytes':1,'success':False,'winerror':299},
                      {'data':b'x','transferred_bytes':2,'success':False,'winerror':299}]:
            f=FlatPe();f.read_overrides[0]=value
            r=self.run_model(f);self.assertEqual(r['status'],'partial')
            self.assertTrue(r['errors']);self.assertNotEqual(self.row(r)['lookup_status'],'not_found')
    def test_partial_header_bytes_are_retained_without_zero_padding(self):
        f=FlatPe();f.read_overrides[0]={'data':b'MZabc','transferred_bytes':5,'success':False,'winerror':299}
        r=self.run_model(f);self.assertEqual(r['status'],'partial')
        self.assertEqual(r['reads'][0]['hex'],b'MZabc'.hex());self.assertEqual(r['reads'][0]['observed_bytes'],5)
    def test_page_guard_target_is_queried_but_not_read(self):
        f=FlatPe();q=f.query(BASE+0x4000);q['protect']=0x120;f.query_overrides[BASE+0x4000]=q;f.queries=[]
        r=self.run_model(f);m=self.row(r)['matches'][0]
        self.assertFalse(m['runtime_executable']);self.assertEqual(m['target_bytes']['observed_bytes'],0)
        self.assertFalse(any(a<=0x4000<a+n for a,n in f.calls))
    def test_nonexecuting_data_export_is_not_mislabeled_function(self):
        f=FlatPe();q=f.query(BASE+0x4000);q['protect']=4;f.query_overrides[BASE+0x4000]=q
        m=self.row(self.run_model(f))['matches'][0]
        self.assertFalse(m['runtime_executable']);self.assertIsNone(m['frida_export_type'])
        self.assertEqual(m['target_bytes']['hex'],'40'*16)
    def test_query_failure_leaves_executable_unknown_and_preserves_error(self):
        f=FlatPe();f.query_overrides[BASE+0x4000]=OSError('query unavailable')
        r=self.run_model(f);m=self.row(r)['matches'][0]
        self.assertIsNone(m['runtime_executable']);self.assertEqual(r['status'],'partial');self.assertTrue(r['queries'][-1]['error'])
    def test_partial_target_read_keeps_only_actual_prefix(self):
        f=FlatPe();f.read_overrides[(0x4000,16)]={'data':b'abcde','transferred_bytes':5,'success':False,'winerror':299}
        m=self.row(self.run_model(f))['matches'][0]
        self.assertEqual(m['target_bytes']['hex'],b'abcde'.hex());self.assertEqual(m['target_bytes']['observed_bytes'],5)
        self.assertFalse(m['target_bytes']['complete'])
    def test_invalid_vqe_size_boolean_or_noncovering_range_is_unknown(self):
        for key,value in [('returned_size',28),('state',True),('base_address',BASE+0x5000),('region_size',0)]:
            f=FlatPe();q=f.query(BASE+0x4000);q[key]=value;f.query_overrides[BASE+0x4000]=q
            m=self.row(self.run_model(f))['matches'][0]
            self.assertIsNone(m['runtime_executable']);self.assertIsNone(m['region'])
    def test_budget_exhaustion_never_becomes_not_found(self):
        names=tuple('N'+str(i) for i in range(257));f=FlatPe(size=0x120000)
        f.setup(names,functions=[0x110000],name_rvas=[0x4000+i*4096 for i in range(257)],eat=0x1100,ent=0x2000,eot=0x3000)
        r=self.run_model(f,('Absent',))
        self.assertEqual(self.row(r,'Absent')['lookup_status'],'indeterminate')
        self.assertEqual(r['status'],'partial');self.assertLessEqual(r['budget']['pages'],256)
        self.assertLessEqual(r['budget']['requested_read_bytes'],1024*1024)
    def test_invalid_pe32_header_or_export_directory_is_partial(self):
        for offset,value,width in [(0x98,0x20b,2),(0x98+56,0x9000,4),(0x98+96,0x7ff0,4),(0x98+100,20,4)]:
            f=FlatPe();struct.pack_into('<H' if width==2 else '<I',f.data,offset,value)
            r=self.run_model(f);self.assertEqual(r['status'],'partial');self.assertNotEqual(self.row(r)['lookup_status'],'not_found')
    def test_ordinal_only_exports_have_conclusive_named_absence(self):
        f=FlatPe(());r=self.run_model(f)
        self.assertEqual(self.row(r)['lookup_status'],'not_found');self.assertEqual(r['status'],'completed')


if __name__=='__main__':
    unittest.main(verbosity=2)

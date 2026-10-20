"""Only three pinned label-state methods under guarded CPU emulation, not native."""
import hashlib
import json
import os
from pathlib import Path
import stat
import struct
import sys
import time
import types
from datetime import datetime, timezone

sys.dont_write_bytecode = True
HERE = Path(__file__).absolute().parent
PROJECT = HERE.parents[1]
BOOTSTRAP_PATH = HERE.parent / 'node-record' / 'replay.py'
BOOTSTRAP_SHA256 = '440ccbd82f3056bfe6b08fb16b63be860bea1f66d53f4c6ec68b995b53b15629'
MODEL_SHA256 = '0d682eecbc7aeab39cbb710033e6b57ac29552cc933d8594bab5ce7a900cfa10'
IMAGE_SHA256 = '50b6bb68637b23d14ee1886ca1e84d944fade255204e70a831f27a3ef4fd6992'
PAGE = 4096
SENTINEL = 0x60001000
STEP_LIMIT = 65536
WRITE_LIMIT = 8192
TIMEOUT_US = 200000


def sha(data): return hashlib.sha256(data).hexdigest()


def _rows(entry, rows): return tuple((entry + offset, bytes.fromhex(data)) for offset, data in rows)


BODIES = {
    'lookup': {'entry':0x47e8e0, 'cleanup':4,
        'sha256':'a06a4266d3f145ad966bebf50f0e4baef0d3f0fd7f208a8043d01de06d533c37',
        'listing':'artifacts/research/vmde/segmentation-results/run-label-lookup-20261020/analysis/0047e8e0.json',
        'listing_sha256':'cb773aca284aa1894823f04059bc87169bb4117e735e83c8f4cc72ffde6a0a3e',
        'rows':_rows(0x47e8e0, ((0,'8b01'),(2,'55'),(3,'8b6c2408'),(7,'8b04a8'),(10,'57'),(11,'8b7910'),
            (14,'833c8700'),(18,'7c1f'),(20,'53'),(21,'56'),(22,'8bf7'),(24,'8b1486'),(27,'8bd8'),(29,'8d4900'),
            (32,'8bc2'),(34,'8b1486'),(37,'85d2'),(39,'7df7'),(41,'89049f'),(44,'8b09'),(46,'5e'),
            (47,'8904a9'),(50,'5b'),(51,'5f'),(52,'5d'),(53,'c20400')))},
    'merge_roots': {'entry':0x47e1b0, 'cleanup':8,
        'sha256':'69b1d393716e9ef0125567d4066fc9ff81b144bf3f4fc49673bbdd8a99bd29a8',
        'listing':'artifacts/research/vmde/segmentation-results/run-label-lookup-20261020/analysis/0047e1b0.json',
        'listing_sha256':'e0f1505366af31e9cd72dde948e7c303d18fa000af3efbb6f059275f51bd8f9e',
        'rows':_rows(0x47e1b0, ((0,'8b4110'),(3,'8b542408'),(7,'56'),(8,'8b742408'),(12,'c6411801'),
            (16,'893490'),(19,'83410cff'),(23,'5e'),(24,'c20800')))},
    'normalize': {'entry':0x47fcb0, 'cleanup':0,
        'sha256':'336af65e9ee27842c3d48338b7654e4339fdc67440d14cf0d8f632cf9deb2a06',
        'listing':'artifacts/research/vmde/segmentation-results/run-label-normalize-20261020/analysis/0047fcb0.json',
        'listing_sha256':'a405360923d98e3b2273a5273c6e5bcc4cc3e64725b6159df9c0fb2c761fe431',
        'rows':_rows(0x47fcb0, ((0,'80791800'),(4,'7461'),(6,'53'),(7,'56'),(8,'57'),(9,'33ff'),(11,'eb03'),
            (16,'8b4108'),(19,'0faf4104'),(23,'3bf8'),(25,'7d2b'),(27,'8b01'),(29,'8b14b8'),(32,'8b7110'),
            (35,'8b0496'),(38,'85c0'),(40,'7c17'),(42,'8bda'),(44,'8d642400'),(48,'8bd0'),(50,'8b0496'),
            (53,'85c0'),(55,'7df7'),(57,'89149e'),(60,'8b01'),(62,'8914b8'),(65,'83c701'),(68,'ebca'),
            (70,'c6411800'),(74,'8b5114'),(77,'33c0'),(79,'85d2'),(81,'7e11'),(83,'8b7110'),
            (86,'c70486ffffffff'),(93,'83c001'),(96,'3bc2'),(98,'7cef'),(100,'5f'),(101,'5e'),(102,'5b'),(103,'c3')))}
}


def compile_bootstrap(data):
    if sha(data) != BOOTSTRAP_SHA256: raise ValueError('Frozen bootstrap identity mismatch')
    module = types.ModuleType('_label_state_trusted_bootstrap')
    module.__file__ = str(BOOTSTRAP_PATH)
    exec(compile(data.decode('utf-8',errors='strict'),str(BOOTSTRAP_PATH),'exec'),module.__dict__)
    return module


def bootstrap():
    # Minimal trust bootstrap: only read a fixed local file, verify its exact
    # bytes before compile, then use its already-reviewed general IO helpers.
    for path in (BOOTSTRAP_PATH,*BOOTSTRAP_PATH.parents):
        info = path.lstat()
        if stat.S_ISLNK(info.st_mode) or getattr(info,'st_file_attributes',0) & 0x400:
            raise ValueError('Bootstrap alias rejected')
    before = BOOTSTRAP_PATH.stat()
    common = lambda s:(s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_nlink)
    state = lambda s:(*common(s),s.st_ctime_ns)
    if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or not 1 <= before.st_size <= 65536:
        raise ValueError('Bootstrap ordinary file bounds rejected')
    with BOOTSTRAP_PATH.open('rb') as stream:
        opened = os.fstat(stream.fileno()); data = stream.read(65537); closed = os.fstat(stream.fileno())
    after = BOOTSTRAP_PATH.stat()
    if common(before)!=common(opened) or state(before)!=state(after) or state(opened)!=state(closed) or len(data)!=before.st_size:
        raise ValueError('Bootstrap changed during retained read')
    module = compile_bootstrap(data)
    module.check_chain(BOOTSTRAP_PATH)
    if module.stable_read(BOOTSTRAP_PATH,65536)!=data: raise ValueError('Bootstrap changed after verification')
    return module, module.identity(BOOTSTRAP_PATH,data)


def verify_image(data):
    if len(data)!=14454272 or sha(data)!=IMAGE_SHA256: raise ValueError('Fixed image identity mismatch')
    pe=struct.unpack_from('<I',data,0x3c)[0]; opt=pe+24
    if data[:2]!=b'MZ' or data[pe:pe+4]!=b'PE\0\0' or struct.unpack_from('<H',data,pe+4)[0]!=0x14c or struct.unpack_from('<H',data,opt)[0]!=0x10b:
        raise ValueError('Pinned PE32 headers mismatch')
    base=struct.unpack_from('<I',data,opt+28)[0]
    if base!=0x400000: raise ValueError('Pinned image base mismatch')
    count=struct.unpack_from('<H',data,pe+6)[0]; optional_size=struct.unpack_from('<H',data,pe+20)[0]
    sections=[]
    for i in range(count):
        position=opt+optional_size+40*i
        _,rva,size,raw=struct.unpack_from('<IIII',data,position+8)
        if raw+size>len(data): raise ValueError('Invalid raw section extent')
        sections.append((rva,size,raw))
    verified=[]
    for method,body in BODIES.items():
        if sha(b''.join(raw for _,raw in body['rows']))!=body['sha256']: raise ValueError('Body constant hash mismatch')
        for va,expected in body['rows']:
            rva=va-base
            matches=[row for row in sections if row[0]<=rva and rva+len(expected)<=row[0]+row[1]]
            if len(matches)!=1: raise ValueError('Instruction has no unique full raw PE mapping')
            start,_,offset=matches[0]; raw_offset=offset+rva-start
            if data[raw_offset:raw_offset+len(expected)]!=expected: raise ValueError('Pinned instruction bytes differ')
            verified.append({'method':method,'va':hex(va),'rva':hex(rva),'raw_file_offset':hex(raw_offset),
                             'bytes':expected.hex(),'matches':True})
    return verified


def code_pages():
    pages={}
    for body in BODIES.values():
        for address,data in body['rows']:
            base=address & -PAGE
            page=pages.setdefault(base,bytearray(b'\xcc'*PAGE))
            page[address-base:address-base+len(data)]=data
    return {address:bytes(data) for address,data in pages.items()}


def check_instruction(method,pc,size,steps):
    allowed={address:len(data) for address,data in BODIES[method]['rows']}
    if allowed.get(pc)!=size or not 0 <= steps < STEP_LIMIT: raise ValueError('Unknown PC/size/method or instruction budget exceeded')


SAVED_PUSHES={
 'lookup':{0x47e8e2:('EBP',4),0x47e8ea:('EDI',8),0x47e8f4:('EBX',12),0x47e8f5:('ESI',16)},
 'merge_roots':{0x47e1b7:('ESI',4)},
 'normalize':{0x47fcb6:('EBX',4),0x47fcb7:('ESI',8),0x47fcb8:('EDI',12)}}


def check_write(method,pc,address,size,layout,state,args,count):
    if not 0<=count<WRITE_LIMIT: raise ValueError('Write budget exceeded')
    if pc in SAVED_PUSHES[method]:
        if size==4 and address==layout['stack']-SAVED_PUSHES[method][pc][1]: return
        raise ValueError('Write outside exact saved-register push slot')
    if method=='lookup':
        initial=state['labels'][args[0]]
        allowed={0x47e909:(layout['parents']+initial*4,4),0x47e90f:(layout['labels']+args[0]*4,4)}
        if allowed.get(pc)==(address,size): return
    elif method=='merge_roots':
        allowed={0x47e1bc:(layout['context']+24,1),0x47e1c0:(layout['parents']+args[1]*4,4),0x47e1c3:(layout['context']+12,4)}
        if allowed.get(pc)==(address,size): return
    else:
        if pc==0x47fcf6 and (address,size)==(layout['context']+24,1): return
        if pc in (0x47fce9,0x47fd06): base,length=layout['parents'],len(state['parents'])*4
        elif pc==0x47fcee: base,length=layout['labels'],len(state['labels'])*4
        else: raise ValueError('Unlisted normalize write instruction')
        if size==4 and base<=address and address+4<=base+length and (address-base)%4==0: return
    raise ValueError('Write outside exact observed state field')


def state_dict(state):
    return {'width':state.width,'height':state.height,'labels':list(state.labels),'parents':list(state.parents),
            'components':state.components,'dirty':state.dirty}


def state_object(model,value):
    return model.LabelState(value['width'],value['height'],tuple(value['labels']),tuple(value['parents']),value['components'],value['dirty'])


def build_scenarios(model_sha):
    if model_sha!=MODEL_SHA256: raise ValueError('Freeze exact model before constructing scenarios')
    specs=[
      ('negative-root',1,1,[0],[-2147483648],-7,255,[('lookup',[0]),('normalize',[])]),
      ('partial-compression',2,2,[0,0,1,3],[1,2,3,-7],123,0,[('lookup',[0]),('lookup',[1]),('normalize',[])]),
      ('dirty-chain',2,2,[0,1,4,0],[1,2,3,-7,-9],-101,255,[('lookup',[0]),('normalize',[])]),
      ('merge-compose',2,1,[0,2],[-1,-7,1],3,0,[('merge_roots',[0,1]),('lookup',[1]),('normalize',[])]),
      ('count-wrap',1,1,[1],[-1,-2],-2147483648,0,[('merge_roots',[0,1]),('normalize',[])]),
      ('unused-parent-reset',1,1,[0],[-8,2,-3,-99],0,1,[('normalize',[]),('normalize',[])]),
      ('root-no-writes',3,1,[0,1,2],[-7,-11,-19],17,0,[('lookup',[1]),('normalize',[])]),
      ('maximum-chain',16,16,[0]*256,list(range(1,256))+[-2147483648],1,1,[('lookup',[255]),('normalize',[])]),
      ('highest-keep-index',16,16,[0,255]*128,[-1]*256,2147483647,0,[('merge_roots',[255,0]),('lookup',[0]),('normalize',[])]),
      ('reverse-links',2,2,[4,3,2,0],[-5,0,1,2,-7],2,19,[('lookup',[1]),('merge_roots',[4,0]),('normalize',[])]),
      ('dirty-byte-one',1,2,[1,0],[-3,0],-2,1,[('normalize',[])]),
      ('unused-maximum',1,1,[0],[-9]*256,0,255,[('normalize',[])])]
    result=[{'id':name,'state':{'width':w,'height':h,'labels':labels,'parents':parents,'components':count,'dirty':dirty},
             'operations':[{'method':method,'arguments':args} for method,args in operations]}
            for name,w,h,labels,parents,count,dirty,operations in specs]
    assert len(result)<=64 and sum(len(row['operations']) for row in result)<=96
    return result


def compare_observation(actual,expected,method,eax,representative):
    state_matches=actual==expected
    return_matches=method!='lookup' or type(eax) is int and eax==representative
    return {'matched':state_matches and return_matches,'state_matches':state_matches,'lookup_return_matches':return_matches,
            'return_scope':'semantic EAX representative' if method=='lookup' else 'EAX incidental; no semantic return claim'}


def check_input(actual,declared):
    if actual!=declared: raise ValueError('CPU input differs from the frozen scenario/model trajectory')


def expected_call(model,current,operation):
    state=state_object(model,current); args=operation['arguments']; method=operation['method']
    if method=='lookup':
        result=model.lookup(state,*args); return state_dict(result.state),result.representative
    return state_dict(getattr(model,method)(state,*args)),None


def load_model(data):
    if sha(data)!=MODEL_SHA256: raise ValueError('Frozen model identity mismatch')
    module=types.ModuleType('_label_state_frozen_candidate'); module.__file__=str(HERE/'model.py')
    sys.modules[module.__name__]=module
    exec(compile(data.decode('utf-8',errors='strict'),module.__file__,'exec'),module.__dict__)
    return module


def _array_bytes(values): return struct.pack('<'+'i'*len(values),*values)


def make_machine(uc,x86,initial):
    cpu=uc.Uc(uc.UC_ARCH_X86,uc.UC_MODE_32)
    pages=code_pages()
    for base,data in {**pages,SENTINEL:b'\xcc'*PAGE}.items():
        cpu.mem_map(base,PAGE,uc.UC_PROT_ALL); cpu.mem_write(base,data)
        cpu.mem_protect(base,PAGE,uc.UC_PROT_READ|uc.UC_PROT_EXEC)
    layout={'context':0x20001100,'labels':0x30002000-len(initial['labels'])*4,
            'parents':0x40002000-len(initial['parents'])*4,'stack':0x50001f00}
    for base in (0x20001000,0x30001000,0x40001000,0x50001000):
        cpu.mem_map(base,PAGE,uc.UC_PROT_READ|uc.UC_PROT_WRITE); cpu.mem_write(base,b'\xa7'*PAGE)
    context=bytearray(b'\x79'*64)
    struct.pack_into('<IIIiII',context,0,layout['labels'],initial['width'],initial['height'],initial['components'],layout['parents'],len(initial['parents']))
    context[24]=initial['dirty']
    cpu.mem_write(layout['context'],bytes(context))
    cpu.mem_write(layout['labels'],_array_bytes(initial['labels'])); cpu.mem_write(layout['parents'],_array_bytes(initial['parents']))
    regs={name:getattr(x86,'UC_X86_REG_'+name) for name in ('EAX','EBX','ECX','EDX','ESI','EDI','EBP','ESP','EIP','EFLAGS')}
    return cpu,layout,regs,pages


def capture(cpu,layout,shape):
    context=bytes(cpu.mem_read(layout['context'],64))
    labels=bytes(cpu.mem_read(layout['labels'],len(shape['labels'])*4))
    parents=bytes(cpu.mem_read(layout['parents'],len(shape['parents'])*4))
    label_pointer,width,height,count,parent_pointer,parent_count=struct.unpack_from('<IIIiII',context)
    state={'width':width,'height':height,'labels':list(struct.unpack('<'+'i'*len(shape['labels']),labels)),
           'parents':list(struct.unpack('<'+'i'*len(shape['parents']),parents)),'components':count,'dirty':context[24]}
    return {'state':state,'context_hex':context.hex(),'labels_hex':labels.hex(),'parents_hex':parents.hex(),
            'pointers':{'labels':label_pointer,'parents':parent_pointer,'parent_count':parent_count}}


def run_call(uc,cpu,layout,regs,pages,model,operation,shape):
    method=operation['method']; args=operation['arguments']; started=time.monotonic(); hooks=[]
    row={'method':method,'arguments':args,'status':'failed','error':None,'emulation_started':False,'emulation_returned':False,
         'actual_before':None,'actual_after':None,'registers_before':None,'registers_after':None,'comparison':None}
    trace_hash=hashlib.sha256(); counts={}; writes=[]; faults=[]; hook_errors=[]; steps=0
    try:
        row['actual_before']=capture(cpu,layout,shape)
        before=row['actual_before']['state']
        check_input(before,shape)
        pointers={'labels':layout['labels'],'parents':layout['parents'],'parent_count':len(shape['parents'])}
        if row['actual_before']['pointers']!=pointers: raise ValueError('CPU input pointers/count differ from guarded layout')
        expected,representative=expected_call(model,shape,operation)
        row['expected_state']=expected; row['expected_representative']=representative
        requested={'EAX':0x11223344,'EBX':0x22334455,'ECX':layout['context'],'EDX':0x33445566,
                   'ESI':0x44556677,'EDI':0x55667788,'EBP':0x66778899,'ESP':layout['stack'],
                   'EIP':BODIES[method]['entry'],'EFLAGS':0x202}
        # Each call has a fresh synthetic stack/register invocation, but
        # context/labels/parents remain the CPU's actual preceding state.
        stack_data=bytearray(b'\xb7'*PAGE)
        struct.pack_into('<I',stack_data,layout['stack']-0x50001000,SENTINEL)
        for index,value in enumerate(args): struct.pack_into('<I',stack_data,layout['stack']-0x50001000+4+index*4,value)
        cpu.mem_write(0x50001000,bytes(stack_data))
        for name,value in requested.items(): cpu.reg_write(regs[name],value)
        row['registers_before']={name:int(cpu.reg_read(key)) for name,key in regs.items()}
        if row['registers_before']!=requested: raise ValueError('Synthetic GP register initialization did not roundtrip')
        before_pages={base:bytes(cpu.mem_read(base,PAGE)) for base in (0x20001000,0x30001000,0x40001000,0x50001000)}
        expected_pages={base:bytearray(data) for base,data in before_pages.items()}
        context_expected=expected_pages[0x20001000]
        struct.pack_into('<i',context_expected,layout['context']-0x20001000+12,expected['components'])
        context_expected[layout['context']-0x20001000+24]=expected['dirty']
        for key,base in (('labels',0x30001000),('parents',0x40001000)):
            raw=_array_bytes(expected[key]); offset=layout[key]-base; expected_pages[base][offset:offset+len(raw)]=raw
        row['mapped_regions_before']=[list(region) for region in cpu.mem_regions()]
        def stop(engine,error):
            if not hook_errors: hook_errors.append(str(error)[:2048])
            engine.emu_stop()
        def code_hook(engine,pc,size,_):
            nonlocal steps
            try:
                check_instruction(method,pc,size,steps); steps+=1
                counts[hex(pc)]=counts.get(hex(pc),0)+1; trace_hash.update(struct.pack('<II',pc,size))
            except Exception as error: stop(engine,error)
        def write_hook(engine,access,address,size,value,_):
            try:
                pc=int(engine.reg_read(regs['EIP']))
                check_write(method,pc,address,size,layout,before,args,len(writes))
                if pc in SAVED_PUSHES[method]:
                    name,offset=SAVED_PUSHES[method][pc]
                    if value & 0xffffffff != requested[name]: raise ValueError('Saved register PUSH value mismatch')
                    struct.pack_into('<I',expected_pages[0x50001000],layout['stack']-0x50001000-offset,requested[name])
                writes.append({'pc':hex(pc),'address':hex(address),'size_bytes':size,'value_bits':hex(value & ((1<<(size*8))-1))})
            except Exception as error: stop(engine,error)
        def invalid_hook(engine,access,address,size,value,_):
            faults.append({'access':access,'address':hex(address),'size_bytes':size}); return False
        hooks.append(cpu.hook_add(uc.UC_HOOK_CODE,code_hook))
        hooks.append(cpu.hook_add(uc.UC_HOOK_MEM_WRITE,write_hook))
        hooks.append(cpu.hook_add(uc.UC_HOOK_MEM_INVALID,invalid_hook))
        cpu_error=None
        try:
            row['emulation_started']=True
            cpu.emu_start(BODIES[method]['entry'],SENTINEL,timeout=TIMEOUT_US,count=STEP_LIMIT)
            row['emulation_returned']=True
        except Exception as error: cpu_error=str(error)[:2048]
        row['actual_after']=capture(cpu,layout,shape)
        row['registers_after']={name:int(cpu.reg_read(key)) for name,key in regs.items()}
        row['mapped_regions_after']=[list(region) for region in cpu.mem_regions()]
        observed=row['actual_after']; after=row['registers_after']
        row['comparison']=compare_observation(observed['state'],expected,method,after['EAX'],representative)
        row['page_checks']=[{'base':hex(base),'size_bytes':PAGE,'before_sha256':sha(before_pages[base]),
             'actual_after_sha256':sha(bytes(cpu.mem_read(base,PAGE))),'expected_after_sha256':sha(bytes(data)),
             'matched':bytes(cpu.mem_read(base,PAGE))==bytes(data)} for base,data in expected_pages.items()]
        row['checks']={'sentinel_reached':after['EIP']==SENTINEL,
            'stack_cleanup':after['ESP']==layout['stack']+4+BODIES[method]['cleanup'],
            'callee_saved':all(after[name]==requested[name] for name in ('EBX','ESI','EDI','EBP')),
            'all_pages_match':all(page['matched'] for page in row['page_checks']),
            'mapping_permissions_unchanged':row['mapped_regions_before']==row['mapped_regions_after'],
            'code_pages_unchanged':all(bytes(cpu.mem_read(base,PAGE))==data for base,data in pages.items()),
            'pointer_and_count_fields_unchanged':observed['pointers']==row['actual_before']['pointers'],
            'no_cpu_or_boundary_error':cpu_error is None and not faults and not hook_errors,
            'state_and_semantic_return_match':row['comparison']['matched']}
        mutant=dict(expected,dirty=expected['dirty'] ^ 1)
        row['negative_controls']={'wrong_state_rejected':not compare_observation(observed['state'],mutant,method,after['EAX'],representative)['matched']}
        if method=='lookup': row['negative_controls']['wrong_return_rejected']=not compare_observation(observed['state'],expected,method,after['EAX'],representative ^ 1)['matched']
        row['cpu_error']=cpu_error
        if not all(row['checks'].values()) or not all(row['negative_controls'].values()): raise ValueError('CPU state/return/preservation or negative-control mismatch')
        row['status']='completed'
    except (Exception,KeyboardInterrupt) as error:
        row['error']={'code':'LABEL_CALL_FAILED','message':str(error)[:2048]}
        if row['emulation_started'] and row['actual_after'] is None:
            try: row['actual_after']=capture(cpu,layout,shape)
            except Exception as capture_error: row['observation_error']=str(capture_error)[:1024]
        if row['emulation_started'] and row['registers_after'] is None:
            try: row['registers_after']={name:int(cpu.reg_read(key)) for name,key in regs.items()}
            except Exception as register_error: row['register_observation_error']=str(register_error)[:1024]
    finally:
        row.update({'steps':steps,'pc_counts':counts,'pc_trace_sha256':trace_hash.hexdigest(),'writes':writes,
                    'invalid_accesses':faults,'hook_errors':hook_errors,'duration_ms':round((time.monotonic()-started)*1000,3)})
        for hook in hooks:
            try: cpu.hook_del(hook)
            except Exception as error:
                row['status']='failed'; row.setdefault('cleanup_errors',[]).append(str(error)[:512])
                if row['error'] is None: row['error']={'code':'HOOK_CLEANUP_FAILED','message':str(error)[:2048]}
    return row


def main(argv=None):
    result={'schema_version':1,'kind':'label_state_bounded_cpu_replay','status':'failed','error':None,
        'observation_kind':'bounded_cpu_emulation','target_execution':'not_run','native_call':False,
        'scope':'Synthetic acyclic label forests only; no natural image labels, flood fill484100 or complete segmentation.',
        'budgets':{'scenarios':64,'method_calls':96,'steps_per_call':STEP_LIMIT,'writes_per_call':WRITE_LIMIT,'timeout_microseconds_per_call':TIMEOUT_US},
        'started_utc':datetime.now(timezone.utc).isoformat(),'rows':[],'inputs':[]}
    helper=None; out=None; registered=result['inputs']
    try:
        helper,bootstrap_id=bootstrap(); registered.append(bootstrap_id)
        parser=helper.Parser(description=__doc__,allow_abbrev=False)
        for arg in ('module-path','image','out'): parser.add_argument('--'+arg,required=True,action=helper.Once)
        args=parser.parse_args(argv)
        module_path,image,destination=(helper.checked_path(v) for v in (args.module_path,args.image,args.out))
        helper.check_chain(destination.parent)
        if os.path.lexists(destination): raise ValueError('Output directory already exists')
        image_data=helper.stable_read(image,16*1024*1024); mapped=verify_image(image_data)
        model_data=helper.stable_read(HERE/'model.py',65536); model=load_model(model_data)
        own_path=Path(__file__).absolute(); own_data=helper.stable_read(own_path,131072)
        pins_path=helper.HERE/'unicorn-pins.json'; pins_data=helper.stable_read(pins_path,65536)
        if sha(pins_data)!=helper.PINS_SHA256: raise ValueError('Frozen runtime pins changed')
        snapshots={'model.py':model_data,'replay.py':own_data,'bootstrap.py':helper.stable_read(BOOTSTRAP_PATH,65536),'unicorn-pins.json':pins_data}
        for path,data in ((image,image_data),(HERE/'model.py',model_data),(own_path,own_data),(pins_path,pins_data)):
            registered.append(helper.identity(path,data))
        for method,body in BODIES.items():
            path=PROJECT/body['listing']; data=helper.stable_read(path,1048576)
            if sha(data)!=body['listing_sha256']: raise ValueError('Frozen listing identity differs: '+method)
            listing=json.loads(data.decode('utf-8',errors='strict'))
            rows=sorted((int(row['va'],16),bytes.fromhex(row['bytes'])) for row in listing['listing'])
            if tuple(rows)!=body['rows'] or listing.get('calls'): raise ValueError('Pinned listing instructions/call closure differ')
            registered.append(helper.identity(path,data)); snapshots[method+'-listing.json']=data
        result['bodies']=[{'method':method,'entry':hex(body['entry']),'size_bytes':sum(len(data) for _,data in body['rows']),
                           'instructions':len(body['rows']),'sha256':body['sha256'],'hash_scope':'listed bytes in ascending original VA, gaps excluded'} for method,body in BODIES.items()]
        result['image_mapping']=mapped
        scenarios=build_scenarios(sha(model_data))
        result['scenarios']=scenarios
        for scenario in scenarios:
            state=state_dict(state_object(model,scenario['state']))
            for index,operation in enumerate(scenario['operations']):
                state,_=expected_call(model,state,operation)
                result['rows'].append({'scenario_id':scenario['id'],'call_index':index,'method':operation['method'],'arguments':operation['arguments'],'status':'unattempted'})
        result['declared_scenarios']=len(scenarios); result['declared_calls']=len(result['rows'])
        destination.mkdir(); out=destination
        for name,data in snapshots.items(): helper.save_new(out/name,data)
        helper.checkpoint(out,result)
        runtime=out/'runtime'; dependency=helper.stage_unicorn(module_path,runtime)
        registered.extend(dependency['source_files']); registered.extend(dependency['staged_files'])
        result['unicorn']={'source_module_path':str(module_path),'loaded_module_path':str(runtime),**dependency}
        helper.checkpoint(out,result)
        uc,x86,origins=helper.load_unicorn(runtime,out/'unused-pycache')
        result['unicorn'].update({'version':uc.__version__,'api_version':list(uc.uc_version()),'loaded_origins':origins})
        cursor=0
        for scenario in scenarios:
            cpu,layout,regs,pages=make_machine(uc,x86,scenario['state'])
            expected_input=scenario['state']
            for index,operation in enumerate(scenario['operations']):
                pending={'scenario_id':scenario['id'],'call_index':index,'method':operation['method'],'arguments':operation['arguments'],
                         'status':'failed','error':{'code':'INTERRUPTED','message':'CPU call has not finished'}}
                result['rows'][cursor]=pending; helper.checkpoint(out,result)
                row=run_call(uc,cpu,layout,regs,pages,model,operation,expected_input)
                row.update({'scenario_id':scenario['id'],'call_index':index,'layout':layout})
                result['rows'][cursor]=row; cursor+=1; helper.checkpoint(out,result)
                if row['status']!='completed':
                    result['error']=row['error'] or {'code':'LABEL_CALL_FAILED','message':'CPU method call did not complete'}
                    raise ValueError('Stopped after failed CPU method call')
                expected_input=row['expected_state']
        result['status']='completed'
    except (Exception,KeyboardInterrupt) as error:
        result['status']='failed'
        if result['error'] is None: result['error']={'code':'LABEL_REPLAY_FAILED','message':str(error)[:2048]}
    finally:
        result['inputs_unchanged']=True
        if helper is not None:
            for row in registered:
                try:
                    data=helper.stable_read(Path(row['path']),max(row['size_bytes'],1))
                    if len(data)!=row['size_bytes'] or sha(data)!=row['sha256']: raise ValueError('Input content changed')
                except Exception as error:
                    result['inputs_unchanged']=False; result['status']='failed'
                    if result['error'] is None: result['error']={'code':'INPUT_CHANGED','message':str(error)[:2048]}
        result['counts']={state:sum(row['status']==state for row in result['rows']) for state in ('completed','failed','unattempted')}
        result['ended_utc']=datetime.now(timezone.utc).isoformat()
        if out is not None:
            try:
                helper.checkpoint(out,result); helper.save_new(out/'result.json',helper.encoded(result))
            except Exception as error:
                result['status']='failed'; result['persistence_error']=str(error)[:2048]
                if result['error'] is None: result['error']={'code':'PERSISTENCE_FAILED','message':str(error)[:2048]}
    output=(json.dumps(result,ensure_ascii=False,allow_nan=False,separators=(',',':'))+'\n').encode('utf-8',errors='strict')
    sys.stdout.buffer.write(output); sys.stdout.buffer.flush()
    return 0 if result['status']=='completed' else 1


if __name__=='__main__':
    sys.stdout.reconfigure(encoding='utf-8',errors='strict'); sys.stderr.reconfigure(encoding='utf-8',errors='strict')
    raise SystemExit(main())

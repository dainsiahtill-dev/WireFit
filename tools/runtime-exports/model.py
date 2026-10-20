"""Bounded PE32 exports from live flat-RVA callback data; no OS calls or raw-file mapping."""
import hashlib
import struct

PAGE = 4096
MAX_IMAGE = 64 * 1024 * 1024
MAX_PAGES = 256
MAX_READ_BYTES = 1024 * 1024
MAX_EXPORTS = 65536
MAX_MATCHES_PER_NAME = 16
READ_KEYS = {'data','transferred_bytes','success','winerror'}
QUERY_KEYS = {'base_address','allocation_base','allocation_protect','region_size','state','protect','type','returned_size'}


class ExportError(Exception):
    def __init__(self, code, message):
        super().__init__(message)
        self.code = code


def need(value, code, message):
    if not value:
        raise ExportError(code, message)


def diagnostic(exc, fallback='EXPORT_OBSERVATION_FAILED'):
    code = getattr(exc, 'code', fallback)
    return {'code':code[:128] if type(code) is str else fallback,
            'message':str(exc).replace('\0','?')[:1024]}


def digest(data):
    return hashlib.sha256(data).hexdigest()


class MemoryView:
    """Per-sample exact-page cache and bounded actual read/query transcript."""
    def __init__(self, read, query, base, size, query_size, result):
        self.read, self.query, self.base, self.size = read, query, base, size
        self.query_size, self.result, self.pages = query_size, result, {}

    def note(self, exc):
        row = diagnostic(exc)
        self.result['status'] = 'partial'
        if len(self.result['errors']) < 64:
            self.result['errors'].append(row)
        else:
            self.result['budget']['omitted_errors'] += 1
        return row

    def range(self, rva, size):
        need(type(rva) is int and type(size) is int and 0 <= rva < self.size and 0 < size <= self.size-rva,
             'EXPORT_RVA_INVALID','Requested RVA range leaves the live module')

    def actual_read(self, rva, size, kind):
        self.range(rva,size)
        need(size <= PAGE,'EXPORT_READ_LIMIT','Each callback read must be at most one page')
        budget = self.result['budget']
        need(budget['requested_read_bytes'] + size <= MAX_READ_BYTES,
             'EXPORT_READ_BUDGET','Per-sample read-byte budget exhausted')
        budget['requested_read_bytes'] += size
        record = {'kind':kind,'rva':hex(rva),'requested_size_bytes':size,'observed_bytes':0,
                  'hex':'','sha256':None,'success':None,'winerror':None,'transferred_bytes':None,
                  'schema_valid':False,'error':None}
        self.result['reads'].append(record)
        data = b''
        try:
            value = self.read(rva,size)
            need(type(value) is dict,'EXPORT_READ_SCHEMA','Read callback must return the fixed result object')
            supplied = value.get('data')
            if type(supplied) is bytes:
                data = supplied[:size]
                record.update({'observed_bytes':len(data),'hex':data.hex(),'sha256':digest(data) if data else None})
                if len(supplied)>size:
                    record['provided_bytes_exceed_request'] = True
            for key in ('success','winerror','transferred_bytes'):
                item = value.get(key)
                if type(item) is (bool if key=='success' else int):
                    record[key] = item
            need(set(value)==READ_KEYS and type(supplied) is bytes and type(value['transferred_bytes']) is int
                 and 0 <= value['transferred_bytes'] <= size and len(supplied)==value['transferred_bytes']
                 and type(value['success']) is bool and type(value['winerror']) is int and 0 <= value['winerror'] <= 0xffffffff,
                 'EXPORT_READ_SCHEMA','Read bytes/count/success/Winerror schema is inconsistent')
            record['schema_valid'] = True
            need(value['success'] and len(data)==size,'EXPORT_READ_INCOMPLETE','Requested memory bytes were not fully observed successfully')
        except Exception as exc:
            record['error'] = self.note(exc)
        budget['observed_read_bytes'] += len(data)
        return data,record

    def exact(self, rva, size):
        self.range(rva,size)
        output = bytearray()
        end = rva+size
        while rva<end:
            page = rva & -PAGE
            if page not in self.pages:
                need(len(self.pages)<MAX_PAGES,'EXPORT_PAGE_BUDGET','Exact-page cache budget exhausted')
                length = min(PAGE,self.size-page)
                data,record = self.actual_read(page,length,'metadata_page')
                self.pages[page] = (data,record)
                self.result['budget']['pages'] = len(self.pages)
            data,record = self.pages[page]
            need(record['error'] is None and len(data)==min(PAGE,self.size-page),
                 'EXPORT_METADATA_UNREADABLE','A required exact metadata page is unreadable or partial')
            count = min(end-rva,PAGE-(rva-page))
            output.extend(data[rva-page:rva-page+count])
            rva += count
        return bytes(output)

    def query_region(self, address):
        record = {'address':hex(address),'result':None,'error':None}
        self.result['queries'].append(record)
        try:
            value = self.query(address)
            need(type(value) is dict and set(value)==QUERY_KEYS and all(type(value[k]) is int for k in QUERY_KEYS),
                 'EXPORT_QUERY_SCHEMA','Query callback must return the fixed integer VQE metadata')
            # Preserve bounded raw integers even when their relationship is invalid.
            if all(-(1<<64) <= value[k] <= 1<<64 for k in QUERY_KEYS):
                record['result'] = dict(value)
            base,size = value['base_address'],value['region_size']
            need(value['returned_size']==self.query_size and 0 <= base <= address < base+size <= 1<<32 and size>0,
                 'EXPORT_QUERY_SCHEMA','VQE size/range does not cover the requested address')
            need(value['state'] in (0x1000,0x2000,0x10000) and all(0<=value[k]<=0xffffffff for k in ('allocation_protect','state','protect','type')),
                 'EXPORT_QUERY_SCHEMA','VQE DWORD/state fields differ')
            allocation = value['allocation_base']
            need((value['state']==0x10000 and allocation==0) or (0<allocation<=base),
                 'EXPORT_QUERY_SCHEMA','VQE allocation base is inconsistent')
            return dict(value)
        except Exception as exc:
            record['error'] = self.note(exc)
            return None


def pe_layout(view):
    dos = view.exact(0,64)
    need(dos[:2]==b'MZ','EXPORT_PE_INVALID','Missing DOS signature')
    offset = struct.unpack_from('<I',dos,60)[0]
    need(64<=offset<=1024*1024-24,'EXPORT_PE_INVALID','PE header offset exceeds bounded header domain')
    coff = view.exact(offset,24)
    need(coff[:4]==b'PE\0\0','EXPORT_PE_INVALID','Missing PE signature')
    machine,count = struct.unpack_from('<HH',coff,4)
    optional_size = struct.unpack_from('<H',coff,20)[0]
    need(machine==0x14c and 1<=count<=96 and 104<=optional_size<=4096,
         'EXPORT_PE_UNSUPPORTED','This domain requires a bounded I386 PE32 header')
    extent = offset+24+optional_size+count*40
    need(extent<=min(view.size,1024*1024),'EXPORT_PE_INVALID','Header extent exceeds bounded module')
    optional = view.exact(offset+24,optional_size)
    need(struct.unpack_from('<H',optional)[0]==0x10b,'EXPORT_PE_UNSUPPORTED','PE32+ is outside this initial domain')
    image_size,headers_size = struct.unpack_from('<II',optional,56)
    directories = struct.unpack_from('<I',optional,92)[0]
    need(image_size==view.size and extent<=headers_size<=image_size and directories<=min(16,(optional_size-96)//8),
         'EXPORT_PE_INVALID','Live SizeOfImage/header/directory count is inconsistent')
    sections = []
    for index in range(count):
        row = view.exact(offset+24+optional_size+40*index,40)
        virtual,rva,raw_size = struct.unpack_from('<III',row,8)
        end = rva+max(virtual,raw_size)
        need(0<=rva<=end<=view.size,'EXPORT_SECTION_INVALID','Section virtual extent exceeds module')
        if end>rva:
            need(rva>=headers_size and all(end<=x['rva'] or rva>=x['end'] for x in sections),
                 'EXPORT_SECTION_INVALID','Section virtual extents overlap headers or each other')
        sections.append({'rva':rva,'end':end,'characteristics':struct.unpack_from('<I',row,36)[0]})
    export = struct.unpack_from('<II',optional,96) if directories else (0,0)
    return {'machine':machine,'optional_magic':0x10b,'size_of_image':image_size,'size_of_headers':headers_size,
            'sections':sections,'export_rva':export[0],'export_size':export[1]}


def target_match(view, header, index, eat, ordinal_base, directory, directory_size, prefix_size):
    match = {'ordinal':None,'eat_index':index,'eat_rva':None,'target_rva':None,'target_va':None,
             'export_kind':'invalid','forwarder':None,'section_characteristics':None,'region':None,
             'runtime_executable':None,'frida_export_type':None,'target_bytes':None,'errors':[]}
    try:
        need(ordinal_base+index<=0xffffffff,'EXPORT_ORDINAL_INVALID','Export ordinal overflows DWORD')
        match['ordinal'] = ordinal_base+index
        match['eat_rva'] = eat+index*4
        target = struct.unpack('<I',view.exact(eat+index*4,4))[0]
        match['target_rva'] = target
        if target==0:
            match['export_kind']='unassigned'
            return match
        need(target<view.size,'EXPORT_TARGET_INVALID','EAT target RVA is outside the module')
        match['target_va']=hex(view.base+target)
        if directory<=target<directory+directory_size:
            match['export_kind']='forwarder'
            length = min(257,directory+directory_size-target)
            raw = view.exact(target,length)
            end = raw.find(b'\0')
            need(0<end<=256 and all(32<=b<=126 for b in raw[:end]),'EXPORT_FORWARDER_INVALID','Forwarder is not bounded terminated ASCII in export directory')
            match['forwarder']=raw[:end].decode('ascii')
            return match
        match['export_kind']='direct'
        section = [x for x in header['sections'] if x['rva']<=target<x['end']]
        if len(section)==1:match['section_characteristics']=section[0]['characteristics']
        region = view.query_region(view.base+target)
        match['region']=region
        if region is None:
            match['target_bytes']={'requested_size_bytes':prefix_size,'observed_bytes':0,'hex':'','sha256':None,'complete':False,
                                   'error':{'code':'EXPORT_QUERY_UNKNOWN','message':'No verified runtime region metadata'}}
            return match
        protect = region['protect']
        committed = region['state']==0x1000
        guard = bool(protect & 0x100)
        readable = committed and not guard and protect & 255 in (2,4,8,0x20,0x40,0x80)
        match['runtime_executable']=committed and not guard and protect & 255 in (0x10,0x20,0x40,0x80)
        if prefix_size==0:return match
        amount = min(prefix_size,view.size-target,region['base_address']+region['region_size']-(view.base+target))
        record = {'requested_size_bytes':prefix_size,'observed_bytes':0,'hex':'','sha256':None,'complete':False,'error':None}
        match['target_bytes']=record
        need(readable,'EXPORT_TARGET_UNREADABLE','Target is not committed/readable or is PAGE_GUARD; no target RPM requested')
        data,reading = view.actual_read(target,amount,'target_prefix')
        record.update({'observed_bytes':len(data),'hex':data.hex(),'sha256':digest(data) if data else None,
                       'complete':len(data)==prefix_size and reading['error'] is None,'error':reading['error']})
        if amount<prefix_size:
            record['error']=view.note(ExportError('EXPORT_TARGET_SHORT_RANGE','Only the in-module/in-region target prefix was requested'))
    except Exception as exc:
        row = view.note(exc);match['errors'].append(row)
        if match['target_bytes'] is not None and match['target_bytes']['error'] is None:
            match['target_bytes']['error']=row
    return match


def inspect_exports(read_rva, query_va, module_base, module_size, requested_symbols, *, query_struct_size, target_prefix_bytes=16):
    """Observe selected raw export-name mappings. No function/data or OS resolver claim."""
    result = {'schema_version':1,'kind':'bounded_live_pe32_exports','status':'failed','atomic':False,
              'frida_export_type':None,'os_resolution_verified':False,
              'module':{'base':hex(module_base) if type(module_base) is int and 0<=module_base<1<<32 else None,
                        'size_bytes':module_size if type(module_size) is int and 0<=module_size<=MAX_IMAGE else None,'header':None},
              'requested_symbols':[],'exports':[],'reads':[],'queries':[],'errors':[],
              'budget':{'page_limit':MAX_PAGES,'read_byte_limit':MAX_READ_BYTES,'pages':0,
                        'requested_read_bytes':0,'observed_read_bytes':0,'names_examined':0,'omitted_errors':0}}
    try:
        need(callable(read_rva) and callable(query_va),'EXPORT_REQUEST_INVALID','Read/query callbacks are required')
        need(type(module_base) is int and type(module_size) is int and module_base>0 and module_base%PAGE==0
             and 0<module_size<=MAX_IMAGE and module_size%PAGE==0 and module_base+module_size<=1<<32,
             'EXPORT_REQUEST_INVALID','Expected a page-aligned bounded PE32 module interval')
        need(type(query_struct_size) is int and query_struct_size in (28,48),'EXPORT_REQUEST_INVALID','Explicit query ABI size must be28or48')
        need(type(target_prefix_bytes) is int and 0<=target_prefix_bytes<=16,'EXPORT_REQUEST_INVALID','Target prefix must be0..16bytes')
        need(type(requested_symbols) in (tuple,list) and 1<=len(requested_symbols)<=8,
             'EXPORT_REQUEST_INVALID','One to eight requested names are required')
        names = tuple(requested_symbols)
        need(all(type(x) is str and 1<=len(x)<=256 and all(32<=ord(c)<=126 for c in x) for x in names) and len(set(names))==len(names),
             'EXPORT_REQUEST_INVALID','Requested names must be unique bounded NUL-free printable ASCII')
    except Exception as exc:
        result['errors'].append(diagnostic(exc,'EXPORT_REQUEST_INVALID'))
        return result
    result['requested_symbols']=list(names)
    result['exports']=[{'name':x,'lookup_status':'indeterminate','match_count':0,'matches':[],'matches_truncated':False,'errors':[]} for x in names]
    result['status']='completed'
    view=MemoryView(read_rva,query_va,module_base,module_size,query_struct_size,result)
    try:
        header=pe_layout(view);result['module']['header']=header
        directory,size = header['export_rva'],header['export_size']
        if directory==size==0:
            for row in result['exports']:row['lookup_status']='not_found'
            return result
        need(directory>0 and size>=40,'EXPORT_DIRECTORY_INVALID','Export directory RVA/size is invalid')
        view.range(directory,size)
        row=view.exact(directory,40)
        ordinal_base,functions,count,eat,ent,eot=struct.unpack_from('<IIIIII',row,16)
        need(functions<=MAX_EXPORTS and count<=MAX_EXPORTS and (functions>0 or count==0),
             'EXPORT_TABLE_BUDGET','Export counts are unsupported or exceed bounded table domain')
        if functions:need(eat>0,'EXPORT_TABLE_INVALID','Missing EAT');view.range(eat,functions*4)
        if count:need(ent>0 and eot>0,'EXPORT_TABLE_INVALID','Missing name/ordinal table');view.range(ent,count*4);view.range(eot,count*2)
        matches={name:[] for name in names};counts={name:0 for name in names};complete=True
        prefix_length=max(len(x) for x in names)+1
        for index in range(count):
            result['budget']['names_examined']+=1
            try:
                pointer=struct.unpack('<I',view.exact(ent+index*4,4))[0]
                need(pointer>0,'EXPORT_NAME_INVALID','Zero export-name RVA')
                prefix=view.exact(pointer,prefix_length)
                need(prefix[0]!=0,'EXPORT_NAME_INVALID','Empty export name')
                for name in names:
                    if prefix.startswith(name.encode('ascii')+b'\0'):
                        counts[name]+=1
                        if len(matches[name])<MAX_MATCHES_PER_NAME:
                            ordinal=struct.unpack('<H',view.exact(eot+index*2,2))[0]
                            need(ordinal<functions,'EXPORT_ORDINAL_INVALID','Name ordinal index is outside EAT')
                            matches[name].append(ordinal)
            except Exception as exc:
                complete=False;view.note(exc)
                if getattr(exc,'code','') in ('EXPORT_PAGE_BUDGET','EXPORT_READ_BUDGET'):break
        for output in result['exports']:
            name=output['name'];output['match_count']=counts[name]
            output['matches_truncated']=counts[name]>len(matches[name])
            output['matches']=[target_match(view,header,index,eat,ordinal_base,directory,size,target_prefix_bytes) for index in matches[name]]
            invalid=any(x['export_kind']=='invalid' for x in output['matches']) or counts[name]!=len(matches[name]) and counts[name]<=MAX_MATCHES_PER_NAME
            if counts[name]>1:
                output['lookup_status']='ambiguous'
            elif not complete or invalid:
                output['lookup_status']='indeterminate'
            elif counts[name]==1:
                output['lookup_status']='resolved'
            else:output['lookup_status']='not_found'
    except Exception as exc:
        view.note(exc)
    return result

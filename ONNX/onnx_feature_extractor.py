import os
import math
import zlib
import numpy as np

FEATURE_SIZE = 512

BYTE_HIST_START = 0
BYTE_HIST_END = 256
FILE_SIZE_IDX = 256
FILE_ENTROPY_IDX = 257
STRING_COUNT_IDX = 258
STRING_AVG_LEN_IDX = 259
STRING_MAX_LEN_IDX = 260
PRINTABLE_RATIO_IDX = 261
PE_NUM_SECTIONS_IDX = 262
PE_CHARACTERISTICS_IDX = 263
PE_DLL_CHARACTERISTICS_IDX = 264
PE_SUBSYSTEM_IDX = 265
PE_MACHINE_IDX = 266
PE_SIZE_OF_CODE_IDX = 267
PE_SIZE_OF_IMAGE_IDX = 268
PE_SIZE_OF_HEADERS_IDX = 269
PE_CHECKSUM_IDX = 270
PE_ADDRESS_OF_ENTRY_POINT_IDX = 271
PE_BASE_OF_CODE_IDX = 272
PE_HAS_DEBUG_IDX = 273
PE_HAS_EXCEPTION_IDX = 274
PE_HAS_EXPORT_IDX = 275
PE_HAS_IMPORT_IDX = 276
PE_HAS_RESOURCE_IDX = 277
PE_HAS_TLS_IDX = 278
PE_HAS_CFG_IDX = 279
PE_HAS_RELOC_IDX = 280
PE_IMPORT_COUNT_IDX = 281
PE_DLL_COUNT_IDX = 282
PE_EXPORT_COUNT_IDX = 283
PE_TEXT_ENTROPY_IDX = 284
PE_TEXT_SIZE_IDX = 285
PE_RDATA_ENTROPY_IDX = 286
PE_RSRC_ENTROPY_IDX = 287
PE_EXEC_SECTIONS_IDX = 288
PE_EP_IN_EXEC_IDX = 289
PE_COMPANY_NAME_LEN_IDX = 290
PE_FILE_DESC_LEN_IDX = 291
PE_FILE_VER_LEN_IDX = 292
PE_PRODUCT_NAME_LEN_IDX = 293
PE_TIMESTAMP_IDX = 294
PE_IS_DLL_IDX = 295
PE_IS_CONSOLE_IDX = 296
PE_SECTION_HASH_START = 297
PE_SECTION_HASH_END = 313
PE_DLL_HASH_START = 313
PE_DLL_HASH_END = 377
PE_API_HASH_START = 377
PE_API_HASH_END = 512


def extract_features(filepath=None, file_data=None, max_read=65536):
    feats = np.zeros(FEATURE_SIZE, dtype=np.float32)
    
    try:
        if file_data is not None:
            raw = file_data[:max_read] if len(file_data) > max_read else file_data
        elif filepath:
            with open(filepath, 'rb') as f:
                raw = f.read(max_read)
        else:
            return None
    except:
        return None
    
    if len(raw) < 2:
        return None
    
    file_size = 0
    if filepath:
        try:
            file_size = os.path.getsize(filepath)
        except:
            file_size = len(raw)
    else:
        file_size = len(raw) if file_data is None else len(file_data)
    
    feats[FILE_SIZE_IDX] = min(file_size, 50 * 1024 * 1024) / (1024 * 1024)
    
    byte_hist = np.zeros(256, dtype=np.float32)
    for b in raw:
        byte_hist[b] += 1
    total = max(len(raw), 1)
    byte_hist /= total
    feats[BYTE_HIST_START:BYTE_HIST_END] = byte_hist
    
    file_entropy = 0.0
    for i in range(256):
        if byte_hist[i] > 0:
            file_entropy -= byte_hist[i] * math.log2(byte_hist[i])
    feats[FILE_ENTROPY_IDX] = file_entropy
    
    strings = []
    current = []
    printable_count = 0
    for b in raw:
        if 32 <= b < 127:
            current.append(b)
            printable_count += 1
        else:
            if len(current) >= 4:
                strings.append(len(current))
            current = []
    if len(current) >= 4:
        strings.append(len(current))
    
    feats[STRING_COUNT_IDX] = min(len(strings), 1000) / 100.0
    if strings:
        feats[STRING_AVG_LEN_IDX] = min(sum(strings) / len(strings), 100) / 10.0
        feats[STRING_MAX_LEN_IDX] = min(max(strings), 500) / 50.0
    feats[PRINTABLE_RATIO_IDX] = printable_count / total
    
    is_pe = raw[:2] == b'MZ'
    if not is_pe:
        return feats
    
    try:
        import pefile
        if filepath:
            pe = pefile.PE(filepath, fast_load=True)
        else:
            pe = pefile.PE(data=file_data if file_data else raw, fast_load=True)
        pe.parse_data_directories()
        
        fh = pe.FILE_HEADER
        oh = pe.OPTIONAL_HEADER
        
        feats[PE_NUM_SECTIONS_IDX] = min(fh.NumberOfSections, 50) / 10.0
        feats[PE_CHARACTERISTICS_IDX] = fh.Characteristics / 65535.0
        feats[PE_DLL_CHARACTERISTICS_IDX] = oh.DllCharacteristics / 65535.0
        feats[PE_SUBSYSTEM_IDX] = getattr(oh, 'Subsystem', 0) / 20.0
        feats[PE_MACHINE_IDX] = fh.Machine / 65535.0
        feats[PE_SIZE_OF_CODE_IDX] = min(getattr(oh, 'SizeOfCode', 0), 10*1024*1024) / (1024*1024)
        feats[PE_SIZE_OF_IMAGE_IDX] = min(getattr(oh, 'SizeOfImage', 0), 50*1024*1024) / (1024*1024)
        feats[PE_SIZE_OF_HEADERS_IDX] = min(getattr(oh, 'SizeOfHeaders', 0), 1024*1024) / (1024*1024)
        feats[PE_CHECKSUM_IDX] = min(getattr(oh, 'CheckSum', 0), 100*1024*1024) / (10*1024*1024)
        feats[PE_ADDRESS_OF_ENTRY_POINT_IDX] = getattr(oh, 'AddressOfEntryPoint', 0) / (10*1024*1024)
        feats[PE_BASE_OF_CODE_IDX] = getattr(oh, 'BaseOfCode', 0) / (10*1024*1024)
        feats[PE_TIMESTAMP_IDX] = min(fh.TimeDateStamp, 2000000000) / 2000000000.0
        
        is_dll = bool(fh.Characteristics & 0x2000)
        is_console = getattr(oh, 'Subsystem', 0) == 3
        feats[PE_IS_DLL_IDX] = 1.0 if is_dll else 0.0
        feats[PE_IS_CONSOLE_IDX] = 1.0 if is_console else 0.0
        
        has_debug = has_exception = has_export = has_import = has_resource = has_tls = has_reloc = False
        
        for i, entry in enumerate(oh.DATA_DIRECTORY):
            sz = getattr(entry, 'Size', 0)
            if sz > 0:
                if i == 0: has_export = True
                elif i == 1: has_import = True
                elif i == 2: has_resource = True
                elif i == 3: has_exception = True
                elif i == 5: has_reloc = True
                elif i == 6: has_debug = True
                elif i == 9: has_tls = True
        
        has_cfg = bool(oh.DllCharacteristics & 0x4000) if hasattr(oh, 'DllCharacteristics') else False
        
        feats[PE_HAS_DEBUG_IDX] = 1.0 if has_debug else 0.0
        feats[PE_HAS_EXCEPTION_IDX] = 1.0 if has_exception else 0.0
        feats[PE_HAS_EXPORT_IDX] = 1.0 if has_export else 0.0
        feats[PE_HAS_IMPORT_IDX] = 1.0 if has_import else 0.0
        feats[PE_HAS_RESOURCE_IDX] = 1.0 if has_resource else 0.0
        feats[PE_HAS_TLS_IDX] = 1.0 if has_tls else 0.0
        feats[PE_HAS_CFG_IDX] = 1.0 if has_cfg else 0.0
        feats[PE_HAS_RELOC_IDX] = 1.0 if has_reloc else 0.0
        
        executable_sections = 0
        ep = getattr(oh, 'AddressOfEntryPoint', 0)
        ep_in_exec = 0
        
        for i, section in enumerate(pe.sections):
            sname = section.Name.decode('utf-8', 'ignore').rstrip('\x00')
            sh = zlib.crc32(sname.encode('utf-8')) & 0x7FFFFFFF
            j = PE_SECTION_HASH_START + (sh % (PE_SECTION_HASH_END - PE_SECTION_HASH_START))
            feats[j] = 1.0
            
            sec_char = section.Characteristics
            if sec_char & 0x20000000:
                executable_sections += 1
            
            if section.VirtualAddress <= ep < section.VirtualAddress + section.Misc_VirtualSize:
                if sec_char & 0x20000000:
                    ep_in_exec = 1
            
            raw_size = section.SizeOfRawData
            ent = 0.0
            try:
                sdata = section.get_data()
                if sdata and len(sdata) > 0:
                    chunk = sdata[:65536]
                    counts = np.bincount(np.frombuffer(chunk, dtype=np.uint8), minlength=256)
                    t = max(len(chunk), 1)
                    probs = counts[:256] / t
                    probs = probs[probs > 0]
                    ent = -np.sum(probs * np.log2(probs))
            except:
                pass
            
            sname_l = sname.lower()
            if sname_l == '.text':
                feats[PE_TEXT_ENTROPY_IDX] = ent
                feats[PE_TEXT_SIZE_IDX] = min(raw_size, 10*1024*1024) / (1024*1024)
            elif sname_l == '.rdata':
                feats[PE_RDATA_ENTROPY_IDX] = ent
            elif sname_l == '.rsrc':
                feats[PE_RSRC_ENTROPY_IDX] = ent
        
        feats[PE_EXEC_SECTIONS_IDX] = min(executable_sections, 10) / 5.0
        feats[PE_EP_IN_EXEC_IDX] = float(ep_in_exec)
        
        import_count = 0
        dll_count = 0
        
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll_name = entry.dll.decode('utf-8', 'ignore').lower()
                dll_count += 1
                dh = zlib.crc32(dll_name.encode('utf-8')) & 0x7FFFFFFF
                j = PE_DLL_HASH_START + (dh % (PE_DLL_HASH_END - PE_DLL_HASH_START))
                feats[j] = 1.0
                
                for imp in entry.imports:
                    if imp.name:
                        import_count += 1
                        api_name = imp.name.decode('utf-8', 'ignore')
                        ah = zlib.crc32(api_name.encode('utf-8')) & 0x7FFFFFFF
                        j = PE_API_HASH_START + (ah % (PE_API_HASH_END - PE_API_HASH_START))
                        feats[j] = 1.0
        
        feats[PE_IMPORT_COUNT_IDX] = min(import_count, 500) / 100.0
        feats[PE_DLL_COUNT_IDX] = min(dll_count, 50) / 10.0
        
        export_count = 0
        if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
            export_count = len(pe.DIRECTORY_ENTRY_EXPORT.symbols)
        feats[PE_EXPORT_COUNT_IDX] = min(export_count, 500) / 100.0
        
        try:
            if hasattr(pe, 'FileInfo'):
                for fi in pe.FileInfo:
                    for entry in fi:
                        if hasattr(entry, 'StringTable'):
                            for st in entry.StringTable:
                                for k, v in st.entries.items():
                                    kl = k.decode('utf-8', 'ignore') if isinstance(k, bytes) else k
                                    vl = v.decode('utf-8', 'ignore') if isinstance(v, bytes) else v
                                    if kl == 'CompanyName':
                                        feats[PE_COMPANY_NAME_LEN_IDX] = min(len(vl), 200) / 50.0
                                    elif kl == 'FileDescription':
                                        feats[PE_FILE_DESC_LEN_IDX] = min(len(vl), 200) / 50.0
                                    elif kl == 'FileVersion':
                                        feats[PE_FILE_VER_LEN_IDX] = min(len(vl), 100) / 25.0
                                    elif kl == 'ProductName':
                                        feats[PE_PRODUCT_NAME_LEN_IDX] = min(len(vl), 200) / 50.0
        except:
            pass
        
        pe.close()
    except:
        pass
    
    return feats

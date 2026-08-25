# -*- coding: utf-8 -*-
import os
import sys
import hashlib
import math
import struct
import pefile

sys.stdout.reconfigure(encoding='utf-8')

files = []
# 从扫描日志读取漏报(CLEAN)文件列表
_log_path = r"D:\Administrator\Desktop\SevenEngineCloud\fullscan_20260805_1000.log"
import re as _re
if os.path.exists(_log_path):
    with open(_log_path, 'r', encoding='utf-8') as _f:
        for _line in _f:
            if "[OK] CLEAN" in _line:
                _m = _re.search(r'CLEAN\s+(D:.+?)\s*$', _line.strip())
                if _m:
                    files.append(_m.group(1).strip())


def calc_entropy(data):
    if not data:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    ent = 0.0
    length = len(data)
    for f in freq:
        if f > 0:
            p = f / length
            ent -= p * math.log2(p)
    return round(ent, 4)


def get_sha256(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        while True:
            chunk = f.read(65536)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def detect_type(path):
    ext = os.path.splitext(path)[1].lower()
    with open(path, 'rb') as f:
        header = f.read(0x400)
    if len(header) >= 2 and header[:2] == b'MZ':
        try:
            pe_off = struct.unpack('<I', header[0x3c:0x40])[0]
            if pe_off + 24 <= len(header) and header[pe_off:pe_off + 4] == b'PE\x00\x00':
                characteristics = struct.unpack('<H', header[pe_off + 22:pe_off + 24])[0]
                if characteristics & 0x2000:
                    return 'DLL'
            return 'PE'
        except Exception:
            return 'PE'
    if len(header) >= 8 and header[:8] == bytes.fromhex('d0cf11e0a1b11ae1'):
        if ext == '.msi':
            return 'MSI'
        return 'OLE'
    if ext in ('.js', '.vbs', '.jse', '.vbe', '.wsf', '.wsh'):
        return 'script'
    return 'other'


def analyze_pe(path):
    result = {}
    try:
        pe = pefile.PE(path)
    except Exception as e:
        return {'error': str(e)}

    is_dll = pe.is_dll()

    is_dotnet = False
    try:
        com_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[14]
        if com_dir.VirtualAddress != 0 and com_dir.Size != 0:
            is_dotnet = True
    except Exception:
        pass

    sig_info = 'No signature'
    try:
        sec_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[4]
        if sec_dir.VirtualAddress != 0 and sec_dir.Size > 0:
            sig_info = 'Has signature (cert table size=%d bytes)' % sec_dir.Size
    except Exception:
        pass

    import_count = 0
    api_list = []
    if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll_name = entry.dll.decode('utf-8', errors='replace') if entry.dll else '?'
            for imp in entry.imports:
                import_count += 1
                if imp.name:
                    api_list.append(imp.name.decode('utf-8', errors='replace'))
                elif imp.ordinal:
                    api_list.append('#%d@%s' % (imp.ordinal, dll_name))

    export_count = 0
    export_names = []
    if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
        export_count = len(pe.DIRECTORY_ENTRY_EXPORT.symbols)
        for sym in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            if sym.name:
                export_names.append(sym.name.decode('utf-8', errors='replace'))
            elif sym.ordinal:
                export_names.append('#%d' % sym.ordinal)

    sections = []
    for section in pe.sections:
        name = section.Name.decode('utf-8', errors='replace').rstrip('\x00')
        entropy = round(section.get_entropy(), 4)
        rawsize = section.SizeOfRawData
        virtualsize = section.Misc_VirtualSize
        sections.append({
            'name': name,
            'entropy': entropy,
            'rawsize': rawsize,
            'virtualsize': virtualsize,
        })

    result['is_dll'] = is_dll
    result['is_dotnet'] = is_dotnet
    result['sig_info'] = sig_info
    result['import_count'] = import_count
    result['export_count'] = export_count
    result['sections'] = sections
    result['api_list'] = api_list[:50]
    result['total_apis'] = len(api_list)
    result['export_names'] = export_names[:20]

    if is_dll:
        result['dll_proxy'] = (import_count == 0 and export_count > 0)

    pe.close()
    return result


def analyze_msi(path):
    result = {}
    with open(path, 'rb') as f:
        data = f.read()
    pe_offsets = []
    pos = 0
    while True:
        idx = data.find(b'MZ', pos)
        if idx == -1:
            break
        if idx + 0x40 <= len(data):
            try:
                pe_off = struct.unpack('<I', data[idx + 0x3c:idx + 0x40])[0]
                if pe_off < 0x1000 and idx + pe_off + 4 <= len(data):
                    if data[idx + pe_off:idx + pe_off + 4] == b'PE\x00\x00':
                        pe_offsets.append(idx)
            except Exception:
                pass
        pos = idx + 2
    result['embedded_pe'] = len(pe_offsets) > 0
    result['pe_count'] = len(pe_offsets)
    result['pe_offsets'] = pe_offsets[:20]
    result['file_size'] = len(data)
    return result


def analyze_script(path):
    with open(path, 'rb') as f:
        raw = f.read(2000)
    try:
        text = raw.decode('utf-8')
    except Exception:
        try:
            text = raw.decode('gbk')
        except Exception:
            text = raw.decode('latin-1')
    return text[:500]


def main():
    print('漏报文件总数: %d' % len(files))
    print()

    # 分类统计
    stats = {
        'PE': 0, 'DLL': 0, 'MSI': 0, 'script': 0, 'OLE': 0, 'other': 0,
        'notfound': 0,
        'pe_has_sig': 0,        # PE 有签名（签名信任漏报嫌疑）
        'pe_no_import': 0,      # PE 无导入（加壳/构造异常）
        'pe_dotnet': 0,         # .NET PE
        'pe_dll_proxy': 0,      # DLL 代理（0导入+有导出）
        'pe_high_entropy': 0,   # 有高熵节(>7.0)
        'pe_rwx': 0,            # 有 RWX 节
        'pe_parse_fail': 0,     # PE 解析失败
        'msi_embedded_pe': 0,   # MSI 嵌入 PE
    }
    # 记录每类抽样
    samples = {'PE_has_sig': [], 'PE_no_import': [], 'PE_dotnet': [], 'PE_dll_proxy': [],
               'PE_high_entropy': [], 'PE_parse_fail': [], 'MSI': [], 'script': [], 'PE_normal': []}
    # 有签名的 PE 详细列表（重点：签名信任漏报）
    signed_pe_list = []

    for i, path in enumerate(files, 1):
        if not os.path.exists(path):
            stats['notfound'] += 1
            continue
        try:
            ftype = detect_type(path)
        except Exception:
            ftype = 'other'
        stats[ftype] = stats.get(ftype, 0) + 1

        if ftype in ('PE', 'DLL'):
            pe_res = analyze_pe(path)
            if 'error' in pe_res:
                stats['pe_parse_fail'] += 1
                if len(samples['PE_parse_fail']) < 3:
                    samples['PE_parse_fail'].append((path, pe_res['error']))
                continue
            has_sig = pe_res['sig_info'] != 'No signature'
            no_import = pe_res['import_count'] == 0
            is_dn = pe_res['is_dotnet']
            is_proxy = pe_res.get('dll_proxy', False)
            high_e = any(s['entropy'] > 7.0 for s in pe_res['sections'])
            has_rwx = False
            if has_sig:
                stats['pe_has_sig'] += 1
                signed_pe_list.append((path, pe_res['sig_info'], pe_res['import_count'], len(pe_res['sections']), is_dn))
                if len(samples['PE_has_sig']) < 3:
                    samples['PE_has_sig'].append((path, pe_res))
            if no_import:
                stats['pe_no_import'] += 1
                if len(samples['PE_no_import']) < 3:
                    samples['PE_no_import'].append((path, pe_res))
            if is_dn:
                stats['pe_dotnet'] += 1
                if len(samples['PE_dotnet']) < 3:
                    samples['PE_dotnet'].append((path, pe_res))
            if is_proxy:
                stats['pe_dll_proxy'] += 1
                if len(samples['PE_dll_proxy']) < 3:
                    samples['PE_dll_proxy'].append((path, pe_res))
            if high_e:
                stats['pe_high_entropy'] += 1
                if len(samples['PE_high_entropy']) < 3:
                    samples['PE_high_entropy'].append((path, pe_res))
            if not has_sig and not no_import and not is_dn and not is_proxy and not high_e:
                if len(samples['PE_normal']) < 3:
                    samples['PE_normal'].append((path, pe_res))
        elif ftype == 'MSI':
            msi_res = analyze_msi(path)
            if msi_res['embedded_pe']:
                stats['msi_embedded_pe'] += 1
            if len(samples['MSI']) < 3:
                samples['MSI'].append((path, msi_res))
        elif ftype == 'script':
            if len(samples['script']) < 5:
                content = analyze_script(path)
                samples['script'].append((path, content))

    print('=' * 90)
    print('漏报原因汇总')
    print('=' * 90)
    print('  文件类型: PE=%d, DLL=%d, MSI=%d, script=%d, OLE=%d, other=%d, 不存在=%d' % (
        stats['PE'], stats['DLL'], stats['MSI'], stats['script'], stats['OLE'], stats['other'], stats['notfound']))
    print()
    print('  PE 漏报细分:')
    print('    有签名(签名信任漏报嫌疑): %d' % stats['pe_has_sig'])
    print('    无导入(加壳/构造异常)   : %d' % stats['pe_no_import'])
    print('    .NET PE                : %d' % stats['pe_dotnet'])
    print('    DLL代理(0导入+有导出)   : %d' % stats['pe_dll_proxy'])
    print('    高熵节(>7.0,加壳)      : %d' % stats['pe_high_entropy'])
    print('    PE解析失败             : %d' % stats['pe_parse_fail'])
    print('  MSI 嵌入PE: %d' % stats['msi_embedded_pe'])
    print()

    # 重点：有签名的 PE（签名信任导致的漏报）
    if signed_pe_list:
        print('=' * 90)
        print('【重点】有签名的 PE 漏报清单（签名信任逻辑放过）共 %d 个' % len(signed_pe_list))
        print('=' * 90)
        for path, sig, imp, sec_cnt, dn in signed_pe_list:
            print('  %s' % os.path.basename(path))
            print('    签名: %s' % sig)
            print('    导入数=%d 节数=%d .NET=%s' % (imp, sec_cnt, dn))
            print('    路径: %s' % path)
        print()

    # 抽样：无导入 PE
    if samples['PE_no_import']:
        print('=' * 90)
        print('抽样: 无导入 PE（加壳/构造异常）')
        print('=' * 90)
        for path, pe_res in samples['PE_no_import']:
            print('  %s' % os.path.basename(path))
            print('    导入=%d 导出=%d .NET=%s 节数=%d' % (
                pe_res['import_count'], pe_res['export_count'], pe_res['is_dotnet'], len(pe_res['sections'])))
            for s in pe_res['sections'][:5]:
                print('      节 %-10s e=%.2f raw=%d' % (s['name'], s['entropy'], s['rawsize']))
            print('    路径: %s' % path)
        print()

    # 抽样：脚本
    if samples['script']:
        print('=' * 90)
        print('抽样: 脚本漏报')
        print('=' * 90)
        for path, content in samples['script']:
            print('  %s' % os.path.basename(path))
            print('    路径: %s' % path)
            for line in content.split('\n')[:6]:
                print('    | %s' % line)
            print()

    # 抽样：MSI
    if samples['MSI']:
        print('=' * 90)
        print('抽样: MSI 漏报')
        print('=' * 90)
        for path, msi_res in samples['MSI']:
            print('  %s' % os.path.basename(path))
            print('    大小=%d 嵌入PE=%s PE数=%d' % (
                msi_res['file_size'], msi_res['embedded_pe'], msi_res['pe_count']))
            print('    路径: %s' % path)
        print()


if __name__ == '__main__':
    main()

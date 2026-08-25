#!/usr/bin/env python
# -*- coding: utf-8 -*-
import os, sys, threading, time, json, subprocess, hashlib
import shutil, zipfile, traceback, re, math, fnmatch, io, queue
import logging, warnings
import ctypes
from collections import OrderedDict, Counter
try:
    from lightgbm_engine import LightGBMScanner
except Exception:
    LightGBMScanner = None
warnings.filterwarnings("ignore", message="PKCS#7.*")
CONFIG = {
    "worker_threads": 20,
    "cache_size": 10000,
    "skip_dirs": [
        "$Recycle.Bin", "System Volume Information", "Windows\\WinSxS",
        "ProgramData\\Package Cache", "AppData\\Local\\Temp", "AppData\\Local\\Microsoft\\Windows\\INetCache",
        "PASW", "Pedefense"
    ],
    "scan_extensions": [
        ".exe", ".dll", ".sys", ".ocx", ".scr", ".cpl", ".drv", ".com", ".msi",
        ".jar", ".vbs", ".ps1", ".js", ".bat", ".cmd", ".py", ".pyw", ".lnk", ".bin"
    ],
    # 默认 False = 不过滤后缀名（扫描目录下所有文件，改名/无后缀的 PE 也能被扫到）。
    # 传入 --DEBUG:UNANY 时置为 True，恢复仅扫描 scan_extensions 列表的旧行为。
    "enable_ext_filter": False,
    "whitelist_file": "whitelist.txt",
    "log_file": "engine.log",
    "confidence_threshold": 60,
    "onnx_confidence_threshold": 85,
    "yara_rules_dir": "yara_rules",
    "custom_rules_dir": "custom_rules",
    "enable_custom_rules": True,
    "custom_rule_scan_cap": 16777216,
    "machine_learning_file": "engines/study-engine.txt",
    "temp_extract_dir": "temp_extract",
    "extract_and_scan": True,
    "onnx_model_dir": "ONNX",
    "enable_onnx": True,
    "enable_lightgbm": True,
    "lightgbm_model": "EngineSET/lightgbm.pda",
    "enable_lightgbm_white": True,
    "lightgbm_white_prob": 0.15,
    "enable_yara": False,  # YARA 依赖外部库且规则编写繁琐，默认关闭，改用内置自定义规则引擎(CUSTOM)
    "enable_pe_scan": True,
    "max_zip_depth": 2,
    "read_chunk_size": 62914560,
    "feature_files_dir": "signatures",
    "enable_stu_txt_scanner": True,
    "enable_json_scanner": True,
    "enable_study_engine": True,
    "signature_min_confidence": 35,
    "signature_max_confidence": 95,
    "signature_min_pattern_len": 4,
    "combo_required_matches": 2,
    "full_scan_batch_size": 2000,
    "cloud_api_base": "https://cloudapi.xiguastudio.top",
    "cloud_api_key": "scan_238e9dc876104329b9488495cfc4ea44",
    "cloud_scan_enabled": True,
    "cloud_timeout": 10,
    "cloud_whitelist_mode": True,
    "enable_external_clouds": False,
    "external_clouds_config": [],
    "avic_api_base": "https://avic.xiguastudio.top",
    "avic_api_key": "AVIC-8EB9801419F42F23CAC58B47ED679E59",
    "avic_scan_enabled": True,
    "avic_timeout": 10,
    "scan_dir_threads": 8,
}

if getattr(sys, 'frozen', False):
    BASE_DIR = os.path.dirname(sys.executable)
else:
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))

_ENGINE_DIR = os.path.join(BASE_DIR, "Engine")
if os.path.isdir(_ENGINE_DIR):
    for _k in ["yara_rules_dir","temp_extract_dir","custom_rules_dir",
               "onnx_model_dir","whitelist_file","log_file","feature_files_dir","lightgbm_model"]:
        _p = os.path.join(_ENGINE_DIR, CONFIG[_k])
        if os.path.exists(_p) or os.path.isdir(os.path.dirname(_p)):
            CONFIG[_k] = _p
        else:
            CONFIG[_k] = os.path.join(BASE_DIR, CONFIG[_k])
    else:
        for _k in ["yara_rules_dir","temp_extract_dir","custom_rules_dir",
               "onnx_model_dir","whitelist_file","log_file","feature_files_dir","lightgbm_model"]:
            CONFIG[_k] = os.path.join(BASE_DIR, CONFIG[_k])
SHARED_CONFIG_PATH = os.path.join(BASE_DIR, 'Main', 'Main', 'config.json')
if not os.path.exists(SHARED_CONFIG_PATH):
    SHARED_CONFIG_PATH = os.path.join(BASE_DIR, 'Main', 'config.json')
if not os.path.exists(SHARED_CONFIG_PATH):
    SHARED_CONFIG_PATH = os.path.join(BASE_DIR, 'config.json')
if os.path.exists(SHARED_CONFIG_PATH):
    try:
        with open(SHARED_CONFIG_PATH, 'r', encoding='utf-8') as _f:
            _shared_cfg = json.load(_f)
        for _k in set(CONFIG.keys()):
            if _k in _shared_cfg:
                CONFIG[_k] = _shared_cfg[_k]
    except Exception:
        pass
for d in [os.path.dirname(CONFIG["machine_learning_file"]), CONFIG["temp_extract_dir"],
          CONFIG["yara_rules_dir"], CONFIG["custom_rules_dir"], CONFIG["onnx_model_dir"], CONFIG["feature_files_dir"],
          os.path.dirname(CONFIG["lightgbm_model"])]:
    os.makedirs(d, exist_ok=True)

logger = logging.getLogger('Engine')
def _log(msg):
    pass
def _scan_log(msg):
    pass
class LRUCache:
    def __init__(self, maxsize=CONFIG["cache_size"]):
        self.cache = OrderedDict()
        self.maxsize = maxsize
        self.lock = threading.Lock()
    def get(self, key):
        with self.lock:
            if key not in self.cache:
                return None
            self.cache.move_to_end(key)
            return self.cache[key]
    def put(self, key, value):
        with self.lock:
            if key in self.cache:
                self.cache.move_to_end(key)
            self.cache[key] = value
            if len(self.cache) > self.maxsize:
                self.cache.popitem(last=False)
class Whitelist:
    def __init__(self):
        self.paths = set()
        self.lock = threading.Lock()
        self.load()
    def load(self):
        if os.path.exists(CONFIG["whitelist_file"]):
            with open(CONFIG["whitelist_file"], 'r', encoding='utf-8') as f:
                self.paths = {line.strip() for line in f if line.strip() and not line.strip().startswith('#')}
        study_file = CONFIG.get("machine_learning_file", "")
        if study_file and os.path.exists(study_file):
            try:
                with open(study_file, 'r', encoding='utf-8') as f:
                    content = f.read()
                brace_idx = content.find('{')
                if brace_idx > 0:
                    path_section = content[:brace_idx]
                    for line in path_section.splitlines():
                        line = line.strip().strip('"').strip("'")
                        if line:
                            self.paths.add(line)
            except Exception:
                pass
    def contains(self, path):
        with self.lock:
            if path in self.paths:
                return True
            norm = os.path.normpath(path)
            for wp in self.paths:
                if os.path.isdir(wp) or not os.path.splitext(wp)[1]:
                    wnorm = os.path.normpath(wp)
                    if norm == wnorm or norm.startswith(wnorm + os.sep):
                        return True
            return False
    def add_path(self, path):
        with self.lock:
            self.paths.add(path)
            self._save()
    def remove_path(self, path):
        with self.lock:
            if path in self.paths:
                self.paths.discard(path)
                self._save()
                return True
            return False
    def get_paths(self):
        with self.lock:
            return sorted(self.paths)
    def _save(self):
        try:
            os.makedirs(os.path.dirname(CONFIG["whitelist_file"]), exist_ok=True)
            with open(CONFIG["whitelist_file"], 'w', encoding='utf-8') as f:
                for p in sorted(self.paths):
                    f.write(p + '\n')
        except Exception as e:
            _log(f"[白名单] 保存失败: {e}")
THREAT_CATEGORIES = {
    'ransom': ('Trojan', 'Ransom'), 'crypt': ('Trojan', 'Crypt'), 'locky': ('Trojan', 'Locky'), 'wannacry': ('Trojan', 'WannaCry'),
    'cerber': ('Trojan', 'Cerber'), 'cryptolocker': ('Trojan', 'CryptoLocker'), 'bitlocker': ('Trojan', 'BitLocker'),
    'bank': ('Trojan', 'Banker'), 'dridex': ('Trojan', 'Dridex'), 'emotet': ('Trojan', 'Emotet'), 'zeus': ('Trojan', 'Zbot'),
    'banker': ('Trojan', 'Banker'), 'onlinebanking': ('Trojan', 'Banker'),
    'stealer': ('Trojan', 'Stealer'), 'password': ('Trojan', 'PSW'), 'grabber': ('Trojan', 'Grabber'), 'info': ('Trojan', 'Stealer'),
    'credential': ('Trojan', 'Stealer'), 'pwd': ('Trojan', 'PSW'), 'mail': ('Trojan', 'MailStealer'),
    'keylog': ('Trojan', 'KeyLogger'), 'keylogger': ('Trojan', 'KeyLogger'), 'hook': ('Trojan', 'Hook'),
    'spy': ('Trojan', 'Spy'), 'agent': ('Trojan', 'Agent'), 'rat': ('Backdoor', 'RAT'), 'remote': ('Backdoor', 'Remote'),
    'backdoor': ('Backdoor', 'Agent'), 'agenttesla': ('Trojan', 'AgentTesla'), 'njrat': ('Backdoor', 'Njrat'),
    'darkcomet': ('Backdoor', 'DarkComet'), 'poisonivy': ('Backdoor', 'Poison'), 'gh0st': ('Backdoor', 'Gh0st'),
    'dropper': ('Trojan', 'Dropper'), 'downloader': ('Trojan', 'Downloader'), 'install': ('Trojan', 'Installer'),
    'miner': ('Trojan', 'CoinMiner'), 'coin': ('Trojan', 'CoinMiner'), 'cryptocurrency': ('Trojan', 'CoinMiner'), 'xmr': ('Trojan', 'XMRMiner'),
    'worm': ('Worm', 'Generic'), 'bot': ('Backdoor', 'Bot'), 'conficker': ('Worm', 'Conficker'), 'morris': ('Worm', 'Morris'),
    'silverfox': ('Trojan', 'SilverFox'), 'sfox': ('Trojan', 'SilverFox'),
    'inject': ('Trojan', 'Injector'), 'reflect': ('Trojan', 'Injector'), 'process hollow': ('Trojan', 'Hollow'),
    'hijack': ('Trojan', 'Hijack'), 'browser': ('Trojan', 'BrowserHijack'), 'dns': ('Trojan', 'DNSHijack'),
    'adware': ('Adware', 'Generic'), 'trojan': ('Trojan', 'Generic'), 'malware': ('Trojan', 'Generic'),
    'packed': ('Trojan', 'Packed'), 'packer': ('Trojan', 'Packed'), 'obfuscated': ('Trojan', 'Obfuscated'),
    'upx': ('Trojan', 'UPX'), 'aspack': ('Trojan', 'ASPack'), 'themida': ('Trojan', 'Themida'),
    'vmprotect': ('Trojan', 'VMProtect'), 'enigma': ('Trojan', 'Enigma'),
    'rootkit': ('Rootkit', 'Generic'), 'bootkit': ('Bootkit', 'Generic'),
    'wiper': ('Trojan', 'Wiper'), 'destructive': ('Trojan', 'Wiper'),
    'exploit': ('Exploit', 'Generic'), 'shellcode': ('Exploit', 'Shellcode'),
    'loader': ('Trojan', 'Loader'), 'stager': ('Trojan', 'Stager'), 'launcher': ('Trojan', 'Launcher'),
    'infostealer': ('Trojan', 'Stealer'), 'exfiltrate': ('Trojan', 'Exfil'), 'clipboard': ('Trojan', 'ClipBanker'),
    'c2': ('Backdoor', 'C2'), 'beacon': ('Backdoor', 'Beacon'),
    'proxy': ('Trojan', 'Proxy'), 'socks': ('Trojan', 'Socks'),
    'ransomware': ('Trojan', 'Ransom'), 'cryptojacking': ('Trojan', 'CoinMiner'),
    'macro': ('Trojan', 'Macro'), 'office': ('Trojan', 'Macro'),
    'phishing': ('Trojan', 'Phish'), 'phish': ('Trojan', 'Phish'), 'fake': ('Trojan', 'Fake'),
    'scareware': ('Trojan', 'Scare'), 'rogue': ('Trojan', 'Rogue'), 'fakeav': ('Trojan', 'FakeAV'),
    'webshell': ('Backdoor', 'Webshell'), 'asp': ('Backdoor', 'Webshell'), 'jsp': ('Backdoor', 'Webshell'),
}

EXTENSION_THREATS = {
    '.scr': ('Trojan', 'Win32', 'SCR'), '.pif': ('Trojan', 'Win32', 'PIF'), '.com': ('Trojan', 'Win32', 'COM'),
    '.vbs': ('Trojan', 'VBS', 'Generic'), '.ps1': ('Trojan', 'Win32', 'PowerShell'),
    '.js': ('Trojan', 'JS', 'Generic'), '.jar': ('Trojan', 'Java', 'Generic'),
    '.wsf': ('Trojan', 'Script', 'WSF'), '.hta': ('Trojan', 'Script', 'HTA'),
    '.vbe': ('Trojan', 'VBS', 'Generic'), '.cpl': ('Trojan', 'Win32', 'CPL'),
    '.msi': ('Trojan', 'Win32', 'MSI'), '.chm': ('Trojan', 'Win32', 'CHM'),
    '.bat': ('Trojan', 'BAT', 'Generic'), '.cmd': ('Trojan', 'BAT', 'Generic'),
    '.sct': ('Trojan', 'Script', 'SCT'), '.wsc': ('Trojan', 'Script', 'WSC'),
}

_VARIANT_POOL = 'abcdefghijkmnpqrstuvwxyz0123456789'

def _gen_variant(seed_str):
    h = hashlib.md5(seed_str.encode('utf-8')).hexdigest()
    v = ''
    for i in range(0, 6, 2):
        idx = int(h[i:i+2], 16) % len(_VARIANT_POOL)
        v += _VARIANT_POOL[idx]
    return v[:3]

def _get_platform(filepath):
    ext = os.path.splitext(filepath)[1].lower()
    if ext in ('.exe', '.dll', '.sys', '.ocx', '.scr', '.cpl', '.drv', '.com', '.msi', '.chm', '.ps1'):
        return 'Win32'
    if ext in ('.vbs', '.vbe'):
        return 'VBS'
    if ext in ('.js',):
        return 'JS'
    if ext in ('.bat', '.cmd'):
        return 'BAT'
    if ext in ('.py', '.pyw'):
        return 'Python'
    if ext in ('.jar',):
        return 'Java'
    if ext in ('.hta', '.wsf', '.sct', '.wsc'):
        return 'Script'
    return 'Generic'

def classify_threat(filepath, rule_name=None, pe_apis=None, heuristic=False):
    basename = os.path.basename(filepath).lower()
    lower_path = filepath.lower()
    ext = os.path.splitext(filepath)[1].lower()
    platform = _get_platform(filepath)
    is_heur = heuristic
    threat_type = 'Trojan'
    family = 'Generic'
    if rule_name:
        rule_lower = rule_name.lower()
        for kw, (ttype, fam) in THREAT_CATEGORIES.items():
            if kw in rule_lower and len(kw) >= 4:
                threat_type = ttype
                family = fam
                break
        if family == 'Generic':
            if 'silverfox' in rule_lower:
                threat_type, family = 'Trojan', 'SilverFox'
            elif any(x in rule_lower for x in ['ransom','crypt','locky','encrypt']):
                threat_type, family = 'Trojan', 'Ransom'
            elif any(x in rule_lower for x in ['keylog','hook']):
                threat_type, family = 'Trojan', 'KeyLogger'
            elif any(x in rule_lower for x in ['bank','dridex','zeus','emotet']):
                threat_type, family = 'Trojan', 'Banker'
            elif any(x in rule_lower for x in ['pack','upx','aspack','themida','vmprotect']):
                threat_type, family = 'Trojan', 'Packed'
            elif any(x in rule_lower for x in ['miner','coin','xmr','stratum']):
                threat_type, family = 'Trojan', 'CoinMiner'
    if pe_apis and isinstance(pe_apis, list):
        if any(api in ['CreateRemoteThread','WriteProcessMemory','VirtualAllocEx','NtCreateThreadEx','QueueUserAPC','NtUnmapViewOfSection','SetThreadContext','RtlCreateUserThread'] for api in pe_apis):
            if family == 'Generic':
                threat_type, family = 'Trojan', 'Injector'
            is_heur = True
        elif any(api in ['SetWindowsHookEx','GetAsyncKeyState','GetClipboardData'] for api in pe_apis):
            if family == 'Generic':
                threat_type, family = 'Trojan', 'KeyLogger'
            is_heur = True
        elif any(api in ['CredEnumerate','CredRead','LsaOpenPolicy','LsaRetrievePrivateData','SamOpenUser','CryptUnprotectData'] for api in pe_apis):
            if family == 'Generic':
                threat_type, family = 'Trojan', 'Stealer'
            is_heur = True
    packer_kw = ['upx','aspack','themida','vmprotect','enigma','molebox','armadillo','telock','pespin','mpress','obsidium','nspack']
    for pk in packer_kw:
        if pk in basename or pk in lower_path:
            threat_type, family = 'Trojan', pk.upper()
            is_heur = True
            break
    if family == 'Generic':
        for kw, (ttype, fam) in THREAT_CATEGORIES.items():
            if len(kw) >= 5 and kw in basename:
                threat_type, family = ttype, fam
                break
            if len(kw) >= 8 and kw in lower_path:
                threat_type, family = ttype, fam
                break
    if ext in EXTENSION_THREATS and family == 'Generic':
        et_type, et_platform, et_family = EXTENSION_THREATS[ext]
        threat_type = et_type
        if platform == 'Generic':
            platform = et_platform
        family = et_family
        is_heur = True
    if ext in ('.ps1',) and family == 'Generic':
        family = 'PowerShell'
        platform = 'Win32'
        is_heur = True
    if ext in ('.bat', '.cmd') and family == 'Generic':
        family = 'Generic'
        is_heur = True
    variant = _gen_variant(filepath + family)
    prefix = 'HEUR:' if is_heur else ''
    return f'{prefix}{threat_type}.{platform}.{family}.{variant}'

def get_file_signature(filepath):
    try:
        stat = os.stat(filepath)
        return (stat.st_size, stat.st_mtime)
    except:
        return None

def is_system_path(file_path):
    norm = os.path.normpath(file_path).lower().replace('\\', '/')
    if norm.find('/windows/') <= 4 and '/windows/' in norm:
        return True
    if norm.find('/$windows.~bt/') <= 4 and '/$windows.~bt/' in norm:
        return True
    if norm.find('/$windows.~ws/') <= 4 and '/$windows.~ws/' in norm:
        return True
    if norm.find('/$winreagent/') <= 4 and '/$winreagent/' in norm:
        return True
    if norm.find('/program files/') <= 4 and '/program files/' in norm:
        return True
    if norm.find('/program files (x86)/') <= 4 and '/program files (x86)/' in norm:
        return True
    if norm.find('/programdata/') <= 4 and '/programdata/' in norm:
        return True
    if norm.find('/esd/') <= 4 and '/esd/' in norm:
        return True
    if norm.find('/drvpath/') <= 4 and '/drvpath/' in norm:
        return True
    if norm.find('/drivers/') <= 4 and '/drivers/' in norm:
        return True
    if norm.find('/driverstore/') <= 4 and '/driverstore/' in norm:
        return True
    if norm.find('/windowsapps/') <= 4 and '/windowsapps/' in norm:
        return True
    if norm.find('/$windows.~q/') <= 4 and '/$windows.~q/' in norm:
        return True
    if norm.find('/windows.old/') <= 4 and '/windows.old/' in norm:
        return True
    return False

_SECURITY_TOOL_DIRS = frozenset({
    'sbie', 'sandboxie', 'melix', 'melix-flash', 'pasw', 'paswe',
    'pedefense', 'edr', 'clamav', 'forserver',
    'floweypet', 'nuitka', 'pyqt6', 'qt6', 'pexgram', 'liquid-glass-main',
    'tor browser', 'testui',
})
_SECURITY_TOOL_EXES = frozenset({
    'sbiedll.dll', 'sbiectrl.exe', 'sbiesvc.exe',
    'melix.exe', 'zeroengine.exe', 'paswe.exe', 'pedefenseserver.exe', 'pedefense.exe',
    'sevenengine.exe', 'sevenengine.py', 'pedefenseserver.py', 'paswe.py', 'paswe_trainer.py',
    'mouseclicktool.exe', 'floweypet.exe', 'bat_to_exe_converter_(x64).exe',
    'peav_setup.exe', 'pysand.pyw', 'undertale.exe',
    'qwindows.dll', 'senew.py', 'firefox.exe', 'plugin-container.exe', 'xul.dll',
    'aidd.dll',
})
_SECURITY_TOOL_SIGNERS = frozenset({
    'sandboxie', 'tencent', 'qihoo', 'kingsoft', 'huorong',
    'sophos', 'avast', 'avg', 'bitdefender', 'kaspersky',
})

def _is_security_tool_component(filepath):
    norm = os.path.normpath(filepath).lower().replace('\\', '/')
    fname = os.path.basename(norm)
    if fname in _SECURITY_TOOL_EXES:
        return True
    parts = norm.split('/')
    for p in parts:
        if p in _SECURITY_TOOL_DIRS:
            return True
    return False

_JS_LIB_PATTERNS = frozenset({
    'ace-', 'mermaid-', 'highlight-', 'elasticlunr-', 'clipboard-',
    'book-', 'editor-', 'mode-', 'searcher-', 'theme-', 'toc-',
    'mark-', 'searchindex-', 'liquid-diamond', 'liquid-glass',
})

def _is_js_library_file(filepath):
    norm = os.path.normpath(filepath).lower().replace('\\', '/')
    fname = os.path.basename(norm)
    if any(fname.startswith(p) for p in _JS_LIB_PATTERNS):
        return True
    lib_dirs = ('/usermanual/', '/node_modules/', '/docs/', '/documentation/',
                '/lib/', '/vendor/', '/assets/', '/static/', '/dist/',
                '/bower_components/', '/clamav/')
    if any(d in norm for d in lib_dirs):
        return True
    return False

_SYS_PROC_NAMES = frozenset({
    'explorer.exe', 'svchost.exe', 'csrss.exe', 'smss.exe', 'wininit.exe',
    'winlogon.exe', 'lsass.exe', 'services.exe', 'dwm.exe', 'conhost.exe',
    'runtimebroker.exe', 'taskhostw.exe', 'sihost.exe', 'fontdrvhost.exe',
    'ctfmon.exe', 'audiodg.exe', 'spoolsv.exe', 'searchhost.exe',
    'startmenuexperiencehost.exe', 'textinputhost.exe',
    'shellexperiencehost.exe', 'applicationframehost.exe',
    'securityhealthsystray.exe', 'securityhealthservice.exe',
    'securityhealthhost.exe', 'msmpeng.exe', 'nissrv.exe', 'sppsvc.exe',
    'wudfhost.exe', 'dashost.exe', 'system', 'wininit.exe', 'userinit.exe',
    'fontdrvhost.exe', 'dllhost.exe', 'taskhost.exe',
})

def verify_name_path(name_lower, path):
    norm = os.path.normpath(path).lower().replace('\\', '/')
    if name_lower in _SYS_PROC_NAMES:
        return '/windows/' in norm
    trusted = ['/program files/', '/program files (x86)/', '/windows/', '/programdata/']
    if any(norm.find(p) <= 4 for p in trusted):
        return True
    if name_lower in {'python.exe', 'pythonw.exe', 'python3.exe', 'python314.exe'}:
        py_markers = ['/python3', '/programs/python', '/appdata/local/programs/python']
        if any(m in norm for m in py_markers):
            return True
    return False
_pe_parse_cache = {}
_pe_parse_lock = threading.Lock()
_pe_cache_max = 600

def _trim_pe_cache():
    with _pe_parse_lock:
        n = len(_pe_parse_cache)
        if n > _pe_cache_max:
            keep = n // 2
            keys = list(_pe_parse_cache.keys())
            for k in keys[:n - keep]:
                _pe_parse_cache.pop(k, None)

_CA_NAMES = {
    'verisign','digicert','symantec corporation','thawte','geotrust',
    'comodo','globalsign','entrust','sectigo','godaddy','starfield',
    'rapidssl','certum','actalis','swisssign','secom trust','buypass',
    'quovadis','network solutions','secure trust','usertrust',
    'xramp security','go daddy','carolinas first','ssl.com',
    'microsoft corporation','google llc',
}

def _parse_pkcs7_signer(pkcs7_data):
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives.serialization import pkcs7
        import warnings
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            certs = pkcs7.load_der_pkcs7_certificates(pkcs7_data)
        if not certs:
            return None
        leaf_cert = None
        for cert in certs:
            is_issuer = False
            for other in certs:
                if other is cert:
                    continue
                if cert.subject == other.issuer:
                    is_issuer = True
                    break
            if not is_issuer:
                leaf_cert = cert
                break
        if leaf_cert is None:
            leaf_cert = certs[-1]
        org_attrs = leaf_cert.subject.get_attributes_for_oid(x509.NameOID.ORGANIZATION_NAME)
        if org_attrs:
            val = org_attrs[0].value
            if val and not any(ca in val.lower() for ca in _CA_NAMES):
                return val
        cn_attrs = leaf_cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
        if cn_attrs:
            val = cn_attrs[0].value
            if val and not any(ca in val.lower() for ca in _CA_NAMES):
                return val
        return None
    except Exception:
        pass
    cert_body = pkcs7_data
    _ct_l = cert_body.decode('latin-1', errors='ignore').lower()
    _ct_u = cert_body.decode('utf-16-le', errors='ignore').lower()
    _PUBLISHERS = [
        'Microsoft Corporation','Google','Apple','Mozilla','Adobe','Oracle',
        'Intel','NVIDIA','AMD','VMware','Dell','HP',
        'Bitdefender','Kaspersky','ESET','Avast','AVG','Avira','McAfee',
        'Norton','Malwarebytes','Trend Micro','Sophos','Fortinet',
        'JetBrains','GitHub','Atlassian','Slack','Zoom','Valve','Epic Games',
        'Electronic Arts','Ubisoft','Blizzard','Autodesk','Docker','Red Hat',
        'Canonical','Tencent','Baidu','Qihoo','Kingsoft','Huawei','Xiaomi',
        'Python','OBS Project','VideoLAN','7-Zip','WinRAR','TeamViewer',
        'AnyDesk','RealVNC','Splashtop','Open Source Developer',
        'Gen Digital','NortonLifeLock','Avast Software','Broadcom',
        'Dell Technologies','Cisco','Lenovo','IBM',
    ]
    for p in _PUBLISHERS:
        pl = p.lower()
        if pl in _ct_l or pl in _ct_u:
            if not any(ca in pl for ca in _CA_NAMES):
                return p
    return None

def _parse_pe_all(filepath):
    try:
        st = os.stat(filepath)
        cache_key = (st.st_mtime_ns, st.st_size, filepath)
    except:
        cache_key = (0, 0, filepath)
    with _pe_parse_lock:
        if cache_key in _pe_parse_cache:
            _pe_parse_cache[cache_key] = _pe_parse_cache.pop(cache_key)
            return _pe_parse_cache[cache_key]
    try:
        import pefile
        pe = pefile.PE(filepath, fast_load=True)
        info = {'apis': [], 'signer': None, 'sections': [], 'has_clr': False, 'import_count': 0, 'version_info': {}, 'exports': [], 'export_count': 0, 'overlay_size': 0, 'is_dll': False, 'ep_section': '', 'import_dlls': [], 'ordinal_imports': 0, 'timestamp': 0, 'rwx_sections': []}
        try:
            pe.parse_data_directories(directories=[
                pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT'],
                pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY'],
                pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR'],
                pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_TLS'],
                pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_EXPORT'],
            ])
            info['is_dll'] = pe.is_dll()
            try:
                info['timestamp'] = pe.FILE_HEADER.TimeDateStamp
            except:
                pass
            try:
                _ep = pe.OPTIONAL_HEADER.AddressOfEntryPoint
                for sec in pe.sections:
                    if sec.VirtualAddress <= _ep < sec.VirtualAddress + max(sec.Misc_VirtualSize, sec.SizeOfRawData):
                        info['ep_section'] = sec.Name.decode('utf-8', 'ignore').rstrip('\x00')
                        break
            except:
                pass
            if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    try:
                        _dll_name = entry.dll.decode('utf-8', 'ignore').lower()
                        info['import_dlls'].append(_dll_name)
                    except:
                        pass
                    for imp in entry.imports:
                        if imp.name:
                            info['apis'].append(imp.name.decode('utf-8', 'ignore'))
                        elif imp.ordinal is not None:
                            info['ordinal_imports'] += 1
                info['import_count'] = len(info['apis'])
            _sec_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[4]
            cert_offset = _sec_dir.VirtualAddress
            cert_size = _sec_dir.Size
            if cert_offset > 0 and 8 <= cert_size <= 0x200000:
                try:
                    with open(filepath, 'rb') as f:
                        f.seek(cert_offset)
                        cert_data = f.read(min(cert_size, 0x200000))
                    if len(cert_data) >= 8:
                        info['signer'] = _parse_pkcs7_signer(cert_data[8:])
                except:
                    pass
            if hasattr(pe, 'DIRECTORY_ENTRY_COM_DESCRIPTOR') and pe.DIRECTORY_ENTRY_COM_DESCRIPTOR and pe.DIRECTORY_ENTRY_COM_DESCRIPTOR.Size:
                info['has_clr'] = True
            if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT') and pe.DIRECTORY_ENTRY_EXPORT and pe.DIRECTORY_ENTRY_EXPORT.symbols:
                for sym in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                    if sym.name:
                        try:
                            info['exports'].append(sym.name.decode('utf-8', 'ignore'))
                        except:
                            pass
                info['export_count'] = len(info['exports'])
            try:
                _overlay_offset = pe.get_overlay_data_start_offset()
                if _overlay_offset:
                    info['overlay_size'] = os.path.getsize(filepath) - _overlay_offset
            except:
                pass
            for sec in pe.sections:
                try:
                    sn = sec.Name.decode('utf-8', 'ignore').rstrip('\x00')
                    se = sec.get_entropy()
                    sr = sec.SizeOfRawData
                    sc = sec.Characteristics
                    info['sections'].append((sn, se, sr, sc))
                    _IMAGE_SCN_MEM_EXECUTE = 0x20000000
                    _IMAGE_SCN_MEM_WRITE = 0x80000000
                    if (sc & _IMAGE_SCN_MEM_EXECUTE) and (sc & _IMAGE_SCN_MEM_WRITE) and sr > 512:
                        info['rwx_sections'].append(sn)
                except:
                    pass
            try:
                pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_RESOURCE']])
                if hasattr(pe, 'VS_FIXEDFILEINFO') and pe.VS_FIXEDFILEINFO:
                    ffi = pe.VS_FIXEDFILEINFO[0]
                    info['version_info']['FileVersion'] = f"{ffi.FileVersionMS >> 16}.{ffi.FileVersionMS & 0xFFFF}.{ffi.FileVersionLS >> 16}.{ffi.FileVersionLS & 0xFFFF}"
                if hasattr(pe, 'FileInfo'):
                    for finfo in pe.FileInfo:
                        for entry in finfo:
                            if hasattr(entry, 'StringTable'):
                                for st in entry.StringTable:
                                    for k, v in st.entries.items():
                                        try:
                                            key = k.decode('utf-8', 'ignore')
                                            val = v.decode('utf-8', 'ignore').strip()
                                            if key == 'FileVersion' and 'FileVersion' in info['version_info'] and info['version_info']['FileVersion']:
                                                continue
                                            if val:
                                                info['version_info'][key] = val
                                        except:
                                            pass
            except:
                pass
        except:
            try:
                if pe and hasattr(pe, 'sections') and not info['sections']:
                    for sec in pe.sections:
                        sn = sec.Name.decode('utf-8', 'ignore').rstrip('\x00')
                        se = sec.get_entropy()
                        sr = sec.SizeOfRawData
                        sc = sec.Characteristics
                        info['sections'].append((sn, se, sr, sc))
                        _IMAGE_SCN_MEM_EXECUTE = 0x20000000
                        _IMAGE_SCN_MEM_WRITE = 0x80000000
                        if (sc & _IMAGE_SCN_MEM_EXECUTE) and (sc & _IMAGE_SCN_MEM_WRITE) and sr > 512:
                            info['rwx_sections'].append(sn)
            except:
                pass
        pe.close()
        with _pe_parse_lock:
            if len(_pe_parse_cache) >= _pe_cache_max:
                keep = len(_pe_parse_cache) // 2
                keys = list(_pe_parse_cache.keys())
                for k in keys[:len(_pe_parse_cache) - keep]:
                    _pe_parse_cache.pop(k, None)
            _pe_parse_cache[cache_key] = info
        return info
    except:
        empty = {'apis': [], 'signer': None, 'sections': [], 'has_clr': False, 'import_count': 0, 'version_info': {}, 'exports': [], 'export_count': 0, 'overlay_size': 0, 'is_dll': False, 'ep_section': '', 'import_dlls': [], 'ordinal_imports': 0, 'timestamp': 0, 'rwx_sections': []}
        with _pe_parse_lock:
            _pe_parse_cache[cache_key] = empty
        return empty

def _extract_signer(filepath):
    try:
        import pefile
        pe = pefile.PE(filepath, fast_load=True)
        pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']])
        _sec_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[4]
        cert_offset = _sec_dir.VirtualAddress
        cert_size = _sec_dir.Size
        pe.close()
        if cert_offset <= 0 or cert_size < 8 or cert_size > 0x200000:
            return None
        with open(filepath, 'rb') as f:
            f.seek(cert_offset)
            cert_data = f.read(min(cert_size, 0x200000))
        if len(cert_data) < 8:
            return None
        return _parse_pkcs7_signer(cert_data[8:])
    except:
        return None

def _extract_msi_signer(filepath):
    try:
        with open(filepath, 'rb') as f:
            data = f.read(min(os.path.getsize(filepath), 80*1024*1024))
        pos = -1
        for i in range(len(data) - 5):
            if data[i:i+3] == b'\x00\x02\x01' and data[i+3] in (0x30,):
                pos = i
                break
        if pos == -1:
            return None
        for start in range(pos, min(pos + 200, len(data) - 4)):
            if data[start:start+2] == b'\x30\x82':
                try:
                    asn1_len = ((data[start+2] << 8) | data[start+3]) + 4
                    if asn1_len > 100 and asn1_len < 0x100000 and start + asn1_len <= len(data):
                        cert_blob = data[start:start+asn1_len]
                        signer = _parse_pkcs7_signer(cert_blob)
                        if signer:
                            return signer
                except:
                    continue
        return None
    except:
        return None

_MSI_API_INJECTION = {
    'createremotethread','virtualallocex','writeprocessmemory','readprocessmemory',
    'ntcreateprocessex','ntmapviewofsection','queueuserapc',
    'setthreadcontext','getthreadcontext','suspendthread','resumethread',
    'ntsetinformationthread','ntsetinformationprocess',
}
_MSI_API_NETWORK = {
    'wsastartup','socket','connect','send','recv','bind','listen','accept',
    'internetopena','internetopenw','internetopenurla','internetopenurlw',
    'internetreadfile','winhttpopen','winhttpconnect','winhttpsendrequest',
    'winhttpreaddata','winhttpopenrequest','httsendrequesta','httsendrequestw',
    'gethostbyname','getaddrinfo','recvfrom','sendto',
}
_MSI_API_PERSISTENCE = {
    'regsetvalueexw','regsetvalueexa','regopenkeyexw','regopenkeyexa',
    'regcreatekeyexw','regcreatekeyexa','regdeletevaluew','regdeletevaluea',
    'regdeletekeyw','regdeletekeya','regenumvaluew','regenumkeyw',
    'shellexecutew','shellexecutea','shellexecuteexw','shellexecuteexa',
    'createmutexw','createmutexa','openmutexw','openmutexa',
    'createservicea','createservicew','changeserviceconfiga','changeserviceconfigw',
    'setfileattributesw','setfileattributesa',
}
_MSI_API_ANTIDEBUG = {
    'isdebuggerpresent','checkremotedebuggerpresent',
    'ntqueryinformationprocess','ntquerysysteminformation',
    'outputdebugstringa','outputdebugstringw',
}
_MSI_API_RESOURCE = {
    'findresourcew','findresourcea','findresourceexw','findresourceexa',
    'loadresource','lockresource','sizeofresource',
    'virtualalloc','virtualprotect','virtualfree',
    'loadlibraryw','loadlibrarya','loadlibraryexw','loadlibraryexa',
    'getprocaddress','getmodulehandlew','getmodulehandlea',
}
_MSI_API_FILE = {
    'createfilew','createfilea','writefile','readfile','deletefilew','deletefilea',
    'movefilew','movefilea','copyfilew','copyfilea','createfilemappingw',
    'mapviewoffile','mapviewoffileex','unmapviewoffile','flushviewoffile',
    'setfilepointer','setendoffile','getfilesize','getfileattributesw',
    'findfirstfilew','findnextfilew','findclose',
    'createdirectoryw','removedirectoryw','gettemppathw','gettempfilenamew',
    'getwindowsdirectoryw','getsystemdirectoryw',
}
_MSI_API_CRYPTO = {
    'cryptacquirecontextw','cryptacquirecontexta','cryptcreatehash','crypthashdata',
    'cryptderivekey','cryptencrypt','cryptdecrypt','cryptdestroykey','cryptdestroyhash',
    'cryptreleasecontext','cryptgenkey','cryptexportkey','cryptimportkey',
    'cryptencrypt','cryptdecrypt','cryptsetkeyparam',
}
_MSI_API_PROCESS = {
    'openprocess','terminateprocess','getcurrentprocess','getcurrentprocessid',
    'getmodulehandlew','getmodulehandlea','getmodulefilenamew','getmodulefilenamea',
    'exitprocess','getexitcodeprocess','waitforsingleobject','closehandle',
    'createfilew','createfilea','getlasterror','setlasterror',
    'getstartupinfow','getcommandlinew','getcommandlinea',
    'getenvironmentvariablew','setenvironmentvariablew',
    'globalalloc','globalfree','globallock','globalunlock',
    'heapalloc','heapfree','getprocessheap','heapcreate','heapdestroy',
    'multibytetowidechar','widechartomultibyte','lstrlenw','lstrlenw',
    'lstrcpyw','lstrcatw','lstrcmpw','lstrcmpiw',
}

def _analyze_msi_embedded(filepath):
    try:
        import struct as _struct
        fsize = os.path.getsize(filepath)
        read_size = min(fsize, 80*1024*1024)
        with open(filepath, 'rb') as f:
            data = f.read(read_size)
        pe_offsets = []
        idx = 0
        while True:
            pos = data.find(b'MZ', idx)
            if pos == -1:
                break
            try:
                if pos + 64 < len(data):
                    pe_off = _struct.unpack_from('<I', data, pos + 60)[0]
                    if pe_off < 1024 and pos + pe_off + 4 <= len(data):
                        if data[pos + pe_off:pos + pe_off + 4] == b'PE\x00\x00':
                            pe_offsets.append(pos)
            except:
                pass
            idx = pos + 2
            if len(pe_offsets) > 50:
                break
        if not pe_offsets:
            return None
        import pefile
        all_apis = set()
        pe_count = 0
        dll_pe_count = 0
        obfuscated_pe_count = 0
        packed_section_count = 0
        high_entropy_count = 0
        has_exports = False
        zero_import_pe_count = 0
        for i, off in enumerate(pe_offsets):
            end = pe_offsets[i+1] if i+1 < len(pe_offsets) else len(data)
            pe_data = data[off:end]
            if len(pe_data) < 512:
                continue
            try:
                pe = pefile.PE(data=pe_data, fast_load=True)
                pe.parse_data_directories(directories=[
                    pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT'],
                    pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_EXPORT'],
                ])
                pe_count += 1
                if pe.is_dll():
                    dll_pe_count += 1
                _pe_imp_count = 0
                if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                    for entry in pe.DIRECTORY_ENTRY_IMPORT:
                        for imp in entry.imports:
                            if imp.name:
                                all_apis.add(imp.name.decode('utf-8', 'ignore'))
                                _pe_imp_count += 1
                if _pe_imp_count == 0:
                    zero_import_pe_count += 1
                if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT') and pe.DIRECTORY_ENTRY_EXPORT and pe.DIRECTORY_ENTRY_EXPORT.symbols:
                    has_exports = True
                _pe_packed = False
                _pe_obf = False
                for sec in pe.sections:
                    sn = sec.Name.decode('utf-8', 'ignore').rstrip('\x00')
                    try:
                        clean = sn.encode('ascii').isascii() and all(c.isalnum() or c == '.' or c == '_' for c in sn)
                    except:
                        clean = False
                    if not clean and (sec.SizeOfRawData > 512 or sec.Misc_VirtualSize > 10000):
                        _pe_obf = True
                    if sec.SizeOfRawData == 0 and sec.Misc_VirtualSize > 50000:
                        _pe_packed = True
                    if sec.SizeOfRawData > 50000:
                        try:
                            entropy = sec.get_entropy()
                            if entropy > 7.5:
                                high_entropy_count += 1
                        except:
                            pass
                if _pe_obf:
                    obfuscated_pe_count += 1
                if _pe_packed:
                    packed_section_count += 1
                pe.close()
            except:
                try:
                    _pe_off_val = _struct.unpack_from('<I', pe_data, 60)[0]
                    if _pe_off_val < 1024 and _pe_off_val + 264 <= len(pe_data):
                        _num_sec_f = _struct.unpack_from('<H', pe_data, _pe_off_val + 6)[0]
                        _opt_size_f = _struct.unpack_from('<H', pe_data, _pe_off_val + 20)[0]
                        _sec_start_f = _pe_off_val + 24 + _opt_size_f
                        pe_count += 1
                        _has_obf_f = False
                        _has_packed_f = False
                        for _si_f in range(min(_num_sec_f, 96)):
                            _so_f = _sec_start_f + _si_f * 40
                            if _so_f + 40 > len(pe_data):
                                break
                            _sn_f = pe_data[_so_f:_so_f+8].decode('latin-1', errors='ignore').rstrip('\x00')
                            _sv_f = _struct.unpack_from('<I', pe_data, _so_f+8)[0]
                            _sr_f = _struct.unpack_from('<I', pe_data, _so_f+16)[0]
                            _clean_f = all(c.isalnum() or c == '.' or c == '_' for c in _sn_f) if _sn_f else False
                            if not _clean_f and (_sr_f > 512 or _sv_f > 10000):
                                _has_obf_f = True
                            if _sr_f == 0 and _sv_f > 50000:
                                _has_packed_f = True
                        if _has_obf_f:
                            obfuscated_pe_count += 1
                        if _has_packed_f:
                            packed_section_count += 1
                        zero_import_pe_count += 1
                        _MSI_FB_APIS = [b'connect', b'send', b'recv', b'WSAStartup', b'socket',
                            b'CreateProcessW', b'CreateThread', b'VirtualAlloc', b'VirtualProtect',
                            b'WriteProcessMemory', b'LoadLibraryW', b'GetProcAddress',
                            b'IsDebuggerPresent', b'CreateFileW', b'WriteFile',
                            b'RegSetValueExW', b'ShellExecuteW', b'OpenProcessToken',
                            b'AdjustTokenPrivileges', b'CryptEncrypt', b'EncryptFile']
                        for _fa in _MSI_FB_APIS:
                            if _fa in pe_data:
                                all_apis.add(_fa.decode('ascii'))
                except:
                    pass
                continue
        api_lower = set(a.lower() for a in all_apis)
        inj = api_lower & _MSI_API_INJECTION
        net = api_lower & _MSI_API_NETWORK
        pers = api_lower & _MSI_API_PERSISTENCE
        anti = api_lower & _MSI_API_ANTIDEBUG
        res = api_lower & _MSI_API_RESOURCE
        file_apis = api_lower & _MSI_API_FILE
        crypto_apis = api_lower & _MSI_API_CRYPTO
        proc_apis = api_lower & _MSI_API_PROCESS
        return {
            'pe_count': pe_count,
            'dll_pe_count': dll_pe_count,
            'obfuscated_pe_count': obfuscated_pe_count,
            'packed_section_count': packed_section_count,
            'high_entropy_count': high_entropy_count,
            'zero_import_pe_count': zero_import_pe_count,
            'has_exports': has_exports,
            'total_apis': len(all_apis),
            'injection_apis': sorted(inj),
            'network_apis': sorted(net),
            'persistence_apis': sorted(pers),
            'antidebug_apis': sorted(anti),
            'resource_apis': sorted(res),
            'file_apis': sorted(file_apis),
            'crypto_apis': sorted(crypto_apis),
            'process_apis': sorted(proc_apis),
            'all_apis': sorted(all_apis),
        }
    except Exception:
        return None

def _compute_entropy(data):
    if not data: return 0.0
    counts = Counter(data)
    total = len(data)
    entropy = 0.0
    for count in counts.values():
        if count > 0:
            p = count / total
            entropy -= p * math.log2(p)
    return entropy
PACKER_SIGNATURES = {
    'UPX': [b'UPX0',b'UPX1',b'UPX2',b'UPX!',b'\x55\x50\x58'],
    'ASPack': [b'.aspack',b'ASPack',b'.adata'],
    'Themida/WinLicense': [b'.themida',b'.winlice',b'Themida',b'WinLicense'],
    'VMProtect': [b'.vmp0',b'.vmp1',b'.vmp2',b'VMProtect',b'.vmp'],
    'Enigma': [b'.enigma1',b'.enigma2',b'Enigma',b'.enigm'],
    'MPRESS': [b'.MPRESS1',b'.MPRESS2',b'MPRESS'],
    'PECompact': [b'pec1',b'pec2',b'PECompact',b'PEC2'],
    'Petite': [b'.petite',b'Petite'],
    'NSIS': [b'Nullsoft',b'NSIS',b'nsis.sf',b'NullsoftInst'],
    'InnoSetup': [b'Inno Setup',b'innosetup',b'My Inno'],
    'SmartAssembly': [b'SmartAssembly',b'{smartassembly}'],
    'Confuser': [b'Confuser',b'ConfuserEx'],
    'Obsidium': [b'.obsidium',b'Obsidium'],
    'Molebox': [b'Molebox',b'.molebox'],
    'Armadillo': [b'Armadillo',b'.armadillo'],
    'tElock': [b'tElock',b'.telock'],
    'PESpin': [b'PESpin',b'.pespin'],
    'RLPack': [b'RLPack'],
    'WinUpack': [b'.winupack',b'WinUpack',b'.Upack'],
}

class EntropyAnalyzer:
    @staticmethod
    def analyze(filepath, raw_data=None):
        try:
            if raw_data is None:
                with open(filepath, 'rb') as f:
                    data = f.read(min(0x200000, os.path.getsize(filepath)))
            else:
                data = raw_data[:0x200000]
            if not data: return 0.0, ""
            total_entropy = _compute_entropy(data)
            chunk_size = 4096
            chunk_entropies = []
            for i in range(0, min(len(data), 0x100000), chunk_size):
                chunk = data[i:i+chunk_size]
                if chunk: chunk_entropies.append(_compute_entropy(chunk))
            max_chunk = max(chunk_entropies) if chunk_entropies else 0
            avg_chunk = sum(chunk_entropies)/len(chunk_entropies) if chunk_entropies else 0
            verdict = ""
            if total_entropy > 7.5: verdict = f"({total_entropy:.1f})_HIGH_/"
            elif total_entropy > 7.0: verdict = f"({total_entropy:.1f})_HIGH"
            elif max_chunk > 7.5 and avg_chunk < 6.0: verdict = f"({max_chunk:.1f})_HIGH"
            return total_entropy, verdict
        except:
            return 0.0, ""

class PackerDetector:
    @staticmethod
    def detect(filepath, pe=None):
        results = []
        try:
            if pe is not None:
                for section in pe.sections:
                    sname = section.Name.decode('utf-8','ignore').rstrip('\x00').lower()
                    for packer, sigs in PACKER_SIGNATURES.items():
                        for sig in sigs:
                            sl = sig.decode('utf-8','ignore').lower() if isinstance(sig, bytes) else sig.lower()
                            if sl in sname or sname.startswith(sl.lstrip('.')):
                                if packer not in [r[0] for r in results]:
                                    results.append((packer, '', 85))
            try:
                with open(filepath, 'rb') as f: head = f.read(0x2000)
            except: head = b''
            if head:
                hl = head.lower()
                for packer, sigs in PACKER_SIGNATURES.items():
                    for sig in sigs:
                        sl = sig.decode('utf-8','ignore').lower() if isinstance(sig, bytes) else sig.lower()
                        if sl.encode('utf-8','ignore') in hl or (isinstance(sig, bytes) and sig in head):
                            if packer not in [r[0] for r in results]:
                                results.append((packer, '', 90)); break
            fname = os.path.basename(filepath).lower()
            for pk in ['upx','aspack','themida','vmprotect','enigma']:
                if pk in fname and pk not in [r[0] for r in results]:
                    results.append((pk.title(), '', 60))
        except: pass
        return results

FILE_MAGIC_DB = {
    b'MZ': ['.exe','.dll','.sys','.ocx','.scr','.cpl','.drv','.com','.pyd','.msp','.mui'],
    b'PK\x03\x04': ['.zip','.docx','.xlsx','.pptx','.jar','.apk','.odt'],
    b'Rar!\x1a\x07': ['.rar'],
    b'\x89PNG\r\n\x1a\n': ['.png'],
    b'\xFF\xD8\xFF': ['.jpg','.jpeg','.jfif'],
    b'GIF89a': ['.gif'], b'GIF87a': ['.gif'],
    b'%PDF': ['.pdf'],
    b'\xD0\xCF\x11\xE0': ['.doc','.xls','.ppt','.msi'],
}

def check_file_disguise(filepath):
    ext = os.path.splitext(filepath)[1].lower()
    if not ext: return ""
    try:
        with open(filepath, 'rb') as f: header = f.read(16)
        if not header: return ""
        for magic, valid_exts in FILE_MAGIC_DB.items():
            if header.startswith(magic):
                if ext not in valid_exts:
                    return f":{ext}({','.join(valid_exts[:3])})"
                return ""
        return ""
    except: return ""

def _run_pe_heuristic(file_path):
    if is_system_path(file_path):
        return False, 0, "", []
    if _is_security_tool_component(file_path):
        return False, 0, "", []
    try:
        import pefile
        pe = pefile.PE(file_path, fast_load=True)
        score = 0; reasons = []; imports = []
        raw_data = None; has_trusted_sig = False; signer = None
        try:
            with open(file_path, 'rb') as rf: raw_data = rf.read()
        except: pass

        TRUSTED = {'microsoft','google','apple','mozilla','adobe','oracle','intel','nvidia','amd','vmware','hp','dell','lenovo','ibm','cisco','avast','avg','avira','bitdefender','kaspersky','eset','mcafee','symantec','norton','malwarebytes','trend micro','sophos','fortinet','check point','palo alto','crowdstrike','sentinelone','jetbrains','github','gitlab','atlassian','slack','zoom','dropbox','notion','spotify','discord','valve','epic games','electronic arts','ubisoft','blizzard','riot games','rockstar','autodesk','maxon','serif','ableton','native instruments','docker','hashicorp','red hat','canonical','apache','python software foundation','node.js','inno setup','nullsoft','7-zip','winrar','winzip','realvnc','teamviewer','anydesk','splashtop','logmein','citrix','mikrotik','ubiquiti','tp-link','netgear','d-link','asus','synology','qnap','obs project','videolan','mozilla corporation','tencent','baidu','qihoo','kingsoft','huawei','xiaomi','sandboxie','sandboxie holdings','qt group','the qt company','nuitka','pyinstaller'}
        signer = _extract_signer(file_path)
        if signer:
            sl = signer.lower()
            for t in TRUSTED:
                if t in sl:
                    has_trusted_sig = True; reasons.append(f":{signer[:40]}"); break
        if has_trusted_sig:
            pe.close(); return False, 0, f":{signer[:30] if signer else ''}", []

        normal_sections = {b'.text',b'.rdata',b'.data',b'.pdata',b'.rsrc',b'.reloc',b'.edata',b'.idata',b'.bss',b'.tls',b'.CRT',b'.gfids',b'.00cfg'}
        for section in pe.sections:
            name_bytes = section.Name.rstrip(b'\x00')
            if name_bytes not in normal_sections and not name_bytes.startswith(b'.text$') and not name_bytes.startswith(b'.data$') and not name_bytes.startswith(b'.rdata$'):
                name = section.Name.decode('utf-8','ignore').rstrip('\x00')
                score += 3; reasons.append(f":{name}"); break

        for section in pe.sections:
            if bool(section.Characteristics & 0x20000000) and bool(section.Characteristics & 0x80000000):
                sname = section.Name.decode('utf-8','ignore').rstrip('\x00')
                score += 15; reasons.append(f"RWX:{sname}"); break

        try:
            ep = pe.OPTIONAL_HEADER.AddressOfEntryPoint
            for section in pe.sections:
                if section.VirtualAddress <= ep < section.VirtualAddress + section.Misc_VirtualSize:
                    ep_section = section.Name.decode('utf-8','ignore').rstrip('\x00')
                    if ep_section.lower() not in ('.text','.code',''):
                        score += 4; reasons.append(f":{ep_section}")
                    break
        except: pass

        try:
            pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_TLS']])
            if hasattr(pe, 'DIRECTORY_ENTRY_TLS') and pe.DIRECTORY_ENTRY_TLS.struct.AddressOfCallBacks:
                score += 5; reasons.append("TLS")
        except: pass

        for section in pe.sections:
            sname = section.Name.decode('utf-8','ignore').rstrip('\x00').lower()
            try:
                se = section.get_entropy()
                sr = section.SizeOfRawData
                if sname == '.rdata' and se > 7.8 and sr > 500000:
                    score += 12; reasons.append(f"RDATA:{se:.1f}")
            except: pass

        if raw_data:
            try:
                ev = _compute_entropy(raw_data[:0x100000])
                if ev > 7.5: score += 8; reasons.append(f":{ev:.1f}(/)")
                elif ev > 7.0: score += 4; reasons.append(f":{ev:.1f}()")
            except: pass

        packer_sections = {'UPX0','UPX1','UPX2','.aspack','.petite','.MPRESS1','.MPRESS2','.themida','.vmp0','.vmp1','.enigma1','.enigma2','.nsp0','.nsp1','.nsp2','.packed','pec1','pec2','.wwpack','.sforce'}
        for section in pe.sections:
            sname = section.Name.decode('utf-8','ignore').rstrip('\x00')
            if any(p.lower() in sname.lower() for p in packer_sections):
                score += 5; reasons.append(f":{sname}"); break

        injection_apis = {'CreateRemoteThread','WriteProcessMemory','VirtualAllocEx','QueueUserAPC','NtCreateThreadEx','RtlCreateUserThread','SetThreadContext','NtUnmapViewOfSection','NtWriteVirtualMemory'}
        anti_analysis_apis = {'IsDebuggerPresent','CheckRemoteDebuggerPresent','NtQueryInformationProcess','NtSetInformationThread','NtQuerySystemInformation'}
        keylog_apis = {'SetWindowsHookEx','GetAsyncKeyState','GetKeyState','GetForegroundWindow','GetClipboardData','GetRawInputData'}
        credential_apis = {'CredEnumerate','CredRead','CryptUnprotectData','LsaOpenPolicy','LsaRetrievePrivateData','SamOpenUser'}
        privilege_apis = {'OpenProcessToken','AdjustTokenPrivileges','LookupPrivilegeValueW','SeDebugPrivilege','ImpersonateLoggedOnUser','SetTokenInformation'}
        try:
            pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT']])
            if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                dll_names = set(); import_count = 0
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    if entry.dll: dll_names.add(entry.dll.decode('utf-8','ignore').lower())
                    for imp in entry.imports:
                        if imp.name:
                            imports.append(imp.name.decode('utf-8','ignore')); import_count += 1
                if import_count > 0 and import_count < 3:
                    score += 8; reasons.append(f"({import_count}API)")
                found_inject = [a for a in imports if a in injection_apis]
                if found_inject: score += 22; reasons.append(f":{','.join(found_inject[:3])}")
                found_anti = [a for a in imports if a in anti_analysis_apis]
                if len(found_anti) >= 2: score += 12; reasons.append(f":{','.join(found_anti[:2])}")
                elif len(found_anti) >= 1: score += 6; reasons.append(f":{','.join(found_anti[:1])}")
                found_keylog = [a for a in imports if a in keylog_apis]
                if len(found_keylog) >= 3: score += 30; reasons.append(f":{','.join(found_keylog[:3])}")
                elif len(found_keylog) >= 2: score += 22; reasons.append(f":{','.join(found_keylog[:3])}")
                elif len(found_keylog) >= 1: score += 12; reasons.append(f":{','.join(found_keylog[:2])}")
                found_cred = [a for a in imports if a in credential_apis]
                if found_cred: score += 22; reasons.append(f":{','.join(found_cred[:2])}")
                found_priv = [a for a in imports if a in privilege_apis]
                if len(found_priv) >= 2: score += 12; reasons.append(f":{','.join(found_priv[:2])}")
                if 'CreateProcessW' in imports and 'CreateThread' in imports:
                    score += 8; reasons.append("CreateProcess+CreateThread")
        except: pass

        try:
            if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
                for resource_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
                    if resource_type.id == pefile.RESOURCE_TYPE.get('RT_RCDATA', 10):
                        for res in resource_type.directory.entries:
                            for res_entry in res.directory.entries:
                                try:
                                    data_rva = res_entry.data.struct.OffsetToData
                                    size = res_entry.data.struct.Size
                                    if size > 0x200:
                                        data = pe.get_data(data_rva, min(size, 0x200))
                                        if data[:2] == b'MZ':
                                            score += 25; reasons.append("PE()")
                                            break
                                except: pass
        except: pass

        try:
            raw_size = os.path.getsize(file_path)
            virtual_size = sum(s.Misc_VirtualSize for s in pe.sections)
            if raw_size > 0 and virtual_size/raw_size > 15:
                score += 4; reasons.append(f":{virtual_size/raw_size:.0f}x")
        except: pass

        try:
            pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_EXPORT']])
            if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
                export_count = len(pe.DIRECTORY_ENTRY_EXPORT.symbols) if pe.DIRECTORY_ENTRY_EXPORT.symbols else 0
                is_dll = bool(pe.FILE_HEADER.Characteristics & 0x2000)
                if not is_dll and export_count > 10: score += 4; reasons.append(f"DLL{export_count}")
        except: pass

        try:
            import datetime
            dt = datetime.datetime.fromtimestamp(pe.FILE_HEADER.TimeDateStamp, tz=datetime.timezone.utc)
            if dt.year < 2000 or dt.year > 2030: score += 2; reasons.append(f":{dt.year}")
        except: pass

        pe.close()
        is_driver = file_path.lower().endswith('.sys')
        threshold = 35 if is_driver else 45
        if score >= threshold:
            confidence = min(90, 30 + score)
            return True, confidence, ";".join(reasons), imports
        return False, 0, ";".join(reasons) if reasons else "", imports
    except Exception as e:
        logger.debug(f"PE {file_path}: {e}")
        return False, 0, "", []

def _run_pe_analysis(file_path):
    return _run_pe_heuristic(file_path)
class YaraScanner:
    def __init__(self, rules_dir):
        self.rules = None
        self.available = False
        self.load_rules(rules_dir)
    def load_rules(self, rules_dir):
        try:
            import yara
            rule_sources = {}
            if os.path.exists(rules_dir):
                for f in os.listdir(rules_dir):
                    if f.endswith(('.yar', '.yara')):
                        full = os.path.join(rules_dir, f)
                        try:
                            with open(full, 'rb') as rf:
                                content = rf.read()
                                for enc in ('utf-8', 'gbk', 'latin-1'):
                                    try:
                                        decoded = content.decode(enc)
                                        break
                                    except:
                                        continue
                                else:
                                    decoded = content.decode('utf-8', errors='ignore')
                                rule_sources[f] = decoded
                        except:
                            continue
                if rule_sources:
                    successful = {}
                    for name, src in rule_sources.items():
                        try:
                            yara.compile(source=src)
                            successful[name] = src
                        except:
                            pass
                    if successful:
                        self.rules = yara.compile(sources=successful)
                        self.available = True
        except:
            pass
    def scan(self, filepath):
        if not self.available:
            return None, 0, ""
        try:
            matches = self.rules.match(filepath)
            if matches:
                return matches[0].rule, 90, matches[0].rule
        except:
            pass
        return None, 0, ""
# === Custom native rule engine (replaces YARA) ===
# Zero-dependency byte/hex/string pattern matching. Author rules in
# `custom_rules/*.srule`. No external library, no compiler, easy to extend.
#
# Rule format (.srule):
#   rule Macro_OLE_VBA {            # rule name (letters/digits/_./-)
#       type = macro                # threat type label
#       severity = 92               # confidence 0-100
#       magic = D0CF11E0A1B11AE1    # file must start with these bytes (hex)
#       hex = D0 CF 11 E0 A1 B1 1A E1   # hex pattern (all `hex` must match, AND)
#       str = AutoOpen              # ASCII substring (any str/wide may match, OR)
#       str = AutoExec
#       wide = Attribut             # UTF-16LE substring
#       at = 0                      # first hex pattern must sit at this offset
#   }
# Hex wildcards: `??` or `*` = any byte. `magic` is sugar for hex@offset0.
import re as _re

def _parse_hex_pattern(tok):
    """Parse a hex token (with optional spaces / ':' / wildcards) -> (bytes, mask)."""
    t = tok.strip().lower().replace(':', '').replace(' ', '')
    if not t or len(t) % 2 != 0:
        return None
    out = bytearray()
    mask = bytearray()
    for i in range(0, len(t), 2):
        pair = t[i:i + 2]
        if pair in ('??', '**', '*'):
            out.append(0)
            mask.append(0)
        else:
            try:
                b = int(pair, 16)
            except ValueError:
                return None
            out.append(b)
            mask.append(1)
    return bytes(out), bytes(mask)

def _match_at(data, pattern, mask, i):
    for j in range(len(pattern)):
        if mask[j] and data[i + j] != pattern[j]:
            return False
    return True

def _hex_search(data, pattern, mask, at=None):
    """Return first offset where pattern matches (mask: 1=exact, 0=wildcard)."""
    n = len(pattern)
    dlen = len(data)
    if at is not None:
        if at < 0:
            at = dlen + at
        if at < 0 or at + n > dlen:
            return -1
        return at if _match_at(data, pattern, mask, at) else -1
    if n > dlen:
        return -1
    anchor = mask.find(1)
    if anchor < 0:
        anchor = 0
    aval = pattern[anchor]
    last = dlen - n
    i = 0
    while i <= last:
        if data[i + anchor] != aval:
            i += 1
            continue
        if _match_at(data, pattern, mask, i):
            return i
        i += 1
    return -1

class _CustomRule:
    __slots__ = ('name', 'rtype', 'severity', 'hexes', 'strs', 'wides', 'magic', 'at')
    def __init__(self, name, rtype, severity, hexes, strs, wides, magic, at):
        self.name = name
        self.rtype = rtype
        self.severity = severity
        self.hexes = hexes
        self.strs = strs
        self.wides = wides
        self.magic = magic
        self.at = at
    def match(self, data):
        if self.magic and data[:len(self.magic)] != self.magic:
            return False
        for k, (pattern, mask) in enumerate(self.hexes):
            off = self.at if k == 0 else None
            if _hex_search(data, pattern, mask, off) < 0:
                return False
        if self.strs or self.wides:
            found = False
            for s in self.strs:
                if s in data:
                    found = True
                    break
            if not found:
                for w in self.wides:
                    if w in data:
                        found = True
                        break
            if not found:
                return False
        return True

class CustomRuleScanner:
    def __init__(self, rules_dir, cap=None):
        self.rules_dir = rules_dir
        self.cap = cap if cap is not None else CONFIG.get("custom_rule_scan_cap", 16 * 1024 * 1024)
        self.rules = []
        self.available = False
        self.load_rules(rules_dir)
    def load_rules(self, rules_dir):
        self.rules = []
        if not os.path.isdir(rules_dir):
            return
        for fn in sorted(os.listdir(rules_dir)):
            if not fn.endswith('.srule'):
                continue
            full = os.path.join(rules_dir, fn)
            try:
                with open(full, 'r', encoding='utf-8', errors='ignore') as f:
                    text = f.read()
            except Exception:
                continue
            self.rules.extend(self._parse_srule(text, fn))
        self.available = len(self.rules) > 0
        if self.available:
            print(f"[CUSTOM] 已加载 {len(self.rules)} 条自定义规则 (来自 {rules_dir})")
    def _parse_srule(self, text, srcname):
        rules = []
        idx = 0
        while True:
            m = _re.search(r'rule\s+([A-Za-z0-9_.\-]+)\s*\{', text[idx:])
            if not m:
                break
            name = m.group(1)
            start = idx + m.end()
            end = text.find('}', start)
            if end < 0:
                break
            body = text[start:end]
            idx = end + 1
            rtype = 'virus'
            severity = 90
            hexes = []
            strs = []
            wides = []
            magic = None
            at = None
            for line in body.splitlines():
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                if '=' not in line:
                    continue
                k, v = line.split('=', 1)
                k = k.strip().lower()
                v = v.strip()
                if k == 'type':
                    rtype = v
                elif k == 'severity':
                    try:
                        severity = int(float(v))
                    except ValueError:
                        severity = 90
                elif k == 'hex':
                    p = _parse_hex_pattern(v)
                    if p:
                        hexes.append(p)
                    else:
                        print(f"[CUSTOM] 警告: 规则 {name} ({srcname}) 的 hex 值 '{v}' 不是合法十六进制，已忽略")
                elif k == 'magic':
                    p = _parse_hex_pattern(v)
                    if p:
                        magic = p[0]
                    else:
                        print(f"[CUSTOM] 警告: 规则 {name} ({srcname}) 的 magic 值 '{v}' 不是合法十六进制，已忽略(规则退化为无头约束!)")
                elif k == 'str':
                    strs.append(v.encode('latin-1', 'ignore'))
                elif k == 'wide':
                    wides.append(v.encode('utf-16-le'))
                elif k == 'at':
                    try:
                        at = int(v)
                    except ValueError:
                        at = None
            if hexes or strs or wides or magic:
                rules.append(_CustomRule(name, rtype, severity, hexes, strs, wides, magic, at))
            else:
                print(f"[CUSTOM] 规则 {name} ({srcname}) 无有效匹配条件，跳过")
        return rules
    def scan(self, filepath):
        if not self.rules:
            return None, 0, ""
        try:
            sz = os.path.getsize(filepath)
        except Exception:
            return None, 0, ""
        if sz == 0:
            return None, 0, ""
        try:
            with open(filepath, 'rb') as f:
                if sz <= self.cap:
                    data = f.read()
                else:
                    head = f.read(self.cap)
                    f.seek(max(0, sz - 524288))
                    tail = f.read()
                    data = head + tail
        except Exception:
            return None, 0, ""
        for r in self.rules:
            if r.match(data):
                return r.name, r.severity, r.name
        return None, 0, ""
DEFAULT_FEATURES = r"""
[恶意程序]  = "asyncrat", "remcos", "quasar" 9
...
"""
DEFAULT_JSON_SIGNATURES = {
    "version": "1.0",
    "metadata": {"name": "PASW  (JSON)"},
    "signatures": [],
    "combo_signatures": [],
    "lore_patterns": []
}

class AdvancedSignatureScanner:
    def __init__(self, features_dir):
        self.single_signatures = []
        self.combo_signatures = []
        self.lore_patterns = []
        self.available = False
        self.lock = threading.Lock()
        self.load_signatures(features_dir)
    def _parse_pattern(self, pattern_str):
        pattern_str = pattern_str.strip()
        if not pattern_str:
            return None
        if pattern_str.startswith('"') and pattern_str.endswith('"'):
            return pattern_str[1:-1].encode('utf-8', errors='ignore')
        hex_part = re.sub(r'[^0-9A-Fa-f]', '', pattern_str)
        if len(hex_part) >= 4 and len(hex_part) % 2 == 0:
            try:
                return bytes.fromhex(hex_part)
            except:
                pass
        return pattern_str.encode('utf-8', errors='ignore')
    def _is_valid_pattern(self, pattern_bytes):
        return pattern_bytes and len(pattern_bytes) >= CONFIG["signature_min_pattern_len"]
    def load_signatures(self, features_dir):
        if (not CONFIG["enable_stu_txt_scanner"] and not CONFIG["enable_json_scanner"]) or not os.path.exists(features_dir):
            return
        single = []
        combo = []
        lore = []
        for root, _, files in os.walk(features_dir):
            for f in files:
                full_path = os.path.join(root, f)
                ext = os.path.splitext(f)[1].lower()
                try:
                    if ext == '.json' and CONFIG["enable_json_scanner"]:
                        with open(full_path, 'r', encoding='utf-8', errors='ignore') as fp:
                            data = json.load(fp)
                        if isinstance(data, dict):
                            for sig in data.get('signatures', []):
                                p = self._parse_pattern(sig.get('pattern', ''))
                                if p and self._is_valid_pattern(p):
                                    single.append((sig.get('threat', ''), p, int(sig.get('weight', 5))))
                            for cs in data.get('combo_signatures', []):
                                patterns = [self._parse_pattern(p) for p in cs.get('patterns', [])]
                                patterns = [p for p in patterns if p and self._is_valid_pattern(p)]
                                if len(patterns) >= CONFIG["combo_required_matches"]:
                                    combo.append((cs.get('threat', ''), patterns, int(cs.get('weight', 8))))
                        continue
                    if ext == '.stu' and CONFIG["enable_stu_txt_scanner"]:
                        with open(full_path, 'r', encoding='utf-8', errors='ignore') as fp:
                            for line in fp:
                                line = line.strip()
                                if not line or line.startswith('#'):
                                    continue
                                if line.startswith('[Lore]'):
                                    rest = line[6:].strip()
                                    pat_str = rest.split()[0] if rest else ''
                                    if pat_str:
                                        pb = self._parse_pattern(pat_str)
                                        if pb:
                                            lore.append(pb)
                                    continue
                                if line.startswith('[]'):
                                    m = re.match(r'^\[\]\s*([^=]+?)\s*=\s*(.+?)(?:\s+(\d+))?$', line)
                                    if m:
                                        threat = m.group(1).strip()
                                        parts = m.group(2).strip()
                                        w = int(m.group(3)) if m.group(3) and m.group(3).isdigit() else 8
                                        w = max(CONFIG["signature_min_confidence"], min(w, CONFIG["signature_max_confidence"]))
                                        patterns = [self._parse_pattern(p.strip()) for p in re.split(r'\s*,\s*', parts)]
                                        patterns = [p for p in patterns if p and self._is_valid_pattern(p)]
                                        if len(patterns) >= CONFIG["combo_required_matches"]:
                                            combo.append((threat, patterns, w))
                                    continue
                                if line.startswith('['):
                                    end = line.find(']')
                                    if end == -1:
                                        continue
                                    threat = line[1:end].strip()
                                    rest = line[end+1:].strip()
                                    if not rest:
                                        continue
                                    weight = 5
                                    pattern_str = rest
                                    space = rest.rfind(' ')
                                    if space > 0 and rest[space+1:].isdigit():
                                        weight = int(rest[space+1:])
                                        pattern_str = rest[:space].strip()
                                    weight = max(CONFIG["signature_min_confidence"], min(weight, CONFIG["signature_max_confidence"]))
                                    pb = self._parse_pattern(pattern_str)
                                    if pb and self._is_valid_pattern(pb):
                                        single.append((threat, pb, weight))
                                else:
                                    weight = 5
                                    pattern_str = line
                                    space = line.rfind(' ')
                                    if space > 0 and line[space+1:].isdigit():
                                        weight = int(line[space+1:])
                                        pattern_str = line[:space].strip()
                                    weight = max(CONFIG["signature_min_confidence"], min(weight, CONFIG["signature_max_confidence"]))
                                    pb = self._parse_pattern(pattern_str)
                                    if pb and self._is_valid_pattern(pb):
                                        single.append(("", pb, weight))
                except:
                    continue
        self.single_signatures = single
        self.combo_signatures = combo
        self.lore_patterns = lore
        self.available = bool(single or combo)
    def scan(self, filepath, file_data=None):
        if not self.available:
            return None, 0, ""
        try:
            if file_data is None:
                with open(filepath, 'rb') as f:
                    content = f.read(CONFIG["read_chunk_size"])
            else:
                content = file_data
            if not content:
                return None, 0, ""
            for lp in self.lore_patterns:
                if lp in content:
                    return None, 0, ""
            best_conf = 0
            best_threat = None
            best_feature = ""
            for threat, pat, w in self.single_signatures:
                if pat in content:
                    if w > best_conf:
                        best_conf = w
                        best_threat = threat
                        best_feature = ""
            for threat, pats, w in self.combo_signatures:
                if all(p in content for p in pats):
                    if w > best_conf:
                        best_conf = w
                        best_threat = threat
                        best_feature = ""
            if best_conf > 0 and best_threat:
                final_conf = max(CONFIG["signature_min_confidence"], min(CONFIG["signature_max_confidence"], best_conf))
                if final_conf >= CONFIG["confidence_threshold"]:
                    return f"Advanced_{best_threat}", final_conf, best_feature
        except:
            pass
        return None, 0, ""
class StudyEngine:
    MAX_RECORDS = 50000
    def __init__(self, study_file):
        self.study_file = study_file
        self.records = {}
        self.path_index = {}
        self.hash_index = {}
        self.whitelist_paths = []
        self.lore_patterns = []
        self.lore_safe_patterns = []
        self.api_chains = {}
        self.suspicious_api_chains = {}
        self.lock = threading.Lock()
        self._dirty = False
        self.load()
    def load(self):
        if not CONFIG.get("enable_study_engine", True):
            return
        if os.path.exists(self.study_file):
            try:
                with open(self.study_file, 'r', encoding='utf-8') as f:
                    content = f.read()
                self.whitelist_paths = []
                self.lore_patterns = []
                self.lore_safe_patterns = []
                self.records = {}
                brace_idx = content.find('{')
                if brace_idx > 0:
                    path_section = content[:brace_idx]
                    for line in path_section.splitlines():
                        line = line.strip().strip('"').strip("'")
                        if line:
                            self.whitelist_paths.append(line)
                remaining = content[brace_idx:] if brace_idx >= 0 else content
                while True:
                    bi = remaining.find('{')
                    if bi < 0:
                        break
                    remaining = remaining[bi:]
                    brace_depth = 0
                    in_string = False
                    escape = False
                    json_end = -1
                    for i in range(len(remaining)):
                        c = remaining[i]
                        if escape:
                            escape = False
                            continue
                        if c == '\\':
                            escape = True
                            continue
                        if c == '"':
                            in_string = not in_string
                            continue
                        if in_string:
                            continue
                        if c == '{':
                            brace_depth += 1
                        elif c == '}':
                            brace_depth -= 1
                            if brace_depth == 0:
                                json_end = i + 1
                                break
                    if json_end > 0:
                        json_text = remaining[:json_end]
                        after_block = remaining[json_end:]
                        try:
                            data = json.loads(json_text)
                            if isinstance(data, dict) and 'records' in data:
                                for md5, rec in data['records'].items():
                                    if md5 not in self.records:
                                        self.records[md5] = rec
                            elif isinstance(data, dict):
                                for md5, rec in data.items():
                                    if md5 not in self.records:
                                        self.records[md5] = rec
                        except Exception:
                            pass
                        for line in after_block.splitlines():
                            line = line.strip()
                            if line.startswith('[Lore]'):
                                hex_str = line[6:].strip()
                                if hex_str:
                                    self.lore_patterns.append(hex_str)
                                    if not hex_str.upper().startswith('4D5A'):
                                        self.lore_safe_patterns.append(hex_str)
                        next_brace = after_block.find('{')
                        if next_brace < 0:
                            break
                        remaining = after_block[next_brace:]
                    else:
                        break
                self.path_index = {}
                for md5, rec in self.records.items():
                    fp = rec.get('filepath', '')
                    if fp:
                        self.path_index[fp] = md5
                    if rec.get('type', '') == 'Lore' or rec.get('category', '') == 'Lore':
                        lore_fp = rec.get('filepath', '')
                        if lore_fp:
                            self.whitelist_paths.append(lore_fp)
                self.api_chains = {}
                self.suspicious_api_chains = {}
                self.hash_index = {}
                for md5, rec in self.records.items():
                    rec_type = rec.get('type', '')
                    features = rec.get('features', [])
                    apis = set()
                    sus_apis = set()
                    for feat in features:
                        if feat.startswith('API{') and feat.endswith('}'):
                            apis.add(feat[4:-1])
                        elif feat.startswith('SuspiciousAPI{') and feat.endswith('}'):
                            sus_apis.add(feat[14:-1])
                    if apis:
                        self.api_chains[md5] = apis
                    if sus_apis:
                        self.suspicious_api_chains[md5] = sus_apis
                    hash_feat = None
                    for feat in features:
                        if feat.startswith('Hash{') and feat.endswith('}'):
                            hash_feat = feat[5:-1]
                            break
                    if hash_feat:
                        self.hash_index[hash_feat.lower()] = md5
            except Exception as e:
                logger.warning(f"Study engine load error: {e}")
                self.records = {}
                self.whitelist_paths = []
                self.lore_patterns = []
                self.lore_safe_patterns = []
        else:
            self.whitelist_paths = []
            self.lore_patterns = []
            self.lore_safe_patterns = []
    def save(self):
        return
        if not CONFIG.get("enable_study_engine", True):
            return
        try:
            os.makedirs(os.path.dirname(self.study_file), exist_ok=True)
            records_to_save = self.records
            if len(records_to_save) > self.MAX_RECORDS:
                sorted_recs = sorted(records_to_save.items(),
                                     key=lambda x: x[1].get('count', 0),
                                     reverse=True)
                records_to_save = dict(sorted_recs[:self.MAX_RECORDS])
            data = {
                "version": "1.0",
                "metadata": {
                    "name": "PASW Study Engine Records",
                    "total_records": len(records_to_save),
                    "last_updated": time.strftime("%Y-%m-%dT%H:%M:%S"),
                    "engine": "PeAV StudyEngine"
                },
                "records": records_to_save
            }
            with open(self.study_file, 'w', encoding='utf-8') as f:
                for path in self.whitelist_paths:
                    f.write(f'"{path}"\n')
                f.write('\n')
                json.dump(data, f, indent=2, ensure_ascii=False)
                for pattern in self.lore_patterns:
                    f.write(f'\n[Lore] {pattern}')
                f.write('\n')
            self._dirty = False
        except Exception as e:
            logger.warning(f"Study engine save error: {e}")
    def _get_file_hash(self, filepath):
        try:
            h = hashlib.md5()
            with open(filepath, 'rb') as f:
                chunk = f.read(1024 * 1024)
                h.update(chunk)
            return h.hexdigest()
        except:
            return None
    def record_result(self, filepath, threat_type, confidence, feature_str, category="Trojan"):
        if not CONFIG.get("enable_study_engine", True):
            return
        if not os.path.exists(filepath):
            return
        with self.lock:
            self._record_result_unlocked(filepath, threat_type, confidence, feature_str, category)
    def _record_result_unlocked(self, filepath, threat_type, confidence, feature_str, category="Trojan"):
        try:
            md5 = self._get_file_hash(filepath)
            if not md5:
                return
            import hashlib as _hl
            sha256 = _hl.sha256()
            with open(filepath, 'rb') as f:
                for chunk in iter(lambda: f.read(8192), b''):
                    sha256.update(chunk)
            sha256_val = sha256.hexdigest()
            
            pe_apis = []
            try:
                import pefile as _pf
                pe = _pf.PE(filepath, fast_load=True)
                pe.parse_data_directories(directories=[_pf.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT']])
                if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                    for entry in pe.DIRECTORY_ENTRY_IMPORT:
                        for imp in entry.imports:
                            if imp.name:
                                pe_apis.append(imp.name.decode('utf-8','ignore'))
                pe.close()
            except:
                pass
            
            features = [f"Hash{{{sha256_val}}}", f"Size{{{os.path.getsize(filepath)}}}", f"Extension{{{os.path.splitext(filepath)[1].lower()}}}"]
            for api in pe_apis[:50]:
                features.append(f"API{{{api}}}")
            
            suspicious_apis = {'CreateRemoteThread','WriteProcessMemory','VirtualAllocEx','NtCreateThreadEx',
                             'SetWindowsHookEx','GetAsyncKeyState','CredEnumerate','CryptUnprotectData',
                             'IsDebuggerPresent','AdjustTokenPrivileges','OpenProcessToken','CreateProcessW',
                             'ShellExecuteW','RegSetValueExW','URLDownloadToFileW','CryptEncrypt','CryptDecrypt',
                             'ShutdownBlockReasonCreate','SetEndOfFile','DeleteFileW'}
            for api in pe_apis:
                if api in suspicious_apis:
                    features.append(f"SuspiciousAPI{{{api}}}")
            
            existing = self.records.get(md5, {})
            count = existing.get('count', 0) + 1
            self.records[md5] = {
                'type': 'malicious',
                'threat_type': threat_type,
                'confidence': max(confidence, existing.get('confidence', 0)),
                'count': count,
                'filepath': filepath,
                'features': features if not existing.get('features') else existing.get('features'),
                'category': category,
                'last_seen': time.strftime('%Y-%m-%dT%H:%M:%S'),
            }
            self.path_index[filepath] = md5
            self.hash_index[sha256_val] = md5
            self._dirty = True
        except Exception as e:
            pass
    def get_boost(self, filepath):
        if not CONFIG.get("enable_study_engine", True):
            return 0
        md5 = self.path_index.get(filepath)
        if not md5 and os.path.exists(filepath):
            md5 = self._get_file_hash(filepath)
        if not md5 or md5 not in self.records:
            return 0
        rec = self.records[md5]
        threat = rec.get('threat_type', '')
        rtype = rec.get('type', '')
        conf = rec.get('confidence', 0)
        count = rec.get('count', 0)
        if rtype == 'malicious' or (threat and threat != "CLEAN"):
            if conf >= 50 or rtype == 'malicious':
                boost = min(20, 10 + count)
                return boost
        if (str(threat or '')).startswith("CLEAN") or (str(rtype or '')).startswith("CLEAN"):
            return 0
        return 0
    def is_lore_whitelisted(self, filepath):
        if not self.lore_safe_patterns:
            return False
        ext = os.path.splitext(filepath)[1].lower()
        if ext in {'.msi', '.exe', '.dll', '.sys', '.ocx', '.scr', '.cpl', '.drv', '.com', '.bat', '.cmd', '.ps1', '.vbs', '.js', '.vbe', '.wsf', '.hta', '.sct', '.wsc', '.doc', '.xls', '.ppt', '.docm', '.xlsm', '.pptm', '.docx', '.xlsx', '.pptx', '.dot', '.xlt', '.xlam', '.ods', '.odt'}:
            return False
        try:
            with open(filepath, 'rb') as f:
                header = f.read(64)
            header_hex = header.hex().upper()
            for pattern in self.lore_safe_patterns:
                if header_hex.startswith(pattern.upper()):
                    return True
        except Exception:
            pass
        return False
    def scan_precise(self, filepath):
        if not self.hash_index:
            return None, 0, ""
        try:
            h = hashlib.sha256()
            with open(filepath, 'rb') as f:
                while True:
                    chunk = f.read(1024 * 1024)
                    if not chunk:
                        break
                    h.update(chunk)
            file_hash = h.hexdigest().lower()
            md5 = self.hash_index.get(file_hash)
            if md5 and md5 in self.records:
                rec = self.records[md5]
                if rec.get('type') == 'malicious':
                    return rec.get('threat_type', 'Trojan'), 95, f"SE精确匹配: {md5[:8]}"
        except:
            pass
        return None, 0, ""
    def scan_api_chains(self, file_apis):
        if not self.api_chains or not file_apis:
            return None, 0, ""
        file_api_set = set(file_apis)
        common_apis = {'CloseHandle', 'CreateThread', 'VirtualAlloc', 'VirtualFree',
                       'GetLastError', 'GetProcAddress', 'LoadLibraryW', 'LoadLibraryExW',
                       'GetModuleHandleW', 'GetModuleHandleA', 'GetCurrentProcess',
                       'GetCurrentThread', 'GetSystemInfo', 'HeapAlloc', 'HeapFree',
                       'WaitForSingleObject', 'WaitForMultipleObjects', 'EnterCriticalSection',
                       'LeaveCriticalSection', 'DeleteCriticalSection', 'InitializeCriticalSection',
                       'GetTickCount', 'GetTickCount64', 'Sleep', 'OutputDebugStringW',
                       'GetEnvironmentVariableW', 'SetEnvironmentVariableW',
                       'GetConsoleMode', 'GetStdHandle', 'WriteFile', 'ReadFile',
                       'GetModuleFileNameW', 'GetModuleFileNameA', 'MultiByteToWideChar',
                       'WideCharToMultiByte', 'lstrlenW', 'lstrlenA', 'GetProcessId',
                       'GetCurrentProcessId', 'GetCurrentThreadId', 'GetEnvironmentStringsW',
                       'FreeEnvironmentStringsW', 'GetCommandLineW', 'GetCommandLineA',
                       'ExitProcess', 'CreateFileW', 'CreateFileA', 'DeviceIoControl',
                       'SetLastError', 'GetFileSize', 'GetFileSizeEx',
                       'CreateDirectoryW', 'DeleteFileW', 'MoveFileW', 'CopyFileW',
                       'FindFirstFileW', 'FindNextFileW', 'FindClose', 'GetCurrentDirectoryW',
                       'SetCurrentDirectoryW', 'GetTempPathW', 'GetWindowsDirectoryW',
                       'GetSystemDirectoryW', 'RegOpenKeyExW', 'RegCloseKey', 'RegQueryValueExW',
                       'RegSetValueExW', 'RegCreateKeyExW', 'RegDeleteKeyW', 'malloc', 'free',
                       'memcpy', 'memset', 'memcmp', 'memmove', 'strlen', 'strcpy', 'strcat',
                       'strcmp', 'strncmp', 'strstr', 'sprintf', 'printf', 'fprintf',
                       'fopen', 'fclose', 'fread', 'fwrite', 'fseek', 'ftell',
                       'IsDebuggerPresent', 'OpenProcessToken', 'TerminateProcess',
                       'AdjustTokenPrivileges', 'CheckRemoteDebuggerPresent', 'OpenProcess',
                       'SetThreadContext', 'GetAsyncKeyState', 'recv', 'send', 'connect'}
        best_conf = 0
        best_type = None
        best_md5 = None
        file_api_count = len(file_api_set)
        with self.lock:
            _chains_snapshot = list(self.api_chains.items())
        for md5, rec_apis in _chains_snapshot:
            rec = self.records.get(md5, {})
            if rec.get('type') != 'malicious':
                continue
            if len(rec_apis) < 5:
                continue
            common = file_api_set & rec_apis
            if len(common) < 5:
                continue
            sus_apis = self.suspicious_api_chains.get(md5, set())
            sus_match = len(file_api_set & sus_apis)
            unique_common = common - common_apis
            if len(unique_common) < 8:
                continue
            rec_coverage = len(common) / len(rec_apis)
            file_coverage = len(common) / file_api_count if file_api_count else 0
            if rec_coverage < 0.85:
                continue
            if sus_match < 2:
                continue
            unique_ratio = len(unique_common) / len(common) if common else 0
            conf = int(rec_coverage * 40 + file_coverage * 20 + unique_ratio * 10 + sus_match * 15 + min(10, rec.get('count', 0)))
            if rec_coverage >= 0.95:
                conf += 15
            conf = min(95, conf)
            if conf > best_conf and conf >= 80:
                best_conf = conf
                best_type = rec.get('threat_type', 'Trojan')
                best_md5 = md5
        if best_type:
            return best_type, best_conf, f"SE API: {best_md5[:8]} ({best_conf}%)"
        return None, 0, ""
class OnnxScanner:
    def __init__(self, model_dir):
        self.session = None
        self.available = False
        self.threshold = 0.75
        self.feature_extractor = None
        self.load_model(model_dir)
    def load_model(self, model_dir):
        try:
            import onnxruntime as ort
            import numpy as np
            if not os.path.exists(model_dir):
                return
            models = [f for f in os.listdir(model_dir) if f.endswith('.onnx')]
            if not models:
                return
            self.session = ort.InferenceSession(os.path.join(model_dir, models[0]), providers=['CPUExecutionProvider'])
            self.available = True
            threshold_path = os.path.join(model_dir, 'threshold.json')
            if os.path.exists(threshold_path):
                import json
                with open(threshold_path, 'r') as f:
                    td = json.load(f)
                    self.threshold = td.get('threshold', 0.75)
            try:
                sys.path.insert(0, BASE_DIR if 'BASE_DIR' in dir() else os.path.dirname(os.path.abspath(__file__)))
                from ONNX.onnx_feature_extractor import extract_features, FEATURE_SIZE
                self.feature_extractor = extract_features
                self.feature_size = FEATURE_SIZE
            except:
                pass
        except:
            pass
    def scan(self, filepath, file_data=None):
        if not self.available or self.feature_extractor is None:
            return None, 0, ""
        try:
            import numpy as np
            if file_data is not None:
                if len(file_data) < 2 or file_data[:2] != b'MZ':
                    return None, 0, ""
            elif filepath:
                with open(filepath, 'rb') as f:
                    header = f.read(2)
                if header != b'MZ':
                    return None, 0, ""
            feats = self.feature_extractor(filepath=filepath, file_data=file_data)
            if feats is None:
                return None, 0, ""
            inp = np.array(feats, dtype=np.float32).reshape(1, -1)
            out = self.session.run(None, {self.session.get_inputs()[0].name: inp})
            prob = self._extract_prob(out)
            if prob is None:
                return None, 0, ""
            if prob >= self.threshold:
                conf = int(prob * 100)
                return "OnnxDetect", conf, f"ONNX{conf}%"
        except:
            pass
        return None, 0, ""

    @staticmethod
    def _extract_prob(out):
        """Tolerant extraction of P(y=1) from an ONNX session output, regardless
        of whether the model was exported with zipmap on/off."""
        try:
            import numpy as np
            last = out[-1]
            arr = np.array(last, dtype=object) if not isinstance(last, (list, tuple, np.ndarray)) else np.array(last)
            if isinstance(arr, np.ndarray):
                if arr.ndim == 2 and arr.shape[1] >= 2:
                    return float(arr[0][1])
                if arr.ndim == 1 and arr.shape[0] >= 2:
                    return float(arr[1])
                if arr.ndim == 1 and arr.shape[0] == 1:
                    return float(arr[0])
            if isinstance(last, (list, tuple)):
                d = last[0]
                if isinstance(d, dict):
                    for k in (1, '1', 1.0):
                        if k in d:
                            return float(d[k])
                    vals = list(d.values())
                    if len(vals) >= 2:
                        return float(vals[1])
            first = out[0]
            arr = np.array(first)
            if arr.ndim >= 1:
                v = float(arr.reshape(-1)[-1])
                return 1.0 / (1.0 + math.exp(-v))
        except Exception:
            return None
        return None
class XiguaCloudScanner:
    def __init__(self):
        self.api_base = CONFIG.get("cloud_api_base", "https://cloudapi.xiguastudio.top")
        self.api_key = CONFIG.get("cloud_api_key", "")
        self.timeout = CONFIG.get("cloud_timeout", 10)
        self._cache = LRUCache(maxsize=2000)
    def is_enabled(self):
        return bool(CONFIG.get("cloud_scan_enabled", False) and self.api_key)
    def _sha256(self, filepath):
        try:
            h = hashlib.sha256()
            with open(filepath, 'rb') as f:
                for chunk in iter(lambda: f.read(65536), b''):
                    h.update(chunk)
            return h.hexdigest()
        except:
            return None
    def extract_features(self, filepath):
        try:
            with open(filepath, "rb") as f:
                data = f.read()
            total = len(data)
            if total < 16:
                return None
            feats = [0.0] * 283
            counts = [0] * 256
            pr = ct = ws = lt = dg = hi = 0
            mz = cz = 0
            for b in data:
                counts[b] += 1
                if 0x20 <= b <= 0x7E:
                    pr += 1
                    if chr(b).isalpha():
                        lt += 1
                    elif chr(b).isdigit():
                        dg += 1
                elif b < 0x20 or b == 0x7F:
                    ct += 1
                if b in (9, 10, 13, 32):
                    ws += 1
                if b >= 0x80:
                    hi += 1
                if b == 0:
                    cz += 1
                    if cz > mz:
                        mz = cz
                else:
                    cz = 0
            tf = float(total)
            for i in range(256):
                feats[i] = counts[i] / tf
            feats[256] = self._entropy(counts, tf)
            self._block_entropy(data, feats)
            feats[273] = pr / tf
            feats[274] = ct / tf
            feats[275] = ws / tf
            feats[276] = lt / tf
            feats[277] = dg / tf
            feats[278] = hi / tf
            feats[279] = float(mz)
            feats[280] = counts[0] / tf
            is_pe = 0.0
            if total > 64 and data[0] == 0x4D and data[1] == 0x5A:
                try:
                    import struct
                    pe_off = struct.unpack_from('<I', data, 60)[0]
                    if pe_off + 4 <= total and data[pe_off] == 0x50:
                        is_pe = 1.0
                except:
                    pass
            feats[281] = is_pe
            feats[282] = math.log10(total + 1)
            return feats
        except:
            return None
    @staticmethod
    def _entropy(counts, total):
        if total <= 0:
            return 0.0
        return -sum(p * math.log2(p) for p in [counts[i] / total for i in range(256) if counts[i] > 0])
    @staticmethod
    def _block_entropy(data, feats):
        n_blocks = min(len(data) // 256, 16)
        for bi in range(n_blocks):
            s = bi * 256
            e = min(s + 256, len(data))
            c = [0] * 256
            for j in range(s, e):
                c[data[j]] += 1
            t = e - s
            if t > 0:
                feats[257 + bi] = -sum(p * math.log2(p) for p in [c[i] / t for i in range(256) if c[i] > 0])
        if n_blocks > 0:
            for i in range(n_blocks, 16):
                feats[257 + i] = feats[257 + n_blocks - 1]
        else:
            for i in range(16):
                feats[257 + i] = 0.0
    def check_hash(self, sha256_hash):
        cached = self._cache.get(sha256_hash)
        if cached is not None:
            return cached
        try:
            import requests
            url = f"{self.api_base}/api/check?key={self.api_key}"
            resp = requests.post(url, json={"hash": sha256_hash}, timeout=self.timeout)
            if resp.status_code == 200:
                data = resp.json()
                if data.get("code") == 200:
                    result = data.get("result", "")
                    family = data.get("family", "")
                    self._cache.put(sha256_hash, (result, family))
                    return result, family
        except:
            pass
        return None, None
    def infer(self, sha256_hash, features=None):
        try:
            import requests
            url = f"{self.api_base}/api/infer?key={self.api_key}"
            payload = {"hash": sha256_hash}
            if features:
                payload["features"] = features
            resp = requests.post(url, json=payload, timeout=self.timeout)
            if resp.status_code == 200:
                data = resp.json()
                if data.get("code") == 200:
                    return data
        except:
            pass
        return None
    def scan_file(self, filepath):
        if not self.is_enabled():
            return None, 0, ""
        sha = self._sha256(filepath)
        if not sha:
            return None, 0, ""
        result, family = self.check_hash(sha)
        if result in ("white", "whitelisted", "clean") or str(result).startswith("CLEAN"):
            return "WHITE", 0, ""
        if result in ("black", "malicious"):
            ttype = classify_threat(filepath, rule_name=family or "Cloud")
            conf = 90
            res = f"MALICIOUS|{ttype}|Cloud-DB|{conf}"
            return res, conf, ttype
        return None, 0, ""
class ExternalCloudScanner:
    def __init__(self, cfg):
        self.name = cfg.get("name", "External")
        self.api_base = cfg.get("api_base", "")
        self.api_key = cfg.get("api_key", "")
        self.timeout = cfg.get("timeout", 15)
        self._cache = LRUCache(maxsize=2000)

    def is_enabled(self):
        return bool(self.api_base and self.api_key)

    def _sha256(self, filepath):
        try:
            h = hashlib.sha256()
            with open(filepath, 'rb') as f:
                for chunk in iter(lambda: f.read(65536), b''):
                    h.update(chunk)
            return h.hexdigest()
        except Exception:
            return None

    def scan_file(self, filepath):
        if not self.is_enabled():
            return None, 0, ""
        sha = self._sha256(filepath)
        if not sha:
            return None, 0, ""
        cached = self._cache.get(sha)
        if cached is not None:
            return cached
        try:
            import requests
            url = f"{self.api_base}?key={self.api_key}"
            resp = requests.post(url, json={"hash": sha}, timeout=self.timeout)
            if resp.status_code == 200:
                data = resp.json()
                result = data.get("result", "")
                family = data.get("family", data.get("virus_family", ""))
                if result in ("black", "malicious"):
                    ttype = classify_threat(filepath, rule_name=family or self.name)
                    conf = int(data.get("confidence", 90))
                    res = f"MALICIOUS|{ttype}|{self.name}|{conf}"
                    self._cache.put(sha, (res, conf, ttype))
                    return res, conf, ttype
                self._cache.put(sha, (None, 0, ""))
        except Exception:
            pass
        return None, 0, ""

class AVICCloudScanner:
    def __init__(self):
        self.api_base = CONFIG.get("avic_api_base", "https://avic.xiguastudio.top")
        self.api_key = CONFIG.get("avic_api_key", "")
        self.timeout = CONFIG.get("avic_timeout", 10)
        self._cache = LRUCache(maxsize=5000)
        self._batch_queue = []
        self._batch_lock = threading.Lock()

    def is_enabled(self):
        return bool(CONFIG.get("avic_scan_enabled", True) and self.api_key)

    def _sha256(self, filepath):
        try:
            h = hashlib.sha256()
            with open(filepath, 'rb') as f:
                for chunk in iter(lambda: f.read(65536), b''):
                    h.update(chunk)
            return h.hexdigest()
        except Exception:
            return None

    def _md5(self, filepath):
        try:
            h = hashlib.md5()
            with open(filepath, 'rb') as f:
                for chunk in iter(lambda: f.read(65536), b''):
                    h.update(chunk)
            return h.hexdigest()
        except Exception:
            return None

    def scan_file(self, filepath):
        if not self.is_enabled():
            return None, 0, ""
        sha = self._sha256(filepath)
        if not sha:
            return None, 0, ""
        cached = self._cache.get(sha)
        if cached is not None:
            return cached
        try:
            import requests
            url = f"{self.api_base}/api/v1/query"
            resp = requests.post(
                url,
                json={"hash": sha},
                headers={"X-API-Key": self.api_key, "Content-Type": "application/json"},
                timeout=self.timeout
            )
            if resp.status_code == 200:
                data = resp.json()
                if data.get("found") and data.get("classification") == "malicious":
                    threat_name = data.get("threat_name", "")
                    family = data.get("family", "")
                    ttype = classify_threat(filepath, rule_name=threat_name or family or "AVIC-Cloud")
                    conf = 95
                    res = f"MALICIOUS|{ttype}|AVIC-Cloud|{conf}"
                    self._cache.put(sha, (res, conf, ttype))
                    return res, conf, ttype
                self._cache.put(sha, (None, 0, ""))
        except Exception:
            pass
        return None, 0, ""

    def scan_batch(self, hashes):
        if not self.is_enabled() or not hashes:
            return {}
        results = {}
        try:
            import requests
            url = f"{self.api_base}/api/v1/batch"
            resp = requests.post(
                url,
                json={"hashes": hashes[:1000]},
                headers={"X-API-Key": self.api_key, "Content-Type": "application/json"},
                timeout=self.timeout
            )
            if resp.status_code == 200:
                data = resp.json()
                for item in data.get("results", []):
                    h = item.get("hash", "")
                    if item.get("found") and item.get("classification") == "malicious":
                        results[h] = {
                            "threat_name": item.get("threat_name", ""),
                            "family": item.get("family", ""),
                        }
        except Exception:
            pass
        return results

    def submit_hash(self, file_hash, threat_name="", family="", description="", tags=""):
        if not self.is_enabled():
            return None
        try:
            import requests
            url = f"{self.api_base}/api/v1/submit"
            resp = requests.post(
                url,
                json={
                    "hash": file_hash,
                    "threat_name": threat_name,
                    "family": family,
                    "description": description,
                    "tags": tags,
                },
                headers={"X-API-Key": self.api_key, "Content-Type": "application/json"},
                timeout=self.timeout
            )
            if resp.status_code == 200:
                return resp.json()
        except Exception:
            pass
        return None

    def check_status(self):
        if not self.is_enabled():
            return None
        try:
            import requests
            url = f"{self.api_base}/api/v1/status"
            resp = requests.get(
                url,
                headers={"X-API-Key": self.api_key},
                timeout=self.timeout
            )
            if resp.status_code == 200:
                return resp.json()
        except Exception:
            pass
        return None

class Scanner:
    def __init__(self):
        self.whitelist = Whitelist()
        self.cache = LRUCache()
        self._file_hash_cache = LRUCache(maxsize=500)
        self.yara = YaraScanner(CONFIG["yara_rules_dir"])
        self.custom = CustomRuleScanner(CONFIG["custom_rules_dir"])
        self.study = StudyEngine(CONFIG["machine_learning_file"])
        self.onnx = OnnxScanner(CONFIG["onnx_model_dir"])
        self.lgbm = None
        try:
            if LightGBMScanner is not None and CONFIG.get("enable_lightgbm", True):
                self.lgbm = LightGBMScanner(os.path.join(BASE_DIR, CONFIG["lightgbm_model"]))
        except Exception:
            self.lgbm = None
        self.advanced = AdvancedSignatureScanner(CONFIG["feature_files_dir"])
        self.entropy = EntropyAnalyzer()
        self.packer = PackerDetector()
        self.cloud = XiguaCloudScanner()
        self.avic = AVICCloudScanner()
        self.external_clouds = self._init_external_clouds()

    def _init_external_clouds(self):
        clouds = []
        if not CONFIG.get("enable_external_clouds"):
            return clouds
        for cfg in CONFIG.get("external_clouds_config", []):
            try:
                clouds.append(ExternalCloudScanner(cfg))
            except Exception:
                continue
        return clouds

    def scan_file_quick(self, filepath):
        try:
            if not os.path.exists(filepath):
                return "CLEAN", 0, ""
            if self.whitelist.contains(filepath):
                return "WHITELIST", 0, ""
            if _is_security_tool_component(filepath):
                return "CLEAN", 0, ""
            ext = os.path.splitext(filepath)[1].lower()
            _quick_mz = False
            try:
                with open(filepath, 'rb') as _f:
                    _quick_mz = _f.read(2) == b'MZ'
            except Exception:
                _quick_mz = False
            _is_pe = (ext in {'.exe','.dll','.sys','.ocx','.scr','.cpl','.drv','.com'}) or _quick_mz
            _is_script = ext in {'.vbs','.ps1','.js','.bat','.cmd','.py','.pyw','.vbe','.wsf','.hta','.sct','.wsc'}
            sha = None
            pe_info = None
            if _is_pe:
                try:
                    pe_info = _parse_pe_all(filepath)
                except:
                    pe_info = None
            if _is_pe or _is_script:
                try:
                    h = hashlib.sha256()
                    with open(filepath, 'rb') as f:
                        for chunk in iter(lambda: f.read(1024 * 1024), b''):
                            h.update(chunk)
                    sha = h.hexdigest().lower()
                except:
                    pass
            if sha and self.study.hash_index:
                md5 = self.study.hash_index.get(sha)
                if md5 and md5 in self.study.records:
                    rec = self.study.records[md5]
                    if rec.get('type') == 'malicious':
                        ttype = classify_threat(filepath, rule_name=rec.get('threat_type', 'Trojan'), heuristic=False)
                        return f"MALICIOUS|{ttype}|SE-Precise|95", 95, ttype
            if self.study.whitelist_paths and not (_is_pe or _is_msi or _is_jar) and not (head_data[:2] == b'MZ'):
                norm_fp = os.path.normpath(filepath).lower().replace('\\', '/').lstrip('/')
                if len(norm_fp) > 1 and norm_fp[1] == ':':
                    norm_fp = norm_fp[2:].lstrip('/')
                for wp in self.study.whitelist_paths:
                    wnorm = os.path.normpath(wp).lower().replace('\\', '/').strip('/')
                    if wnorm and norm_fp.startswith(wnorm):
                        return "WHITELIST", 0, ""
            if self.study.is_lore_whitelisted(filepath) and not (_is_pe or _is_msi or _is_jar) and not (head_data[:2] == b'MZ'):
                return "WHITELIST", 0, ""
            # === High-confidence white ML verdict (quick path) ===
            # Same gate as scan_file: short-circuit SE-Chain / PE heuristics on
            # model-confident-clean PEs to suppress false positives on system binaries.
            if (CONFIG.get("enable_lightgbm_white", True)
                    and CONFIG.get("enable_lightgbm", True)
                    and _is_pe and _quick_mz
                    and getattr(self, "lgbm", None) is not None and self.lgbm.available):
                _ml_p_q = self.lgbm.score(filepath)
                if 0.0 <= _ml_p_q < CONFIG.get("lightgbm_white_prob", 0.15):
                    return "CLEAN|LightGBM-White", 0, ""
            if pe_info:
                pe_apis = pe_info['apis']
                if pe_apis:
                    se_type, se_conf, se_feat = self.study.scan_api_chains(pe_apis)
                    if se_type and se_conf >= 80:
                        _norm_fp_se3 = os.path.normpath(filepath).lower().replace('\\', '/')
                        _is_winsxs_se3 = 'windows/winsxs/' in _norm_fp_se3
                        _se3_ok = not _is_winsxs_se3
                        if _se3_ok and not pe_info.get('signer'):
                            _se3_vi_co = (pe_info.get('version_info', {}).get('CompanyName', '') or '').lower()
                            if _se3_vi_co:
                                _TRUSTED_VI_SE3 = {'microsoft','7-zip','dell','steam','valve','google','apple','oracle','intel','nvidia','amd','vmware','hp','lenovo','ibm','cisco','tencent','baidu','qihoo','kingsoft','huawei','xiaomi','broadcom','symantec','norton','avast','avg','bitdefender','kaspersky','eset','mcafee','coloros','oppo','realtek','samsung','lg electronics','igor pavlov'}
                                if any(t in _se3_vi_co for t in _TRUSTED_VI_SE3):
                                    _se3_ok = False
                        if _se3_ok:
                            final = min(95, se_conf + self.study.get_boost(filepath))
                            ttype = classify_threat(filepath, rule_name=se_type, pe_apis=pe_apis, heuristic=True)
                            return f"MALICIOUS|{ttype}|SE-Chain|{final}", final, ttype
                signer = pe_info['signer']
                if signer:
                    sl = signer.lower()
                    TRUSTED = {'microsoft','google','apple','mozilla','adobe','oracle','intel','nvidia','amd','vmware','hp','dell','lenovo','ibm','cisco','avast','avg','avira','bitdefender','kaspersky','eset','mcafee','symantec','norton','malwarebytes','trend micro','sophos','fortinet','check point','palo alto','crowdstrike','sentinelone','jetbrains','github','gitlab','python software foundation','docker','red hat','canonical','apache','tencent','baidu','qihoo','kingsoft','huawei','xiaomi','gen digital','nortonlifelock','avast software','broadcom','glarysoft','glary','netease','ldplayer','npcap','eclipse','steam','valve','adoptium','redis','mongo','postgresql','sqlite','electron','discord','slack','zoom','teams','dropbox','1password','lastpass','dashlane','nord','expressvpn','surfshark','cyberghost','private internet','windscribe','proton','ccleaner','speccy','recuva','defraggler','audacity','obs','ffmpeg','vlc','videolan','imagemagick','git for windows','mingw','msys2','curl','openssl','putty','winscp','filezilla','notepad++','7-zip','winrar','peazip','bandizip','sumatrapdf','foxit','libreoffice','openoffice','thunderbird','firefox','chrome','edge','opera','brave','vivaldi','maxthon','yandex','duckduckgo','sap','siemens','autodesk','atlassian','keepass','wireshark','nmap','sysinternals','voidtools','anydesk','teamviewer','rustdesk','chromium','webkit','nodejs','logitech','razer','corsair','asus','gigabyte','samsung','lg electronics','qualcomm','mediatek','wacom','bosch','honeywell','schneider electric','mathworks','grafana','elastic','datadog','splunk','sentry','kubernetes','terraform','ansible','helm','istio'}
                    _vi_quick = pe_info.get('version_info', {})
                    _vi_quick_has = bool(_vi_quick.get('CompanyName') or _vi_quick.get('FileVersion') or _vi_quick.get('ProductName') or _vi_quick.get('FileDescription'))
                    if any(t in sl for t in TRUSTED) and _vi_quick_has:
                        return "CLEAN", 0, ""
            if (_is_pe or _is_script or ext in {'.jar', '.bin'}) and self.cloud.is_enabled():
                _cr, _cc, _ct = self.cloud.scan_file(filepath)
                if _cr and _cr.startswith("MALICIOUS"):
                    return _cr, _cc, _ct
                if _cr == "WHITE":
                    return "CLEAN", 0, ""
            if (_is_pe or _is_script or ext in {'.jar', '.bin'}) and self.avic.is_enabled():
                _ar, _ac, _at = self.avic.scan_file(filepath)
                if _ar and _ar.startswith("MALICIOUS"):
                    return _ar, _ac, _at
            return "CLEAN", 0, ""
        except Exception:
            return "ERROR", 0, ""

    def scan_file(self, filepath, depth=0):
        try:
            if not os.path.exists(filepath):
                return "CLEAN", 0, ""
            if self.whitelist.contains(filepath):
                return "WHITELIST", 0, ""
            if _is_security_tool_component(filepath):
                return "CLEAN", 0, ""
            sig = get_file_signature(filepath)
            key = (filepath, sig) if sig else filepath
            cached = self.cache.get(key)
            if cached:
                return cached[0], cached[1], cached[2] if len(cached) > 2 else ""
            try:
                with open(filepath, 'rb') as f:
                    head_data = f.read()
            except:
                head_data = b""

            ext = os.path.splitext(filepath)[1].lower()
            _head_mz = head_data[:2] == b'MZ'
            # Content-based PE detection: keep the extension hint but ALSO accept
            # any file whose first two bytes are MZ, so renamed / extension-less
            # PE files are no longer missed by the suffix filter.
            _is_pe = (ext in {'.exe','.dll','.sys','.ocx','.scr','.cpl','.drv','.com'}) or _head_mz
            _is_script = ext in {'.vbs','.ps1','.js','.bat','.cmd','.py','.pyw','.vbe','.wsf','.hta','.sct','.wsc'}
            _is_msi = ext == '.msi'
            _is_jar = ext in {'.jar', '.bin'}
            if (_is_pe or _is_script or _is_msi or _is_jar) and CONFIG.get("enable_study_engine", True):
                se_type, se_conf, se_feat = self.study.scan_precise(filepath)
                if se_type:
                    ttype = classify_threat(filepath, rule_name=se_type, heuristic=False)
                    res = f"MALICIOUS|{ttype}|SE-Precise|{se_conf}"
                    self.cache.put(key, (res, se_conf, ttype))
                    self.study.record_result(filepath, ttype, se_conf, se_feat)
                    return res, se_conf, ttype

            # === High-confidence white ML verdict ===
            # If LightGBM is highly confident this PE image is CLEAN (malware
            # probability far below its operating threshold), short-circuit the
            # noisy heuristics (PE-Suspicious / ".NET binary without signature" /
            # SE-Chain / Packer-Entropy ...) that otherwise flag legitimate system
            # binaries (notepad.exe, explorer.exe, *.ni.dll, ...) as MALICIOUS.
            # Legacy heuristic / rule / YARA / cloud logic is preserved and still
            # runs for every other file; this gate only fires on model-confident-clean PEs.
            if (CONFIG.get("enable_lightgbm_white", True)
                    and CONFIG.get("enable_lightgbm", True)
                    and _is_pe and head_data[:2] == b'MZ'
                    and getattr(self, "lgbm", None) is not None and self.lgbm.available):
                _ml_p = self.lgbm.score(filepath, file_data=head_data)
                if 0.0 <= _ml_p < CONFIG.get("lightgbm_white_prob", 0.15):
                    self.cache.put(key, ("CLEAN|LightGBM-White", 0, ""))
                    self.study.record_result(filepath, "CLEAN", 0, "LightGBM-White")
                    return "CLEAN|LightGBM-White", 0, ""

            if CONFIG.get("enable_pe_scan", True) and _is_msi and head_data[:4] == b'\xD0\xCF\x11\xE0':
                try:
                    _msi_signer = _extract_msi_signer(filepath)
                    if _msi_signer:
                        _msi_sl = _msi_signer.lower()
                        _MSI_TRUSTED = {'microsoft','google','apple','adobe','oracle','intel','nvidia','amd','vmware','hp','dell','lenovo','ibm','cisco','avast','avg','avira','bitdefender','kaspersky','eset','mcafee','norton','malwarebytes','trend micro','sophos','fortinet','jetbrains','github','gitlab','python software foundation','docker','red hat','canonical','apache','tencent','baidu','qihoo','kingsoft','huawei','xiaomi','gen digital','nortonlifelock','avast software','broadcom'}
                        if any(t in _msi_sl for t in _MSI_TRUSTED):
                            self.cache.put(key, ("CLEAN", 0, ""))
                            return "CLEAN", 0, ""
                    _msi_info = _analyze_msi_embedded(filepath)
                    if _msi_info:
                        _msi_score = 0
                        _msi_reasons = []
                        _inj = _msi_info['injection_apis']
                        _net = _msi_info['network_apis']
                        _pers = _msi_info['persistence_apis']
                        _anti = _msi_info['antidebug_apis']
                        _res = _msi_info['resource_apis']
                        _file_apis = _msi_info.get('file_apis', [])
                        _crypto_apis = _msi_info.get('crypto_apis', [])
                        _proc_apis = _msi_info.get('process_apis', [])
                        _obf = _msi_info['obfuscated_pe_count']
                        _packed = _msi_info.get('packed_section_count', 0)
                        _high_ent = _msi_info.get('high_entropy_count', 0)
                        _zero_imp = _msi_info.get('zero_import_pe_count', 0)
                        _pe_ct = _msi_info['pe_count']
                        _total_apis = _msi_info['total_apis']
                        _high_risk_cat = sum(1 for x in [_inj, _net] if x)
                        _suspicious_cat_count = sum(1 for x in [_inj, _net, _pers, _anti] if x)
                        if _inj:
                            _msi_score += min(40, 15 + len(_inj) * 8)
                            _msi_reasons.append(f'Injection APIs: {",".join(_inj[:5])}')
                        if _net:
                            _msi_score += min(35, 12 + len(_net) * 5)
                            _msi_reasons.append(f'Network APIs: {",".join(_net[:5])}')
                        if _pers and (_inj or _net or _packed or _obf):
                            _msi_score += min(20, 5 + len(_pers) * 3)
                            _msi_reasons.append(f'Persistence APIs: {",".join(_pers[:5])}')
                        if _anti and (_inj or _net or _packed or _obf):
                            _msi_score += min(15, 5 + len(_anti) * 3)
                            _msi_reasons.append(f'Anti-debug APIs: {",".join(_anti[:3])}')
                        if _crypto_apis and (_inj or _net):
                            _msi_score += min(15, 5 + len(_crypto_apis) * 3)
                            _msi_reasons.append(f'Crypto APIs: {",".join(_crypto_apis[:3])}')
                        if _obf > 0:
                            _msi_score += 40
                            _msi_reasons.append(f'Obfuscated PE sections ({_obf} files)')
                        if _packed > 0:
                            _msi_score += 45
                            _msi_reasons.append(f'Packed sections ({_packed} PEs)')
                        if _high_ent > 0 and (_packed or _obf):
                            _msi_score += min(25, 15 * _high_ent)
                            _msi_reasons.append(f'High entropy sections ({_high_ent})')
                        if _total_apis > 100 and _high_risk_cat >= 1:
                            _msi_score += 15
                            _msi_reasons.append(f'High API count ({_total_apis}) with high-risk APIs')
                        if _pe_ct > 2 and _msi_info['dll_pe_count'] == _pe_ct and _high_risk_cat >= 1:
                            _msi_score += 10
                            _msi_reasons.append(f'{_pe_ct} embedded DLLs with high-risk APIs')
                        if _zero_imp > 0 and _total_apis <= 5 and (_packed or _obf):
                            _msi_score += 35
                            _msi_reasons.append(f'Zero-import PE ({_zero_imp} files) - packed/obfuscated')
                        if _zero_imp > 0 and _total_apis > 5 and (_packed or _obf):
                            _msi_score += 25
                            _msi_reasons.append(f'Zero-import PE + packed/obfuscated ({_total_apis} string APIs)')
                        if _total_apis <= 3 and _pe_ct >= 1:
                            with open(filepath, 'rb') as f:
                                _msi_raw = f.read(min(os.path.getsize(filepath), 50*1024*1024))
                            _msi_text_lower = _msi_raw.decode('latin-1', errors='ignore').lower()
                            _has_ca = 'customaction' in _msi_text_lower
                            _has_appdata = 'appdata' in _msi_text_lower
                            _has_ps = 'powershell' in _msi_text_lower
                            _has_cmd = 'cmd.exe' in _msi_text_lower
                            _has_rundll = 'rundll32' in _msi_text_lower
                            _has_schtasks = 'schtasks' in _msi_text_lower
                            if _has_ca and _has_appdata and (_packed or _obf or _zero_imp):
                                _msi_score += 35
                                _msi_reasons.append('CustomAction + AppData (packed payload)')
                            if _has_ps or _has_cmd or _has_rundll or _has_schtasks:
                                _msi_score += 20
                                _msi_reasons.append('Suspicious execution command in MSI')
                        if _msi_score >= 40:
                            _msi_final = min(90, 55 + _msi_score + self.study.get_boost(filepath))
                            _msi_ttype = classify_threat(filepath, heuristic=True)
                            _msi_res = f"MALICIOUS|{_msi_ttype}|MSI-Heuristic|{_msi_final}"
                            self.cache.put(key, (_msi_res, _msi_final, _msi_ttype))
                            self.study.record_result(filepath, _msi_ttype, _msi_final, '; '.join(_msi_reasons))
                            return _msi_res, _msi_final, _msi_ttype
                except Exception:
                    pass
            if self.study.whitelist_paths and not (_is_pe or _is_msi or _is_jar) and not (head_data[:2] == b'MZ'):
                norm_fp = os.path.normpath(filepath).lower().replace('\\', '/').lstrip('/')
                if len(norm_fp) > 1 and norm_fp[1] == ':':
                    norm_fp = norm_fp[2:].lstrip('/')
                for wp in self.study.whitelist_paths:
                    wnorm = os.path.normpath(wp).lower().replace('\\', '/').strip('/')
                    if wnorm and norm_fp.startswith(wnorm):
                        return "WHITELIST", 0, ""
            if self.study.is_lore_whitelisted(filepath) and not (_is_pe or _is_msi or _is_jar) and not (head_data[:2] == b'MZ'):
                return "WHITELIST", 0, ""
            _norm_fp_dos = os.path.normpath(filepath).lower().replace('\\', '/')
            _is_winsxs_dos = 'windows/winsxs/' in _norm_fp_dos
            if CONFIG.get("enable_pe_scan", True) and ext in {'.com', '.exe'} and not _is_security_tool_component(filepath) and not _is_winsxs_dos:
                _dos_score = 0
                _dos_reasons = []
                _dos_fsize = os.path.getsize(filepath)
                _dos_is_com = ext == '.com'
                _dos_has_mz = head_data[:2] == b'MZ'
                _dos_has_pe_sig = False
                if _dos_has_mz and len(head_data) > 0x40:
                    try:
                        _dos_lfanew = int.from_bytes(head_data[0x3C:0x40], 'little')
                        if _dos_lfanew > 0 and _dos_lfanew + 4 <= len(head_data):
                            if head_data[_dos_lfanew:_dos_lfanew+4] == b'PE\x00\x00':
                                _dos_has_pe_sig = True
                    except:
                        pass
                _dos_is_raw = not _dos_has_mz
                _dos_is_dos_exe = _dos_has_mz and not _dos_has_pe_sig
                if _dos_is_raw or _dos_is_dos_exe:
                    _dos_data = head_data[:min(len(head_data), 65536)]
                    _dos_int21 = _dos_data.count(b'\xcd\x21')
                    _dos_int13 = _dos_data.count(b'\xcd\x13')
                    _dos_int20 = _dos_data.count(b'\xcd\x20')
                    _dos_int27 = _dos_data.count(b'\xcd\x27')
                    _dos_int08 = _dos_data.count(b'\xcd\x08')
                    _dos_int1c = _dos_data.count(b'\xcd\x1c')
                    _dos_int10 = _dos_data.count(b'\xcd\x10')
                    _dos_int24 = _dos_data.count(b'\xcd\x24')
                    _dos_int2f = _dos_data.count(b'\xcd\x2f')
                    _dos_int16 = _dos_data.count(b'\xcd\x16')
                    _dos_int17 = _dos_data.count(b'\xcd\x17')
                    _dos_int19 = _dos_data.count(b'\xcd\x19')
                    _dos_starts_jmp = len(_dos_data) > 0 and _dos_data[0] in (0xE9, 0xEB)
                    _dos_file_ops = False
                    for _dos_ah in [b'\xb4\x3d', b'\xb4\x3e', b'\xb4\x3f', b'\xb4\x40', b'\xb4\x4e', b'\xb4\x4f', b'\xb4\x43', b'\xb4\x25', b'\xb4\x35', b'\xb4\x41', b'\xb4\x56', b'\xb4\x3c', b'\xb4\x5b', b'\xb4\x5a', b'\xb4\x57', b'\xb4\x39']:
                        if _dos_ah in _dos_data:
                            _dos_file_ops = True
                            break
                    if _dos_int21 >= 2:
                        _dos_score += 30
                        _dos_reasons.append(f'INT 21h x{_dos_int21}')
                    elif _dos_int21 >= 1:
                        _dos_score += 15
                        _dos_reasons.append(f'INT 21h x{_dos_int21}')
                    if _dos_int21 >= 5:
                        _dos_score += 15
                    if _dos_int20 > 0:
                        _dos_score += 10
                        _dos_reasons.append(f'INT 20h x{_dos_int20}')
                    if _dos_int10 > 0:
                        _dos_score += 10
                        _dos_reasons.append(f'INT 10h x{_dos_int10}')
                    if _dos_starts_jmp and (_dos_is_raw or _dos_is_com):
                        _dos_score += 15
                        _dos_reasons.append('Starts with JMP')
                    if _dos_int13 > 0:
                        _dos_score += 15
                        _dos_reasons.append(f'INT 13h (disk) x{_dos_int13}')
                    if _dos_int13 >= 3:
                        _dos_score += 10
                        _dos_reasons.append('Boot sector pattern')
                    if _dos_int27 > 0:
                        _dos_score += 15
                        _dos_reasons.append('INT 27h (TSR)')
                    if _dos_int08 > 0 or _dos_int1c > 0:
                        _dos_score += 15
                        _dos_reasons.append('Timer interrupt (resident)')
                    if _dos_int24 > 0:
                        _dos_score += 5
                    if _dos_int2f > 0:
                        _dos_score += 10
                        _dos_reasons.append(f'INT 2Fh x{_dos_int2f}')
                    if _dos_int16 > 0 or _dos_int17 > 0:
                        _dos_score += 5
                    if _dos_int19 > 0:
                        _dos_score += 5
                    if _dos_file_ops:
                        _dos_score += 20
                        _dos_reasons.append('DOS file operations')
                    if _dos_is_raw and _dos_fsize < 4096:
                        _dos_score += 10
                    elif _dos_is_raw and _dos_fsize < 8192:
                        _dos_score += 5
                    if _dos_is_dos_exe and _dos_fsize < 65536:
                        _dos_score += 15
                        _dos_reasons.append('DOS-EXE<64K')
                    if _dos_is_dos_exe and _dos_fsize < 8192:
                        _dos_score += 10
                        _dos_reasons.append('Small DOS-EXE')
                    if _dos_is_dos_exe and (_dos_int21 > 0 or _dos_int13 > 0 or _dos_int20 > 0):
                        _dos_score += 10
                        _dos_reasons.append('DOS-EXE with interrupts')
                    _dos_any_int = _dos_int21 + _dos_int13 + _dos_int20 + _dos_int27 + _dos_int08 + _dos_int1c + _dos_int10 + _dos_int24 + _dos_int2f
                    if _dos_any_int == 0:
                        try:
                            _dos_ent = _compute_entropy(head_data)
                            if _dos_ent > 6.5 and _dos_fsize < 8192:
                                _dos_score += 30
                                _dos_reasons.append(f'High entropy DOS binary (e={_dos_ent:.1f})')
                            elif _dos_ent > 5.0 and _dos_fsize < 8192:
                                _dos_score += 25
                                _dos_reasons.append(f'Elevated entropy DOS binary (e={_dos_ent:.1f})')
                            elif _dos_ent > 4.0 and _dos_fsize < 4096:
                                _dos_score += 20
                                _dos_reasons.append(f'Moderate entropy DOS binary (e={_dos_ent:.1f})')
                            elif _dos_ent > 3.5 and _dos_fsize < 2048:
                                _dos_score += 15
                                _dos_reasons.append(f'Small DOS binary with entropy (e={_dos_ent:.1f})')
                        except:
                            pass
                    if _dos_is_raw and _dos_fsize < 2048 and _dos_starts_jmp:
                        _dos_score += 10
                        _dos_reasons.append('Tiny COM with JMP')
                    if _dos_is_raw and _dos_fsize < 256:
                        _dos_score += 10
                        _dos_reasons.append('Very tiny COM file')
                    if _dos_starts_jmp and _dos_int21 >= 1:
                        try:
                            _dos_ent2 = _compute_entropy(head_data)
                            if _dos_ent2 < 1.0:
                                _dos_score += 15
                                _dos_reasons.append('Overlay virus pattern')
                            elif _dos_ent2 < 2.0:
                                _dos_score += 10
                                _dos_reasons.append('Low entropy overlay')
                        except:
                            pass
                    if _dos_starts_jmp and _dos_int13 >= 1:
                        try:
                            _dos_ent3 = _compute_entropy(head_data)
                            if _dos_ent3 < 2.0:
                                _dos_score += 10
                                _dos_reasons.append('Boot virus pattern')
                        except:
                            pass
                    if _dos_fsize <= 512 and _dos_int13 > 0:
                        _dos_score += 15
                        _dos_reasons.append('Boot sector size with disk access')
                    if _dos_int21 > 0 and _dos_int13 > 0:
                        _dos_score += 10
                        _dos_reasons.append('INT 21h + INT 13h combo')
                    if _dos_is_raw and _dos_int21 >= 1 and _dos_fsize < 16384:
                        _dos_score += 10
                        _dos_reasons.append('Small DOS binary with INT 21h')
                    if _dos_is_raw and _dos_starts_jmp and _dos_fsize < 8192 and _dos_any_int == 0:
                        _dos_score += 15
                        _dos_reasons.append('JMP-start DOS binary no interrupts')
                    if _dos_is_raw and _dos_fsize < 16:
                        _dos_score += 20
                        _dos_reasons.append('Microscopic COM file')
                    _dos_threshold = 30 if _dos_is_raw else 30
                    if _dos_score >= _dos_threshold:
                        _dos_final = min(95, 55 + _dos_score + self.study.get_boost(filepath))
                        _dos_ttype = classify_threat(filepath, heuristic=True)
                        _dos_res = f"MALICIOUS|{_dos_ttype}|DOS-Heuristic|{_dos_final}"
                        self.cache.put(key, (_dos_res, _dos_final, _dos_ttype))
                        self.study.record_result(filepath, _dos_ttype, _dos_final, '; '.join(_dos_reasons))
                        return _dos_res, _dos_final, _dos_ttype
            if CONFIG.get("enable_pe_scan", True) and _is_pe and head_data[:2] == b'MZ':
                _pe_info = _parse_pe_all(filepath)
                pe_apis = _pe_info['apis']
                signer = _pe_info['signer']
                _vi_trust = _pe_info.get('version_info', {})
                _vi_trust_co = (_vi_trust.get('CompanyName', '') or '').lower()
                if signer:
                    sl = signer.lower()
                    _is_timestamp = 'time stamping' in sl or 'timestamp' in sl
                    TRUSTED = {'microsoft','google','apple','mozilla','adobe','oracle','intel','nvidia','amd','vmware','hp','dell','lenovo','ibm','cisco','avast','avg','avira','bitdefender','kaspersky','eset','mcafee','norton','malwarebytes','trend micro','sophos','fortinet','check point','palo alto','crowdstrike','sentinelone','jetbrains','github','gitlab','python software foundation','docker','red hat','canonical','apache','tencent','baidu','qihoo','kingsoft','huawei','xiaomi','gen digital','nortonlifelock','avast software','broadcom','glarysoft','glary','netease','ldplayer','ldplayer9','npcap','eclipse','steam','valve','adoptium','redis','mongo','postgresql','sqlite','electron','discord','slack','zoom','teams','dropbox','1password','lastpass','dashlane','nord','expressvpn','surfshark','cyberghost','private internet','windscribe','proton','malware','hunter','ccleaner','speccy','recuva','defraggler','audacity','obs','ffmpeg','vlc','videolan','imagemagick','git for windows','mingw','msys2','curl','wget','openssl','putty','winscp','filezilla','notepad++','7-zip','winrar','peazip','bandizip','sumatrapdf','foxit','libreoffice','openoffice','thunderbird','firefox','chrome','edge','opera','brave','vivaldi','maxthon','yandex','duckduckgo','sap','siemens','autodesk','atlassian','cyberduck','keepass','wireshark','nmap','sysinternals','windirstat','voidtools','paint.net','greenshot','sharex','snipaste','poweriso','ultraiso','daemon tools','anydesk','teamviewer','rustdesk','chromium','webkit','node.js','nodejs','npm','yarn','typescript','deno','obs studio','streamlabs','elgato','logitech','razer','corsair','asus','gigabyte','asrock','biostar','realtek','creative','samsung','lg electronics','oppo','vivo','oneplus','motorola','nokia','ericsson','qualcomm','mediatek','arm ltd','wacom','bosch','honeywell','siemens ag','rockwell','schneider electric','siemens plm','mathworks','wolfram','maplesoft','jetbrains s.r.o.','jetbrains sro','zeebe','confluent','cloudera','databricks','snowflake','tableau','power bi','grafana','prometheus','elastic','datadog','splunk','new relic','dynatrace','raygun','sentry','rollbar','bugsnag','loggly','sumo logic','logstash','kibana','fluentd','fluentbit','loki','tempo','mimir','cortex','vault','consul','nomad','terraform','packer','vagrant','ansible','chef','puppet','saltstack','helm','istio','linkerd','envoy','cilium','calico','flannel','weave','cri-o','containerd','runc','kubernetes','knative','openfaas','kubeless','fission','nuclio','openzeppelin','truffle','ganache','hardhat','infura','alchemy','moralis','quicknode','ankr','chainstack'}
                    if any(t in sl for t in TRUSTED) and not _is_timestamp:
                        _vi_has_ver = bool(_vi_trust.get('CompanyName') or _vi_trust.get('FileVersion') or _vi_trust.get('ProductName') or _vi_trust.get('FileDescription') or _vi_trust.get('LegalCopyright'))
                        if not _vi_has_ver:
                            pass
                        else:
                            _trust_mismatch = False
                            if _vi_trust_co:
                                _truncated_signer = sl.split(',')[0].split('(')[0].strip()
                                _vi_co_lower = _vi_trust_co.lower().strip()
                                _shared_trust = any(t in sl and t in _vi_co_lower for t in TRUSTED)
                                if not _shared_trust:
                                    if _truncated_signer not in _vi_co_lower and _vi_co_lower not in _truncated_signer:
                                        if len(_vi_co_lower) > 2 and len(_truncated_signer) > 2:
                                            _trust_mismatch = True
                            if not _trust_mismatch:
                                _apis_lower_trust = set(a.lower() for a in pe_apis) if pe_apis else set()
                                _ransom_apis_trust = {'shutdownblockreasoncreate','shutdownblockreasondestroy'}
                                _has_ransom_api = bool(_apis_lower_trust & _ransom_apis_trust)
                                _has_destruct_api = bool(_apis_lower_trust & {'deletefilew','deletefilea','setendoffile','encryptfile','cryptencrypt','cryptderivekey'})
                                if _has_ransom_api and _has_destruct_api:
                                    pass
                                else:
                                    self.cache.put(key, ("CLEAN", 0, ""))
                                    return "CLEAN", 0, ""
                if pe_apis:
                    se_type, se_conf, se_feat = self.study.scan_api_chains(pe_apis)
                    if se_type and se_conf >= 80:
                        _se_ok = True
                        _norm_fp_se1 = os.path.normpath(filepath).lower().replace('\\', '/')
                        _is_winsxs_se1 = 'windows/winsxs/' in _norm_fp_se1
                        if _is_winsxs_se1:
                            _se_ok = False
                        _vi = _pe_info.get('version_info', {})
                        _vi_company = _vi.get('CompanyName', '') or ''
                        _vi_product = _vi.get('ProductName', '') or ''
                        _vi_desc = _vi.get('FileDescription', '') or ''
                        _vi_comments = _vi.get('Comments', '') or ''
                        _vi_info = _vi_company or _vi_product or _vi_desc
                        _is_inno = 'inno setup' in _vi_comments.lower()
                        if signer:
                            _se_sl = signer.lower()
                            _SE_TRUSTED = {'microsoft','microsoft windows','microsoft corporation'}
                            if any(t in _se_sl for t in _SE_TRUSTED):
                                _se_ok = False
                        if not signer and _vi_company:
                            _vi_co_se1 = _vi_company.lower()
                            _TRUSTED_VI_SE1 = {'microsoft','7-zip','dell','steam','valve','google','apple','oracle','intel','nvidia','amd','vmware','hp','lenovo','ibm','cisco','tencent','baidu','qihoo','kingsoft','huawei','xiaomi','broadcom','symantec','norton','avast','avg','bitdefender','kaspersky','eset','mcafee','coloros','oppo','realtek','samsung','lg electronics','igor pavlov','broadcom corporation','valve corporation'}
                            if any(t in _vi_co_se1 for t in _TRUSTED_VI_SE1):
                                _se_ok = False
                        if not signer and not _vi_info:
                            _ucrt_apis = sum(1 for a in pe_apis if a.lower().startswith('_o_') or a.lower().startswith('_initterm'))
                            if _ucrt_apis >= 5:
                                _se_ok = False
                        _susp_vi = False
                        if _vi_product and len(_vi_product) > 4:
                            import re as _re_vi
                            if _re_vi.match(r'^[a-zA-Z0-9]{5,}\.exe$', _vi_product):
                                _susp_vi = True
                        if _vi_company and len(_vi_company) <= 2:
                            _susp_vi = True
                        if not signer:
                            _go_secs = any(s[0].lower() in ('.gopclntab','.gosymtab','.noptrdata','.typelink','.itablink','.symtab') for s in _pe_info.get('sections', []))
                            _large_static = False
                            if _pe_info.get('sections'):
                                _text_sz = sum(s[2] for s in _pe_info['sections'] if s[0].lower() == '.text')
                                _import_ct = _pe_info.get('import_count', 0)
                                if _text_sz > 5000000 and _import_ct < 100:
                                    _large_static = True
                            if _go_secs or _large_static:
                                _se_ok = False
                        elif _vi_info and not _susp_vi:
                            _signer_match_vi = False
                            if _vi_company:
                                _sl = signer.lower()
                                _cl = _vi_company.lower()
                                if _sl in _cl or _cl in _sl:
                                    _signer_match_vi = True
                            if _signer_match_vi:
                                _se_ok = False
                        if _se_ok:
                            final = min(95, se_conf + self.study.get_boost(filepath))
                            ttype = classify_threat(filepath, rule_name=se_type, pe_apis=pe_apis, heuristic=True)
                            res = f"MALICIOUS|{ttype}|SE-Chain|{final}"
                            self.cache.put(key, (res, final, ttype))
                            self.study.record_result(filepath, ttype, final, se_feat)
                            return res, final, ttype
                # Low import heuristic (simplified)
                if not pe_apis or len(pe_apis) <= 1:
                    if not _pe_info['has_clr']:
                        _fname_low = os.path.basename(filepath).lower()
                        _skip_low = (_fname_low.startswith('api-ms-win-') or
                                     _fname_low in ('ucrtbase.dll','ucrtbase_dotpatch.dll') or
                                     'etw' in _fname_low or
                                     _fname_low.startswith('kd_') or
                                     _fname_low.endswith('res.dll') or
                                     _fname_low.endswith('resr.dll') or
                                     _fname_low.endswith('resource.dll'))
                        if not _skip_low and _pe_info['sections']:
                            _text_sz = 0
                            _rsrc_sz = 0
                            _total_sz = 0
                            for _sn, _se, _sr, _sc in _pe_info['sections']:
                                _sn_l = _sn.lower()
                                _total_sz += _sr
                                if _sn_l == '.text':
                                    _text_sz = _sr
                                elif _sn_l == '.rsrc':
                                    _rsrc_sz = _sr
                            if _rsrc_sz > 0 and _text_sz < 4096 and _rsrc_sz / max(_total_sz, 1) > 0.5:
                                _skip_low = True
                        if not _skip_low:
                            _low_api_entropy = _compute_entropy(head_data)
                            _low_api_fsize = os.path.getsize(filepath)
                            _low_api_susp = 0
                            if not pe_apis:
                                _low_api_susp += 20
                            elif len(pe_apis) == 1:
                                _low_api_susp += 15
                                if any(a.lower() == '_corexemain' for a in pe_apis):
                                    _low_api_susp += 18
                            if _low_api_entropy > 7.0:
                                _low_api_susp += 18
                            elif _low_api_entropy > 6.0:
                                _low_api_susp += 10
                            if _low_api_fsize < 50000:
                                _low_api_susp += 10
                            elif _low_api_fsize < 200000:
                                _low_api_susp += 5
                            if _pe_info['sections']:
                                _max_sec_e = max(s[1] for s in _pe_info['sections'])
                                if _max_sec_e > 7.5:
                                    _low_api_susp += 15
                                elif _max_sec_e > 6.5:
                                    _low_api_susp += 8
                            if _low_api_susp >= 65:
                                _low_api_final = min(95, 50 + _low_api_susp - 40 + self.study.get_boost(filepath))
                                _low_api_ttype = classify_threat(filepath, heuristic=True)
                                _low_api_res = f"MALICIOUS|{_low_api_ttype}|PE-LowImport|{_low_api_final}"
                                self.cache.put(key, (_low_api_res, _low_api_final, _low_api_ttype))
                                self.study.record_result(filepath, _low_api_ttype, _low_api_final, "Low-import PE")
                                return _low_api_res, _low_api_final, _low_api_ttype

            if (CONFIG.get("enable_pe_scan", True)
                    and _is_pe and head_data[:2] == b'MZ' and '_pe_info' in dir()
                    and not _is_security_tool_component(filepath)):
                _apis_set = set(a.lower() for a in pe_apis) if pe_apis else set()
                _susp_score = 0
                _susp_reasons = []
                _string_apis_found = set()
                if not pe_apis or len(pe_apis) <= 2:
                    _SA_PATTERNS = [
                        b'CreateProcessW', b'CreateProcessA', b'CreateThread', b'CreateRemoteThread',
                        b'WriteProcessMemory', b'VirtualAllocEx', b'VirtualAlloc', b'VirtualProtect',
                        b'LoadLibraryA', b'LoadLibraryW', b'GetProcAddress', b'GetModuleHandleA', b'GetModuleHandleW',
                        b'OpenProcess', b'TerminateProcess', b'ResumeThread', b'SuspendThread',
                        b'NtCreateThreadEx', b'NtWriteVirtualMemory', b'QueueUserAPC',
                        b'SetWindowsHookExW', b'GetAsyncKeyState', b'GetForegroundWindow',
                        b'WSAStartup', b'connect', b'recv', b'send', b'gethostbyname',
                        b'InternetOpenW', b'WinHttpOpen', b'URLDownloadToFileW',
                        b'IsDebuggerPresent', b'CheckRemoteDebuggerPresent', b'NtQueryInformationProcess',
                        b'CreateFileW', b'CreateFileA', b'WriteFile', b'DeleteFileW', b'DeleteFileA',
                        b'SHFileOperationW', b'SetFilePointer', b'SetEndOfFile', b'EncryptFile',
                        b'FindResourceW', b'FindResourceA', b'LoadResource', b'LockResource', b'SizeofResource',
                        b'OpenProcessToken', b'AdjustTokenPrivileges', b'LookupPrivilegeValueW',
                        b'BitBlt', b'GetDC', b'GetDesktopWindow',
                        b'RegOpenKeyExW', b'RegSetValueExW', b'RegCreateKeyExW',
                        b'CreateServiceW', b'StartServiceW',
                        b'ShellExecuteW', b'ShellExecuteExW',
                        b'CreateMutexW', b'OpenMutexW',
                        b'CryptAcquireContextW', b'CryptEncrypt', b'CryptDecrypt', b'CryptDeriveKey',
                        b'MoveFileW', b'CopyFileW', b'SetFileAttributesW',
                        b'NtMapViewOfSection', b'NtCreateProcessEx', b'RtlCreateUserThread',
                        b'NtSetInformationThread', b'NtQuerySystemInformation',
                        b'CreateToolhelp32Snapshot', b'Process32FirstW', b'Process32NextW',
                        b'WinHttpConnect', b'WinHttpSendRequest', b'WinHttpReadData',
                        b'InternetConnectW', b'InternetReadFile', b'HttpQueryInfoW',
                        b'RecvFrom', b'SendTo', b'GetAddrInfo', b'inet_ntoa',
                        b'CryptCreateHash', b'CryptHashData', b'CryptImportKey',
                        b'SetTokenInformation', b'DuplicateTokenEx', b'ImpersonateLoggedOnUser',
                        b'FindFirstFileW', b'FindNextFileW', b'RemoveDirectoryW',
                        b'GetClipboardData', b'GetRawInputData', b'RegisterRawInputDevices',
                        b'StretchBlt', b'GetDIBits', b'CreateCompatibleDC',
                    ]
                    for _sa in _SA_PATTERNS:
                        if _sa in head_data:
                            _string_apis_found.add(_sa.decode('ascii').lower())
                    if _string_apis_found:
                        _apis_set = _apis_set | _string_apis_found
                        if len(_string_apis_found) >= 5 and not _pe_info.get('has_clr'):
                            _susp_score_str_apis = min(40, len(_string_apis_found) * 3)
                            _susp_score += _susp_score_str_apis
                            _susp_reasons.append(f'String APIs ({len(_string_apis_found)}) in 0-import PE: packed/manual resolve')
                _sec_names_list = [s[0].lower() for s in _pe_info.get('sections', [])]
                _vi_susp = _pe_info.get('version_info', {})
                _vi_co_susp = (_vi_susp.get('CompanyName', '') or '').lower()
                _vi_desc_susp = (_vi_susp.get('FileDescription', '') or '').lower()
                _vi_prod_susp = (_vi_susp.get('ProductName', '') or '').lower()
                if _apis_set == {'_corexemain'} and not signer:
                    _vi_co_corex = (_vi_susp.get('CompanyName', '') or '').lower()
                    _COREX_TRUSTED = {'microsoft','google','apple','adobe','oracle','intel','nvidia','amd','vmware','hp','dell','lenovo','ibm','cisco','tencent','baidu','qihoo','kingsoft','huawei','xiaomi'}
                    _vi_trusted_co = any(t in _vi_co_corex for t in _COREX_TRUSTED) if _vi_co_corex else False
                    if not _vi_trusted_co:
                        _susp_score += 40
                        _susp_reasons.append('.NET stub loader')
                if not pe_apis and ext == '.dll':
                    _has_apiset_0 = '.apiset' in _sec_names_list
                    _text_sz_0 = sum(s[2] for s in _pe_info.get('sections', []) if s[0].lower() == '.text')
                    _rsrc_sz_0 = sum(s[2] for s in _pe_info.get('sections', []) if s[0].lower() == '.rsrc')
                    _total_sz_0 = sum(s[2] for s in _pe_info.get('sections', []))
                    _is_resource_only_0 = (_text_sz_0 < 4096 and _rsrc_sz_0 > 0 and _rsrc_sz_0 / max(_total_sz_0, 1) > 0.4)
                    _is_microsoft_0 = signer and 'microsoft' in signer.lower()
                    _is_clr_0 = _pe_info.get('has_clr', False)
                    if not (_has_apiset_0 or _is_resource_only_0 or _is_microsoft_0 or _is_clr_0):
                        _susp_score += 35
                        _susp_reasons.append('DLL with 0 imports')
                if not pe_apis and not _pe_info.get('has_clr') and not signer:
                    _max_ent_0imp = max((s[1] for s in _pe_info.get('sections', [])), default=0)
                    _max_ent_sec_name = ''
                    for _s_obj in _pe_info.get('sections', []):
                        if _s_obj[1] == _max_ent_0imp and _max_ent_0imp > 7.5:
                            _max_ent_sec_name = _s_obj[0]
                            break
                    if _max_ent_0imp > 7.5:
                        _susp_score += 40
                        _susp_reasons.append(f'0-import PE with high-entropy section ({_max_ent_sec_name}, e={_max_ent_0imp:.1f})')
                _inj_trusted = False
                if signer:
                    _inj_sl = signer.lower()
                    _INJ_TRUSTED = {'microsoft','mozilla','google','apple','adobe','oracle','intel','nvidia','amd','vmware','tencent','baidu','qihoo','kingsoft','huawei','xiaomi','sandboxie','kaspersky','avast','avg','bitdefender','eset','mcafee','symantec','norton','sophos','fortinet','glarysoft','glary','netease','ldplayer','npcap','eclipse','steam','valve','adoptium','electron','discord','slack','zoom','teams','dropbox'}
                    if any(t in _inj_sl for t in _INJ_TRUSTED):
                        _inj_trusted = True
                if not _inj_trusted and not signer and _vi_co_susp and 'microsoft' in _vi_co_susp:
                    _vi_ms_suspicious = False
                    if _pe_info.get('sections'):
                        _ms_sec_names = [s[0].lower() for s in _pe_info['sections']]
                        _PACKER_CHECK_MS = {'.aspack','.adata','upx0','upx1','upx2','upx3','.mpress1','.mpress2','.petite','.themida','.vmp0','.vmp1','.nsp0','.nsp1','.pec1','.pec2','.packman'}
                        if any(s in _PACKER_CHECK_MS for s in _ms_sec_names):
                            _vi_ms_suspicious = True
                        _ms_rsrc_ent = max((s[1] for s in _pe_info['sections'] if s[0].lower() == '.rsrc'), default=0)
                        _ms_rsrc_sz = sum(s[2] for s in _pe_info['sections'] if s[0].lower() == '.rsrc')
                        _ms_total_sz = sum(s[2] for s in _pe_info['sections'])
                        if _ms_rsrc_ent > 7.5 and _ms_rsrc_sz > 50000 and _ms_rsrc_sz / max(_ms_total_sz, 1) > 0.3:
                            _vi_ms_suspicious = True
                        _ms_max_ent = max((s[1] for s in _pe_info['sections']), default=0)
                        if not pe_apis and _ms_max_ent > 7.5 and not _pe_info.get('has_clr'):
                            _vi_ms_suspicious = True
                    if not _vi_ms_suspicious:
                        _inj_trusted = True
                if not _inj_trusted and not signer and _pe_info.get('import_dlls'):
                    _api_set_dlls = [d for d in _pe_info['import_dlls'] if d.startswith('api-ms-win-')]
                    _ucrt_dlls = [d for d in _pe_info['import_dlls'] if d.startswith('api-ms-win-crt')]
                    if _ucrt_dlls and len(_api_set_dlls) / max(len(_pe_info['import_dlls']), 1) > 0.5:
                        _inj_trusted = True
                _triggered_groups = []
                _partial_groups = []
                if not _inj_trusted and _apis_set:
                    _API_GROUPS = {
                        'injection': {'apis': {'createremotethread','writeprocessmemory','virtualallocex','ntcreatethreadex','queueuserapc','rtlcreateuserthread','setthreadcontext','ntunmapviewofsection','ntwritevirtualmemory','ntcreateprocessex','ntopenprocess','ntmapviewofsection','zwmapviewofsection','rtlcreatethreadex','ntcreatethread','rtlmovememory','createthread'}, 'min': 2, 'w': 35},
                        'process_hijack': {'apis': {'createprocessw','createprocessa','createthread','createthreadex','resumethread','suspendthread','openprocess','terminateprocess','getprocaddress','getmodulehandlea','getmodulehandlew','loadlibrarya','loadlibraryw','ntresumeprocess','createtoolhelp32snapshot','process32firstw','process32nextw','module32firstw','module32nextw'}, 'min': 5, 'w': 25},
                        'persistence': {'apis': {'regsetvalueexw','regsetvalueexa','regcreatekeyexw','regcreatekeyexa','openscmanagerw','createservicew','startservicew','shellexecuteexw','shellexecuteexa','shellexecutew','shellexecutea','copyfilew','movetofileex','writeprofilestringw','regopenkeyexw','regopenkeyexa','regdeletevaluew','regdeletevaluea','regsetvaluew','regsetvaluea'}, 'min': 2, 'w': 20},
                        'anti_analysis': {'apis': {'isdebuggerpresent','checkremotedebuggerpresent','ntqueryinformationprocess','ntsetinformationthread','ntquerysysteminformation','enumprocessmodules','enumprocesses','ntqueryobject','ntclose','ntsetinformationthread','outputdebugstringa','outputdebugstringw','gettickcount','queryperformancecounter'}, 'min': 2, 'w': 15},
                        'credential': {'apis': {'credenumerate','credread','cryptunprotectdata','lsaopenpolicy','lsaretrieveprivatedata','samopenuser','samconnect','samrconnect','cryptacquirecontextw','cryptderivekey','cryptencrypt','cryptdecrypt','cryptcreatehash','crypthashdata','cryptgetuserkey','cryptimportkey','cryptexportkey','cypryptgenkey'}, 'min': 2, 'w': 28},
                        'network': {'apis': {'wsastartup','connect','send','recv','socket','bind','listen','accept','gethostbyname','gethostname','inet_addr','htons','select','ioctlsocket','closesocket','internetopenw','internetopena','winhttpopen','winhttpopenrequest','winhttpsendrequest','urldownloadtofilew','urldownloadtofilea','httpqueryinfow','internetconnectw','internetreadfile','recvfrom','sendto','setsockopt','getsockopt','inet_ntoa','inet_pton','getaddrinfo','freeaddrinfo','wsacleanup','wsagetlasterror','getpeername','getsockname','htons','ntohs','htonl'}, 'min': 2, 'w': 18},
                        'file_destructive': {'apis': {'deletefilew','deletefilea','shfileoperationw','shfileoperationa','setfilepointer','setendoffile','encryptfile','decryptfile','fileencryptionstatus','createfilew','createfilea','writefile','movefilew','movefilea','shutdownblockreasoncreate','shutdownblockreasondestroy','findfirstfilew','findnextfilew','removeDirectoryw','removedirectorya','setfileattributesw','setfileattributesa'}, 'min': 5, 'w': 25},
                        'keylog': {'apis': {'setwindowshookexw','setwindowshookexa','getasynckeystate','getkeystate','getforegroundwindow','getclipboarddata','getrawinputdata','registerhotkey','mapvirtualkeyw','mapvirtualkeya','oemkeyscan','getkeyboardstate','getkeynametexta','getkeynametextw','toasciiex','tounicodeex','registerrawinputdevices'}, 'min': 3, 'w': 25},
                        'privilege': {'apis': {'openprocesstoken','adjusttokenprivileges','lookupprivilegevaluew','lookupprivilegevaluea','impersonateloggedonuser','settokeninformation','duplicatehandle','duplicatetokenex','duplicatetoken','openprocesstoken','gettokeninformation','setthreadtoken','impersonateclientself'}, 'min': 3, 'w': 15},
                        'resource_load': {'apis': {'loadresource','findresourcea','findresourcew','lockresource','sizeofresource','virtualalloc','virtualprotect','memcpy','rtlmoveMemory','findresourceexw','findresourceexa','loadlibraryexw','loadlibraryexa','enumresourcetypesw','enumresourcenamesw'}, 'min': 3, 'w': 15},
                        'screen_capture': {'apis': {'bitblt','getdc','createdca','createdcw','getdesktopwindow','getwindowdc','releasedc','selectobject','createcompatiblebitmap','createcompatibledc','getdibits','stretchblt','patblt','plgblt','alphablend','transparentblt','getscreenshot'}, 'min': 5, 'w': 15},
                    }
                    for _gname, _ginfo in _API_GROUPS.items():
                        _hit_apis = _apis_set & _ginfo['apis']
                        if len(_hit_apis) >= _ginfo['min']:
                            _triggered_groups.append((_gname, _ginfo['w'], _hit_apis))
                        elif len(_hit_apis) >= 1:
                            _partial_groups.append((_gname, _ginfo['w'], len(_hit_apis), _ginfo['min'], _hit_apis))
                    if len(_triggered_groups) >= 3:
                        _group_total = sum(g[1] for g in _triggered_groups)
                        _group_bonus = (len(_triggered_groups) - 1) * 10
                        _group_score = min(60, _group_total + _group_bonus)
                        _susp_score += _group_score
                        _susp_reasons.append(f'API groups[{len(_triggered_groups)}]: {",".join(g[0] for g in _triggered_groups)} (+{_group_score})')
                    elif len(_triggered_groups) == 2:
                        _g0 = _triggered_groups[0][0]
                        _g1 = _triggered_groups[1][0]
                        _high_risk = {'injection','credential','keylog','file_destructive','network'}
                        _group_total = sum(g[1] for g in _triggered_groups)
                        if _g0 in _high_risk or _g1 in _high_risk:
                            _group_score = min(45, _group_total + 5)
                        else:
                            _group_score = min(35, _group_total)
                        _susp_score += _group_score
                        _susp_reasons.append(f'API groups[2]: {",".join(g[0] for g in _triggered_groups)} (+{_group_score})')
                    elif len(_triggered_groups) == 1:
                        _g = _triggered_groups[0]
                        if _g[0] in ('injection','credential','keylog','network','resource_load'):
                            _susp_score += _g[1]
                            _susp_reasons.append(f'API group[{_g[0]}] (+{_g[1]})')
                    if len(_triggered_groups) <= 1 and len(_partial_groups) >= 3 and not signer:
                        _skip_partial = False
                        if ext == '.dll' and len(pe_apis) >= 100:
                            _skip_partial = True
                        if not _skip_partial:
                            _partial_score = min(35, len(_partial_groups) * 8)
                            _susp_score += _partial_score
                            _susp_reasons.append(f'Partial API groups[{len(_partial_groups)}]: {",".join(g[0] for g in _partial_groups)} (+{_partial_score})')
                            if _triggered_groups:
                                _susp_score += 10
                                _susp_reasons.append(f'Triggered + partial groups combo (+10)')
                    if not signer and _pe_info.get('sections'):
                        _rdata_sz = sum(s[2] for s in _pe_info['sections'] if s[0].lower() == '.rdata')
                        _text_sz_packed = sum(s[2] for s in _pe_info['sections'] if s[0].lower() == '.text')
                        _rdata_ent = max((s[1] for s in _pe_info['sections'] if s[0].lower() == '.rdata'), default=0)
                        if _rdata_sz > 100000 and _rdata_ent > 7.5 and _text_sz_packed < 50000:
                            _susp_score += 20
                            _susp_reasons.append(f'Packed .rdata ({_rdata_sz}B, entropy={_rdata_ent:.1f})')
                            if _triggered_groups:
                                _susp_score += 20
                                _susp_reasons.append(f'Packed .rdata + API groups[{",".join(g[0] for g in _triggered_groups)}]')
                    if not signer and _pe_info.get('sections'):
                        _PACKER_SECTIONS = {
                            '.aspack': 'aspack', '.adata': 'aspack',
                            'upx0': 'UPX', 'upx1': 'UPX', 'upx2': 'UPX', 'upx3': 'UPX',
                            '.mpress1': 'MPRESS', '.mpress2': 'MPRESS',
                            '.petite': 'Petite', '.themida': 'Themida',
                            '.vmp0': 'VMProtect', '.vmp1': 'VMProtect',
                            '.nsp0': 'Nspack', '.nsp1': 'Nspack',
                            '.pec1': 'PECrypt', '.pec2': 'PECrypt',
                            '.packman': 'Packman',
                        }
                        _found_packers = set()
                        for _sn in _sec_names_list:
                            if _sn in _PACKER_SECTIONS:
                                _found_packers.add(_PACKER_SECTIONS[_sn])
                        if _found_packers:
                            _susp_score += 40
                            _susp_reasons.append(f'Packer detected: {",".join(_found_packers)}')
                            if _triggered_groups or _partial_groups:
                                _susp_score += 15
                                _susp_reasons.append(f'Packer + suspicious APIs (+15)')
                        _max_sec_ent = max((s[1] for s in _pe_info['sections']), default=0)
                        _max_ent_sec = ''
                        for _s_obj in _pe_info['sections']:
                            if _s_obj[1] == _max_sec_ent and _max_sec_ent > 7.5:
                                _max_ent_sec = _s_obj[0]
                                break
                        if not pe_apis and _max_sec_ent > 7.5 and not _pe_info.get('has_clr'):
                            _susp_score += 40
                            _susp_reasons.append(f'0-import PE with high-entropy section ({_max_ent_sec}, e={_max_sec_ent:.1f})')
                        for _s_obj in _pe_info['sections']:
                            _sn_pt = _s_obj[0].lower()
                            _raw_pt = _s_obj[2]
                            _virt_pt = _s_obj[3] if len(_s_obj) > 3 else 0
                            _ent_pt = _s_obj[1]
                            if _sn_pt in ('.text','.code') and _ent_pt > 7.5 and _virt_pt > 0 and _raw_pt / max(_virt_pt, 1) < 0.2:
                                _susp_score += 35
                                _susp_reasons.append(f'Packed {_sn_pt} (e={_ent_pt:.1f}, raw/virt={_raw_pt}/{_virt_pt})')
                                break
                        _net_hit = _apis_set & _API_GROUPS['network']['apis']
                        if len(_net_hit) >= 5:
                            _susp_score += 20
                            _susp_reasons.append(f'Network worm pattern ({len(_net_hit)} socket APIs)')
                        _crypto_apis = _apis_set & {'cryptdecrypt','cryptencrypt','cryptderivekey','cryptacquirecontextw','cryptcreatehash','crypthashdata'}
                        _file_apis = _apis_set & {'createfilew','createfilea','writefile','deletefilew','deletefilea','setfilepointer','setendoffile','encryptfile'}
                        if _crypto_apis and _file_apis and not signer:
                            _susp_score += 25
                            _susp_reasons.append(f'Ransomware combo: crypto({len(_crypto_apis)})+file({len(_file_apis)})')
                        _non_std_with_apis = [s for s in _sec_names_list if s not in {'.text','.rdata','.data','.pdata','.rsrc','.reloc','.edata','.idata','.bss','.tls','.crt','.gfids','.00cfg','.xdata','.symtab','fothk','.didat'} and not s.startswith('/')]
                        if _non_std_with_apis and not signer and (_triggered_groups or _partial_groups):
                            _susp_score += 15
                            _susp_reasons.append(f'Non-standard sections + APIs: {_non_std_with_apis[:3]}')
                        _rsrc_ent_max = max((s[1] for s in _pe_info['sections'] if s[0].lower() == '.rsrc'), default=0)
                        _rsrc_sz_big = sum(s[2] for s in _pe_info['sections'] if s[0].lower() == '.rsrc')
                        if _rsrc_ent_max > 7.5 and _rsrc_sz_big > 50000 and not signer:
                            _rsrc_ratio = _rsrc_sz_big / max(sum(s[2] for s in _pe_info['sections']), 1)
                            if _rsrc_ratio > 0.3:
                                _susp_score += 20
                                _susp_reasons.append(f'Packed .rsrc (e={_rsrc_ent_max:.1f}, {_rsrc_sz_big}B, {_rsrc_ratio*100:.0f}% of file)')
                if '.ndata' in _sec_names_list and 'runtime' in _vi_desc_susp and 'local' in _vi_desc_susp:
                    _susp_score += 40
                    _susp_reasons.append('NSIS suspicious installer')
                if '.code' in _sec_names_list and not signer and not _vi_co_susp and not _vi_susp.get('ProductName', ''):
                    _susp_score += 35
                    _susp_reasons.append('Non-standard .code section, no version info')
                if 'loadresource' in _apis_set and 'findresourcea' in _apis_set and 'virtualalloc' in _apis_set:
                    if not signer and ('runtime' in _vi_desc_susp or 'local.org' in _vi_desc_susp):
                        _susp_score += 40
                        _susp_reasons.append('Resource-based loader')
                if ext == '.dll' and _pe_info.get('is_dll'):
                    _exp_ct = _pe_info.get('export_count', 0)
                    _overlay = _pe_info.get('overlay_size', 0)
                    _fsize = os.path.getsize(filepath)
                    _dup_secs = len(_sec_names_list) != len(set(_sec_names_list))
                    _has_apiset = '.apiset' in _sec_names_list
                    _has_text = '.text' in _sec_names_list
                    _text_sz = sum(s[2] for s in _pe_info.get('sections', []) if s[0].lower() == '.text')
                    _rsrc_sz = sum(s[2] for s in _pe_info.get('sections', []) if s[0].lower() == '.rsrc')
                    _total_sec_sz = sum(s[2] for s in _pe_info.get('sections', []))
                    _is_resource_only = (_text_sz < 4096 and _rsrc_sz > 0 and _rsrc_sz / max(_total_sec_sz, 1) > 0.4)
                    _is_apiset_schema = _has_apiset or (_vi_prod_susp and 'apiset' in _vi_desc_susp)
                    _is_microsoft = signer and 'microsoft' in signer.lower()
                    _sys_dll_names = {'uxtheme.dll','version.dll','winhttp.dll','wininet.dll','ws2_32.dll',
                        'cryptbase.dll','cryptsp.dll','dbghelp.dll','iphlpapi.dll','msvcr100.dll',
                        'msvcp140.dll','vcruntime140.dll','nlaapi.dll','napinsp.dll','pnrpnsp.dll',
                        'wshbth.dll','winrnr.dll','nrm.dll','mimefilt.dll','urlmon.dll',
                        'mscoree.dll','msvcr110.dll','msvcr120.dll','d3d11.dll','dxgi.dll',
                        'dwmapi.dll','userenv.dll','secur32.dll','netprofm.dll','npmproxy.dll',
                        'wtsapi32.dll','powrprof.dll','psapi.dll','samlib.dll','sensapi.dll',
                        'winmm.dll','ws2_32.dll','mswsock.dll','shlwapi.dll','setupapi.dll',
                        'cfgmgr32.dll','clusapi.dll','user32.dll','kernel32.dll','ntdll.dll',
                        'advapi32.dll','gdi32.dll','ole32.dll','comctl32.dll','comdlg32.dll',
                        'shell32.dll','rpcrt4.dll','oleaut32.dll','wintrust.dll','crypt32.dll'}
                    _fname_lower = os.path.basename(filepath).lower()
                    if _is_microsoft or _is_apiset_schema or _is_resource_only:
                        pass
                    else:
                        if not pe_apis and _exp_ct > 0:
                            _susp_score += 25
                            _susp_reasons.append(f'DLL proxy: 0 imports + {_exp_ct} exports')
                        if _overlay > 0 and _overlay / max(_fsize, 1) > 0.3:
                            _susp_score += 25
                            _susp_reasons.append(f'Large overlay ({_overlay} bytes, {_overlay*100//max(_fsize,1)}% of file)')
                        if _dup_secs:
                            _susp_score += 20
                            _susp_reasons.append(f'Duplicate section names: {_sec_names_list}')
                        if _fname_lower in _sys_dll_names and not signer:
                            _susp_score += 25
                            _susp_reasons.append(f'System DLL name impersonation ({_fname_lower})')
                if not signer and _pe_info.get('sections'):
                    _has_symtab = '.symtab' in _sec_names_list
                    _text_sz_all = sum(s[2] for s in _pe_info['sections'] if s[0].lower() == '.text')
                    _rdata_sz_all = sum(s[2] for s in _pe_info['sections'] if s[0].lower() == '.rdata')
                    _import_ct_all = _pe_info.get('import_count', 0)
                    if _has_symtab and _rdata_sz_all > 500000 and _import_ct_all <= 50:
                        _susp_score += 40
                        _susp_reasons.append(f'Static binary with .symtab + large .rdata ({_rdata_sz_all}B, {_import_ct_all} imports)')
                    if not pe_apis and _text_sz_all > 100000 and not _pe_info.get('has_clr'):
                        _max_text_ent = max((s[1] for s in _pe_info['sections'] if s[0].lower() == '.text'), default=0)
                        if _max_text_ent > 7.5:
                            _susp_score += 45
                            _susp_reasons.append(f'0-import PE with packed .text (entropy={_max_text_ent:.1f}, size={_text_sz_all}B)')
                        elif _text_sz_all > 500000:
                            _susp_score += 35
                            _susp_reasons.append(f'0-import PE with large .text ({_text_sz_all}B)')
                    _has_ndata = '.ndata' in _sec_names_list
                    if _has_ndata and ('OpenProcessToken' in pe_apis or 'AdjustTokenPrivileges' in pe_apis):
                        _susp_score += 40
                        _susp_reasons.append('NSIS installer with privilege APIs')
                    _stripped_secs = [s for s in _sec_names_list if s.startswith('/')]
                    if _stripped_secs and not signer:
                        _rsrc_sz_stripped = sum(s[2] for s in _pe_info['sections'] if s[0].lower() == '.rsrc')
                        if _rsrc_sz_stripped > 50000:
                            _susp_score += 30
                            _susp_reasons.append(f'Stripped sections ({len(_stripped_secs)}) + large .rsrc ({_rsrc_sz_stripped}B)')
                        if len(_stripped_secs) >= 5 and not pe_apis:
                            _susp_score += 30
                            _susp_reasons.append(f'Rust/Go binary ({len(_stripped_secs)} stripped sections) + 0 imports')
                            if _string_apis_found:
                                _susp_score += 15
                                _susp_reasons.append(f'Stripped binary + string APIs ({len(_string_apis_found)})')
                    _dup_data_secs = [s for s in _pe_info['sections'] if s[0].lower() == '.data']
                    if len(_dup_data_secs) > 1:
                        _dup_data_ent = max(s[1] for s in _dup_data_secs)
                        _dup_data_sz = sum(s[2] for s in _dup_data_secs)
                        if _dup_data_ent > 7.0 and _dup_data_sz > 1000000:
                            _susp_score += 40
                            _susp_reasons.append(f'Duplicate .data sections (entropy={_dup_data_ent:.1f}, size={_dup_data_sz}B)')
                    _non_std_secs_nonsys = [s for s in _sec_names_list if s not in {'.text','.rdata','.data','.pdata','.rsrc','.reloc','.edata','.idata','.bss','.tls','.crt','.gfids','.00cfg','.xdata','.idata','.symtab','fothk','.didat'} and not s.startswith('/')]
                    if _non_std_secs_nonsys and not signer and not pe_apis:
                        _susp_score += 25
                        _susp_reasons.append(f'Non-standard sections + 0 imports: {_non_std_secs_nonsys[:3]}')
                    _special_char_secs = []
                    for _s_obj in _pe_info.get('sections', []):
                        _sn_sc = _s_obj[0]
                        if _sn_sc and not _sn_sc.startswith('/'):
                            _has_special = any(not (c.isalnum() or c == '.' or c == '_') for c in _sn_sc)
                            if _has_special:
                                _special_char_secs.append(_sn_sc)
                    if _special_char_secs and not signer:
                        _susp_score += 35
                        _susp_reasons.append(f'Sections with special chars: {_special_char_secs[:3]}')
                _overlay_sz = _pe_info.get('overlay_size', 0) if '_pe_info' in dir() else 0
                _fsize_susp = os.path.getsize(filepath)
                _text_sz_ov = sum(s[2] for s in _pe_info.get('sections', []) if s[0].lower() == '.text')
                _rsrc_sz_ov = sum(s[2] for s in _pe_info.get('sections', []) if s[0].lower() == '.rsrc')
                _total_sz_ov = sum(s[2] for s in _pe_info.get('sections', []))
                _is_res_only_ov = (_text_sz_ov < 4096 and _rsrc_sz_ov > 0 and _rsrc_sz_ov / max(_total_sz_ov, 1) > 0.4)
                if _overlay_sz > 0 and not _is_res_only_ov:
                    _overlay_ratio = _overlay_sz / max(_fsize_susp, 1)
                    _overlay_thresh = 0.3 if not signer else 0.5
                    if _overlay_ratio > _overlay_thresh:
                        _susp_score += 35
                        _susp_reasons.append(f'Massive overlay ({_overlay_sz}B, {_overlay_sz*100//max(_fsize_susp,1)}% of file)')
                if _apis_set == {'_corexemain'}:
                    _vi_co_net = (_vi_susp.get('CompanyName', '') or '')
                    _vi_desc_net = (_vi_susp.get('FileDescription', '') or '')
                    _vi_prod_net = (_vi_susp.get('ProductName', '') or '')
                    _garbled = False
                    for _vi_val in [_vi_co_net, _vi_desc_net, _vi_prod_net]:
                        if _vi_val and len(_vi_val) > 3:
                            _non_ascii_vi = sum(1 for c in _vi_val if ord(c) > 127 or ord(c) < 32)
                            if _non_ascii_vi / len(_vi_val) > 0.3:
                                _garbled = True
                            _special_ct = sum(1 for c in _vi_val if c in '<>?{}[]|\\^~`!@#$%&*()+=:;"\'')
                            _has_space = ' ' in _vi_val
                            if not _has_space and len(_vi_val) > 5 and _special_ct / len(_vi_val) > 0.15:
                                _garbled = True
                            _upper_digit_ct = sum(1 for c in _vi_val if c.isupper() or c.isdigit())
                            if not _has_space and len(_vi_val) > 8 and _upper_digit_ct / len(_vi_val) > 0.7 and _special_ct > 0:
                                _garbled = True
                    if _garbled:
                        _susp_score += 45
                        _susp_reasons.append('.NET stub with garbled version info')
                if '_corexemain' in _apis_set and _string_apis_found and not signer:
                    _net_strong_apis = _string_apis_found & {'createremotethread','writeprocessmemory','virtualallocex','createmutexw','openmutexw'}
                    _net_resolve_apis = _string_apis_found & {'getprocaddress','virtualprotect','loadlibrarya','loadlibraryw'}
                    if _net_strong_apis:
                        _susp_score += 40
                        _susp_reasons.append(f'.NET stub with strong string APIs: {_net_strong_apis}')
                    elif len(_net_resolve_apis) >= 2:
                        _susp_score += 35
                        _susp_reasons.append(f'.NET stub with API resolve strings: {_net_resolve_apis}')
                if _pe_info.get('has_clr') and not signer and not _inj_trusted:
                    _vi_net_co = _vi_susp.get('CompanyName', '') or ''
                    _vi_net_ver = _vi_susp.get('FileVersion', '') or ''
                    _vi_net_prod = _vi_susp.get('ProductName', '') or ''
                    _vi_net_desc = _vi_susp.get('FileDescription', '') or ''
                    _vi_net_has_any = bool(_vi_net_co or _vi_net_ver or _vi_net_prod or _vi_net_desc)
                    if not _vi_net_has_any:
                        _susp_score += 30
                        _susp_reasons.append('.NET binary without signature or version info')
                if not signer and not _inj_trusted and _pe_info.get('rwx_sections'):
                    _susp_score += 35
                    _susp_reasons.append(f'RWX section(s): {",".join(_pe_info["rwx_sections"])}')
                if not signer and not _inj_trusted and _pe_info.get('ep_section') and _pe_info.get('sections'):
                    _ep_sec = _pe_info['ep_section'].lower()
                    _sec_count = len(_pe_info['sections'])
                    if _ep_sec and _ep_sec not in ('.text','.code','') and not _pe_info.get('has_clr'):
                        if _ep_sec == _pe_info['sections'][-1][0].lower() or _sec_count > 6:
                            _susp_score += 30
                            _susp_reasons.append(f'Entry point in non-.text section ({_pe_info["ep_section"]})')
                if not signer and not _inj_trusted and _pe_info.get('ordinal_imports', 0) > 0:
                    _total_imp_all = _pe_info.get('import_count', 0) + _pe_info.get('ordinal_imports', 0)
                    if _total_imp_all > 0 and _pe_info.get('ordinal_imports', 0) / _total_imp_all > 0.5 and _total_imp_all >= 3:
                        _susp_score += 25
                        _susp_reasons.append(f'Ordinal-heavy imports ({_pe_info["ordinal_imports"]}/{_total_imp_all})')
                _triggered_names = set(g[0] for g in _triggered_groups) if '_triggered_groups' in dir() else set()
                _partial_names = set(g[0] for g in _partial_groups) if '_partial_groups' in dir() else set()
                if _triggered_names:
                    _has_net = 'network' in _triggered_names
                    _has_inj = 'injection' in _triggered_names
                    _has_key = 'keylog' in _triggered_names
                    _has_pers = 'persistence' in _triggered_names
                    _has_proc = 'process_hijack' in _triggered_names
                    if _has_inj and _has_net and not signer:
                        _susp_score += 20
                        _susp_reasons.append('RAT combo: injection+network (+20)')
                    if _has_key and _has_net and not signer:
                        _susp_score += 20
                        _susp_reasons.append('Infostealer combo: keylog+network (+20)')
                    if _has_pers and _has_net and not signer:
                        _susp_score += 15
                        _susp_reasons.append('Backdoor combo: persistence+network (+15)')
                    if _has_proc and _has_net and not signer:
                        _susp_score += 15
                        _susp_reasons.append('Downloader combo: process_hijack+network (+15)')
                _wmi_apis = _apis_set & {'coinitialize','cocreateinstance','clsidfromprogid','iwbemservices','wbemlevel1login','ntcreateevent'}
                _shadow_apis = _apis_set & {'createsnapshot','deletesnapshot','ivssbackupcomponents'}
                _svc_apis = _apis_set & {'openscmanagerw','openscmanagera','createservicew','createservicea','changeserviceconfigw','startservicew','startservicea','deleteservice','controlservice'}
                if _wmi_apis and not signer and not _inj_trusted and len(_wmi_apis) >= 2:
                    _susp_score += 20
                    _susp_reasons.append(f'WMI manipulation APIs ({len(_wmi_apis)})')
                if _svc_apis and not signer and not _inj_trusted and len(_svc_apis) >= 3:
                    _susp_score += 20
                    _susp_reasons.append(f'Service manipulation APIs ({len(_svc_apis)})')
                if not signer and _pe_info.get('import_dlls'):
                    _rare_dlls = set(_pe_info['import_dlls']) & {'vssapi.dll','samlib.dll','netapi32.dll','wtsapi32.dll','dbghelp.dll','psapi.dll','secur32.dll','wintrust.dll','cryptsp.dll'}
                    if _rare_dlls and _triggered_groups:
                        _susp_score += 15
                        _susp_reasons.append(f'Rare DLL imports + API groups: {",".join(list(_rare_dlls)[:3])}')
                if not signer and not _inj_trusted and not _pe_info.get('has_clr'):
                    try:
                        _ts = _pe_info.get('timestamp', 0)
                        if _ts == 0 and _apis_set and len(_apis_set) >= 5:
                            _susp_score += 15
                            _susp_reasons.append('Zero timestamp with API imports')
                        elif _ts > 0:
                            import time as _time_mod
                            if _ts > int(_time_mod.time()) + 86400:
                                _susp_score += 20
                                _susp_reasons.append('Future compilation timestamp')
                    except:
                        pass
                if not signer and not _inj_trusted and len(head_data) > 4096:
                    try:
                        _pe_text_scan = head_data[:min(len(head_data), 1024*1024)]
                        import re as _re_pe_str
                        _urls = _re_pe_str.findall(rb'https?://[a-zA-Z0-9\-._~:/?#\[\]@!$&\'()*+,;=%]{10,}', _pe_text_scan)
                        _susp_urls = [u for u in _urls if not any(d in u.lower() for d in [b'microsoft.com',b'google.com',b'apache.org',b'sourceforge.net',b'github.com',b'gnu.org',b'w3.org',b'xml.org'])]
                        if len(_susp_urls) >= 2 and (_triggered_groups or _partial_groups):
                            _susp_score += 15
                            _susp_reasons.append(f'Suspicious URLs in PE ({len(_susp_urls)})')
                        _b64_blobs = _re_pe_str.findall(rb'[A-Za-z0-9+/]{500,}={0,2}', _pe_text_scan[:65536])
                        if len(_b64_blobs) >= 5 and not _pe_info.get('has_clr'):
                            _susp_score += 15
                            _susp_reasons.append(f'Base64 blobs in PE ({len(_b64_blobs)})')
                        _pdb_paths = _re_pe_str.findall(rb'[A-Za-z]:\\[^\x00]{5,200}\.pdb', _pe_text_scan)
                        if _pdb_paths:
                            _pdb_susp = False
                            for _pdb in _pdb_paths:
                                _pdb_l = _pdb.lower()
                                if any(d in _pdb_l for d in [b'desktop',b'temp',b'download',b'release',b'debug',b'build']):
                                    if b'users' in _pdb_l or b'documents' in _pdb_l:
                                        _pdb_susp = True
                                        break
                            if _pdb_susp and not signer:
                                _susp_score += 10
                                _susp_reasons.append(f'Suspicious PDB path: {_pdb_paths[0][:60].decode("ascii","ignore")}')
                    except:
                        pass
                _norm_fp_susp = os.path.normpath(filepath).lower().replace('\\', '/')
                _is_winsxs_susp = 'windows/winsxs/' in _norm_fp_susp
                _is_dotnet_dir_susp = 'windows/microsoft.net/' in _norm_fp_susp
                _is_resources_dll = filepath.lower().endswith('.resources.dll')
                _vi_co_susp_val = (_vi_susp.get('CompanyName', '') or '').lower() if '_vi_susp' in dir() else ''
                _is_ms_vi_susp = 'microsoft' in _vi_co_susp_val
                _is_clr_susp = _pe_info.get('has_clr', False) if '_pe_info' in dir() else False
                _TRUSTED_VI_SUSP = {'microsoft','7-zip','dell','steam','valve','google','apple','oracle','intel','nvidia','amd','vmware','hp','lenovo','ibm','cisco','tencent','baidu','qihoo','kingsoft','huawei','xiaomi','broadcom','symantec','norton','avast','avg','bitdefender','kaspersky','eset','mcafee','coloros','oppo','realtek','samsung','lg electronics','igor pavlov','broadcom corporation','valve corporation'}
                _is_trusted_vi_susp = any(t in _vi_co_susp_val for t in _TRUSTED_VI_SUSP) if _vi_co_susp_val else False
                if _is_winsxs_susp or _is_dotnet_dir_susp:
                    _susp_score = 0
                elif _is_resources_dll:
                    _susp_score = 0
                elif _is_clr_susp and (_is_ms_vi_susp or _is_trusted_vi_susp):
                    _susp_score = 0
                elif _is_trusted_vi_susp and not signer and _susp_score < 50:
                    _susp_score = 0
                if _susp_score >= 30:
                    _group_names_str = '; '.join(_susp_reasons)
                    _has_destructive = any('file_destructive' in r for r in _susp_reasons)
                    _has_credential = any('credential' in r for r in _susp_reasons)
                    _has_injection = any('injection' in r for r in _susp_reasons)
                    _has_rat = any('RAT combo' in r for r in _susp_reasons)
                    _has_stealer = any('Infostealer' in r for r in _susp_reasons)
                    _has_backdoor = any('Backdoor combo' in r for r in _susp_reasons)
                    _has_downloader = any('Downloader combo' in r for r in _susp_reasons)
                    _susp_final = min(95, 55 + _susp_score + self.study.get_boost(filepath))
                    if _has_destructive and (_has_credential or _has_injection):
                        _susp_final = min(95, _susp_final + 10)
                    _susp_ttype = classify_threat(filepath, heuristic=True, pe_apis=pe_apis)
                    if _has_destructive and 'Generic' in _susp_ttype:
                        _susp_ttype = _susp_ttype.replace('Generic','Ransom')
                    if _has_rat and 'Generic' in _susp_ttype:
                        _susp_ttype = _susp_ttype.replace('Generic','RAT')
                    if _has_stealer and 'Generic' in _susp_ttype:
                        _susp_ttype = _susp_ttype.replace('Generic','Stealer')
                    if _has_backdoor and 'Generic' in _susp_ttype:
                        _susp_ttype = _susp_ttype.replace('Generic','Backdoor')
                    if _has_downloader and 'Generic' in _susp_ttype:
                        _susp_ttype = _susp_ttype.replace('Generic','Trojan')
                    _susp_res = f"MALICIOUS|{_susp_ttype}|PE-Suspicious|{_susp_final}"
                    self.cache.put(key, (_susp_res, _susp_final, _susp_ttype))
                    self.study.record_result(filepath, _susp_ttype, _susp_final, _group_names_str)
                    return _susp_res, _susp_final, _susp_ttype

            study_boost = self.study.get_boost(filepath)

            if CONFIG.get("enable_pe_scan", True) and head_data[:4] == b'\x4c\x00\x00\x00' and not _is_security_tool_component(filepath):
                try:
                    _lnk_text_all = head_data.decode('utf-16-le','ignore').lower() + head_data.decode('latin-1','ignore').lower()
                    _lnk_score_all = 0
                    for _lk, _lw in {'powershell':15,'windowspowershell':10,'powershell\\v1.0':10,'powershell/v1.0':10,'-windowstyle hidden':12,'-executionpolicy bypass':12,'iex(':15,'invoke-expression':10,'-enc ':10,'-encodedcommand':10,'downloadstring':12,'downloadfile':10,'new-object net.webclient':12,'start-process':8,'cmd /c':8,'-w hidden':10,'irm ':8,'iwr ':8,'/c ':5,'wscript':8,'cscript':8,'mshta':10,'rundll32':8,'-nop':8,'-noprofile':8,'/windows/system32/windowspowershell':10}.items():
                        if _lk in _lnk_text_all: _lnk_score_all += _lw
                    if _lnk_score_all >= 20:
                        _lnk_ttype = classify_threat(filepath, heuristic=True)
                        _lnk_final = min(95, 55 + _lnk_score_all + study_boost)
                        _lnk_res = f"MALICIOUS|{_lnk_ttype}|LNK|{_lnk_final}"
                        self.cache.put(key, (_lnk_res, _lnk_final, _lnk_ttype))
                        self.study.record_result(filepath, _lnk_ttype, _lnk_final, "LNK heuristic")
                        return _lnk_res, _lnk_final, _lnk_ttype
                except: pass

            is_script = ext in {'.vbs','.ps1','.js','.bat','.cmd','.py','.pyw','.vbe','.wsf','.hta','.sct','.wsc'}
            is_pe_file = _is_pe

            if CONFIG.get("enable_study_engine", True) and ext != '.sys' and not is_script:
                name, conf, feat = self.advanced.scan(filepath, file_data=head_data)
                if name and conf >= CONFIG["confidence_threshold"]:
                    final = min(100, conf + study_boost)
                    ttype = classify_threat(filepath, rule_name=name.replace("Advanced_", ""))
                    res = f"MALICIOUS|{ttype}|Signature|{final}"
                    self.cache.put(key, (res, final, ttype))
                    self.study.record_result(filepath, ttype, final, "Signature: " + name)
                    return res, final, ttype

            if CONFIG.get("enable_study_engine", True) and is_script:
                script_tool_names = {'scan','detect','kill','clean','protect','defense','security','antivirus','antimalware','pasw','injectscan','setup'}
                fname_lower = os.path.basename(filepath).lower()
                is_bat = ext in {'.bat', '.cmd'}
                _is_py = ext in {'.py', '.pyw'}
                _is_js = ext in {'.js', '.jse'}
                _skip_script = False
                if _is_security_tool_component(filepath):
                    _skip_script = True
                if _is_js and _is_js_library_file(filepath):
                    _skip_script = True
                if _is_py and any(t in fname_lower for t in script_tool_names):
                    _skip_script = True
                if not _skip_script and head_data[:4] == b'\x4c\x00\x00\x00':
                    try:
                        _lnk_text = head_data.decode('utf-16-le','ignore').lower() + head_data.decode('latin-1','ignore').lower()
                        _lnk_score = 0
                        for _lk, _lw in {'powershell':15,'-windowstyle hidden':12,'-executionpolicy bypass':12,'iex(':15,'invoke-expression':10,'-enc ':10,'-encodedcommand':10,'downloadstring':12,'downloadfile':10,'new-object net.webclient':12,'start-process':8,'cmd /c':8}.items():
                            if _lk in _lnk_text: _lnk_score += _lw
                        if _lnk_score >= 20:
                            ttype = classify_threat(filepath, heuristic=True)
                            final_conf = min(95, 55 + _lnk_score + study_boost)
                            res = f"MALICIOUS|{ttype}|LNK|{final_conf}"
                            self.cache.put(key, (res, final_conf, ttype))
                            self.study.record_result(filepath, ttype, final_conf, "LNK heuristic")
                            return res, final_conf, ttype
                    except: pass
                if not _skip_script and (is_bat or not any(t in fname_lower for t in script_tool_names)):
                    try:
                        if head_data[:2] == b'\xff\xfe':
                            text_content = head_data.decode('utf-16-le','ignore').lower()
                        elif head_data[:2] == b'\xfe\xff':
                            text_content = head_data.decode('utf-16-be','ignore').lower()
                        else:
                            text_content = head_data.decode('utf-8','ignore').lower()
                        script_score = 0
                        if _is_py:
                            _py_patterns = {
                                'subprocess.popen': 8, 'os.system': 6, 'os.popen': 6,
                                'base64.b64decode': 8, 'base64.b32decode': 8,
                                'socket.socket': 8, 'socket.connect': 8,
                                'ctypes.windll': 10, 'ctypes.cdll': 8,
                                'win32api': 6, 'win32process': 8,
                                'pickle.loads': 8, 'marshal.loads': 8,
                                '__import__': 6, 'tempfile.gettempdir': 4,
                            }
                            for kw, w in _py_patterns.items():
                                if kw in text_content: script_score += w
                            _py_has_sub = 'subprocess' in text_content
                            _py_has_b64 = 'base64' in text_content
                            _py_has_sock = 'socket' in text_content
                            _py_has_ctypes = 'ctypes' in text_content
                            _py_has_exec = 'exec(' in text_content
                            _py_has_net = any(n in text_content for n in ['socket', 'requests', 'urllib', 'http.client', 'websocket'])
                            _py_has_reg = 'winreg' in text_content or '_winreg' in text_content
                            if _py_has_sub and _py_has_b64 and _py_has_net:
                                script_score += 25
                            if _py_has_ctypes and ('virtualalloc' in text_content or 'writeprocessmemory' in text_content or 'createremotethread' in text_content):
                                script_score += 30
                            if 'createremotethread' in text_content and 'writeprocessmemory' in text_content:
                                script_score += 25
                            if _py_has_sock and _py_has_exec and _py_has_b64:
                                script_score += 25
                            if _py_has_reg and 'currentversion\\run' in text_content:
                                script_score += 25
                            if 'shutil.copy' in text_content and ('startup' in text_content or 'appdata' in text_content):
                                script_score += 20
                            if 'disableregistrytools' in text_content or 'disabletaskmgr' in text_content:
                                script_score += 15
                            _py_obf = text_content.count('chr(') + text_content.count('ord(')
                            if _py_obf > 30:
                                script_score += 20
                            elif _py_obf > 15:
                                script_score += 10
                            _py_b64_count = text_content.count('b64decode')
                            if _py_b64_count > 3:
                                script_score += 15
                            _script_threshold = 55
                        else:
                            for kw, w in {'iex(new-object net.webclient)':15,'invoke-expression':10,'set-mppreference -disable':15,'add-mppreference -exclusion':15,'certutil -decode':12,'new-object system.net.sockets.tcpclient':15,'powershell -enc':12,'powershell -encodedcommand':12,'frombase64string':10,'invoke-webrequest':8,'invoke-restmethod':8}.items():
                                if kw in text_content: script_score += w
                            for kw, w in {'-windowstyle hidden':10,'-noprofile -exec bypass':12,'createobject("wscript.shell")':10,'shell.application':8,'rundll32.exe':7,'regsvr32.exe':8,'mshta.exe':10,'adodb.stream':8,'scripting.filesystemobject':7}.items():
                                if kw in text_content: script_score += w
                            if not _is_py:
                                for kw, w in {'eval(':8,'escape(':4,'unescape(':4,'string.fromcharcode':6,'new activexobject':12,'wscript.shell':10,'shell.application':8,'document.write':5,'msxml2.xmlhttp':10,'winhttp.winhttprequest':10,'settimeout(':3,'setinterval(':3,'::createobject':10,'wscript.createobject':10}.items():
                                    if kw in text_content: script_score += w
                            if is_bat:
                                for kw, w in {'disallowrun':15,'reg add':5,'reg delete':8,'taskkill':8,'netsh':6,'net user':8,'net localgroup':10,'powershell':8,'-enc ':10,'-encodedcommand':10,'wmic':6,'bitsadmin':10,'certutil':8,'mshta':8,'regsvr32':6,'rundll32':6,'schtasks':8,'currentversion\\run':12,'policies\\explorer':10,'policies\\system':10,'disabletaskmgr':12,'disableregistrytools':12}.items():
                                    if kw in text_content: script_score += w
                            if not _is_py:
                                _eval_count = text_content.count('eval(')
                                if _eval_count > 5:
                                    script_score += min(20, _eval_count * 2)
                                elif _eval_count > 0:
                                    script_score += _eval_count * 3
                            _text_len = len(text_content)
                            if _text_len > 1000 and not _is_py:
                                _non_ascii = sum(1 for c in text_content if ord(c) > 127)
                                _non_ascii_ratio = _non_ascii / _text_len
                                if _non_ascii_ratio > 0.15:
                                    script_score += 12
                                elif _non_ascii_ratio > 0.08:
                                    script_score += 8
                            _fp_lower = filepath.lower()
                            if any(d in _fp_lower for d in ['.pdf.js','.doc.js','.jpg.js','.xls.js','.docx.js']):
                                script_score += 12
                            _fsize = os.path.getsize(filepath)
                            if _fsize > 500000 and _is_js:
                                script_score += 8
                            _long_lines = 0
                            for _line in text_content.split('\n')[:200]:
                                if len(_line) > 500:
                                    _long_lines += 1
                            if _long_lines > 10:
                                script_score += 10
                            elif _long_lines > 3:
                                script_score += 5
                            import re as _re_mod
                            _hex_seqs = len(_re_mod.findall(r'\\x[0-9a-f]{2}', text_content[:50000]))
                            if _hex_seqs > 50:
                                script_score += 12
                            elif _hex_seqs > 20:
                                script_score += 8
                            _script_threshold = 30 if _is_js else (50 if ext in ('.vbs', '.vbe') else 15)
                            if _is_js:
                                _js_fsize = os.path.getsize(filepath)
                                if _js_fsize > 500000:
                                    _obf_var = text_content.count('_0x')
                                    if _obf_var > 10:
                                        script_score += 30
                                    _colon_pad = text_content[:500].count(':')
                                    if _colon_pad > 100:
                                        script_score += 25
                                    _ascii_ratio = sum(1 for c in text_content[:5000] if ord(c) < 128) / max(len(text_content[:5000]), 1)
                                    if _ascii_ratio < 0.7 and _js_fsize > 200000:
                                        script_score += 20
                                    _var_assigns = len(_re_mod.findall(r'var\s+_0x[0-9a-f]+', text_content[:50000]))
                                    if _var_assigns > 5:
                                        script_score += 25
                                _hukg_pattern = 'hukgsuite' in text_content or 'hollyhukg' in text_content
                                if _hukg_pattern:
                                    script_score += 40
                            if ext in ('.vbs', '.vbe'):
                                _vbs_fsize = os.path.getsize(filepath)
                                _colon_count_1k = text_content[:1000].count(':')
                                if _vbs_fsize > 500000:
                                    if _colon_count_1k > 200:
                                        script_score += 45
                                    _vbs_obf = text_content.count('chr(') + text_content.count('execute')
                                    if _vbs_obf > 10:
                                        script_score += 30
                                if _colon_count_1k > 500:
                                    script_score += 20
                        if ext in ('.vbs', '.vbe') and ('etwprovider' in text_content or 'registertraceguids' in text_content or 'wevtutil' in text_content):
                            _script_threshold = 999
                        if script_score >= _script_threshold:
                            ttype = classify_threat(filepath, heuristic=True)
                            final_conf = min(95, 50 + script_score + study_boost)
                            res = f"MALICIOUS|{ttype}|Script|{final_conf}"
                            self.cache.put(key, (res, final_conf, ttype))
                            self.study.record_result(filepath, ttype, final_conf, "Script heuristic")
                            return res, final_conf, ttype
                    except: pass

            disguise = check_file_disguise(filepath)

            if CONFIG["enable_onnx"]:
                name, conf, feat = self.onnx.scan(filepath, file_data=head_data)
                if name and conf >= CONFIG["confidence_threshold"]:
                    final = min(100, conf + study_boost)
                    ttype = classify_threat(filepath, rule_name=name, heuristic=True)
                    res = f"MALICIOUS|{ttype}|ONNX|{final}"
                    self.cache.put(key, (res, final, ttype))
                    self.study.record_result(filepath, ttype, final, "ONNX AI")
                    return res, final, ttype

            if CONFIG.get("enable_lightgbm", True) and self.lgbm is not None:
                name, conf, feat = self.lgbm.scan(filepath, file_data=head_data)
                if name and conf >= CONFIG["confidence_threshold"]:
                    final = min(100, conf + study_boost)
                    ttype = classify_threat(filepath, rule_name=name, heuristic=True)
                    res = f"MALICIOUS|{ttype}|LightGBM|{final}"
                    self.cache.put(key, (res, final, ttype))
                    self.study.record_result(filepath, ttype, final, "LightGBM AI")
                    return res, final, ttype

            if CONFIG.get("enable_yara", True):
                name, conf, feat = self.yara.scan(filepath)
                if name and conf >= CONFIG["confidence_threshold"]:
                    final = min(100, conf + study_boost)
                    ttype = classify_threat(filepath, rule_name=name)
                    res = f"MALICIOUS|{ttype}|YARA|{final}"
                    self.cache.put(key, (res, final, ttype))
                    self.study.record_result(filepath, ttype, final, "YARA: " + name)
                    return res, final, ttype

            if CONFIG.get("enable_custom_rules", True):
                name, conf, feat = self.custom.scan(filepath)
                if name and conf >= CONFIG["confidence_threshold"]:
                    final = min(100, conf + study_boost)
                    ttype = classify_threat(filepath, rule_name=name)
                    res = f"MALICIOUS|{ttype}|CUSTOM|{final}"
                    self.cache.put(key, (res, final, ttype))
                    self.study.record_result(filepath, ttype, final, "CUSTOM: " + name)
                    return res, final, ttype

            if _is_pe and head_data[:2] == b'MZ':
                _signer2 = _pe_info.get('signer') if '_pe_info' in dir() else _extract_signer(filepath)
                if _signer2:
                    _sl2 = _signer2.lower()
                    _TRUSTED2 = {'microsoft','google','apple','mozilla','adobe','oracle','intel','nvidia','amd','vmware','hp','dell','lenovo','ibm','cisco','avast','avg','avira','bitdefender','kaspersky','eset','mcafee','symantec','norton','malwarebytes','trend micro','sophos','fortinet','check point','palo alto','crowdstrike','sentinelone','jetbrains','github','gitlab','python software foundation','docker','red hat','canonical','apache','tencent','baidu','qihoo','kingsoft','huawei','xiaomi','gen digital','nortonlifelock','avast software'}
                    if any(t in _sl2 for t in _TRUSTED2):
                        self.cache.put(key, ("CLEAN", 0, ""))
                        return "CLEAN", 0, ""

            if CONFIG["enable_pe_scan"]:
                is_mal, conf, feat, apis = _run_pe_analysis(filepath)
                if is_mal and conf >= 60:
                    final = min(100, conf + study_boost)
                    ttype = classify_threat(filepath, pe_apis=apis, heuristic=True)
                    res = f"MALICIOUS|{ttype}|PE|{final}"
                    self.cache.put(key, (res, final, ttype))
                    self.study.record_result(filepath, ttype, final, "PE: " + feat[:100])
                    return res, final, ttype

                if apis:
                    se_type, se_conf, se_feat = self.study.scan_api_chains(apis)
                    if se_type and se_conf >= 80:
                        _se2_ok = True
                        _norm_fp_se2 = os.path.normpath(filepath).lower().replace('\\', '/')
                        _is_winsxs_se2 = 'windows/winsxs/' in _norm_fp_se2
                        if _is_winsxs_se2:
                            _se2_ok = False
                        _signer2 = _pe_info.get('signer') if '_pe_info' in dir() else _extract_signer(filepath)
                        _vi2 = _pe_info.get('version_info', {}) if '_pe_info' in dir() else {}
                        _vi2_company = _vi2.get('CompanyName', '') or ''
                        _vi2_product = _vi2.get('ProductName', '') or ''
                        _vi2_desc = _vi2.get('FileDescription', '') or ''
                        _vi2_info = _vi2_company or _vi2_product or _vi2_desc
                        _susp_vi2 = False
                        if _vi2_product and len(_vi2_product) > 4:
                            import re as _re_vi2
                            if _re_vi2.match(r'^[a-zA-Z0-9]{5,}\.exe$', _vi2_product):
                                _susp_vi2 = True
                        if _vi2_company and len(_vi2_company) <= 2:
                            _susp_vi2 = True
                        if not _signer2:
                            _secs2 = _pe_info.get('sections', []) if '_pe_info' in dir() else []
                            _go_secs2 = any(s[0].lower() in ('.gopclntab','.gosymtab','.noptrdata','.typelink','.itablink','.symtab') for s in _secs2)
                            _large_static2 = False
                            if _secs2:
                                _text_sz2 = sum(s[2] for s in _secs2 if s[0].lower() == '.text')
                                _import_ct2 = _pe_info.get('import_count', 0) if '_pe_info' in dir() else 0
                                if _text_sz2 > 5000000 and _import_ct2 < 100:
                                    _large_static2 = True
                            if _go_secs2 or _large_static2:
                                _se2_ok = False
                            if _se2_ok and _vi2_company:
                                _vi2_co_lower = _vi2_company.lower()
                                _TRUSTED_VI_SE2 = {'microsoft','7-zip','dell','steam','valve','google','apple','oracle','intel','nvidia','amd','vmware','hp','lenovo','ibm','cisco','tencent','baidu','qihoo','kingsoft','huawei','xiaomi','broadcom','symantec','norton','avast','avg','bitdefender','kaspersky','eset','mcafee','coloros','oppo','realtek','samsung','lg electronics','igor pavlov','broadcom corporation','valve corporation'}
                                if any(t in _vi2_co_lower for t in _TRUSTED_VI_SE2):
                                    _se2_ok = False
                        elif _vi2_info and not _susp_vi2:
                            _signer2_match_vi = False
                            if _vi2_company and _signer2:
                                _sl2 = _signer2.lower()
                                _cl2 = _vi2_company.lower()
                                if _sl2 in _cl2 or _cl2 in _sl2:
                                    _signer2_match_vi = True
                            if _signer2_match_vi:
                                _se2_ok = False
                        if _se2_ok:
                            final = min(95, se_conf + study_boost)
                            ttype = classify_threat(filepath, rule_name=se_type, pe_apis=apis, heuristic=True)
                            res = f"MALICIOUS|{ttype}|SE-Chain|{final}"
                            self.cache.put(key, (res, final, ttype))
                            self.study.record_result(filepath, ttype, final, se_feat)
                            return res, final, ttype

                significant_feats = [r for r in feat.split(';') if r]
                if CONFIG.get("enable_pe_scan", True) and _is_pe and (significant_feats or (not feat and not is_mal)):
                    _pe_signer3 = _pe_info.get('signer') if '_pe_info' in dir() else None
                    _pe_vi3 = _pe_info.get('version_info', {}) if '_pe_info' in dir() else {}
                    _pe_has_vi3 = any(_pe_vi3.get(k) for k in ('CompanyName','ProductName','FileDescription','LegalCopyright') if k)
                    _norm_fp3 = os.path.normpath(filepath).lower().replace('\\', '/')
                    _is_winsxs3 = 'windows/winsxs/' in _norm_fp3
                    if not _pe_signer3 and not _pe_has_vi3 and not _is_winsxs3:
                        entropy_val, entropy_verdict = self.entropy.analyze(filepath, raw_data=head_data)
                        packers = self.packer.detect(filepath)
                        if entropy_verdict or packers:
                            combined_score = 0
                            if entropy_verdict:
                                if '_HIGH_/' in entropy_verdict: combined_score += 18
                                elif '_HIGH' in entropy_verdict: combined_score += 10
                            if packers: combined_score += packers[0][2] // 5
                            if combined_score >= 15 and not is_mal:
                                final = min(85, 55 + combined_score + study_boost)
                                ttype = classify_threat(filepath, heuristic=True)
                                res = f"MALICIOUS|{ttype}|Packer/Entropy|{final}"
                                self.cache.put(key, (res, final, ttype))
                                self.study.record_result(filepath, ttype, final, "Packer/Entropy")
                                return res, final, ttype

            if CONFIG.get("enable_pe_scan", True) and _is_pe and head_data[:2] == b'MZ':
                _sec_scores = 0
                _susp_secs = []
                for _sn, _se, _sr, _sc in _pe_info.get('sections', []):
                    _sn_l = _sn.lower()
                    if _se > 7.5 and _sr > 10000:
                        _sec_scores += 8
                        _susp_secs.append(f"{_sn_l}:{_se:.1f}")
                    elif _se > 7.0 and _sr > 50000:
                        _sec_scores += 5
                        _susp_secs.append(f"{_sn_l}:{_se:.1f}")
                    if _sn_l in ('.vmp0','.vmp1','.themida','.enigma1','.enigma2','.aspack','mpress1'):
                        _sec_scores += 12
                if _sec_scores >= 35:
                    _sec_final = min(80, 40 + _sec_scores + study_boost)
                    _sec_ttype = classify_threat(filepath, heuristic=True)
                    _sec_res = f"MALICIOUS|{_sec_ttype}|PE-SectionEntropy|{_sec_final}"
                    self.cache.put(key, (_sec_res, _sec_final, _sec_ttype))
                    self.study.record_result(filepath, _sec_ttype, _sec_final, f"Section entropy: {','.join(_susp_secs[:3])}")
                    return _sec_res, _sec_final, _sec_ttype

            if depth == 0 and CONFIG["extract_and_scan"] and filepath.lower().endswith('.zip'):
                pass

            if CONFIG.get("enable_pe_scan", True) and disguise:
                res = "MALICIOUS||Disguise|55"
                self.cache.put(key, (res, 55, ""))
                self.study.record_result(filepath, "", 55, "Disguise")
                return res, 55, ""

            if CONFIG.get("enable_external_clouds") and self.external_clouds and (_is_pe or _is_script or _is_msi):
                for _ext in self.external_clouds:
                    try:
                        _er, _ec, _et = _ext.scan_file(filepath)
                        if _er and _er.startswith("MALICIOUS"):
                            self.cache.put(key, (_er, _ec, _et))
                            self.study.record_result(filepath, _et, _ec, _ext.name)
                            return _er, _ec, _et
                    except Exception:
                        continue

            if (_is_pe or _is_script or _is_msi or _is_jar or ext in {'.com', '.exe', '.dll', '.sys', '.ocx', '.scr', '.cpl', '.drv'}) and self.cloud.is_enabled():
                cloud_res, cloud_conf, cloud_ttype = self.cloud.scan_file(filepath)
                if cloud_res and cloud_res.startswith("MALICIOUS"):
                    self.cache.put(key, (cloud_res, cloud_conf, cloud_ttype))
                    self.study.record_result(filepath, cloud_ttype, cloud_conf, "Cloud-DB")
                    return cloud_res, cloud_conf, cloud_ttype
                if cloud_res == "WHITE":
                    self.cache.put(key, ("CLEAN", 0, ""))
                    self.study.record_result(filepath, "CLEAN", 0, "Cloud-Whitelist")
                    return "CLEAN", 0, ""
            if (_is_pe or _is_script or _is_msi or _is_jar or ext in {'.com', '.exe', '.dll', '.sys', '.ocx', '.scr', '.cpl', '.drv'}) and self.avic.is_enabled():
                avic_res, avic_conf, avic_ttype = self.avic.scan_file(filepath)
                if avic_res and avic_res.startswith("MALICIOUS"):
                    self.cache.put(key, (avic_res, avic_conf, avic_ttype))
                    self.study.record_result(filepath, avic_ttype, avic_conf, "AVIC-Cloud")
                    return avic_res, avic_conf, avic_ttype

            self.cache.put(key, ("CLEAN", 0, ""))
            self.study.record_result(filepath, "CLEAN", 0, "Clean scan")
            return "CLEAN", 0, ""
        except Exception as e:
            logger.error(f"扫描 {filepath}: {traceback.format_exc()}")
            return "ERROR", 0, ""

    def scan_directory(self, dir_path, callback=None, recursive=True):
        results = {"total": 0, "scanned": 0, "malicious": 0, "clean": 0,
                   "whitelist": 0, "error": 0, "threats": []}
        if not os.path.isdir(dir_path):
            return results
        import queue
        from concurrent.futures import ThreadPoolExecutor
        exts = set(CONFIG["scan_extensions"])
        _use_ext_filter = CONFIG.get("enable_ext_filter", False)
        skip_dirs = set(CONFIG.get("skip_dirs", []))
        threads = CONFIG.get("scan_dir_threads", 8)
        _SENTINEL = object()
        fq = queue.Queue(maxsize=threads * 4)
        rlock = threading.Lock()

        def _enumerate():
            try:
                for root, dirs, fs in os.walk(dir_path):
                    dirs[:] = [d for d in dirs if d not in skip_dirs]
                    if not recursive:
                        dirs[:] = []
                    for f in fs:
                        # 默认不过滤后缀名：扫描所有文件（改名/无后缀 PE 也能命中 MZ 内容判定）。
                        # 仅当 --DEBUG:UNANY 启用扩展名过滤时，才跳过不在 scan_extensions 的文件。
                        if _use_ext_filter and os.path.splitext(f)[1].lower() not in exts:
                            continue
                        fq.put(os.path.join(root, f))
                        with rlock:
                            results["total"] += 1
            except Exception:
                pass
            finally:
                for _ in range(threads):
                    fq.put(_SENTINEL)

        def _worker():
            while True:
                fp = fq.get()
                if fp is _SENTINEL:
                    fq.task_done()
                    break
                try:
                    res, conf, ttype = self.scan_file(fp)
                except Exception:
                    with rlock:
                        results["error"] += 1
                        results["scanned"] += 1
                    fq.task_done()
                    continue
                with rlock:
                    results["scanned"] += 1
                    if res.startswith("MALICIOUS"):
                        results["malicious"] += 1
                        results["threats"].append((fp, res, conf, ttype))
                    elif res == "WHITELIST":
                        results["whitelist"] += 1
                    elif res.startswith("CLEAN"):
                        results["clean"] += 1
                    else:
                        results["error"] += 1
                if callback:
                    try:
                        callback(fp, res, conf, ttype)
                    except Exception:
                        pass
                fq.task_done()

        enum_t = threading.Thread(target=_enumerate, daemon=True)
        enum_t.start()
        with ThreadPoolExecutor(max_workers=threads) as pool:
            wfs = [pool.submit(_worker) for _ in range(threads)]
            enum_t.join()
            for wf in wfs:
                wf.result()
        return results
def ensure_default_signatures():
    sig_files = [f for f in os.listdir(CONFIG["feature_files_dir"]) if not f.startswith('.')]
    has_stu = any(f.endswith('.stu') for f in sig_files)
    has_json = any(f.endswith('.json') for f in sig_files)
    if not has_stu:
        default_path = os.path.join(CONFIG["feature_files_dir"], "default.stu")
        with open(default_path, 'w', encoding='utf-8') as f:
            f.write("# 默认特征规则\n")
    if not has_json:
        json_path = os.path.join(CONFIG["feature_files_dir"], "default.json")
        with open(json_path, 'w', encoding='utf-8') as f:
            json.dump(DEFAULT_JSON_SIGNATURES, f, indent=2, ensure_ascii=False)

# === DEBUG mode: isolate a single engine layer for testing ===
# Usage:  python SevenEngine.py <target> --DEBUG:ONNX
#         python SevenEngine.py <target> --DEBUG:LIGHTGBM
#         python SevenEngine.py <target> --DEBUG:HEUR
#         python SevenEngine.py <target> --DEBUG:YARA
#         python SevenEngine.py <target> --DEBUG:CUSTOM
#         python SevenEngine.py <target> --DEBUG:CLOUD
# No --DEBUG flag -> all engines active (default).
#
# Each mode disables every engine layer except the named one, so you can
# measure that layer's standalone detection / false-positive behaviour.
_DEBUG_MODES = {
    "ONNX": {
        "enable_onnx": True, "enable_lightgbm": False, "enable_lightgbm_white": False,
        "enable_pe_scan": False, "enable_study_engine": False,
        "enable_stu_txt_scanner": False, "enable_json_scanner": False,
        "enable_yara": False,
        "cloud_scan_enabled": False, "avic_scan_enabled": False, "enable_external_clouds": False,
    },
    "LIGHTGBM": {
        "enable_onnx": False, "enable_lightgbm": True, "enable_lightgbm_white": False,
        "enable_pe_scan": False, "enable_study_engine": False,
        "enable_stu_txt_scanner": False, "enable_json_scanner": False,
        "enable_yara": False,
        "cloud_scan_enabled": False, "avic_scan_enabled": False, "enable_external_clouds": False,
    },
    "HEUR": {
        "enable_onnx": False, "enable_lightgbm": False, "enable_lightgbm_white": False,
        "enable_pe_scan": True, "enable_study_engine": True,
        "enable_stu_txt_scanner": True, "enable_json_scanner": True,
        "enable_yara": False,
        "cloud_scan_enabled": False, "avic_scan_enabled": False, "enable_external_clouds": False,
    },
    "YARA": {
        "enable_onnx": False, "enable_lightgbm": False, "enable_lightgbm_white": False,
        "enable_pe_scan": False, "enable_study_engine": False,
        "enable_stu_txt_scanner": False, "enable_json_scanner": False,
        "enable_yara": True,
        "cloud_scan_enabled": False, "avic_scan_enabled": False, "enable_external_clouds": False,
    },
    "CUSTOM": {
        "enable_onnx": False, "enable_lightgbm": False, "enable_lightgbm_white": False,
        "enable_pe_scan": False, "enable_study_engine": False,
        "enable_stu_txt_scanner": False, "enable_json_scanner": False,
        "enable_yara": False, "enable_custom_rules": True,
        "cloud_scan_enabled": False, "avic_scan_enabled": False, "enable_external_clouds": False,
    },
    "CLOUD": {
        "enable_onnx": False, "enable_lightgbm": False, "enable_lightgbm_white": False,
        "enable_pe_scan": False, "enable_study_engine": False,
        "enable_stu_txt_scanner": False, "enable_json_scanner": False,
        "enable_yara": False,
        "cloud_scan_enabled": True, "avic_scan_enabled": True, "enable_external_clouds": True,
    },
}

def _write_scan_output(path, rows):
    """Write scan results to `path` (relative -> current working directory).

    Format is chosen by the file extension:
      * .json -> JSON array of {path, result, confidence, type}
      * .csv  -> CSV with header row
      * else  -> plain text, one record per line (result<TAB>confidence<TAB>type<TAB>path)
    """
    import csv as _csv
    import json as _json
    if not os.path.isabs(path):
        path = os.path.join(os.getcwd(), path)
    _ext = os.path.splitext(path)[1].lower()
    try:
        if _ext == ".json":
            with open(path, "w", encoding="utf-8") as f:
                _json.dump([{"path": p, "result": r, "confidence": c, "type": t}
                            for p, r, c, t in rows], f, ensure_ascii=False, indent=2)
        elif _ext == ".csv":
            with open(path, "w", encoding="utf-8", newline="") as f:
                _w = _csv.writer(f)
                _w.writerow(["path", "result", "confidence", "type"])
                for p, r, c, t in rows:
                    _w.writerow([p, r, c, t])
        else:
            with open(path, "w", encoding="utf-8") as f:
                f.write("# SevenEngine scan results\n")
                f.write("# result\tconfidence\ttype\tpath\n")
                for p, r, c, t in rows:
                    f.write(f"{r}\t{c}\t{t}\t{p}\n")
        print(f"[OUTPUT] 扫描结果已写入: {path} ({len(rows)} 条)")
    except Exception as e:
        print(f"[OUTPUT] 写入失败: {e}")


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: python SevenEngine.py <file_path|dir_path> "
              "[--DEBUG:ONNX|LIGHTGBM|HEUR|YARA|CUSTOM|CLOUD|UNANY] [--OUTPUT:name.ext]")
        sys.exit(1)

    # Parse flags (case-insensitive). --DEBUG: selects an engine layer (or UNANY
    # to re-enable extension filtering); --OUTPUT: saves results to a file in cwd.
    _debug_mode = None
    _ext_filter = False
    _output_path = None
    _positional = []
    for _arg in sys.argv[1:]:
        _a = _arg.strip()
        _au = _a.upper()
        if _au.startswith("--DEBUG:"):
            _mode = _a[len("--DEBUG:"):].strip().upper()
            if _mode == "UNANY":
                _ext_filter = True
                print("[DEBUG] 启用后缀过滤 (UNANY)：仅扫描 scan_extensions 列表中的文件")
            elif _mode in _DEBUG_MODES:
                _debug_mode = _mode
            else:
                print(f"ERROR: unknown DEBUG mode '{_mode}'. "
                      f"Valid: {', '.join(sorted(_DEBUG_MODES))}, UNANY")
                sys.exit(1)
        elif _au.startswith("--OUTPUT:"):
            _output_path = _a[len("--OUTPUT:"):].strip()
            if not _output_path:
                print("ERROR: --OUTPUT: 需要文件名，例如 --OUTPUT:result.csv")
                sys.exit(1)
        else:
            _positional.append(_arg)
    if not _positional:
        print("ERROR: no target path specified.")
        sys.exit(1)
    target = _positional[0]

    # Default: NO extension filtering (scan every file). UNANY turns it on.
    CONFIG["enable_ext_filter"] = _ext_filter

    # Apply engine DEBUG overrides (UNANY leaves every engine layer enabled).
    if _debug_mode:
        _overrides = _DEBUG_MODES[_debug_mode]
        CONFIG.update(_overrides)
        print(f"[DEBUG] 模式: {_debug_mode}  (仅启用 {_debug_mode} 引擎层，其余全部禁用)")
        _active = [k.replace("enable_", "").replace("_", " ").upper()
                   for k, v in _overrides.items() if v and k.startswith("enable_")]
        print(f"[DEBUG] 激活: {', '.join(_active)}")
    else:
        print("[DEBUG] 模式: ALL (全部引擎默认启用，不过滤后缀名)")

    if not os.path.exists(target):
        print(f"ERROR: Not found: {target}")
        sys.exit(1)

    os.makedirs(CONFIG["feature_files_dir"], exist_ok=True)
    ensure_default_signatures()

    scanner = Scanner()
    _output_rows = []

    def _cb(fp, res, conf, ttype):
        _output_rows.append((fp, res, conf, ttype))
        if res.startswith("MALICIOUS"):
            print(f"  [!] {res}  {fp}")
        elif res == "WHITELIST":
            print(f"  [WL] {res}  {fp}")
        elif res.startswith("CLEAN"):
            print(f"  [OK] {res}  {fp}")
        else:
            print(f"  [??] {res}  {fp}")

    if os.path.isdir(target):
        print(f"扫描目录: {target}")
        r = scanner.scan_directory(target, callback=_cb)
        print(f"\n扫描完成: 共 {r['total']} 文件, 扫描 {r['scanned']}, 恶意 {r['malicious']}, 干净 {r['clean']}, 白名单 {r['whitelist']}, 错误 {r['error']}")
        if r["threats"]:
            print("\n--- 检出威胁 ---")
            for fp, res, conf, ttype in r["threats"]:
                print(f"  {res}  conf={conf}  {ttype}  {fp}")
    else:
        result, confidence, vt = scanner.scan_file(target)
        _output_rows.append((target, result, confidence, vt))
        print(f"Result: {result}")
        print(f"Confidence: {confidence}")
        print(f"Info: {vt}")

    if _output_path:
        _write_scan_output(_output_path, _output_rows)
    sys.exit(1 if any(r[1].startswith("MALICIOUS") for r in _output_rows) else 0)
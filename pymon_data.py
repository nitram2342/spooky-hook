from winappdbg.win32.defines import *

knownmods = ['ntdll.dll', 'kernel32.dll', 'user32.dll',
     'ole32.dll', 'advapi32.dll', 'ws2_32.dll',
     'wininet.dll', 'rtutils.dll', 'dnsapi.dll',
     'shlwapi.dll', 'mswsock.dll', 'urlmon.dll',
     'comctl32.dll', 'rsaenh.dll', 'rpcrt4.dll',
     'rasadhlp.dll', 'userenv.dll', 'oleaut32.dll',
     'crypt32.dll', 'shell32.dll', 'winmm.dll',
     'tapi32.dll', 'rasapi32.dll', 'iphlpapi.dll',
     'sensapi.dll', 'rasman.dll', 'secur32.dll',
     'msi.dll', 'ddraw.dll', 'setupapi.dll', 
     'uxtheme.dll', 'version.dll', 'msacm32.dll', 
     'netapi32.dll', 'msvcrt.dll', 'mpr.dll', 
     'clbcatq.dll', 'psapi.dll', 'msasn1.dll', 
     'wintrust.dll', 'acgenral.dll', 'olepro32.dll', 
     'ws2help.dll', 'mlang.dll', 'msvbvm60.dll', 'sxs.dll',
     'gdi32.dll', 'usp10.dll', 'comdlg32.dll', 'duser.dll',
     'explorerframe.dll', 'thumbcache.dll', 'propsys.dll', 
     'ieframe.dll',]

#-----------------------------------------------------
# file_whitelist: Ignore file operations on items that
# match an item in the list 
#-----------------------------------------------------

file_whitelist = [
    '\\\\.\\PIPE\\lsarpc',
    '\\\\.\\MountPointManager',
    'WindowsShell.Manifest',
    'R000000000007.clb',
]

#-------------------------------------------------------------------------
# alert_file_content_write: Highlight attempts to write particular patterns. 
#-------------------------------------------------------------------------

alert_file_content_write = [
    'This program cannot be run in DOS mode',   # PE header string
    'This program must be run under Win32',     # PE header string
    'Scripting.FileSystemObject',               # WScript self-delete scripts
    '@echo off',                                # BAT scripts
    'net stop',                                 # BAT scripts
    'reg add',                                  # BAT scripts 
    'Windows Registry Editor',                  # REG scripts
    '[Autorun]',                                # Autorun scripts
    ]

#-------------------------------------------------------------------------
# alert_file_write: Highlight attempts to write to files/directories that match
#-------------------------------------------------------------------------

alert_file_write = [
    'C:\\windows\\system32\\',              # Writes to system32 directory
    '\\\\.\\PhysicalDrive0',                # Writes to the physical drive
    '.dll',                                 # DLLs in any directory
    '.exe',                                 # EXEs in any directory
    '.sys',                                 # SYSs in any directory
    '.bat',                                 # BATs in any directory
    '.reg',                                 # REGs in any directory
    '\\\\.\\PIPE\\SfcApi',                  # Attempts to disable WFP
    '\\\\.\\pipe\\acsipc_server',           # Tigger
    'Autorun.inf',                          # Writes to autorun
    ]

#-----------------------------------------------------
# alert_file_read: Highlight attempts to read files/directories that match
#-----------------------------------------------------

alert_file_read = [
    '#SharedObjects',                                   # Flash cookies
    '\\Application Data\\Macromedia\\Flash Player',     # Flash cookies
    'C:\\RECYCLER',                                     # Accesing deleted files
    '\\\\.\\SIWVID',                                    # Anti-Debugging stuff
    '\\\\.\\REGSYS',                                    # ...
    '\\\\.\\REGVXG',
    '\\\\.\\FILEVXG',
    '\\\\.\\FILEM',
    '\\\\.\\TRW',
    '\\\\.\\SICE',
    '\\\\.\\NTICE',
    '\\\\.\\ICEEXT',
    'wcx_ftp.ini',                                      # Total Commander passwors
    'Ipswitch\\WS_FTP',                                 # WS FTP passwords
    'FlashFXP',                                         # FLashFXP passwords
    'SmartFTP',                                         # SmartFTP passwords
    'TurboFTP',                                         # TurboFTP passwords
    '\\Application Data\\Opera\\',                      # Opera passwords
    'Cookies',                                          # Cookies
    '.pfx',                                             # Certificates 
    ]

#-----------------------------------------------------
# reg_whitelist: Ignore registry operations (query/open/create only) on keys/values
# This does not affect delete and modify operations...
#-----------------------------------------------------

reg_whitelist = [
    'User Shell Folders',
    'MountPoints2',
    'Shell Folders',
]

#-----------------------------------------------------
# alert_reg_write: Highlight attempts to write to registry keys that match
#-----------------------------------------------------

alert_reg_write = [
    'HKEY_CLASSES_ROOT',
    'HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Run',
    'FirewallPolicy\\StandardProfile\\AuthorizedApplications\\List',
    'Image File Execution Options',
    'HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Notify',
    'ShellIconOverlayIdentifiers',
    'InprocServer32',
    'Software\\Microsoft\\Windows NT\\CurrentVersion\\Drivers32',
    ]

#-----------------------------------------------------
# alert_reg_read: Highlight attempts to read from registry keys that match
#-----------------------------------------------------

alert_reg_read = []

#-----------------------------------------------------
# alert_reg_content_write: Highlight attempts to write strings/patterns to registry
#-----------------------------------------------------

alert_reg_content_write = [
    '.dll',
    '.sys',
    '.exe',
    ]

#-----------------------------------------------------
# alert_resolved_api: Highlight attempts to resolve API function names
#-----------------------------------------------------

alert_resolved_api = [
    'KeServiceDescriptorTable'      # Trying to locate SSDT
    'PStoreCreateInstance',         # Pstore access 
    'CryptUnprotectData',           # Stealing credentials   
    'MoveFileExA', 
    'SetFileTime',
    'VirtualAllocEx',
    'WriteProcessMemory',
    'CreateRemoteThread',
    'CreateProcessA', 
    'CreateProcessW', 
    'WinExec',
    'ShellExecuteA',
    'ShellExecuteW',
    ]

#-----------------------------------------------------
# alert_loaded_dll: Highlight attempts to load particular DLLs
#-----------------------------------------------------

alert_loaded_dll = [
    'pstorec.dll',                  # Accessing protected storage
    'sfc_os.dll',                   # Accessing WFP services
    'ntoskrnl.exe',                 # Probably trying to resolve exports for SSDT hook
    ]

#-----------------------------------------------------
# alert_mutex_access: Highlight attempts to create/open certain mutex names
#-----------------------------------------------------

alert_mutex_access = [
    '___b0th____',                  # Tigger
    ]

#-----------------------------------------------------
# alert_find_window: Highlight attempts to find certain windows
#-----------------------------------------------------

alert_find_window = [
    'FileMonClass',                 # FileMon
    '18467-41',                     # RegMon, I think
    'OLLYDBG',                      # OllyDbg
    'AVP.Tray',                     #
    'Q360SafeMonClass',             #
    '____AVP.Root',                 # Tigger
    ]

#-----------------------------------------------------
# alert_create_window: Highlight attempts to create windows
#-----------------------------------------------------

alert_create_window = [
    'COM2PLUS_MessageWindowClass',  # Coreflood
    ]

ctx_flags = { # See kernel32.py
    0x00010001 : 'CONTEXT_CONTROL',
    0x00010002 : 'CONTEXT_INTEGER',
    0x00010004 : 'CONTEXT_SEGMENTS',
    0x00010008 : 'CONTEXT_FLOATING_POINT',
    0x00010010 : 'CONTEXT_DEBUG_REGISTERS',
    0x00010020 : 'CONTEXT_EXTENDED_REGISTERS',
    0x00010007 : 'CONTEXT_FULL',
    0x0001003f : 'CONTEXT_ALL',
    }

alloc_types = {
    0x00001000 : 'MEM_COMMIT',
    0x00002000 : 'MEM_RESERVE',
    0x00080000 : 'MEM_RESET',
    0x20000000 : 'MEM_LARGE_PAGES',
    0x00400000 : 'MEM_PHYSICAL',
    0x00100000 : 'MEM_TOP_DOWN',
    }

load_flags = {
    0x00000001 : 'DONT_RESOLVE_DLL_REFERENCES',
    0x00000010 : 'LOAD_IGNORE_CODE_AUTHZ_LEVEL',
    0x00000002 : 'LOAD_LIBRARY_AS_DATAFILE',
    0x00000040 : 'LOAD_LIBRARY_AS_DATAFILE_EXCLUSIVE',
    0x00000020 : 'LOAD_LIBRARY_AS_IMAGE_RESOURCE',
    0x00000008 : 'LOAD_WITH_ALTERED_SEARCH_PATH',
    }

generic_access = {
    0x80000000 : 'GENERIC_READ',
    0x40000000 : 'GENERIC_WRITE',
    0x20000000 : 'GENERIC_EXECUTE',
    }

file_disps = {
    0x00000001 : 'CREATE_NEW',
    0x00000002 : 'CREATE_ALWAYS',
    0x00000003 : 'OPEN_EXISTING',
    0x00000004 : 'OPEN_ALWAYS',
    0x00000005 : 'TRUNCATE_EXISTING',
    }

file_move = {
    0x00000000 : 'FILE_BEGIN',
    0x00000001 : 'FILE_CURRENT',
    0x00000002 : 'FILE_END',
    }

create_flags = {
    0x00000001 : 'DEBUG_PROCESS',
    0x00000002 : 'DEBUG_ONLY_THIS_PROCESS',
    0x00000004 : 'CREATE_SUSPENDED',
    0x00000010 : 'CREATE_NEW_CONSOLE',
    0x00000020 : 'NORMAL_PRIORITY_CLASS',
    0x00000040 : 'IDLE_PRIORITY_CLASS',
    0x00000080 : 'HIGH_PRIORITY_CLASS',
    0x04000000 : 'CREATE_DEFAULT_ERROR_MODE',
    0x00000400 : 'CREATE_UNICODE_ENVIRONMENT',
    0x08000000 : 'CREATE_NO_WINDOW',
    0x00000200 : 'CREATE_NEW_PROCESS_GROUP',
    0x00040000 : 'CREATE_PROTECTED_PROCESS',
    0x00000008 : 'DETACHED_PROCESS',
    }

show_flags = {
    0x00000000 : 'SW_HIDE',
    0x00000001 : 'SW_NORMAL',
    0x00000003 : 'SW_MAXIMIZE',
    0x00000006 : 'SW_MINIMIZE',
    0x0000000a : 'SW_SHOWDEFAULT',
    }

process_rights = {
    0x00000001 : 'PROCESS_TERMINATE',
    0x00000002 : 'PROCESS_CREATE_THREAD',
    0x00000008 : 'PROCESS_VM_OPERATION',
    0x00000010 : 'PROCESS_VM_READ',
    0x00000020 : 'PROCESS_VM_WRITE',
    0x00000040 : 'PROCESS_DUP_HANDLE',
    0x00000080 : 'PROCESS_CREATE_PROCESS',
    0x00000200 : 'PROCESS_SET_INFORMATION',
    0x00000400 : 'PROCESS_QUERY_INFORMATION',
    0x001f0fff : 'PROCESS_ALL_ACCESS'
    }

page_protect = {
    0x00000002 : 'PAGE_READONLY',
    0x00000004 : 'PAGE_READWRITE',
    0x00000010 : 'PAGE_EXECUTE',
    0x00000040 : 'PAGE_EXECUTE_READWRITE',
    }

map_access = {
    0x000f001f : 'FILE_MAP_ALL_ACCESS',
    0x00000001 : 'FILE_MAP_COPY',
    0x00000002 : 'FILE_MAP_WRITE',
    0x00000004 : 'FILE_MAP_READ',
    0x00000020 : 'FILE_MAP_EXECUTE',
    }

reg_hkey = {
    0x80000000 : 'HKEY_CLASSES_ROOT',
    0x80000001 : 'HKEY_CURRENT_USER',
    0x80000002 : 'HKEY_LOCAL_MACHINE',
    0x80000003 : 'HKEY_USERS',
    0x80000004 : 'HKEY_PERFORMANCE_DATA',
    0x80000005 : 'HKEY_CURRENT_CONFIG',
    }

key_access = {
    0x00000001 : 'KEY_QUERY_VALUE',
    0x00000002 : 'KEY_SET_VALUE',
    0x00000004 : 'KEY_CREATE_SUB_KEY',
    0x00000008 : 'KEY_ENUMERATE_SUB_KEYS',
    0x00000010 : 'KEY_NOTIFY',
    0x00020019 : 'KEY_READ',
    0x00020006 : 'KEY_WRITE',
    0x000f003f : 'KEY_ALL_ACCESS',
    0x02000000 : 'MAXMUM_ALLOWED',
    }

svc_access = {
    0x00000020 : 'SERVICE_STOP',
    0x00000010 : 'SERVICE_START',
    0x00000004 : 'SERVICE_QUERY_STATUS',
    0x00000001 : 'SERVICE_QUERY_CONFIG',
    0x00000002 : 'SERVICE_CHANGE_CONFIG',
    0x00000008 : 'SERVICE_ENUMERATE_DEPENDENTS',
    0x000f01ff : 'SERVICE_ALL_ACCESS',
    }

event_access = {
    0x00000002 : 'EVENT_MODIFY_STATE',
    0x001f0003 : 'EVENT_ALL_ACCESS',
    }

mutex_access = {
    0x00000001 : 'MUTEX_MODIFY_STATE',
    0x001f0001 : 'MUTEX_ALL_ACCESS',
    }

svc_types = {
    0x00000001 : 'SERVICE_KERNEL_DRIVER',
    0x00000002 : 'SERVICE_FILE_SYSTEM_DRIVER',
    0x00000010 : 'SERVICE_WIN32_OWN_PROCESS',
    0x00000020 : 'SERVICE_WIN32_SHARE_PROCESS',
    0x00000100 : 'SERVICE_INTERACTIVE_PROCESS',
    }

svc_start = {
    0x00000000 : 'SERVICE_BOOT_START',
    0x00000001 : 'SERVICE_SYSTEM_START',
    0x00000002 : 'SERVICE_AUTO_START',
    0x00000003 : 'SERVICE_DEMAND_START',
    0x00000004 : 'SERVICE_DISABLED',
    }

token_access = {
    0x00000002 : 'TOKEN_DUPLICATE',
    0x00000004 : 'TOKEN_IMPERSONATE',
    0x00000008 : 'TOKEN_QUERY',
    0x00000020 : 'TOKEN_ADJUST_PRIVILEGES',
    0x000f01ff : 'TOKEN_ALL_ACCESS',
    }

std_access = {
    0x00010000 : 'DELETE',
    0x00020000 : 'READ_CONTROL',
    0x00040000 : 'WRITE_DAC',
    0x00080000 : 'WRITE_OWNER',
    0x00100000 : 'SYNCHRONIZE',
    0x02000000 : 'MAXIMUM_ALLOWED',
    }

sec_level = {
    0x00000000 : 'SecurityAnonymous',
    0x00000001 : 'SecurityIdentification',
    0x00000002 : 'SecurityImpersonation',
    0x00000003 : 'SecurityDelegation',
    }

reg_types = {
    0x00000000 : 'REG_NONE',
    0x00000001 : 'REG_SZ',
    0x00000002 : 'REG_EXPAND_SZ',
    0x00000003 : 'REG_BINARY',
    0x00000004 : 'REG_DWORD',
    0x00000007 : 'REG_MULTI_SZ',
    }

context_flags = {
    0xf0000000 : 'CRYPT_VERIFYCONTEXT',
    0x00000008 : 'CRYPT_NEWKEYSET',
    0x00000010 : 'CRYPT_DELETEKEYSET',
    0x00000020 : 'CRYPT_MACHINE_KEYSET',
    0x00000040 : 'CRYPT_SILENT',
    }

prov_types = {
    0x00000001 : 'PROV_RSA_FULL',
    0x00000003 : 'PROV_DSS',
    0x00000006 : 'PROV_SSL',
    0x00000012 : 'PROV_RSA_SCHANNEL',
    0x00000013 : 'PROV_DSS_DH',
    0x00000018 : 'PROV_DH_SCHANNEL',
    0x00000024 : 'PROV_RSA_AES',
}

alg_ids = {
    0x00008003 : 'CALG_MD5',
    0x00008004 : 'CALC_SHA1',
    0x00006601 : 'CALG_DES',
    0x00006611 : 'CALG_AES',
    }

window_msg = {
    0x00000001 : 'WM_CREATE',
    0x00000002 : 'WM_DESTROY',
    0x00000003 : 'WM_MOVE',
    0x00000005 : 'WM_SIZE',
    0x00000006 : 'WM_ACTIVATE',
    0x00000007 : 'WM_SETFOCUS',
    0x00000008 : 'WM_KILLFOCUS',
    0x0000000a : 'WM_ENABLE',
    0x0000000f : 'WM_PAINT',
    0x00000010 : 'WM_CLOSE',
    0x00000012 : 'WM_QUIT',
    0x00000018 : 'WM_SHOWWINDOW',
    0x0000001b : 'WM_DEVMODECHANGE',
    0x0000004a : 'WM_COPYDATA',
    0x00000100 : 'WM_KEYDOWN',
    0x00000101 : 'WM_KEYUP',
    }

event_types = {
    0x00000001 : 'EVENT_MIN',
    0x7fffffff : 'EVENT_MAX'
    }

inet_access = {
    0x00000000 : 'INTERNET_OPEN_TYPE_PRECONFIG',
    0x00000001 : 'INTERNET_OPEN_TYPE_DIRECT',
    0x00000002 : 'INTERNET_OPEN_TYPE_PROXY',
    }

inet_services = {
    0x00000001 : 'INTERNET_SERVICE_FTP',
    0x00000003 : 'INTERNET_SERVICE_HTTP',
    }

file_attr = {
    0x00000001 : 'FILE_ATTRIBUTE_READONLY',
    0x00000002 : 'FILE_ATTRIBUTE_HIDDEN',
    0x00000004 : 'FILE_ATTRIBUTE_SYSTEM',
    0x00000010 : 'FILE_ATTRIBUTE_DIRECTORY',
    0x00000020 : 'FILE_ATTRIBUTE_ARCHIVE',
    0x00000040 : 'FILE_ATTRIBUTE_DEVICE',
    0x00000080 : 'FILE_ATTRIBUTE_NORMAL',
    0x00002000 : 'FILE_ATTRIBUTE_NOT_CONTENT_INDEXED',
    0x00004000 : 'FILE_ATTRIBUTE_ENCRYPTED',
    0x00000800 : 'FILE_ATTRIBUTE_COMPRESSED',
    }

inet_flags = {
    0x00000040 : 'INTERNET_REQFLAG_CACHE_WRITE_DISABLED',
    0x00001000 : 'INTERNET_FLAG_IGNORE_CERT_CN_INVALID',
    0x00002000 : 'INTERNET_FLAG_IGNORE_CERT_DATE_INVALID',
    0x00004000 : 'INTERNET_FLAG_IGNORE_REDIRECT_TO_HTTPS',
    0x00008000 : 'INTERNET_FLAG_IGNORE_REDIRECT_TO_HTTP',
    0x00010000 : 'INTERNET_FLAG_CACHE_IF_NET_FAIL',
    0x00020000 : 'INTERNET_FLAG_RESTRICTED_ZONE',
    0x00040000 : 'INTERNET_FLAG_NO_AUTH',
    0x00080000 : 'INTERNET_FLAG_NO_COOKIES',
    0x00200000 : 'INTERNET_FLAG_NO_AUTO_REDIRECT',
    0x00400000 : 'INTERNET_FLAG_KEEP_CONNECTION',
    0x00800000 : 'INTERNET_FLAG_SECURE',
    0x04000000 : 'INTERNET_FLAG_NO_CACHE_WRITE',
    0x08000000 : 'INTERNET_FLAG_PASSIVE',
    0x80000000 : 'INTERNET_FLAG_RELOAD',
    }

inet_ports = {
    21         : 'INTERNET_DEFAULT_FTP_PORT',
    80         : 'INTERNET_DEFAULT_HTTP_PORT',
    443        : 'INTERNET_DEFAULT_HTTPS_PORT',
    1080       : 'INTERNET_DEFAULT_SOCKS_PORT',
    }

inet_opts = {
    0x00000001 : 'INTERNET_OPTION_CALLBACK',
    0x0000003b : 'INTERNET_OPTION_HTTP_VERSION',
    0x00000015 : 'INTERNET_OPTION_PARENT_HANDLE',
    0x00000017 : 'INTERNET_OPTION_REQUEST_FLAGS',
    0x0000001d : 'INTERNET_OPTION_PASSWORD',
    0x00000026 : 'INTERNET_OPTION_PROXY',
    0x0000002c : 'INTERNET_OPTION_PROXY_PASSWORD',
    0x0000002b : 'INTERNET_OPTION_PROXY_USERNAME',
    0x0000001f : 'INTERNET_OPTION_SECURITY_FLAGS',
    0x00000022 : 'INTERNET_OPTION_URL',
    0x00000029 : 'INTERNET_OPTION_USER_AGENT',
    0x0000001c : 'INTERNET_OPTION_USERNAME',
    0x00000032 : 'INTERNET_OPTION_CONNECTED_STATE',
    }

snap_flags = {
    0x80000000 : 'TH32CS_INHERIT',
    0x00000001 : 'TH32CS_SNAPHEAPLIST',
    0x00000008 : 'TH32CS_SNAPMODULE',
    0x00000010 : 'TH32CS_SNAPMODULE32',
    0x00000002 : 'TH32CS_SNAPPROCESS',
    0x00000004 : 'TH32CS_SNAPTHREAD',
    0x0000000f : 'TH32CS_SNAPALL',
    }

move_flags = {
    0x00000001 : 'MOVEFILE_REPLACE_EXISTING',
    0x00000002 : 'MOVEFILE_COPY_ALLOWED',
    0x00000010 : 'MOVEFILE_CREATE_HARDLINK',
    0x00000004 : 'MOVEFILE_DELAY_UNTIL_REBOOT',
    0x00000020 : 'MOVEFILE_FAIL_IF_NOT_TRACKABLE',
    0x00000008 : 'MOVEFILE_WRITE_THROUGH',
    }

crypt_flags = {
    0x00000001 : 'CRYPTPROTECT_UI_FORBIDDEN',
    0x00000004 : 'CRYPTPROTECT_LOCAL_MACHINE',
    }

cb_formats = { # uFormat types for GetClipboardData
    0x00000001 : 'CF_TEXT',
    0x00000002 : 'CF_BITMAP',
    0x0000000d : 'CF_UNICODETEXT',
    }

dns_options = {
    0x00000000 : 'DNS_QUERY_STANDARD',
    0x00000004 : 'DNS_QUERY_NO_RECURSION',
    0x00000008 : 'DNS_QUERY_BYPASS_CACHE',
    0x00000020 : 'DNS_QUERY_NO_LOCAL_NAME',
    0x00000040 : 'DNS_QUERY_NO_HOSTS_FILE',
    }

dns_types = {
    0x00000001 : 'DNS_TYPE_A',
    0x00000002 : 'DNS_TYPE_NS',
    0x00000005 : 'DNS_TYPE_CNAME',
    0x00000006 : 'DNS_TYPE_SOA',
    0x0000000c : 'DNS_TYPE_PTR',
    0x0000000f : 'DNS_TYPE_MX',
    }

export_flags = {
    0x00000001 : 'REPORT_NO_PRIVATE_KEY',
    0x00000002 : 'REPORT_NOT_ABLE_TO_EXPORT_PRIVATE_KEY',
    0x00000004 : 'EXPORT_PRIVATE_KEYS',
    0x00000010 : 'PKCS12_INCLUDE_EXTENDED_PROPERTIES',
    }

cert_providers = {
    0x00000001 : 'CERT_STORE_PROV_MSG',
    0x00000002 : 'CERT_STORE_PROV_MEMORY',
    0x00000003 : 'CERT_STORE_PROV_FILE',
    0x00000004 : 'CERT_STORE_PROV_REG',
    0x00000007 : 'CERT_STORE_PROV_FILENAME_A',
    0x00000008 : 'CERT_STORE_PROV_FILENAME_W',
    0x00000009 : 'CERT_STORE_PROV_SYSTEM_A',
    0x0000000a : 'CERT_STORE_PROV_SYSTEM_W',
    }

thread_access = {
    0x001fffff : 'THREAD_ALL_ACCESS',
    0x00000008 : 'THREAD_GET_CONTEXT',
    0x00000100 : 'THREAD_IMPERSONATE',
    0x00000040 : 'THREAD_QUERY_INFORMATION',
    0x00000010 : 'THREAD_SET_CONTEXT',
    0x00000020 : 'THREAD_SET_INFORMATION',
    0x00000080 : 'THREAD_SET_THREAD_TOKEN',
    0x00000002 : 'THREAD_SUSPEND_RESUME',
    0x00000001 : 'THREAD_TERMINATE',
    }

hook_ids = {
    0xFFFFFFFF : 'WH_MIN|WH_MSGFILTER',
    0x00000000 : 'WH_JOURNALRECORD',
    0x00000001 : 'WH_JOURNALPLAYBACK',
    0x00000002 : 'WH_KEYBOARD',
    0x00000003 : 'WH_GETMESSAGE',
    0x00000004 : 'WH_CALLWNDPROC',
    0x00000005 : 'WH_CBT',
    0x00000006 : 'WH_SYSMSGFILTER',
    0x00000007 : 'WH_MOUSE',
    0x00000008 : 'WH_HARDWARE',
    0x00000009 : 'WH_DEBUG',
    0x0000000a : 'WH_SHELL',
    0x0000000b : 'WH_FOREGROUNDIDLE',
    0x0000000c : 'WH_CALLWNDPROCRET',
    0x0000000d : 'WH_KEYBOARD_LL',
    0x0000000e : 'WH_MOUSE_LL',
}

wait_states = {
    0xFFFFFFFF : 'WAIT_FAILED',
    0x00000000 : 'WAIT_OBJECT_0',
    0x00000080 : 'WAIT_ABANDONED',
    0x000000C0 : 'WAIT_IO_COMPLETION',
    0x00000102 : 'WAIT_TIMEOUT',
}




__INVALID_HANDLE_VALUE__ = 0xffffffff
__STILL_ACTIVE__         = 0x103
__ERROR_SUCCESS__        = 0
__S_OK__                 = 0
__SERVICES_ACTIVE_DATABASE__ = "ServicesActive"



class DATA_BLOB(Structure):
    _fields_ = [
        ("cbData",   DWORD),
        ("pbData",   DWORD), # its LPBYTE, but DWORD is OK
    ]

class QUERY_SERVICE_CONFIG(Structure):
    _fields_ = [
        ("dwServiceType",      DWORD),
        ("dwStartType",        DWORD),
        ("dwErrorControl",     DWORD),
        ("lpBinaryPathName",   LPSTR),
        ("lpLoadOrderGroup",   LPSTR),
        ("dwTagId",            DWORD),
        ("lpDependencies",     LPSTR),
        ("lpServiceStartName", LPSTR),
        ("lpDisplayName",      LPSTR),
    ]

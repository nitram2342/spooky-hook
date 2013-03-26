#!/usr/bin/python
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

from winappdbg import Debug, EventHandler, HexDump, System, PathOperations, Thread, CrashDump, Process
import winappdbg.win32.kernel32 as kernel32
import optparse
import pefile
import functools
from winappdbg.win32.defines import *
from pymon_helper import *
from pymon_data import *
from pymon_hooked_funcs import *
import re
    
# EventHandler,
class MyEventHandler( KnownFunctions):

    apiHooks = {}

    dir = ''
    report = None
    myself = None

    copyid = 0
    handles = []

    modules_seen = []

    api_hooks_kernel32 = [
                           ( 'CreateFileW'     ,   7  ),
                           ( 'CreateFileA'     ,   7  ),
                           ( 'GetModuleHandleA',   1  ),
                           ( 'GetModuleHandleW',   1  ),
                           ( 'GetTempFileNameA',   4  ),
                           ( 'GetTempFileNameW',   4  ),
                           ( 'WriteFile'       ,   5  ),
                           ( 'CreateThread'    ,   6  ),
                           ( 'ExitProcess'     ,   1  ),
                           ( 'FindNextFileW'   ,   2  ),
                           ( 'FindNextFileA'   ,   2  ),
                           ( 'FindFirstFileExW',   6  ),
                           ( 'FindFirstFileExA',   6  ),
                           ( 'ReplaceFileW'    ,   6  ),
                           ( 'MoveFileWithProgressW', 5),
                           ( 'CreateFileMappingW', 6  ),
                           ( 'WritePrivateProfileStringW', 4),
                           ( 'WritePrivateProfileStringA', 4),
                           ( 'GetSystemDirectoryA',   2),
                           ( 'GetSystemDirectoryW',   2  ),
                           ( 'OpenFileMappingW',   3  ),
                           ( 'MapViewOfFileEx',    6  ),
                           ( 'FlushViewOfFile',    2  ),
                           ( 'UnmapViewOfFile',    1  ),
                           ( 'ReadFile',           5  ),
                           ( 'DeleteFileW',        1  ),
                           ( 'DeleteFileA',        1  ),
                           ( 'SetFilePointer',     4  ),
                           ( 'CreatePipe',         4  ),
                           ( 'CreateNamedPipeW',   8  ),
                           ( 'ConnectNamedPipe',   2  ),
                           ( 'ResumeThread',       1  ),
                           ( 'SuspendThread',      1  ),
                           ( 'SetThreadContext',   2  ),
                           ( 'GetThreadContext',   2  ),
                           ( 'TerminateProcess',   2  ),
                           ( 'TerminateThread',    2  ),
                           ( 'CreateDirectoryW',   2  ),
                           ( 'CreateDirectoryA',   2  ),
                           ( 'RemoveDirectoryW',   1  ),
                           ( 'CreateDirectoryExA', 3  ),
                           ( 'CreateDirectoryExW', 3  ),
                           ( 'CreateProcessA',    10  ),
                           ( 'CreateProcessW',    10  ),
                           ( 'VirtualAllocEx',     5  ),
                           ( 'WinExec',            2  ),
                           ( 'OpenEventW',         3  ),
                           ( 'OpenEventA',         3  ),
                           ( 'CreateEventW',       4  ),
                           ( 'CreateEventA',       4  ),
                           ( 'OpenThread',         3  ),
                           ( 'OpenProcess',        3  ),
                           ( 'WriteProcessMemory', 5  ),
                           ( 'ReadProcessMemory',  5  ),
                           ( 'OpenMutexW',         3  ),
                           ( 'OpenMutexA',         3  ),
                           ( 'CreateMutexW',       3  ),
                           ( 'CreateMutexA',       3  ),
                           ( 'CopyFileExW',        6  ),
                           ( 'CopyFileExA',        6  ),
                           ( 'CopyFileA',          3  ), 
                           ( 'CopyFileW',          3  ),
                           ( 'CreateRemoteThread', 7  ),
                           ( 'GetExitCodeThread',  2  ),
                           ( 'GetComputerNameW',   2  ),
                           ( 'GetComputerNameA',   2  ),
                           ( 'LoadLibraryExW',     3  ),
                           ( 'LoadLibraryExA',     3  ),
                           ( 'GetProcAddress',     2  ),
                           ( 'CreateToolhelp32Snapshot',   2  ),
                           ( 'Process32FirstW',    2  ),
                           ( 'Process32FirstA',    2  ),
                           ( 'Process32NextW',     2  ),
                           ( 'Process32NextA',     2  ),
                           ( 'SetFileAttributesW',    2  ),
                           ( 'SetFileAttributesA',    2  ),
                           ( 'SetFileTime',        4  ),
                           ( 'CloseHandle',        1  ),
                           ( 'FindClose',          1  ),
                           ( 'SleepEx'         ,   2  ),
                           ( 'WaitForSingleObjectEx',  3  ),
                           ( 'GetCurrentProcessId',  0  ),
                         ]
    api_hooks_psapi =    [
                            ( 'GetModuleFileNameExW',   4  ),
                         ]
    api_hooks_advapi32 = [
                           ( 'RegCreateKeyExA' ,   9  ),
                           ( 'RegCreateKeyExW' ,   9  ),
                           ( 'RegCreateKeyA'   ,   3  ),
                           ( 'RegCreateKeyW'   ,   3  ),
                           ( 'CreateServiceA',    13  ),
                           ( 'CreateServiceW',    13  ),
                           ( 'OpenServiceA',       3  ),
                           ( 'OpenServiceW',       3  ),
                           ( 'CloseServiceHandle', 1  ),
                           ( 'QueryServiceConfigA',  4  ),
                           ( 'QueryServiceConfigW',  4  ),
                           ( 'OpenSCManagerA',     3  ),
                           ( 'OpenSCManagerW',     3  ),
                           ( 'ChangeServiceConfigA',   11  ),
                           ( 'ChangeServiceConfigW',   11  ),
                           ( 'OpenProcessToken',   3  ),
                           ( 'OpenThreadToken',    4  ),
                           ( 'DuplicateToken',     3  ),
                           ( 'RegDeleteKeyA',      2  ),
                           ( 'RegDeleteKeyW',      2  ),
                           ( 'RegDeleteValueA',    2  ),
                           ( 'RegDeleteValueW',    2  ),
                           ( 'RegOpenKeyA',        5  ),
                           ( 'RegOpenKeyW',        5  ),
                           ( 'RegOpenKeyExA',      5  ),
                           ( 'RegOpenKeyExW',      5  ),
                           ( 'RegQueryValueExA',   6  ),
                           ( 'RegQueryValueExW',   6  ),
                           ( 'RegSetValueExA',     6  ),
                           ( 'RegSetValueExW',     6  ),
                           ( 'StartServiceA',      3  ),
                           ( 'StartServiceW',      3  ),
                           ( 'CryptAcquireContextA',  5  ),
                           ( 'CryptEncrypt',       7  ),
                           ( 'CryptHashData',      4  ),
                           ( 'CryptCreateHash',    5  ),
                           ( 'CryptEncrypt',       7  ),
                           ( 'CryptDecrypt',       6  ),
                         ]
    api_hooks_user32 =   [
                           ( 'GetClipboardData' ,   1  ),
                           #( 'CreateWindowExA',    12  ),
                           #( 'CreateWindowExW',    12  ),
                           ( 'FindWindowA',         2  ),
                           ( 'FindWindowW',         2  ),
                           ( 'FindWindowExA',       4  ),
                           ( 'FindWindowExW',       4  ),
                           ( 'SetWinEventHook',     7  ),
                           ( 'SetWindowsHookExA',   4  ),
                           ( 'SetWindowsHookExW',   4  ),
                           ( 'UnhookWindowsHookEx', 1  ),
                           ( 'UnhookWinEvent',      1  ),
                           #( 'SendMessageA',        4  ),
                           #( 'SendMessageW',        4  ),
                           #( 'DestroyWindow',       1  ),
                           #( 'ShowWindow',          2  ),
                           #( 'SetTimer',            4  ),
                           #( 'KillTimer',           2  ),
                           #( 'GetClassNameA',       3  ),
                           #( 'GetClassNameW',       3  ),
                           #( 'GetWindowTextA',      3  ),
                           #( 'GetWindowTextW',      3  ),
                         ]
    api_hooks_wininet =  [
                            ( 'HttpAddRequestHeadersA',  4  ),
                            ( 'HttpAddRequestHeadersW',  4  ),
                            ( 'HttpOpenRequestA',        8  ),
                            ( 'HttpOpenRequestW',        8  ),
                            ( 'HttpSendRequestA',        5  ),
                            ( 'HttpSendRequestW',        5  ),
                            ( 'InternetConnectA',        8  ),
                            ( 'InternetConnectW',        8  ),
                            ( 'InternetOpenA',           5  ),
                            ( 'InternetOpenW',           5  ),
                            ( 'InternetOpenUrlA',        6  ),
                            ( 'InternetOpenUrlW',        6  ),
                            ( 'InternetQueryDataAvailable', 4  ),
                            ( 'InternetQueryOptionA',    4  ),
                            ( 'InternetQueryOptionW',    4  ),
                            ( 'InternetReadFile',        4  ),
                            ( 'InternetWriteFile',       4  ),
                         ]
    api_hooks_shell32 =  [
                            ( 'ShellExecuteA',           6  ),
                            ( 'ShellExecuteW',           6  ),
                         ]
    api_hooks_crypt32 =  [
                            ( 'CryptProtectData',        7  ),
                            ( 'CryptUnprotectData',      7  ),
                            ( 'CertOpenStore',           5  ),
                            ( 'PFXExportCertStore',      4  ),
                        ]
    api_hooks_dnsapi =  [
                            ( 'DnsQuery_W',              6  ),
                        ]
    api_hooks_ole32  =  [
                            ( 'CoCreateInstance',        5  ),
                            ( 'CoCreateGuid',            1  ),
                            ( 'StringFromGUID2',         3  ),
                        ]
    api_hooks_ws2_32 =  [
#                            ( 'WSAStartup',              2  ),
#                            ( 'gethostbyname',           2  ),
#                            ( 'connect',                 3  ),
#                            ( 'WSAConnect',              0  ), # 7
        ( 'send',                    4 ), # (DWORD, PVOID, DWORD, DWORD)
#                            ( 'socket',                  3  ),

        ( 'WSAConnectByNameA', 0  ),
        ( 'WSAConnectByNameW', 0  ),
                            
                        ]
    api_hooks_shlwapi = [
                            ( 'HashData',                4  ),
                            ( 'PathFindFileNameA',       1  ),
                            ( 'PathFindFileNameW',       1  ),
                            ( 'SHDeleteKeyA',            2  ),
                            ( 'SHDeleteKeyW',            2  ),
                        ]
    api_hooks_ntdll =   [
                           ( 'ZwLoadDriver'     ,   7  ),
                        ]



    # Here we set which API calls we want to intercept
    hooks = {

#        'ntdll.dll'    : api_hooks_ntdll, 
#        'kernel32.dll' : api_hooks_kernel32,
#        'psapi.dll'    : api_hooks_psapi,
#        'advapi32.dll' : api_hooks_advapi32,
#        'user32.dll'   : api_hooks_user32 ,
#        'wininet.dll'  : api_hooks_wininet,
#        'shell32.dll'  : api_hooks_shell32,
#        'crypt32.dll'  : api_hooks_crypt32,
#        'dnsapi.dll'   : api_hooks_dnsapi,
#        'ole32.dll'    : api_hooks_ole32,
        'ws2_32.dll'   : api_hooks_ws2_32,
#        'shlwapi.dll'  : api_hooks_shlwapi
        }


    def set_hooks(self, hooks):
        self.hooks = hooks

    def hook_func(self, event, filename, dll_name, address, func, paramCount, signature=None):

        # Get the process ID
        pid = event.get_pid()

        print "+\thook function: " + func

        pre_hook_func = getattr(self, "pre_" + func, None)
        post_hook_func = getattr(self, "post_" + func, None)

        identifier = dll_name + "!" + func + "()"

        if callable(pre_hook_func):
            print "+\t\thandler already implements a pre-hook for " + func
        else:
            pre_hook_func = functools.partial(self.generic_pre_hook, name=identifier)

        if callable(post_hook_func):
            print "+\t\thandler already implements a post-hook for " + func
        else:
            post_hook_func = functools.partial(self.generic_post_hook, name=identifier)

        try:
            event.debug.hook_function(pid, address, pre_hook_func, post_hook_func, paramCount, signature)
        except Exception, e:
            print e

    def load_dll(self, event):
        # Get the new module object
        module = event.get_module()
        self.modules_seen.append(module)

        module_filename = module.get_filename()
        basename = os.path.split(module_filename)[1]

        print "+ Module loaded: %s" % (module_filename)

#        print_funcs(self.modules_seen)

        for dll_name in self.hooks.keys():

            if dll_name.lower() == basename.lower():
                print "+\tshould hook " + basename

               
                for func in self.hooks[dll_name]:
                    # func is a tuple: (func_name, num_args)

                    if func == "*":
                        print "+\tShould hook all exported functions from " + dll_name
                        pe =  pefile.PE(module_filename)
                        for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                            print "+\twill resolv address of: " + \
                                exp.name
                            address = module.resolve(exp.name)
                            self.hook_func(event, module_filename, dll_name, address, \
                                               str(exp.name))

                    else:
                        address = module.resolve(func[0])
                        self.hook_func(event, module_filename, dll_name, address, 
                                       func[0], func[1])


def print_funcs(modules):
    mlist = open("modules.txt", 'w')

    for m in modules:
        pe =  pefile.PE(m.get_filename())
        for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            if m.get_filename():
                fn = os.path.split(m.get_filename())[1]
                mlist.write(fn + "!" + str(exp.name) + "\n")
                
    mlist.close()

def cb_parse_multiple_args(option, opt_str, value, parser):
    args=[value]
    for arg in parser.rargs:
        if arg[0] != "-" and arg[0] != "--":
            args.append(arg)
        else:
            del parser.rargs[:len(args)]
            break
    if getattr(parser.values, option.dest):
        args.extend(getattr(parser.values, option.dest))
    setattr(parser.values, option.dest, args)

def list_processes(match_name=""):
    print "[+] processes:"
    s = System()

    l = []

    if len(match_name) > 0:
        l1 = []
        for p in s.find_processes_by_filename(match_name):
            l.append(p[0])
    else:
        l = s

    for p in l:
        print "%5d\t%s" % (p.get_pid(), p.get_filename())

    return l

def print_threads_and_modules( pid, debug ):

    # Instance a Process object.
    process = Process( pid )
    print "Process %d" % process.get_pid()

    # Now we can enumerate the threads in the process...
    print "Threads:"
    for thread in process.iter_threads():
        print "\t%d" % thread.get_tid()

    # ...and the modules in the process.
    print "Modules:"
    bits = process.get_bits()
    for module in process.iter_modules():
        print "\thas module: %s\t%s" % (
            HexDump.address( module.get_base(), bits ),
            module.get_filename()
        )

    print "Breakpoints:"
    for i in debug.get_all_breakpoints():
        bp = i[2]
        print "breakpoint: %s %x" % (bp.get_state_name(), bp.get_address())


    

def parse_hook_spec(func_specs):
    ret = {}
    for fs in func_specs:

        fs_a = fs.split("!")
        
        if len(fs_a) < 2:
            print "++ Error: can't parse \"" + fs + "\"\n"
            return {}
        else:
            print "  " + fs_a[0]
            print "  " + fs_a[1] +"\n"
            if not ret.has_key(fs_a[0]):
                ret[fs_a[0]] = []

            if len(fs_a) == 3:                
                tupel = (fs_a[1], int(fs_a[2]))
            else:
                tupel = (fs_a[1], 0)

            ret[fs_a[0]].append(tupel)
            
    return ret
        

# When invoked from the command line,
# the first argument is an executable file,
# and the remaining arguments are passed to the newly created process
if __name__ == "__main__":

    parser = optparse.OptionParser( "Usage: %prog [options]");
    parser.add_option("--list", dest = 'list', action = 'store_true', 
                      help = 'attach to a process specified by an ID')
    parser.add_option("--attach-pid", dest = 'pid', type = 'int', 
                      help = 'attach to a process specified by an ID')
    parser.add_option("--attach-prog", dest = 'program', type = 'string', 
                      help = 'attach to a process specified by a program name')
    parser.add_option("--exec", dest = 'command', type = 'string', 
                      help = 'execute command', action = 'callback', 
                      callback = cb_parse_multiple_args)
    parser.add_option("--hook", dest = 'functions', type = 'string', 
                      help = 'functions to hook (format: lib.dll!function-name[!num-args]; examples: ws2_32.dll!send!4 or ws2_32!*)', 
                      action = 'callback', 
                      callback = cb_parse_multiple_args)
    parser.add_option("--log", dest = 'logfile', type = 'string', 
                      help = 'log data to the specified file',
                      default = "recording.log")
    (options, args) = parser.parse_args()

    
    if options.pid:
        print "[+] Attach to PID: %d" % options.pid
    elif options.program:
        print "[+] Attach to program: %s" % options.program
    elif options.command:
        print "[+] Execute: " + str(options.command)
    elif options.list:
        list_processes()
    else:
        parser.print_help()
        sys.exit()


    report = open(options.logfile, 'a')
    if report == None:
        print "\nCannot open log file!"
        sys.exit()


    myevent = MyEventHandler()
    myevent.dir = dir
    myevent.report = report
    myevent.myself = os.path.basename(sys.argv[1])

    if options.functions:
        hooks = parse_hook_spec(options.functions)
        if len(hooks) == 0:
            sys.exit()
        else:
            myevent.set_hooks(hooks)


    # Instance a Debug object, passing it the MyEventHandler instance
    debug = Debug( myevent )

    try:

        if options.pid:
            debug.attach(options.pid)
            print_threads_and_modules(options.pid, debug)
        elif options.program:
            procs = list_processes(options.program)

            if len(procs) == 0:
                print "[E] no matching process"
            elif len(procs) == 1:
                debug.attach(procs[0].get_pid())
                print_threads_and_modules(procs[0].get_pid(), debug)
            else:
                print "[E] ambigious"
        elif options.command:
            p = debug.execv( options.command, bFollow = True )

        # Wait for the debugee to finish
        debug.loop()

    # Stop the debugger
    finally:
        debug.stop()

    #report = open("%s/report.html" % dir, 'a')
    #if report:
    report.close()

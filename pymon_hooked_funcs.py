import os
from pymon_data import *
import inspect
from time import time, gmtime, strftime
import shutil
import uuid
import binascii
import sys
import cgi
from distorm3 import Decode, Decode16Bits, Decode32Bits, Decode64Bits
from winappdbg import Debug, EventHandler, HexDump, System, PathOperations, Thread, CrashDump, Process

class KnownFunctions(EventHandler):

    def generic_pre_hook(self, event, retval, name):

        print "+ in pre-handler for function  : " + name
        caller = self.__getcaller(event, 2)
        if caller == None or caller in knownmods:
            return

        tid = event.get_tid()
        params = event.hook.get_params(tid)

        #
        # get a string 
        # -----------------
        # val = event.get_process().peek_string(params[0])

        #
        # read bytes:
        # -----------------

        # if pbdata != None:
        #    inbuf = event.get_process().read(pbdata, cbdata)
        #    if inbuf != None:
        #        self.__loghex(inbuf)

        
        self.__log(event, caller, "val?", "", retval, 
                   # 'ok' if retval == __ERROR_SUCCESS__ else 'fail'
                   )
        
    def generic_post_hook(self, event, retval, name):

        print "+ in post-handler for function : " + name
        caller = self.__getcaller(event, 2)
        if caller == None or caller in knownmods:
            return

        tid = event.get_tid()
        params = event.hook.get_params(tid)
        
        # val = event.get_process().peek_string(params[0])

        self.__log(event, caller, "val?", "", retval, 
                   # 'ok' if retval == __ERROR_SUCCESS__ else 'fail'
                   )




    # Functions in ws2_32.dll

    #-----------------------------------------------------
    '''
    int WSAStartup(
      __in          WORD wVersionRequested,
      __out         LPWSADATA lpWSAData
    );
    '''
    #-----------------------------------------------------
    def post_WSAStartup(self, event, retval):
        
        caller = self.__getcaller(event, 2)
        if caller == None or caller in knownmods:
            return
            
        self.__log(event, caller, "", "", retval, 'ok' if retval == 0 else 'fail')

    #-----------------------------------------------------
    '''
    struct hostent* FAR gethostbyname(
      __in          const char* name
    );
    '''
    #-----------------------------------------------------
    def post_gethostbyname(self, event, retval):
    
        caller = self.__getcaller(event, 2)
        if caller == None or caller in knownmods:
            return
            
        tid = event.get_tid()
        params = event.hook.get_params(tid)
        host_name = event.get_process().peak_string(params[0])
        
        self.__log(event, caller, host_name, "", retval, 'ok' if retval != None else 'fail')

    #-----------------------------------------------------
    '''
    int connect(
       _In_  SOCKET s,
       _In_  const struct sockaddr *name,
       _In_  int namelen
    );
    '''
    #-----------------------------------------------------
    def post_connect(self, event, retval):
    
        caller = self.__getcaller(event, 2)
        if caller == None or caller in knownmods:
            return
            
        tid = event.get_tid()
        params = event.hook.get_params(tid)
#        print "connect()"
#        host_name = event.get_process().peak_string(params[0])
        
        self.__log(event, caller, host_name, "", retval, 'ok' if retval != None else 'fail')
    #-----------------------------------------------------
    '''
    int send(
      _In_  SOCKET s,
      _In_  const char *buf,
      _In_  int len,
      _In_  int flags
    );
    '''

    #-----------------------------------------------------
    def post_send(self, event, retval):

        tid = event.get_tid()
        params2 = event.hook.get_params(tid)

        if len(params2) <= 3:
            print "  [E] send(): not enough params (" +str(len(params2))+ ")"
            return

        s_len = params2[2]
        s_buf = params2[1]
        
        print "+ post-send(): " + str(s_len) + " bytes"

        if s_len > 0:
             inbuf = event.get_process().read(s_buf, s_len)
             if inbuf != None:
                 self.__loghex(inbuf)


    def pre_send(self, event, retval, sock, buf, lenght, flags):

        tid = event.get_tid()
        params = event.hook.get_params(tid)

        s_len = params[2]
        s_buf = params[1]
        
        print "+ pre-send(): " + str(s_len) + " bytes"

        if s_len > 0:
             inbuf = event.get_process().read(s_buf, s_len)
             if inbuf != None:
                 self.__loghex(inbuf)



    def post_WSAConnect(self, event, retval):
        print "WSAConnect()"


    # Functions in shlwapi.dll

    #-----------------------------------------------------
    '''
    LSTATUS SHDeleteKey(          
        HKEY hkey,
        LPCTSTR pszSubKey
    );
    '''
    #-----------------------------------------------------
    def post_SHDeleteKeyA(self, event, retval):
        
        caller = self.__getcaller(event, 2)
        if caller == None or caller in knownmods:
            return

        tid = event.get_tid()
        params = event.hook.get_params(tid)
        hKey = params[0]
        
        key_name = reg_hkey[hKey] if reg_hkey.has_key(hKey) else hex(hKey)
        sub_key = event.get_process().peek_string(params[1])
        key_name = "%s\\%s" % (key_name, sub_key)
        
        self.__log(event, caller, key_name, "", retval, 
            'ok' if retval == __ERROR_SUCCESS__ else 'fail')

    def post_SHDeleteKeyW(self, event, retval):
        
        caller = self.__getcaller(event, 2)
        if caller == None or caller in knownmods:
            return

        tid = event.get_tid()
        params = event.hook.get_params(tid)
        hKey = params[0]
        
        key_name = reg_hkey[hKey] if reg_hkey.has_key(hKey) else hex(hKey)
        sub_key = event.get_process().peek_string(params[1], fUnicode=True)
        key_name = "%s\\%s" % (key_name, sub_key)
        
        self.__log(event, caller, key_name, "", retval, 
            'ok' if retval == __ERROR_SUCCESS__ else 'fail')

    #-----------------------------------------------------
    '''
    LPTSTR PathFindFileName(          
        LPCTSTR pPath
    );
    '''
    #-----------------------------------------------------
    def post_PathFindFileNameA(self, event, retval):
        
        caller = self.__getcaller(event, 1)
        if caller == None or caller in knownmods:
            return

        tid = event.get_tid()
        params = event.hook.get_params(tid)
        in_path = event.get_process().peek_string(params[0])
        
        self.__log(event, caller, "Path:%s" % in_path, "", retval, 
            'ok' if retval == params[0] else 'fail')
        
    def post_PathFindFileNameW(self, event, retval):
        
        caller = self.__getcaller(event, 1)
        if caller == None or caller in knownmods:
            return

        tid = event.get_tid()
        params = event.hook.get_params(tid)
        in_path = event.get_process().peek_string(params[0], fUnicode=True)
        
        self.__log(event, caller, "Path:%s" % in_path, "", retval, 
            'ok' if retval == params[0] else 'fail')
        
    #-----------------------------------------------------
    '''
    HRESULT HashData(
        LPBYTE pbData,
        DWORD cbData,
        LPBYTE pbHash,
        DWORD cbHash
    );
    '''
    #-----------------------------------------------------
    def post_HashData(self, event, retval):

        caller = self.__getcaller(event, 4)
        if caller == None or caller in knownmods:
            return

        tid = event.get_tid()
        params = event.hook.get_params(tid)

        pbdata = params[0]
        cbdata = params[1]
        pbhash = params[2]
        cbhash = params[3]

        if retval != __S_OK__:
            css='fail'
        else:
            css='ok'

        self.__log(event, caller, 
            "cbData: 0x%x, cbHash: 0x%x" % (cbdata,cbhash),
            "", retval, css)

        if pbdata != None:
            inbuf = event.get_process().read(pbdata, cbdata)
            if inbuf != None:
                self.__loghex(inbuf)

        if pbhash != None:
            outbuf = event.get_process().read(pbhash, cbhash)
            if outbuf != None:
                self.__loghex(outbuf)

    # Functions in shell32.dll

    #-----------------------------------------------------
    '''
    HINSTANCE ShellExecute(         
        HWND hwnd,
        LPCTSTR lpOperation,
        LPCTSTR lpFile,
        LPCTSTR lpParameters,
        LPCTSTR lpDirectory,
        INT nShowCmd
    );
    '''
    #-----------------------------------------------------
    def post_ShellExecuteA(self, event, retval):
        
        caller = self.__getcaller(event, 3)
        if caller == None or caller in knownmods:
            return

        tid = event.get_tid()
        params = event.hook.get_params(tid)
        if params[1] == None:
            verb = ""
        else:
            verb = event.get_process().peek_string(params[1])
        if params[2] == None:
            file = ""
        else:
            file = event.get_process().peek_string(params[2])
        if params[3] == None:
            args = ""
        else:
            args = event.get_process().peek_string(params[3])
        show = self.__get_flags(show_flags, params[5])
        
        self.__log(event, caller, "%s %s %s" % (verb, file, args), 
            show, retval, 
            'ok' if retval > 32 else 'fail')

    def post_ShellExecuteW(self, event, retval):
        
        caller = self.__getcaller(event, 3)
        if caller == None or caller in knownmods:
            return

        tid = event.get_tid()
        params = event.hook.get_params(tid)
        if params[1] == None:
            verb = ""
        else:
            verb = event.get_process().peek_string(params[1], fUnicode=True)
        if params[2] == None:
            file = ""
        else:
            file = event.get_process().peek_string(params[2], fUnicode=True)
        if params[3] == None:
            args = ""
        else:
            args = event.get_process().peek_string(params[3], fUnicode=True)
        show = self.__get_flags(show_flags, params[5])
        
        self.__log(event, caller, "%s %s %s" % (verb, file, args), 
            show, retval, 
            'ok' if retval > 32 else 'fail')

    # Functions in ole32.dll

    #-----------------------------------------------------
    '''
    int StringFromGUID2(
        REFGUID rguid,
        LPOLESTR lpsz,
        int cchMax
    );
    '''
    #-----------------------------------------------------
    def post_StringFromGUID2(self, event, retval):

        caller = self.__getcaller(event, 3)
        if caller == None or caller in knownmods:
            return

        tid = event.get_tid()
        params = event.hook.get_params(tid)
        rguid = params[0]

        if rguid != None:
            rguid = event.get_process().read(rguid, sizeof(GUID))
            guid  = str(uuid.UUID(bytes=rguid))
        else:
            guid = ""

        if retval == 0:
            css = 'fail'
        else:
            css = 'ok'

        self.__log(event, caller, "{%s}" % guid, "", retval, css)

    #-----------------------------------------------------
    '''
    STDAPI CoCreateInstance(
        REFCLSID rclsid,
        LPUNKNOWN pUnkOuter,
        DWORD dwClsContext,
        REFIID riid,
        LPVOID * ppv
    );
    '''
    #-----------------------------------------------------
    def post_CoCreateInstance(self, event, retval):

        caller = self.__getcaller(event, 5)
        if caller == None or caller in knownmods:
            return

        tid = event.get_tid()
        params = event.hook.get_params(tid)
        rclsid = params[0]

        if rclsid != NULL:
            guid = event.get_process().read(rclsid, sizeof(GUID))
            guid = str(uuid.UUID(bytes=guid))
        else:
            guid = ""

        if retval == __S_OK__:
            css = 'ok'
        else:
            css = 'fail'

        self.__log(event, caller, "{%s}" % rclsid, "", retval, css)

    #-----------------------------------------------------
    '''
    HRESULT CoCreateGuid(
        GUID * pguid
    );
    '''
    #-----------------------------------------------------
    def post_CoCreateGuid(self, event, retval):

        caller = self.__getcaller(event, 1)
        if caller == None or caller in knownmods:
            return

        tid = event.get_tid()
        params = event.hook.get_params(tid)
        pguid = params[0]

        if pguid != NULL:
            pguid = event.get_process().read(pguid, sizeof(GUID))
            guid  = str(uuid.UUID(bytes=pguid))
        else:
            guid = ""

        if retval == __S_OK__:
            css = 'ok'
        else:
            css = 'fail'

        self.__log(event, caller, "{%s}" % guid, "", retval, css)

    # Functions in dnsapi.dll

    #-----------------------------------------------------
    # Todo: parse ppQueryResults: http://support.microsoft.com/kb/831226
    '''
    DNS_STATUS WINAPI DnsQuery(
      __in          PCSTR lpstrName,
      __in          WORD wType,
      __in          DWORD fOptions,
      __in_out_opt  PVOID pExtra,
      __in_out      PDNS_RECORD* ppQueryResultsSet,
      __in_out      PVOID* pReserved
    );
    '''
    def post_DnsQuery_W(self, event, retval):

        caller = self.__getcaller(event, 6)
        if caller == None or caller in knownmods:
            return

        tid = event.get_tid()
        params = event.hook.get_params(tid)

        owner = event.get_process().peek_string(params[0], fUnicode=True)
        types = self.__get_flags(dns_types, params[1])
        opts = self.__get_flags(dns_options, params[2])

        self.__log(event, 
            caller, owner,
            "Options: %s; Type: %s" % (opts, types),
            retval,
            css = 'suspicious')

    # Functions in crypt32.dll

    #-----------------------------------------------------
    '''
    BOOL WINAPI PFXExportCertStore(
      __in          HCERTSTORE hStore,
      __in_out      CRYPT_DATA_BLOB* pPFX,
      __in          LPCWSTR szPassword,
      __in          DWORD dwFlags
    );
    '''
    #-----------------------------------------------------
    def post_PFXExportCertStore(self, event, retval):

        caller = self.__getcaller(event, 4)
        if caller == None or caller in knownmods:
            return

        tid = event.get_tid()
        params = event.hook.get_params(tid)

        hs    = params[0]
        ppfx  = params[1]
        pwd   = event.get_process().peek_string(params[2], fUnicode=True)
        flags = self.__get_flags(export_flags, params[3])

        self.__log(event, caller, 
            "hStore: 0x%x" % hs, "Password: %s; Flags: %s" % (pwd, flags),
            retval,
            css='suspicious')

        if retval == True and ppfx != None:
            pfx = event.get_process().read_structure(ppfx, DATA_BLOB)
            if (pfx.cbData != 0) and (pfx.pbData != None):
                buf = event.get_process().read(pfx.pbData, pfx.cbData)
                if buf != None:
                    self.__loghex(buf)

    #-----------------------------------------------------
    '''
    HCERTSTORE WINAPI CertOpenStore(
      __in          LPCSTR lpszStoreProvider,
      __in          DWORD dwMsgAndCertEncodingType,
      __in          HCRYPTPROV_LEGACY hCryptProv,
      __in          DWORD dwFlags,
      __in          const void* pvPara
    );
    '''
    #-----------------------------------------------------
    def post_CertOpenStore(self, event, retval):

        caller = self.__getcaller(event, 5)
        if caller == None or caller in knownmods:
            return

        tid = event.get_tid()
        params = event.hook.get_params(tid)

        provider = self.__get_flags(cert_providers, params[0])
        pvPara   = params[4]

        str1 = "pvPara: 0x%x" % pvPara

        if retval != None:
            if (provider == 'CERT_STORE_PROV_FILENAME_W') or \
               (provider == 'CERT_STORE_PROV_SYSTEM_W'):
                str1 = event.get_process().peek_string(pvPara, fUnicode=True)
            elif (provider == 'CERT_STORE_PROV_FILENAME_A') or \
                 (provider == 'CERT_STORE_PROV_SYSTEM_A'):
                str1 = event.get_process().peek_string(pvPara)

        self.__log(event, caller, 
            provider, "pvPara: %s" % str1,
            retval,
            css='suspicious')

    #-----------------------------------------------------
    '''
    BOOL WINAPI CryptUnprotectData(
      __in          DATA_BLOB* pDataIn,
      __out_opt     LPWSTR* ppszDataDescr,
      __in_opt      DATA_BLOB* pOptionalEntropy,
      __in          PVOID pvReserved,
      __in_opt      CRYPTPROTECT_PROMPTSTRUCT* pPromptStruct,
      __in          DWORD dwFlags,
      __out         DATA_BLOB* pDataOut
    );
    '''
    #-----------------------------------------------------
    def post_CryptUnprotectData(self, event, retval):

        caller = self.__getcaller(event, 7)
        if caller == None or caller in knownmods:
            return

        tid = event.get_tid()
        params = event.hook.get_params(tid)

        i_buf, i_size = self.__read_blob(event, params[0])
        e_buf, e_size = self.__read_blob(event, params[2])
        o_buf, o_size = self.__read_blob(event, params[6])

        flags = self.__get_flags(crypt_flags, params[5])

        if retval == True:

            self.__log(event, caller, 
                "Input Length: 0x%x" % i_size, "Flags: %s" % flags, retval)

            if i_buf != None:
                self.__loghex(i_buf)

            if e_size != 0:
                self.__log(event, caller, 
                    "Entropy Length: 0x%x" % e_size, "", 0, css = 'after')
                if e_buf != None:
                    self.__loghex(e_buf)

            if o_size != 0:
                self.__log(event, caller, 
                    "Plaintext Length: 0x%x" % o_size, "", 0, css = 'after')
                if o_buf != None:
                    self.__loghex(o_buf)

        else:
            self.__log(event, caller, "Input Length: 0x%x" % i_size,
                "Flags: %s" % flags, retval, css = 'fail')

    #-----------------------------------------------------
    '''
    BOOL WINAPI CryptProtectData(
      __in          DATA_BLOB* pDataIn,
      __in          LPCWSTR szDataDescr,
      __in          DATA_BLOB* pOptionalEntropy,
      __in          PVOID pvReserved,
      __in_opt      CRYPTPROTECT_PROMPTSTRUCT* pPromptStruct,
      __in          DWORD dwFlags,
      __out         DATA_BLOB* pDataOut
    );
    '''
    #-----------------------------------------------------
    def post_CryptProtectData(self, event, retval):

        caller = self.__getcaller(event, 7)
        if caller == None or caller in knownmods:
            return

        tid = event.get_tid()
        params = event.hook.get_params(tid)

        i_buf, i_size = self.__read_blob(event, params[0])
        e_buf, e_size = self.__read_blob(event, params[2])
        o_buf, o_size = self.__read_blob(event, params[6])

        flags = self.__get_flags(crypt_flags, params[5])

        if retval == True:

            self.__log(event, caller, 
                "Input Length: 0x%x" % i_size, "Flags: %s" % flags, retval)

            if i_buf != None:
                self.__loghex(i_buf)

            if e_size != 0:
                self.__log(event, caller, 
                    "Entropy Length: 0x%x" % e_size, "", 0, css = 'after')
                if e_buf != None:
                    self.__loghex(e_buf)

            if o_size != 0:
                self.__log(event, caller, 
                    "Crypted Length: 0x%x" % o_size, "", 0, css = 'after')
                if o_buf != None:
                    self.__loghex(o_buf)

        else:
            self.__log(event, caller, 
                "Input Length: 0x%x" % i_size,
                "Flags: %s" % flags, retval, css = 'fail')

    # Functions in wininet.dll

    #-----------------------------------------------------
    '''
    BOOL InternetWriteFile(
      __in          HINTERNET hFile,
      __in          LPCVOID lpBuffer,
      __in          DWORD dwNumberOfBytesToWrite,
      __out         LPDWORD lpdwNumberOfBytesWritten
    );
    '''
    #-----------------------------------------------------
    def post_InternetWriteFile(self, event, retval):

        caller = self.__getcaller(event, 4)
        if caller == None or caller in knownmods:
            return
            
        tid = event.get_tid()
        params = event.hook.get_params(tid)

        url = self.__lookup_handle("Internet", params[0])

        pbuf = params[1]
        to_write = params[2]
        pwritten = params[3]

        if retval == True:

            if pwritten != None:
                written = event.get_process().read_uint(pwritten)
            else:
                written = to_write

            if pbuf != None:
                buf = event.get_process().read(pbuf, written)
            else:
                buf = None

            self.__log(event, caller, 
                url, "Bytes to write: 0x%x; Bytes written: 0x%x" % (to_write, written), 
                retval)

            if buf != None:
                self.__loghex(buf)

        else:
            self.__log(event, caller, 
                url, "Bytes to write: 0x%x" % (to_write), retval, css = 'fail')

    #-----------------------------------------------------
    '''
    BOOL InternetReadFile(
      __in          HINTERNET hFile,
      __out         LPVOID lpBuffer,
      __in          DWORD dwNumberOfBytesToRead,
      __out         LPDWORD lpdwNumberOfBytesRead
    );
    '''
    #-----------------------------------------------------
    def post_InternetReadFile(self, event, retval):

        caller = self.__getcaller(event, 4)
        if caller == None or caller in knownmods:
            return

        tid = event.get_tid()
        params = event.hook.get_params(tid)

        url = self.__lookup_handle("Internet", params[0])

        pbuf = params[1]
        to_read = params[2]
        pread = params[3]

        css = 'suspicious'

        if retval == True:

            if pread != None:
                cread = event.get_process().read_uint(pread)
            else:
                cread = to_read

            if pbuf != None:
                buf = event.get_process().read(pbuf, cread)
            else:
                buf = None

            self.__log(event, caller, url,
                "Bytes to read: 0x%x; Bytes read: 0x%x" % (to_read, cread),
                retval, css)

            if buf != None:
                self.__loghex(buf)

        else:
            self.__log(event, caller, 
                url, "Bytes to read: 0x%x" % (to_read), retval, css)

    #-----------------------------------------------------
    '''
    BOOL InternetQueryOption(
      __in          HINTERNET hInternet,
      __in          DWORD dwOption,
      __out         LPVOID lpBuffer,
      __in_out      LPDWORD lpdwBufferLength
    );
    '''
    #-----------------------------------------------------
    def post_InternetQueryOptionA(self, event, retval):

        caller = self.__getcaller(event, 4)
        if caller == None or caller in knownmods:
            return

        tid = event.get_tid()
        params = event.hook.get_params(tid)

        name = self.__lookup_handle("Internet", params[0])

        option = self.__get_flags(inet_opts, params[1])
        pbuf   = params[2]
        plen   = params[3]

        if retval == True:
            self.__log(event, caller, name, option, retval)

            if (pbuf != None) and (plen != None):

                length = event.get_process().read_uint(plen)
                buf = event.get_process().read(pbuf, length)

                if buf != None:
                    self.__loghex(buf)
        else:
            self.__log(event, caller, name, option, retval, css = 'fail')

    def post_InternetQueryOptionW(self, event, retval):

        caller = self.__getcaller(event, 4)
        if caller == None or caller in knownmods:
            return

        tid = event.get_tid()
        params = event.hook.get_params(tid)

        name = self.__lookup_handle("Internet", params[0])

        option = self.__get_flags(inet_opts, params[1])
        pbuf   = params[2]
        plen   = params[3]

        if retval == True:
            self.__log(event, caller, name, option, retval)

            if (pbuf != None) and (plen != None):

                length = event.get_process().read_uint(plen)
                buf = event.get_process().read(pbuf, length)

                if buf != None:
                    self.__loghex(buf)
        else:
            self.__log(event, caller, name, option, retval, css = 'fail')

    #-----------------------------------------------------
    '''
    BOOL InternetQueryDataAvailable(
      __in          HINTERNET hFile,
      __out         LPDWORD lpdwNumberOfBytesAvailable,
      __in          DWORD dwFlags,
      __in          DWORD_PTR dwContext
    );
    '''
    #-----------------------------------------------------
    def post_InternetQueryDataAvailable(self, event, retval):

        caller = self.__getcaller(event, 4)
        if caller == None or caller in knownmods:
            return
            
        tid = event.get_tid()
        params = event.hook.get_params(tid)

        url = self.__lookup_handle("Internet", params[0])
        addr = params[1]

        if retval == True:

            self.__log(event, url, "", retval)

            if addr != None:
                bytes = event.get_process().read_uint(addr)
                self.__log(event, caller, "0x%x" % bytes, "", 0, 'after')

        else:
            self.__log(event, caller, url, "", retval, 'failed')

    #-----------------------------------------------------
    '''
    HINTERNET InternetOpenUrl(
      __in          HINTERNET hInternet,
      __in          LPCTSTR lpszUrl,
      __in          LPCTSTR lpszHeaders,
      __in          DWORD dwHeadersLength,
      __in          DWORD dwFlags,
      __in          DWORD_PTR dwContext
    );
    '''
    #-----------------------------------------------------
    def post_InternetOpenUrlA(self, event, retval):

        caller = self.__getcaller(event, 6)
        if caller == None or caller in knownmods:
            return

        tid = event.get_tid()
        params = event.hook.get_params(tid)

        request = self.__lookup_handle("Internet", params[0])
        url = event.get_process().peek_string(params[1])
        headers = event.get_process().peek_string(params[2])
        flags = self.__get_flags(inet_flags, params[4])

        self.__log(event, caller, 
            "%s; URL: %s" % (request, url),
            "Headers: %s; Flags: %s" % (headers, flags),
            retval,
            css='suspicious')

    def post_InternetOpenUrlW(self, event, retval):

        caller = self.__getcaller(event, 6)
        if caller == None or caller in knownmods:
            return

        tid = event.get_tid()
        params = event.hook.get_params(tid)

        request = self.__lookup_handle("Internet", params[0])
        url = event.get_process().peek_string(params[1], fUnicode=True)
        headers = event.get_process().peek_string(params[2], fUnicode=True)
        flags = self.__get_flags(inet_flags, params[4])

        self.__log(event, caller,
            "%s; URL: %s" % (request, url),
            "Headers: %s; Flags: %s" % (headers, flags),
            retval,
            css='suspicious')

    #-----------------------------------------------------
    '''
    HINTERNET InternetOpen(
      __in          LPCTSTR lpszAgent,
      __in          DWORD dwAccessType,
      __in          LPCTSTR lpszProxyName,
      __in          LPCTSTR lpszProxyBypass,
      __in          DWORD dwFlags
    );
    '''
    #-----------------------------------------------------
    def post_InternetOpenA(self, event, retval):

        caller = self.__getcaller(event, 5)
        if caller == None or caller in knownmods:
            return

        tid = event.get_tid()
        params = event.hook.get_params(tid)

        agent  = event.get_process().peek_string(params[0])
        access = self.__get_flags(inet_access, params[1])

        if retval != None:
            self.__add_handle("Internet", retval, "<Top level HINTERNET>")

        self.__log(event, caller,
            "Agent: %s" % agent, "Access: %s" % access,
            retval,
            css='suspicious')

    def post_InternetOpenW(self, event, retval):

        caller = self.__getcaller(event, 5)
        if caller == None or caller in knownmods:
            return

        tid = event.get_tid()
        params = event.hook.get_params(tid)

        agent  = event.get_process().peek_string(params[0], fUnicode=True)
        access = self.__get_flags(inet_access, params[1])

        if retval != None:
            self.__add_handle("Internet", retval, "<Top level HINTERNET>")

        self.__log(event, caller, 
            "Agent: %s" % agent, "Access: %s" % access,
            retval,
            css='suspicious')

    #-----------------------------------------------------
    '''
    HINTERNET InternetConnect(
      __in          HINTERNET hInternet,
      __in          LPCTSTR lpszServerName,
      __in          INTERNET_PORT nServerPort,
      __in          LPCTSTR lpszUsername,
      __in          LPCTSTR lpszPassword,
      __in          DWORD dwService,
      __in          DWORD dwFlags,
      __in          DWORD_PTR dwContext
    );
    '''
    #-----------------------------------------------------
    def post_InternetConnectA(self, event, retval):

        caller = self.__getcaller(event, 8)
        if caller == None or caller in knownmods:
            return
            
        tid = event.get_tid()
        params = event.hook.get_params(tid)

        server  = event.get_process().peek_string(params[1])
        port    = self.__get_flags(inet_ports, params[2])
        service = self.__get_flags(inet_services, params[5])
        flags   = self.__get_flags(inet_flags, params[6])

        if retval != None:
            self.__add_handle("Internet", retval, server)

        self.__log(event,
            caller, 
            self.__lookup_handle("Internet", retval),
            "Port: %s; Service: %s; Flags: %s" % (port, service, flags),
            retval,
            'suspicious')

    def post_InternetConnectW(self, event, retval):

        caller = self.__getcaller(event, 8)
        if caller == None or caller in knownmods:
            return

        tid = event.get_tid()
        params = event.hook.get_params(tid)

        server  = event.get_process().peek_string(params[1], fUnicode=True)
        port    = self.__get_flags(inet_ports, params[2])
        service = self.__get_flags(inet_services, params[5])
        flags   = self.__get_flags(inet_flags, params[6])

        if retval != None:
            self.__add_handle("Internet", retval, server)

        self.__log(event,
            caller, 
            self.__lookup_handle("Internet", retval),
            "Port: %s; Service: %s; Flags: %s" % (port, service, flags),
            retval,
            'suspicious')

    #-----------------------------------------------------
    '''
    BOOL HttpSendRequest(
      __in          HINTERNET hRequest,
      __in          LPCTSTR lpszHeaders,
      __in          DWORD dwHeadersLength,
      __in          LPVOID lpOptional,
      __in          DWORD dwOptionalLength
    );
    '''
    #-----------------------------------------------------
    def post_HttpSendRequestA(self, event, retval):

        caller = self.__getcaller(event, 5)
        if caller == None or caller in knownmods:
            return

        tid = event.get_tid()
        params = event.hook.get_params(tid)

        request = self.__lookup_handle("Internet", params[0])
        headers = event.get_process().peek_string(params[1])
        lpOptional = params[3]
        dwOptionalLength = params[4]

        if (lpOptional != None) and (dwOptionalLength != 0):
            data = event.get_process().read(lpOptional, dwOptionalLength)
        else:
            data = ""

        self.__log(event, caller, request,
            "Headers: %s; Optional Length: 0x%x" % (headers, len(data)),
            retval,
            css='suspicious')

        if len(data) > 0:
            self.__loghex(data)

    def post_HttpSendRequestW(self, event, retval):

        caller = self.__getcaller(event, 5)
        if caller == None or caller in knownmods:
            return

        tid = event.get_tid()
        params = event.hook.get_params(tid)

        request = self.__lookup_handle("Internet", params[0])
        headers = event.get_process().peek_string(params[1], fUnicode=True)
        lpOptional = params[3]
        dwOptionalLength = params[4]

        if (lpOptional != None) and (dwOptionalLength != 0):
            data = event.get_process().read(lpOptional, dwOptionalLength)
        else:
            data = ""

        self.__log(event, caller, request,
            "Headers: %s; Optional Length: 0x%x" % (headers, len(data)),
            retval,
            css='suspicious')

        if len(data) > 0:
            self.__loghex(data)

    #-----------------------------------------------------
    '''
    HINTERNET HttpOpenRequest(
      __in          HINTERNET hConnect,
      __in          LPCTSTR lpszVerb,
      __in          LPCTSTR lpszObjectName,
      __in          LPCTSTR lpszVersion,
      __in          LPCTSTR lpszReferer,
      __in          LPCTSTR* lplpszAcceptTypes,
      __in          DWORD dwFlags,
      __in          DWORD_PTR dwContext
    );
    '''
    #-----------------------------------------------------
    def post_HttpOpenRequestA(self, event, retval):

        caller = self.__getcaller(event, 8)
        if caller == None or caller in knownmods:
            return

        tid = event.get_tid()
        params = event.hook.get_params(tid)

        server = self.__lookup_handle("Internet", params[0])
        name = self.__get_name("Internet", params[0])

        verb = event.get_process().peek_string(params[1])
        object_name = event.get_process().peek_string(params[2])
        referrer = event.get_process().peek_string(params[3])
        flags = self.__get_flags(inet_flags, params[6])

        name = "%s/%s" % (name, object_name)

        if retval != None:
            self.__add_handle("Internet", retval, name)

        self.__log(event, caller, 
            self.__lookup_handle("Internet", retval),
            "Referrer: %s; Flags: %s" % (referrer, flags),
            retval, 'suspicious')

    def post_HttpOpenRequestW(self, event, retval):

        caller = self.__getcaller(event, 8)
        if caller == None or caller in knownmods:
            return

        tid = event.get_tid()
        params = event.hook.get_params(tid)

        server = self.__lookup_handle("Internet", params[0])
        name = self.__get_name("Internet", params[0])

        verb = event.get_process().peek_string(params[1], fUnicode=True)
        object_name = event.get_process().peek_string(params[2], fUnicode=True)
        referrer = event.get_process().peek_string(params[3], fUnicode=True)
        flags = self.__get_flags(inet_flags, params[6])

        name = "%s/%s" % (name, object_name)

        if retval != None:
            self.__add_handle("Internet", retval, name)

        self.__log(event, caller, 
            self.__lookup_handle("Internet", retval),
            "Referrer: %s; Flags: %s" % (referrer, flags),
            retval, 'suspicious')

    #-----------------------------------------------------
    '''
    BOOL HttpAddRequestHeaders(
      __in          HINTERNET hConnect,
      __in          LPCTSTR lpszHeaders,
      __in          DWORD dwHeadersLength,
      __in          DWORD dwModifiers
    );
    '''
    #-----------------------------------------------------
    def post_HttpAddRequestHeadersA(self, event, retval):

        caller = self.__getcaller(event, 4)
        if caller == None or caller in knownmods:
            return

        tid = event.get_tid()
        params = event.hook.get_params(tid)

        request = self.__lookup_handle("Internet", params[0])
        headers = event.get_process().peek_string(params[1])

        self.__log(event, caller, 
            request,
            "Headers: %s" % headers,
            retval,
            'ok' if retval == True else 'fail')

    def post_HttpAddRequestHeadersW(self, event, retval):

        caller = self.__getcaller(event, 4)
        if caller == None or caller in knownmods:
            return

        tid = event.get_tid()
        params = event.hook.get_params(tid)

        request = self.__lookup_handle("Internet", params[0])
        headers = event.get_process().peek_string(params[1], fUnicode=True)

        self.__log(event, caller, 
            request,
            "Headers: %s" % headers,
            retval,
            'ok' if retval == True else 'fail')

    # Functions in user32.dll

    #-----------------------------------------------------
    '''
    UINT_PTR WINAPI SetTimer(
      __in_opt  HWND hWnd,
      __in      UINT_PTR nIDEvent,
      __in      UINT uElapse,
      __in_opt  TIMERPROC lpTimerFunc
    );
    '''
    #-----------------------------------------------------
    def post_SetTimer(self, event, retval):

        caller = self.__getcaller(event, 4)
        if caller == None or caller in knownmods:
            return

        tid = event.get_tid()
        params = event.hook.get_params(tid)

        event_id = params[1]
        lpfn = params[3]

        window = self.__lookup_handle("Window", params[0])

        self.__log(event, caller, window,
            "Event ID: 0x%x; Function: 0x%x" % (event_id, lpfn),
            retval,
            'ok' if retval != 0 else 'fail')

    #-----------------------------------------------------
    '''
    BOOL WINAPI KillTimer(
      __in_opt  HWND hWnd,
      __in      UINT_PTR uIDEvent
    );
    '''
    #-----------------------------------------------------
    def post_KillTimer(self, event, retval):

        caller = self.__getcaller(event, 2)
        if caller == None or caller in knownmods:
            return

        tid = event.get_tid()
        params = event.hook.get_params(tid)

        event_id = params[1]
        window = self.__lookup_handle("Window", params[0])

        self.__log(event, caller, window,
            "Event ID: 0x%x" % event_id,
            retval,
            'ok' if retval == True else 'fail')

    #-----------------------------------------------------
    '''
    HWINEVENTHOOK WINAPI SetWinEventHook(
      __in  UINT eventMin,
      __in  UINT eventMax,
      __in  HMODULE hmodWinEventProc,
      __in  WINEVENTPROC lpfnWinEventProc,
      __in  DWORD idProcess,
      __in  DWORD idThread,
      __in  UINT dwflags
    );
    '''
    #-----------------------------------------------------
    def post_SetWinEventHook(self, event, retval):

        caller = self.__getcaller(event, 7)
        if caller == None or caller in knownmods:
            return

        tid = event.get_tid()
        params = event.hook.get_params(tid)

        event_min = self.__get_flags(event_types, params[0])
        event_max = self.__get_flags(event_types, params[1])
        hmod_proc = params[2]
        event_proc = params[3]
        pid = params[4]
        tid = params[5]

        event.get_process().scan_modules()

        try:
            mod = event.get_process().get_module_at_address(hmod_proc)
        except:
            mod = None

        mod_name = mod.get_name() if mod is not None else ""

        combo = "%s!0x%x" % (mod_name, event_proc)

        if retval != 0:
            css = 'ok'
            self.__add_handle("Hook", retval, combo)
        else:
            css = 'fail'

        # attempts to inject code into all processes
        if pid == 0 and tid == 0:
            css = 'suspicious'

        self.__log(event, caller, 
            combo, "Event Range: %s - %s; Process: %d; Thread: %d" % \
            (event_min, event_max, pid, tid),
            retval, css)

    #-----------------------------------------------------
    '''
    BOOL WINAPI UnhookWinEvent(
      __in  HWINEVENTHOOK hWinEventHook
    );
    '''
    #-----------------------------------------------------
    def post_UnhookWinEvent(self, event, retval):

        caller = self.__getcaller(event, 1)
        if caller == None or caller in knownmods:
            return

        tid = event.get_tid()
        params = event.hook.get_params(tid)
        lpfn = self.__lookup_handle("Hook", params[0])

        self.__log(event, caller, lpfn, "", retval,
            'ok' if retval == True else 'fail')

    #-----------------------------------------------------
    '''
    HHOOK WINAPI SetWindowsHookEx(
      __in  int idHook,
      __in  HOOKPROC lpfn,
      __in  HINSTANCE hMod,
      __in  DWORD dwThreadId
    );
    '''
    #-----------------------------------------------------
    def post_SetWindowsHookExA(self, event, retval):

        caller = self.__getcaller(event, 4)
        if caller == None or caller in knownmods:
            return

        tid = event.get_tid()
        params = event.hook.get_params(tid)

        idhook = self.__get_flags(hook_ids, params[0])
        lpfn = params[1]
        hmod = params[2]
        thread_id = params[3]

        if hmod != None:
            event.get_process().scan_modules()
            try:
                mod = event.get_process().get_module_at_address(hmod)
            except:
                mod = None

            mod_name = mod.get_name() if mod is not None else ""
        else:
            mod_name = ""

        hook_func = "%s!0x%x" % (mod_name, lpfn)

        if retval != None:
            self.__add_handle("Hook", retval, hook_func)
            css = 'ok'
        else:
            css = 'fail'

        # Reset the css if this is a suspicious call
        if (hmod != None) and (thread_id == 0):
            css = 'suspicious'

        self.__log(event, caller, hook_func,
            "Module: 0x%x; Hook ID: %s; Thread: 0x%x" % (hmod, idhook, thread_id),
            retval, css)

    def post_SetWindowsHookExW(self, event, retval):

        caller = self.__getcaller(event, 4)
        if caller == None or caller in knownmods:
            return

        tid = event.get_tid()
        params = event.hook.get_params(tid)

        idhook = self.__get_flags(hook_ids, params[0])
        hmod = params[2]
        threadid = params[3]

        if hmod != None:
            event.get_process().scan_modules()
            try:
                mod = event.get_process().get_module_at_address(hmod)
            except:
                mod = None

            mod_name = mod.get_name() if mod is not None else ""
        else:
            mod_name = ""

        hook_func = "%s!0x%x" % (mod_name, params[1])

        if retval != None:
            self.__add_handle("Hook", retval, hook_func)
            css = 'ok'
        else:
            css = 'fail'

        # Determine if the hook is suspicious or not
        if (hmod != None) and (threadid == 0):
            css = 'suspicious'

        self.__log(event, caller, hook_func,
            "Module: 0x%x; Hook ID: %s; Thread: 0x%x" % (hmod, idhook, threadid),
            retval, css)

    #-----------------------------------------------------
    '''
    BOOL WINAPI UnhookWindowsHookEx(
      __in  HHOOK hhk
    );
    '''
    #-----------------------------------------------------
    def post_UnhookWindowsHookEx(self, event, retval):

        caller = self.__getcaller(event, 1)
        if caller == None or caller in knownmods:
            return

        tid = event.get_tid()
        params = event.hook.get_params(tid)
        lpfn = self.__lookup_handle("Hook", params[0])

        self.__log(event, caller, lpfn, "", retval,
            'ok' if retval != 0 else 'fail')

    #-----------------------------------------------------
    '''
    HWND WINAPI FindWindow(
      __in_opt  LPCTSTR lpClassName,
      __in_opt  LPCTSTR lpWindowName
    );
    '''
    #-----------------------------------------------------
    def post_FindWindowA(self, event, retval):

        caller = self.__getcaller(event, 2)
        if caller == None or caller in knownmods:
            return

        tid = event.get_tid()
        params = event.hook.get_params(tid)

        class_name = event.get_process().peek_string(params[0])
        wnd_name = event.get_process().peek_string(params[1])
        both_names = "%s/%s" % (class_name, wnd_name)

        if retval != NULL:
            self.__add_handle("Window", retval, both_names)
            css = 'ok'
        else:
            css = 'fail'

        if self.__matches(both_names, alert_find_window):
            css = 'suspicious'

        self.__log(event, caller, both_names, "", retval, css)

    def post_FindWindowW(self, event, retval):

        caller = self.__getcaller(event, 2)
        if caller == None or caller in knownmods:
            return

        tid = event.get_tid()
        params = event.hook.get_params(tid)

        class_name = event.get_process().peek_string(params[0], fUnicode=True)
        wnd_name = event.get_process().peek_string(params[1], fUnicode=True)
        both_names = "%s/%s" % (class_name, wnd_name)

        if retval != NULL:
            self.__add_handle("Window", retval, both_names)
            css = 'ok'
        else:
            css = 'fail'

        if self.__matches(both_names, alert_find_window):
            css = 'suspicious'

        self.__log(event, caller, both_names, "", retval, css)

    #-----------------------------------------------------
    '''
    HWND WINAPI FindWindowEx(
      __in_opt  HWND hwndParent,
      __in_opt  HWND hwndChildAfter,
      __in_opt  LPCTSTR lpszClass,
      __in_opt  LPCTSTR lpszWindow
    );
    '''
    #-----------------------------------------------------
    def post_FindWindowExA(self, event, retval):

        caller = self.__getcaller(event, 4)
        if caller == None or caller in knownmods:
            return

        tid = event.get_tid()
        params = event.hook.get_params(tid)

        class_name = event.get_process().peek_string(params[2])
        wnd_name = event.get_process().peek_string(params[3])
        both_names = "%s/%s" % (class_name, wnd_name)

        if retval != NULL:
            self.__add_handle("Window", retval, both_names)
            css = 'ok'
        else:
            css = 'fail'

        if self.__matches(both_names, alert_find_window):
            css = 'suspicious'

        self.__log(event, caller, both_names, "", retval, css)

    def post_FindWindowExW(self, event, retval):

        caller = self.__getcaller(event, 4)
        if caller == None or caller in knownmods:
            return

        tid = event.get_tid()
        params = event.hook.get_params(tid)

        class_name = event.get_process().peek_string(params[2], fUnicode=True)
        wnd_name = event.get_process().peek_string(params[3], fUnicode=True)
        both_names = "%s/%s" % (class_name, wnd_name)

        if retval != NULL:
            self.__add_handle("Window", retval, both_names)
            css = 'ok'
        else:
            css = 'fail'

        if self.__matches(both_names, alert_find_window):
            css = 'suspicious'

        self.__log(event, caller, both_names, "", retval, css)

    #-----------------------------------------------------
    '''
    int WINAPI GetWindowText(
      __in   HWND hWnd,
      __out  LPTSTR lpString,
      __in   int nMaxCount
    );
    '''
    #-----------------------------------------------------
    def post_GetWindowTextA(self, event, retval):

        caller = self.__getcaller(event, 3)
        if caller == None or caller in knownmods:
            return

        tid = event.get_tid()
        params = event.hook.get_params(tid)
        window = self.__lookup_handle("Window", params[0])

        if retval != 0:
            self.__log(event, caller, window, "", retval)
            text = event.get_process().peek_string(params[1])
            self.__log(event, caller, text, "", "", css = 'after')
        else:
            self.__log(event, caller, window, "", retval, 'fail')

    def post_GetWindowTextA(self, event, retval):

        caller = self.__getcaller(event, 3)
        if caller == None or caller in knownmods:
            return

        tid = event.get_tid()
        params = event.hook.get_params(tid)

        window = self.__lookup_handle("Window", params[0])

        if retval != 0:

            self.__log(event, caller, window, "", retval)
            text = event.get_process().peek_string(params[1], fUnicode=True)
            self.__log(event, caller, text, "", "", css = 'after')

        else:
            self.__log(event, caller, window, "", retval, 'fail')

    #-----------------------------------------------------
    '''
    BOOL WINAPI ShowWindow(
      __in  HWND hWnd,
      __in  int nCmdShow
    );
    '''
    #-----------------------------------------------------
    def post_ShowWindow(self, event, retval):

        caller = self.__getcaller(event, 2)
        if caller == None or caller in knownmods:
            return

        tid = event.get_tid()
        params = event.hook.get_params(tid)
        show = self.__get_flags(show_flags, params[1])
        window = self.__lookup_handle("Window", params[0])

        self.__log(event, caller, window, "Show: %s" % show, retval)

    #-----------------------------------------------------
    '''
    BOOL WINAPI DestroyWindow(
      __in  HWND hWnd
    );
    '''
    #-----------------------------------------------------
    def post_DestroyWindow(self, event, retval):

        caller = self.__getcaller(event, 1)
        if caller == None or caller in knownmods:
            return

        tid = event.get_tid()
        params = event.hook.get_params(tid)
        window = self.__lookup_handle("Window", params[0])

        self.__log(event, caller, window, "", retval,
            'ok' if retval == True else 'fail')

    #-----------------------------------------------------
    '''
    HWND WINAPI CreateWindowEx(
      __in      DWORD dwExStyle,
      __in_opt  LPCTSTR lpClassName,
      __in_opt  LPCTSTR lpWindowName,
      __in      DWORD dwStyle,
      __in      int x,
      __in      int y,
      __in      int nWidth,
      __in      int nHeight,
      __in_opt  HWND hWndParent,
      __in_opt  HMENU hMenu,
      __in_opt  HINSTANCE hInstance,
      __in_opt  LPVOID lpParam
    );
    '''
    #-----------------------------------------------------
    def post_CreateWindowExA(self, event, retval):

        caller = self.__getcaller(event, 12)
        if caller == None or caller in knownmods:
            return

        tid = event.get_tid()
        params = event.hook.get_params(tid)

        class_name = event.get_process().peek_string(params[1])
        wnd_name = event.get_process().peek_string(params[2])
        both_names = "%s/%s" % (class_name, wnd_name)

        if retval != NULL:
            self.__add_handle("Window", retval, both_names)
            css = 'ok'
        else:
            css = 'fail'
            
        if self.__matches(both_names, alert_create_window):
            css = 'suspicious'

        self.__log(event, caller, both_names, "", retval, css)

    def post_CreateWindowExW(self, event, retval):

        caller = self.__getcaller(event, 12)
        if caller == None or caller in knownmods:
            return

        tid = event.get_tid()
        params = event.hook.get_params(tid)

        class_name = event.get_process().peek_string(params[1], fUnicode=True)
        wnd_name = event.get_process().peek_string(params[2], fUnicode=True)
        both_names = "%s/%s" % (class_name, wnd_name)

        if retval != NULL:
            self.__add_handle("Window", retval, both_names)
            css = 'ok'
        else:
            css = 'fail'
            
        if self.__matches(both_names, alert_create_window):
            css = 'suspicious'

        self.__log(event, caller, both_names, "", retval, css)

    #-----------------------------------------------------
    '''
    HANDLE WINAPI GetClipboardData(
      __in  UINT uFormat
    );
    '''
    #-----------------------------------------------------
    def post_GetClipboardData(self, event, retval):

        caller = self.__getcaller(event, 1)
        if caller == None or caller in knownmods:
            return

        tid = event.get_tid()
        params = event.hook.get_params(tid)

        format = self.__get_flags(cb_formats, params[0])

        if retval != None:

            self.__log(event, caller, format, "", retval)

            if format == 'CF_TEXT':
                str1 = event.get_process().peek_string(retval)
            elif format == 'CF_UNICODETEXT':
                str1 = event.get_process().peek_string(retval, fUnicode=True)
            else:
                str1 = None

            if str1 != None:
                self.__log(event, caller, str1, "", 0, 'after')

        else:
            self.__log(event, caller, format, "", retval, 'fail')

    #-----------------------------------------------------
    '''
    int WINAPI GetClassName(
      __in   HWND hWnd,
      __out  LPTSTR lpClassName,
      __in   int nMaxCount
    );
    '''
    #-----------------------------------------------------
    def post_GetClassNameA(self, event, retval):

        caller = self.__getcaller(event, 3)
        if caller == None or caller in knownmods:
            return

        tid = event.get_tid()
        params = event.hook.get_params(tid)

        window = self.__lookup_handle("Window", params[0])
        class_name = params[1]

        if retval != 0:

            self.__log(event, "", "", retval)

            if class_name != None:
                str1 = event.get_process().peek_string(class_name)
                self.__log(event, caller, str1, "", 0, 'after')
        else:
            self.__log(event, caller, "", "", 0, 'fail')

    def post_GetClassNameW(self, event, retval):

        caller = self.__getcaller(event, 3)
        if caller == None or caller in knownmods:
            return

        tid = event.get_tid()
        params = event.hook.get_params(tid)

        window = self.__lookup_handle("Window", params[0])
        class_name = params[1]

        if retval != 0:

            self.__log(event, caller, "", "", retval)

            if class_name != NULL:
                str1 = event.get_process().peek_string(class_name, fUnicode=True)
                self.__log(event, caller, str1, "", 0, 'after')
        else:
            self.__log(event, caller, "", "", 0, 'fail')

    #-----------------------------------------------------
    # This function's return value is dependent on the message sent, so we don't
    # try to distinguish between success/failure of this API
    #-----------------------------------------------------
    def post_SendMessageA(self, event, retval):

        caller = self.__getcaller(event, 4)
        if caller == None or caller in knownmods:
            return

        tid = event.get_tid()
        params = event.hook.get_params(tid)

        window = self.__lookup_handle("Window", params[0])
        msg = self.__get_flags(window_msg, params[1])
        wparam = params[2]
        lparam = params[3]

        self.__log(event, caller, window,
            "Msg: %s; wParam: 0x%x; lParam: 0x%x" % (msg, wparam, lparam),
            retval)

    def post_SendMessageW(self, event, retval):

        caller = self.__getcaller(event, 4)
        if caller == None or caller in knownmods:
            return

        tid = event.get_tid()
        params = event.hook.get_params(tid)

        window = self.__lookup_handle("Window", params[0])
        msg = self.__get_flags(window_msg, params[1])
        wparam = params[2]
        lparam = params[3]

        self.__log(event, caller, window,
            "Msg: %s; wParam: 0x%x; lParam: 0x%x" % (msg, wparam, lparam),
            retval)

    # Functions in psapi.dll

    #-----------------------------------------------------
    '''
    DWORD WINAPI GetModuleFileNameEx(
      __in      HANDLE hProcess,
      __in_opt  HMODULE hModule,
      __out     LPTSTR lpFilename,
      __in      DWORD nSize
    );
    '''
    #-----------------------------------------------------
    def post_GetModuleFileNameExW(self, event, retval):

        caller = self.__getcaller(event, 4)
        if caller == None or caller in knownmods:
            return

        tid = event.get_tid()
        params = event.hook.get_params(tid)
        hProcess = params[0]

        if hProcess == 0xffffffff:
            proc_name = "<current process>"
        else:
            proc_name = self.__lookup_handle("Process", hProcess)

        hmod = params[1]
        pfile = params[2]

        if retval != 0:
            self.__log(event, caller, proc_name, "hModule: 0x%x" % hmod, retval)
            if pfile != None:
                str1 = event.get_process().peek_string(pfile, fUnicode=True)
                self.__log(event, caller, "Name: %s" % str1, "", 0, 'after')
        else:
            self.__log(event, caller, proc_name, 
                "hModule: 0x%x" % hmod, retval, 'fail')

    # Functions in kernel32.dll

    #-----------------------------------------------------
    '''
    LPVOID WINAPI VirtualAllocEx(
      __in      HANDLE hProcess,
      __in_opt  LPVOID lpAddress,
      __in      SIZE_T dwSize,
      __in      DWORD flAllocationType,
      __in      DWORD flProtect
    );
    '''
    #-----------------------------------------------------
    def post_VirtualAllocEx(self, event, retval):

        caller = self.__getcaller(event, 5)
        if caller == None or caller in knownmods:
            return

        tid = event.get_tid()
        params = event.hook.get_params(tid)

        types = self.__get_flags(alloc_types, params[3])
        protect = self.__get_flags(page_protect, params[4])

        size = params[2]
        addr = params[1]
        hProcess = params[0]

        # Ignore VirtualAlloc calls for the current process
        if hProcess == 0xffffffff:
            return

        proc_name = self.__lookup_handle("Process", hProcess)
        css = 'suspicious'

        if retval != None:

            self.__log(event, caller, proc_name, \
                "Address: 0x%x; Size: 0x%x; Type: %s; Protection: %s" %(addr, size, types, protect), \
                retval, css)
            self.__log(event, caller, "Allocation: 0x%x" % retval, "", 0, 'after')
        else:
            self.__log(event, caller, proc_name, \
                "Address: 0x%x; Size: 0x%x; Type: %s; Protection: %s" %(addr, size, types, protect), \
                retval, css)

    #-----------------------------------------------------
    # DWORD WINAPI GetCurrentProcessId(void);
    #-----------------------------------------------------
    def post_GetCurrentProcessId(self, event, retval):
        caller = self.__getcaller(event, 0)
        if caller == None or caller in knownmods:
            return
        self.__log(event, caller, "Pid: %d" % retval, "", retval)

    #-----------------------------------------------------
    '''
    HANDLE WINAPI CreateToolhelp32Snapshot(
      __in  DWORD dwFlags,
      __in  DWORD th32ProcessID
    );
    '''
    #-----------------------------------------------------
    def post_CreateToolhelp32Snapshot(self, event, retval):

        caller = self.__getcaller(event, 2)
        if caller == None or caller in knownmods:
            return

        tid = event.get_tid()
        params = event.hook.get_params(tid)

        flags = self.__get_flags(snap_flags, params[0])
        pid = params[1]

        if retval != __INVALID_HANDLE_VALUE__:
            self.__add_handle("Snapshot", retval, "")
            css = 'ok'
        else:
            css = 'fail'

        # Attempts to do process listings
        if 'TH32CS_SNAPPROCESS' in flags or 'TH32CS_SNAPALL' in flags:
            css = 'suspicious'

        self.__log(event, caller, 
            "Pid: 0x%x" % pid, "Flags: %s" % flags, retval, css)

    #-----------------------------------------------------
    '''
    BOOL WINAPI Process32First(
      __in     HANDLE hSnapshot,
      __inout  LPPROCESSENTRY32 lppe
    );
    '''
    #-----------------------------------------------------
    def post_Process32FirstW(self, event, retval):

        caller = self.__getcaller(event, 2)
        if caller == None or caller in knownmods:
            return

        tid = event.get_tid()
        params = event.hook.get_params(tid)
        lppe = params[1]

        if retval == True:
            if lppe != NULL:
                pe   = event.get_process().read_structure(lppe, kernel32.PROCESSENTRY32)
                pid  = pe.th32ProcessID
                ppid = pe.th32ParentProcessID
                exe  = event.get_process().peek_string(lppe + 36, fUnicode=True)
            else:
                pid  = 0
                ppid = 0
                exe  = ""
            self.__log(event, caller, 
                "Pid: %d; Name: %s; Parent Pid: %d" % (pid, exe, ppid), "", retval)
        else:
            self.__log(event, caller, "", "", retval, 'fail')

    def post_Process32FirstA(self, event, retval):

        caller = self.__getcaller(event, 2)
        if caller == None or caller in knownmods:
            return

        tid = event.get_tid()
        params = event.hook.get_params(tid)
        lppe = params[1]

        if retval == True:
            if lppe != NULL:
                pe   = event.get_process().read_structure(lppe, kernel32.PROCESSENTRY32)
                pid  = pe.th32ProcessID
                ppid = pe.th32ParentProcessID
                exe  = event.get_process().peek_string(lppe + 36)
            else:
                pid  = 0
                ppid = 0
                exe  = ""
            self.__log(event, caller, 
                "Pid: %d; Name: %s; Parent Pid: %d" % (pid, exe, ppid), "", retval)
        else:
            self.__log(event, caller, "", "", retval, 'fail')

    #-----------------------------------------------------
    '''
    BOOL WINAPI Process32Next(
      __in   HANDLE hSnapshot,
      __out  LPPROCESSENTRY32 lppe
    );
    '''
    #-----------------------------------------------------
    def post_Process32NextW(self, event, retval):

        caller = self.__getcaller(event, 2)
        if caller == None or caller in knownmods:
            return

        tid = event.get_tid()
        params = event.hook.get_params(tid)

        lppe = params[1]

        if retval == True:

            if lppe != NULL:
                pe   = event.get_process().read_structure(lppe, kernel32.PROCESSENTRY32)
                pid  = pe.th32ProcessID
                ppid = pe.th32ParentProcessID
                exe  = event.get_process().peek_string(lppe + 36, fUnicode=True)
            else:
                pid  = 0
                ppid = 0
                exe  = ""

            self.__log(event, caller, 
                "Pid: %d; Name: %s; Parent Pid: %d" % (pid, exe, ppid),
                "", retval)

        else:
            self.__log(event, caller, "", "", retval, 'fail')

    def post_Process32NextA(self, event, retval):

        caller = self.__getcaller(event, 2)
        if caller == None or caller in knownmods:
            return

        tid = event.get_tid()
        params = event.hook.get_params(tid)

        lppe = params[1]

        if retval == True:

            if lppe != NULL:
                pe   = event.get_process().read_structure(lppe, kernel32.PROCESSENTRY32)
                pid  = pe.th32ProcessID
                ppid = pe.th32ParentProcessID
                exe  = event.get_process().peek_string(lppe + 36)
            else:
                pid  = 0
                ppid = 0
                exe  = ""

            self.__log(event, caller, 
                "Pid: %d; Name: %s; Parent Pid: %d" % (pid, exe, ppid),
                "", retval)

        else:
            self.__log(event, caller, "", "", retval, 'fail')

    #-----------------------------------------------------
    '''
    HANDLE WINAPI FindFirstFileEx(
      __in        LPCTSTR lpFileName,
      __in        FINDEX_INFO_LEVELS fInfoLevelId,
      __out       LPVOID lpFindFileData,
      __in        FINDEX_SEARCH_OPS fSearchOp,
      __reserved  LPVOID lpSearchFilter,
      __in        DWORD dwAdditionalFlags
    );
    '''
    #-----------------------------------------------------
    def post_FindFirstFileExW(self, event, retval):

        caller = self.__getcaller(event, 6)
        if caller == None or caller in knownmods:
            return

        tid = event.get_tid()
        params = event.hook.get_params(tid)

        search_name = event.get_process().peek_string(params[0], fUnicode=True)
        search_name = self.__filter(search_name)
        struct_ptr = params[2]

        if retval != __INVALID_HANDLE_VALUE__:
            self.__add_handle("Search", retval, search_name)

            if self.__matches(search_name, alert_file_read):
                css = 'suspicious'
            else:
                css = 'ok'

            self.__log(event, "Search for: %s" % search_name, "", retval, css)

            if struct_ptr != NULL:
                found_item = event.get_process().peek_string(struct_ptr + 44, fUnicode=True)
                self.__log(event, caller, "Found: %s" % found_item, "", 0, 'after')
        else:

            if self.__matches(search_name, alert_file_read):
                css = 'suspicious'
            else:
                css = 'fail'

            self.__log(event, caller, "Search for: %s" % search_name, "", retval, css)

    def post_FindFirstFileExA(self, event, retval):

        caller = self.__getcaller(event, 6)
        if caller == None or caller in knownmods:
            return

        tid = event.get_tid()
        params = event.hook.get_params(tid)

        search_name = event.get_process().peek_string(params[0])
        search_name = self.__filter(search_name)
        struct_ptr = params[2]

        if retval != __INVALID_HANDLE_VALUE__:
            self.__add_handle("Search", retval, search_name)

            if self.__matches(search_name, alert_file_read):
                css = 'suspicious'
            else:
                css = 'ok'

            self.__log(event, "Search for: %s" % search_name, "", retval, css)

            if struct_ptr != NULL:
                found_item = event.get_process().peek_string(struct_ptr + 44, fUnicode=True)
                self.__log(event, caller, "Found: %s" % found_item, "", 0, 'after')
        else:

            if self.__matches(search_name, alert_file_read):
                css = 'suspicious'
            else:
                css = 'fail'

            self.__log(event, caller, "Search for: %s" % search_name, "", retval, css)

    #-----------------------------------------------------
    '''
    BOOL WINAPI FindNextFile(
      __in   HANDLE hFindFile,
      __out  LPWIN32_FIND_DATA lpFindFileData
    );
    '''
    #-----------------------------------------------------
    def post_FindNextFileW(self, event, retval):

        caller = self.__getcaller(event, 2)
        if caller == None or caller in knownmods:
            return

        tid = event.get_tid()
        params = event.hook.get_params(tid)

        hfind = self.__lookup_handle("Search", params[0])
        struct_ptr = params[1]

        if retval != 0:
            self.__log(event, caller, hfind, "", retval)
            if struct_ptr != NULL:
                found_item = event.get_process().peek_string(struct_ptr + 44, fUnicode=True)
                self.__log(event, caller, "Found: %s" % found_item, "", 0, 'after')
        else:
            self.__log(event, caller, hfind, "", retval, 'fail')

    def post_FindNextFileA(self, event, retval):

        caller = self.__getcaller(event, 2)
        if caller == None or caller in knownmods:
            return

        tid = event.get_tid()
        params = event.hook.get_params(tid)

        hfind = self.__lookup_handle("Search", params[0])
        struct_ptr = params[1]

        if retval != 0:
            self.__log(event, caller, hfind, "", retval)
            if struct_ptr != NULL:
                found_item = event.get_process().peek_string(struct_ptr + 44)
                self.__log(event, caller, "Found: %s" % found_item, "", 0, 'after')
        else:
            self.__log(event, caller, hfind, "", retval, 'fail')

    #-----------------------------------------------------
    '''
    BOOL WINAPI WriteFile(
      __in         HANDLE hFile,
      __in         LPCVOID lpBuffer,
      __in         DWORD nNumberOfBytesToWrite,
      __out_opt    LPDWORD lpNumberOfBytesWritten,
      __inout_opt  LPOVERLAPPED lpOverlapped
    );
    '''
    #-----------------------------------------------------
    def post_WriteFile(self, event, retval):

        caller = self.__getcaller(event, 5)
        if caller == None or caller in knownmods:
            return

        tid = event.get_tid()
        params = event.hook.get_params(tid)

        file_name = self.__lookup_handle("File", params[0])

        pbuf = params[1]
        size = params[2]
        pwrite = params[3]

        if retval == True:

            if (pbuf != None) and (pwrite != None):
                length = event.get_process().read_uint(pwrite)
                buf = event.get_process().read(pbuf, length)
            else:
                length = 0
                buf = ""

            if self.__matches(file_name, alert_file_write):
                css = 'suspicious'
            elif self.__matches(buf, alert_file_content_write):
                css = 'suspicious'
            else:
                css = 'ok'

            self.__log(event, caller, file_name,
                "Bytes to write: 0x%x; Bytes written: 0x%x" % (size, length),
                retval, css)

            if (buf != None) and (buf != ""):
                self.__loghex(buf)
        else:

            if self.__matches(file_name, alert_file_write):
                css = 'suspicious'
            else:
                css = 'ok'

            self.__log(event, caller, file_name,
                "Bytes to write: 0x%x" % size,
                retval, 'fail')

    #-----------------------------------------------------
    '''
    BOOL WINAPI ReadFile(
      __in         HANDLE hFile,
      __out        LPVOID lpBuffer,
      __in         DWORD nNumberOfBytesToRead,
      __out_opt    LPDWORD lpNumberOfBytesRead,
      __inout_opt  LPOVERLAPPED lpOverlapped
    );
    '''
    #-----------------------------------------------------
    def post_ReadFile(self, event, retval):

        caller = self.__getcaller(event, 5)
        if caller == None or caller in knownmods:
            return

        tid = event.get_tid()
        params = event.hook.get_params(tid)
        file_name = self.__lookup_handle("File", params[0])

        cbytes    = params[2]
        size_ptr  = params[3]
        data_ptr  = params[1]

        if retval == True:

            if (size_ptr != 0) and (data_ptr != 0):
                bytes_read = event.get_process().read_uint(size_ptr)
                data = event.get_process().read(data_ptr, bytes_read)
            else:
                bytes_read = 0
                data = None

            if self.__matches(file_name, alert_file_read):
                css = 'suspicious'
            else:
                css = 'ok'

            if not self.__matches(file_name, file_whitelist):
                self.__log(event, caller, file_name,
                    "Bytes to read: 0x%x; Bytes read: 0x%x" % (cbytes, bytes_read),
                    retval, css)

                if (data != None) and (data != ""):
                    self.__loghex(data)
        else:
            if self.__matches(file_name, alert_file_read):
                css = 'suspicious'
            else:
                css = 'fail'

            if not self.__matches(file_name, file_whitelist):
                self.__log(event, caller, file_name,
                    "Bytes to read: 0x%x" % cbytes,
                    retval, css)
    #-----------------------------------------------------
    '''
    BOOL WINAPI CopyFile(
      __in          LPCTSTR lpExistingFileName,
      __in          LPCTSTR lpNewFileName,
      __in          BOOL bFailIfExists
    );
    '''
    #-----------------------------------------------------
    def post_CopyFileA(self, event, retval):
        
        caller = self.__getcaller(event, 6)
        if caller == None or caller in knownmods:
            return

        tid = event.get_tid()
        params = event.hook.get_params(tid)

        old_name = event.get_process().peek_string(params[0])
        new_name = event.get_process().peek_string(params[1])

        if retval == True:
            css = 'ok'
        else:
            css = 'fail'

        if self.__matches(new_name, alert_file_write):
            css = 'suspicious'

        if (old_name != "") and (new_name != ""):
            copy_string = "%s -> %s" % (old_name, new_name)
        elif old_name != "":
            copy_string = "Existing File: %s" % old_name
        else:
            copy_string = "New File: %s" % new_name

        self.__archive(new_name)
        self.__log(event, caller, copy_string, "", retval, css)

    def post_CopyFileW(self, event, retval):
        
        caller = self.__getcaller(event, 6)
        if caller == None or caller in knownmods:
            return

        tid = event.get_tid()
        params = event.hook.get_params(tid)

        old_name = event.get_process().peek_string(params[0], fUnicode=True)
        new_name = event.get_process().peek_string(params[1], fUnicode=True)

        if retval == True:
            css = 'ok'
        else:
            css = 'fail'

        if self.__matches(new_name, alert_file_write):
            css = 'suspicious'

        if (old_name != "") and (new_name != ""):
            copy_string = "%s -> %s" % (old_name, new_name)
        elif old_name != "":
            copy_string = "Existing File: %s" % old_name
        else:
            copy_string = "New File: %s" % new_name

        self.__archive(new_name)
        self.__log(event, caller, copy_string, "", retval, css)

    #-----------------------------------------------------
    '''
    BOOL WINAPI CopyFileEx(
      __in      LPCTSTR lpExistingFileName,
      __in      LPCTSTR lpNewFileName,
      __in_opt  LPPROGRESS_ROUTINE lpProgressRoutine,
      __in_opt  LPVOID lpData,
      __in_opt  LPBOOL pbCancel,
      __in      DWORD dwCopyFlags
    );
    '''
    #-----------------------------------------------------
    def post_CopyFileExW(self, event, retval):

        caller = self.__getcaller(event, 6)
        if caller == None or caller in knownmods:
            return

        tid = event.get_tid()
        params = event.hook.get_params(tid)

        old_name = event.get_process().peek_string(params[0], fUnicode=True)
        new_name = event.get_process().peek_string(params[1], fUnicode=True)

        if retval == True:
            css = 'ok'
        else:
            css = 'fail'

        if self.__matches(new_name, alert_file_write):
            css = 'suspicious'

        if (old_name != "") and (new_name != ""):
            copy_string = "%s -> %s" % (old_name, new_name)
        elif old_name != "":
            copy_string = "Existing File: %s" % old_name
        else:
            copy_string = "New File: %s" % new_name

        self.__archive(new_name)
        self.__log(event, caller, copy_string, "", retval, css)

    def post_CopyFileExA(self, event, retval):

        caller = self.__getcaller(event, 6)
        if caller == None or caller in knownmods:
            return

        tid = event.get_tid()
        params = event.hook.get_params(tid)

        old_name = event.get_process().peek_string(params[0])
        new_name = event.get_process().peek_string(params[1])

        if retval == True:
            css = 'ok'
        else:
            css = 'fail'

        if self.__matches(new_name, alert_file_write):
            css = 'suspicious'

        if (old_name != "") and (new_name != ""):
            copy_string = "%s -> %s" % (old_name, new_name)
        elif old_name != "":
            copy_string = "Existing File: %s" % old_name
        else:
            copy_string = "New File: %s" % new_name

        self.__archive(new_name)
        self.__log(event, caller, copy_string, "", retval, css)

    #-----------------------------------------------------
    '''
    HANDLE WINAPI CreateThread(
      __in_opt   LPSECURITY_ATTRIBUTES lpThreadAttributes,
      __in       SIZE_T dwStackSize,
      __in       LPTHREAD_START_ROUTINE lpStartAddress,
      __in_opt   LPVOID lpParameter,
      __in       DWORD dwCreationFlags,
      __out_opt  LPDWORD lpThreadId
    );
    '''
    #-----------------------------------------------------
    def post_CreateThread(self, event, retval):

        caller = self.__getcaller(event, 6)
        if caller == None or caller in knownmods:
            return

        tid = event.get_tid()
        params = event.hook.get_params(tid)

        flags = self.__get_flags(create_flags, params[4])
        thread_param = params[3]
        ptid = params[5]

        event.get_process().scan_modules()
        mod = None

        try:
            mod = event.get_process().get_module_at_address(params[2])
        except:
            pass

        if mod is not None:
            modName = mod.get_name()
        else:
            modName = ""

        func_string = "%s!0x%x" % (modName, params[2])

        if retval != None:
            if ptid != None and event.get_process().is_address_readable(ptid):
                tid = event.get_process().read_uint(ptid)
                self.__add_handle("Thread", retval, "%s; Tid: %x" % (func_string, tid))
            else:
                tid = 0

            self.__log(event, caller, func_string,
                "Parameter: 0x%x; Flags: %s" % (thread_param, flags), retval)

            if event.get_process().is_address_readable(thread_param+128):
                buf = event.get_process().read(thread_param, 128)
                self.__loghex(buf)
        else:
            self.__log(event, caller, func_string,
                "Parameter: 0x%x; Flags: %s" % (thread_param, flags),
                retval, 'fail')

    #-----------------------------------------------------
    '''
    BOOL WINAPI CloseHandle(
      __in  HANDLE hObject
    );
    '''
    #-----------------------------------------------------
    def post_CloseHandle(self, event, retval):

        caller = self.__getcaller(event, 1)
        if caller == None or caller in knownmods:
            return

        tid = event.get_tid()
        params = event.hook.get_params(tid)

        object_name = self.__lookup_handle(None, params[0])

        if retval == True:
            css = 'ok'
        else:
            css = 'fail'

        # Don't log the closing of whitelisted files
        if not self.__matches(object_name, file_whitelist):
            self.__log(event, caller, object_name, "", retval, css)

    #-----------------------------------------------------
    '''
    FARPROC WINAPI GetProcAddress(
      __in  HMODULE hModule,
      __in  LPCSTR lpProcName
    );
    '''
    #-----------------------------------------------------

    def post_GetProcAddress(self, event, retval):

        caller = self.__getcaller(event, 2)
        if caller == None or caller in knownmods:
            return

        tid = event.get_tid()
        params = event.hook.get_params(tid)
        hModule = params[0]
        lpProcName = params[1]

        event.get_process().scan_modules()

        try:
            mod = event.get_process().get_module(hModule)
        except:
            mod = None

        mod_name = mod.get_name() if mod != None else ""

        if lpProcName < 0xFFFF:
            func_name = hex(lpProcName)
        else:
            func_name = event.get_process().peek_string(params[1])

        the_func = "%s!%s" % (mod_name, func_name)

        if retval != None:
            css = 'ok'
        else:
            css = 'fail'

        if self.__matches(alert_resolved_api, the_func):
            css = 'suspicious'

        self.__log(event, caller, the_func, "", retval, css)

    #-----------------------------------------------------
    '''
    DWORD WINAPI WaitForSingleObjectEx(
      __in  HANDLE hHandle,
      __in  DWORD dwMilliseconds,
      __in  BOOL bAlertable
    );
    '''
    #-----------------------------------------------------
    def post_WaitForSingleObjectEx(self, event, retval):

        caller = self.__getcaller(event, 3)
        if caller == None or caller in knownmods:
            return

        tid = event.get_tid()
        params = event.hook.get_params(tid)
        object_name = self.__lookup_handle(None, params[0])
        wait_status = self.__get_flags(wait_states, retval)

        self.__log(event, caller, object_name, "Ms: 0x%x" % params[1], retval)
        self.__log(event, caller, "Wait returned: %s" % wait_status, "", 0, 'after')

    #-----------------------------------------------------
    '''
    HMODULE WINAPI LoadLibraryEx(
      __in        LPCTSTR lpFileName,
      __reserved  HANDLE hFile,
      __in        DWORD dwFlags
    );
    '''
    #-----------------------------------------------------
    def post_LoadLibraryExW(self, event, retval):

        caller = self.__getcaller(event, 3)
        if caller == None or caller in knownmods:
            return

        tid = event.get_tid()
        params = event.hook.get_params(tid)

        flags = self.__get_flags(load_flags, params[2])
        name = event.get_process().peek_string(params[0], fUnicode=True)

        if retval != 0:
            self.__add_handle("Library", retval, name)
            css = 'ok'
        else:
            css = 'fail'

        self.__log(event, caller, name, flags, retval, css)

    def post_LoadLibraryExA(self, event, retval):

        caller = self.__getcaller(event, 3)
        if caller == None or caller in knownmods:
            return

        tid = event.get_tid()
        params = event.hook.get_params(tid)

        flags = self.__get_flags(load_flags, params[2])
        name = event.get_process().peek_string(params[0])

        if retval != 0:
            self.__add_handle("Library", retval, name)
            css = 'ok'
        else:
            css = 'fail'

        self.__log(event, caller, name, flags, retval, css)

    #-----------------------------------------------------
    '''
    UINT WINAPI GetSystemDirectory(
      __out  LPTSTR lpBuffer,
      __in   UINT uSize
    );
    '''
    #-----------------------------------------------------

    def post_GetSystemDirectoryA(self, event, retval):

        caller = self.__getcaller(event, 2)
        if caller == None or caller in knownmods:
            return

        tid = event.get_tid()
        params = event.hook.get_params(tid)

        pbuf = params[0]
        sys_dir = ""

        if (retval > 0) and (pbuf != None):
            sys_dir = event.get_process().peek_string(pbuf)
            css = 'ok'
        else:
            css = 'fail'

        self.__log(event, caller, sys_dir, "", retval, css)

    def post_GetSystemDirectoryW(self, event, retval):

        caller = self.__getcaller(event, 2)
        if caller == None or caller in knownmods:
            return

        tid = event.get_tid()
        params = event.hook.get_params(tid)
        name = ""

        if retval > 0:
            name = event.get_process().peek_string(params[0], fUnicode=True)
            css = 'ok'
        else:
            css = 'fail'

        self.__log(event, caller, name, "", retval, css)

    #-----------------------------------------------------
    '''
    BOOL WINAPI GetComputerName(
      __out    LPTSTR lpBuffer,
      __inout  LPDWORD lpnSize
    );
    '''
    #-----------------------------------------------------
    def post_GetComputerNameW(self, event, retval):

        caller = self.__getcaller(event, 2)
        if caller == None or caller in knownmods:
            return

        tid = event.get_tid()
        params = event.hook.get_params(tid)
        pbuf = params[0]
        name = ""

        if retval != 0:
            name = event.get_process().peek_string(pbuf, fUnicode=True)
            css = 'ok'
        else:
            css = 'fail'

        self.__log(event, caller, name, "", retval, css)

    def post_GetComputerNameA(self, event, retval):

        caller = self.__getcaller(event, 2)
        if caller == None or caller in knownmods:
            return

        tid = event.get_tid()
        params = event.hook.get_params(tid)
        pbuf = params[0]
        name = ""

        if retval != 0:
            name = event.get_process().peek_string(pbuf)
            css = 'ok'
        else:
            css = 'fail'

        self.__log(event, caller, name, "", retval, css)

    #-----------------------------------------------------
    '''
    BOOL WINAPI CreateDirectory(
      __in      LPCTSTR lpPathName,
      __in_opt  LPSECURITY_ATTRIBUTES lpSecurityAttributes
    );
    '''
    #-----------------------------------------------------
    def post_CreateDirectoryW(self, event, retval):

        caller = self.__getcaller(event, 2)
        if caller == None or caller in knownmods:
            return

        tid = event.get_tid()
        params = event.hook.get_params(tid)

        path_name = event.get_process().peek_string(params[0], fUnicode=True)

        if retval == True:
            css = 'ok'
        else:
            css = 'fail'

        self.__log(event, caller, path_name, "", retval, css)

    def post_CreateDirectoryA(self, event, retval):

        caller = self.__getcaller(event, 2)
        if caller == None or caller in knownmods:
            return

        tid = event.get_tid()
        params = event.hook.get_params(tid)

        path_name = event.get_process().peek_string(params[0])

        if retval == True:
            css = 'ok'
        else:
            css = 'fail'

        self.__log(event, caller, path_name, "", retval, css)

    #-----------------------------------------------------
    '''
    BOOL WINAPI CreateDirectoryEx(
      __in          LPCTSTR lpTemplateDirectory,
      __in          LPCTSTR lpNewDirectory,
      __in          LPSECURITY_ATTRIBUTES lpSecurityAttributes
    );
    '''
    #-----------------------------------------------------
    def post_CreateDirectoryExW(self, event, retval):

        caller = self.__getcaller(event, 3)
        if caller == None or caller in knownmods:
            return

        tid = event.get_tid()
        params = event.hook.get_params(tid)

        path_name = event.get_process().peek_string(params[0], fUnicode=True)

        if retval == True:
            css = 'ok'
        else:
            css = 'fail'

        self.__log(event, caller, path_name, "", retval, css)

    def post_CreateDirectoryExA(self, event, retval):

        caller = self.__getcaller(event, 3)
        if caller == None or caller in knownmods:
            return

        tid = event.get_tid()
        params = event.hook.get_params(tid)

        path_name = event.get_process().peek_string(params[0])

        if retval == True:
            css = 'ok'
        else:
            css = 'fail'

        self.__log(event, caller, path_name, "", retval, css)

    #-----------------------------------------------------
    '''
    BOOL WINAPI SetFileTime(
      __in      HANDLE hFile,
      __in_opt  const FILETIME *lpCreationTime,
      __in_opt  const FILETIME *lpLastAccessTime,
      __in_opt  const FILETIME *lpLastWriteTime
    );
    '''
    #-----------------------------------------------------
    def post_SetFileTime(self, event, retval):

        caller = self.__getcaller(event, 4)
        if caller == None or caller in knownmods:
            return

        tid = event.get_tid()
        params = event.hook.get_params(tid)

        file_name = self.__lookup_handle("File", params[0])

        create_ptr = params[1]
        access_ptr = params[2]
        write_ptr  = params[3]
        
        if retval == True:
            css = 'ok'
        else:
            css = 'fail'
        
        Now = kernel32.FILETIME()
        GetSystemTimeAsFileTime(ctypes.byref(Now))
        now_64 = ((Now.dwHighDateTime << 32) | (Now.dwLowDateTime)) & 0xffffffff

        if access_ptr != 0:
            access_time = event.get_process().read_structure(access_ptr, kernel32.FILETIME)
            access_64 = (access_time.dwHighDateTime << 32) | access_time.dwLowDateTime
            access_64 = self.__windows_to_unix_time(access_64)
            ts_access = self.__format_time(access_64)
            if access_64 < now_64:
                css = 'suspicious'
        else:
            ts_access = ""

        if write_ptr != 0:
            write_time = event.get_process().read_structure(write_ptr, kernel32.FILETIME)
            write_64 = (write_time.dwHighDateTime << 32) | write_time.dwLowDateTime
            write_64 = self.__windows_to_unix_time(write_64)
            ts_write = self.__format_time(write_64)
            if write_64 < now_64:
                css = 'suspicious'
        else:
            ts_write = ""

        if create_ptr != 0:
            create_time = event.get_process().read_structure(create_ptr, kernel32.FILETIME)
            create_64 = (create_time.dwHighDateTime << 32) | create_time.dwLowDateTime
            create_64 = self.__windows_to_unix_time(create_64)
            ts_create = self.__format_time(create_64)
            if create_64 < now_64:
                css = 'suspicious'
        else:
            ts_create = ""

        self.__log(event, caller, file_name,
            "LastAccess: %s; LastWrite: %s; Created: %s" % (ts_access, ts_write, ts_create),
            retval, css)

    #-----------------------------------------------------
    '''
    BOOL WINAPI SetFileAttributes(
      __in  LPCTSTR lpFileName,
      __in  DWORD dwFileAttributes
    );
    '''
    #-----------------------------------------------------
    def post_SetFileAttributesW(self, event, retval):

        caller = self.__getcaller(event, 2)
        if caller == None or caller in knownmods:
            return

        tid = event.get_tid()
        params = event.hook.get_params(tid)

        attribs = self.__get_flags(file_attr, params[1])
        file_name = event.get_process().peek_string(params[0], fUnicode=True)

        # Any attempts to hide a file based on attributes is suspicious
        if ('FILE_ATTRIBUTE_SYSTEM' in attribs) or \
           ('FILE_ATTRIBUTE_HIDDEN' in attribs) or \
           ('FILE_ATTRIBUTE_ARCHIVE' in attribs):
            css = 'suspicious'

        self.__log(event, caller, 
            file_name,
            "Attributes: %s" % attribs,
            retval,
            'ok' if retval == True else 'fail')

    def post_SetFileAttributesA(self, event, retval):

        caller = self.__getcaller(event, 2)
        if caller == None or caller in knownmods:
            return

        tid = event.get_tid()
        params = event.hook.get_params(tid)

        attribs = self.__get_flags(file_attr, params[1])
        file_name = event.get_process().peek_string(params[0])

        # Any attempts to hide a file based on attributes is suspicious
        if ('FILE_ATTRIBUTE_SYSTEM' in attribs) or \
           ('FILE_ATTRIBUTE_HIDDEN' in attribs) or \
           ('FILE_ATTRIBUTE_ARCHIVE' in attribs):
            css = 'suspicious'

        self.__log(event, caller, 
            file_name,
            "Attributes: %s" % attribs,
            retval,
            'ok' if retval == True else 'fail')

    #-----------------------------------------------------
    '''
    HANDLE WINAPI CreateFile(
      __in      LPCTSTR lpFileName,
      __in      DWORD dwDesiredAccess,
      __in      DWORD dwShareMode,
      __in_opt  LPSECURITY_ATTRIBUTES lpSecurityAttributes,
      __in      DWORD dwCreationDisposition,
      __in      DWORD dwFlagsAndAttributes,
      __in_opt  HANDLE hTemplateFile
    );
    '''
    #-----------------------------------------------------
    def post_CreateFileA(self, event, retval):

        caller = self.__getcaller(event, 7)
        if caller == None or caller in knownmods:
            return

        tid = event.get_tid()
        params = event.hook.get_params(tid)

        name = event.get_process().peek_string(params[0])
        rights = self.__get_flags(generic_access, params[1])
        disps  = self.__get_flags(file_disps, params[4])

        if retval != __INVALID_HANDLE_VALUE__:
            css = 'ok'
            self.__add_handle("File", retval, name)
        else:
            css = 'fail'

        # Highlight attempts to open files/paths in the alert list(s)
        if self.__matches(name, alert_file_write) and 'GENERIC_WRITE' in rights:
            css = 'suspicious'

        elif self.__matches(name, alert_file_read) and 'GENERIC_READ' in rights:
            css = 'suspicious'

        # Highlight when the monitored process opens itself
        if self.__matches(name, [self.myself]):
            css = 'suspicious'
        
        self.__log(event, caller, name,
            "Access: %s; Disposition: %s" % (rights, disps),
            retval, css)

    def post_CreateFileW(self, event, retval):

        caller = self.__getcaller(event, 7)
        if caller == None or caller in knownmods:
            return

        tid = event.get_tid()
        params = event.hook.get_params(tid)

        name = event.get_process().peek_string(params[0], fUnicode=True)
        rights = self.__get_flags(generic_access, params[1])
        disps  = self.__get_flags(file_disps, params[4])

        if retval != __INVALID_HANDLE_VALUE__:
            css = 'ok'
            self.__add_handle("File", retval, name)
        else:
            css = 'fail'

        # Highlight attempts to open files/paths in the alert list(s)
        if self.__matches(name, alert_file_write) and 'GENERIC_WRITE' in rights:
            css = 'suspicious'

        elif self.__matches(name, alert_file_read) and 'GENERIC_READ' in rights:
            css = 'suspicious'

        #if not self.__matches(name, file_whitelist):
        self.__log(event, caller, name,
            "Access: %s; Disposition: %s" % (rights, disps),
            retval, css)

    #-----------------------------------------------------
    '''
    DWORD WINAPI SetFilePointer(
      __in         HANDLE hFile,
      __in         LONG lDistanceToMove,
      __inout_opt  PLONG lpDistanceToMoveHigh,
      __in         DWORD dwMoveMethod
    );
    '''
    #-----------------------------------------------------
    def post_SetFilePointer(self, event, retval):

        caller = self.__getcaller(event, 4)
        if caller == None or caller in knownmods:
            return

        tid = event.get_tid()
        params = event.hook.get_params(tid)

        move = self.__get_flags(file_move, params[3])
        file_name = self.__lookup_handle("File", params[0])
        distance = params[1]

        if not self.__matches(file_name, file_whitelist):
            self.__log(event, caller, file_name,
                "Method: %s; Distance: 0x%x" % (move, distance),
                retval)

    #-----------------------------------------------------
    '''
    VOID WINAPI ExitProcess(
      __in  UINT uExitCode
    );
    '''
    #-----------------------------------------------------
    def pre_ExitProcess( self, event, ra, uExitCode):

        caller = self.__getcaller(event, 1)
        if caller == None or caller in knownmods:
            return

        tid = event.get_tid()
        params = event.hook.get_params(tid)
        self.__log(event, caller, "0x%x" % params[0], "", 0)

    #-----------------------------------------------------
    '''
    BOOL WINAPI TerminateProcess(
      __in  HANDLE hProcess,
      __in  UINT uExitCode
    );
    '''
    #-----------------------------------------------------
    def post_TerminateProcess(self, event, retval):

        caller = self.__getcaller(event, 2)
        if caller == None or caller in knownmods:
            return

        tid = event.get_tid()
        params = event.hook.get_params(tid)
        file_name = self.__lookup_handle("Process", params[0])
        exit_code = params[1]

        self.__log(event, caller, file_name,
            "Exit code: 0x%x" % exit_code,
            retval, 'suspicious')

    #-----------------------------------------------------
    '''
    BOOL WINAPI TerminateThread(
      __inout  HANDLE hThread,
      __in     DWORD dwExitCode
    );
    '''
    #-----------------------------------------------------
    def post_TerminateThread(self, event, retval):

        caller = self.__getcaller(event, 2)
        if caller == None or caller in knownmods:
            return

        tid = event.get_tid()
        params = event.hook.get_params(tid)
        thread_name = self.__lookup_handle("Thread", params[0])

        self.__log(event, caller, thread_name,
            "Exit code: 0x%x" % params[1], retval,
            'ok' if retval == True else 'fail')

    #-----------------------------------------------------
    '''
    BOOL WINAPI GetThreadContext(
      __in     HANDLE hThread,
      __inout  LPCONTEXT lpContext
    );
    '''
    #-----------------------------------------------------
    def post_GetThreadContext(self, event, retval):

        caller = self.__getcaller(event, 2)
        if caller == None or caller in knownmods:
            return

        tid = event.get_tid()
        params = event.hook.get_params(tid)

        thread_name = self.__lookup_handle("Thread", params[0])

        context_ptr = params[1]
        flags = ""

        if retval == True:
            if context_ptr != NULL:
                flags = self.get_context_flags(event, context_ptr)
            css = 'ok'
        else:
            css = 'fail'

        self.__log(event, caller, thread_name, "Flags: %s" % flags, retval, css)

    #-----------------------------------------------------
    '''
    BOOL WINAPI SetThreadContext(
      __in  HANDLE hThread,
      __in  const CONTEXT *lpContext
    );
    '''
    #-----------------------------------------------------
    def post_SetThreadContext(self, event, retval):

        caller = self.__getcaller(event, 2)
        if caller == None or caller in knownmods:
            return

        tid = event.get_tid()
        params = event.hook.get_params(tid)
        thread_name = self.__lookup_handle("Thread", params[0])

        context_ptr = params[1]
        flags = ""

        if retval == True:
            if context_ptr != NULL:
                flags = self.get_context_flags(event, context_ptr)

        self.__log(event, caller, thread_name, "Flags: %s" % flags, retval, 'suspicious')

    #-----------------------------------------------------
    '''
    HANDLE WINAPI OpenProcess(
      __in  DWORD dwDesiredAccess,
      __in  BOOL bInheritHandle,
      __in  DWORD dwProcessId
    );
    '''
    #-----------------------------------------------------
    def post_OpenProcess(self, event, retval):

        caller = self.__getcaller(event, 3)
        if caller == None or caller in knownmods:
            return

        tid = event.get_tid()
        params = event.hook.get_params(tid)

        pid = params[2]
        exe_name = self.__nameof(pid)
        access = self.__get_flags(process_rights, params[0])

        if retval != NULL:
            self.__add_handle("Process", retval, "%s:%d" % (exe_name, pid))

        # Mark openprocess calls for threads and writing as suspicious
        if ('PROCESS_CREATE_THREAD' in access) or \
            ('PROCESS_VM_WRITE' in access) or \
            ('PROCESS_VM_OPERATION' in access) or \
            ('PROCESS_ALL_ACCESS' in access):
            css = 'suspicious'

        self.__log(event, caller, "%s:%d" % (exe_name, pid), 
            "Access: %s" % access, 
            retval, 'suspicious')

    #-----------------------------------------------------
    '''
    UINT WINAPI GetTempFileName(
      __in          LPCTSTR lpPathName,
      __in          LPCTSTR lpPrefixString,
      __in          UINT uUnique,
      __out         LPTSTR lpTempFileName
    );
    '''
    #-----------------------------------------------------  
    def post_GetTempFileNameA(self, event, retval):
    
        caller = self.__getcaller(event, 4)
        if caller == None or caller in knownmods:
            return
            
        tid = event.get_tid()
        params = event.hook.get_params(tid)
        path = event.get_process().peek_string(params[0])
        prefix = event.get_process().peek_string(params[1])
        uniq = params[2]
            
        self.__log(event, caller, 
            "Path:%s, Prefix:%s, Uniq:%d" % (path, prefix, uniq), 
            "", retval, 
            'ok' if retval > 0 else 'fail')

        if retval > 0:
            temp_file = event.get_process().peek_string(params[3])
            self.__log(event, caller, "Filename:%s" % temp_file, "", 0, 'after')
          
    def post_GetTempFileNameW(self, event, retval):
    
        caller = self.__getcaller(event, 4)
        if caller == None or caller in knownmods:
            return
            
        tid = event.get_tid()
        params = event.hook.get_params(tid)
        path = event.get_process().peek_string(params[0], fUnicode=True)
        prefix = event.get_process().peek_string(params[1], fUnicode=True)
        uniq = params[2]
            
        self.__log(event, caller, 
            "Path:%s, Prefix:%s, Uniq:%d" % (path, prefix, uniq), 
            "", retval, 
            'ok' if retval > 0 else 'fail')

        if retval > 0:
            temp_file = event.get_process().peek_string(params[3], fUnicode=True)
            self.__log(event, caller, "Filename:%s" % temp_file, "", 0, 'after')          
          
    #-----------------------------------------------------
    '''
    HMODULE WINAPI GetModuleHandle(
        __in          LPCTSTR lpModuleName
    );
    '''
    #-----------------------------------------------------      
    def post_GetModuleHandleA(self, event, retval):
    
        caller = self.__getcaller(event, 1)
        if caller == None or caller in knownmods:
            return

        tid = event.get_tid()
        params = event.hook.get_params(tid)
        lpname = params[0]
        
        if lpname == None:
            mod_name = "<current module>"
        else:
            mod_name = event.get_process().peek_string(lpname)
        
        if retval != None:
            self.__add_handle("Library", retval, mod_name)
            css = 'ok'
        else:
            css = 'fail'

        self.__log(event, caller, mod_name, "", retval, css)
      
    def post_GetModuleHandleW(self, event, retval):
    
        caller = self.__getcaller(event, 1)
        if caller == None or caller in knownmods:
            return

        tid = event.get_tid()
        params = event.hook.get_params(tid)
        
        lpname = params[0]
        
        if lpname == None:
            mod_name = "<current module>"
        else:
            mod_name = event.get_process().peek_string(lpname, fUnicode=True)
        
        if retval != None:
            self.__add_handle("Library", retval, mod_name)
            css = 'ok'
        else:
            css = 'fail'

        self.__log(event, caller, mod_name, "", retval, css)

    #-----------------------------------------------------
    '''
    DWORD WINAPI SleepEx(
      __in  DWORD dwMilliseconds,
      __in  BOOL bAlertable
    );
    '''
    #-----------------------------------------------------
    def post_SleepEx(self, event, retval):
        caller = self.__getcaller(event, 2)
        if caller == None or caller in knownmods:
            return
        self.__log(event, caller, "0x%x" % dwMilliseconds, "")

    #-----------------------------------------------------
    '''
    BOOL WINAPI ReplaceFile(
      __in        LPCTSTR lpReplacedFileName,
      __in        LPCTSTR lpReplacementFileName,
      __in_opt    LPCTSTR lpBackupFileName,
      __in        DWORD dwReplaceFlags,
      __reserved  LPVOID lpExclude,
      __reserved  LPVOID lpReserved
    );
    '''
    #-----------------------------------------------------
    def post_ReplaceFileW(self, event, retval):

        caller = self.__getcaller(event, 6)
        if caller == None or caller in knownmods:
            return

        tid = event.get_tid()
        params = event.hook.get_params(tid)

        old_file = event.get_process().peek_string(lpReplacedFileName, fUnicode=True)
        new_file = event.get_process().peek_string(lpReplacementFileName, fUnicode=True)
        self.__log(event, caller, 
            old_file, new_file, "", retval, 'ok' if retval == True else 'fail')

    #-----------------------------------------------------
    '''
    BOOL WINAPI DeleteFile(
      __in  LPCTSTR lpFileName
    );
    '''
    #-----------------------------------------------------
    def pre_DeleteFileW(self, event, ra, lpFileName):

        name = event.get_process().peek_string(lpFileName, fUnicode=True)

        # Archive the file to be deleted
        self.__archive(name)

    def post_DeleteFileW(self, event, retval):

        caller = self.__getcaller(event, 1)
        if caller == None or caller in knownmods:
            return

        tid = event.get_tid()
        params = event.hook.get_params(tid)

        name = event.get_process().peek_string(params[0], fUnicode=True)

        # Offending sample 613EAC0488C7517158435D3D934F6544 sends bad characters
        # that make cgi.escape() choke during the __log function
        name = self.__filter(name)

        self.__log(event, caller, name, "", retval, 'suspicious')

    def post_DeleteFileA(self, event, retval):

        caller = self.__getcaller(event, 1)
        if caller == None or caller in knownmods:
            return

        tid = event.get_tid()
        params = event.hook.get_params(tid)

        name = event.get_process().peek_string(params[0])

        # Offending sample 613EAC0488C7517158435D3D934F6544 sends bad characters
        # that make cgi.escape() choke during the __log function
        name = self.__filter(name)

        self.__log(event, caller, name, "", retval, 'suspicious')

    #-----------------------------------------------------
    '''
    BOOL WINAPI MoveFileWithProgress(
      __in      LPCTSTR lpExistingFileName,
      __in_opt  LPCTSTR lpNewFileName,
      __in_opt  LPPROGRESS_ROUTINE lpProgressRoutine,
      __in_opt  LPVOID lpData,
      __in      DWORD dwFlags
    );
    '''
    #-----------------------------------------------------
    def pre_MoveFileWithProgressW(self, event, ra, lpExistingFileName, lpNewFileName,
                                                lpProgressRoutine, lpData, dwFlags):

        name = event.get_process().peek_string(lpExistingFileName, fUnicode=True)

        # Archive the file to be deleted
        self.__archive(name)

    def post_MoveFileWithProgressW(self, event, retval):

        caller = self.__getcaller(event, 5)
        if caller == None or caller in knownmods:
            return

        tid = event.get_tid()
        params = event.hook.get_params(tid)

        old_file = event.get_process().peek_string(params[0], fUnicode = True)
        new_file = event.get_process().peek_string(params[1], fUnicode = True)
        flags = self.__get_flags(move_flags, params[4])

        if retval == True:
            css = 'ok'
        else:
            css = 'fail'

        # Catch those tricky attempts to delete a file at next reboot
        if 'MOVEFILE_DELAY_UNTIL_REBOOT' in flags:
            css = 'suspicious'
        elif self.__matches(new_file, alert_file_write):
            css = 'suspicious'

        if (old_file != "") and (new_file != ""):
            the_string = "%s -> %s" % (old_file, new_file)
        elif (old_file != ""):
            the_string = "Existing File: %s" % old_file
        elif (new_file != ""):
            the_string = "New File: %s" % new_file
        else:
            the_string = "<NULL>"

        self.__log(event, caller, the_string, "Flags: %s" % flags, retval, css)

    #-----------------------------------------------------
    '''
    HANDLE WINAPI CreateFileMapping(
      __in      HANDLE hFile,
      __in_opt  LPSECURITY_ATTRIBUTES lpAttributes,
      __in      DWORD flProtect,
      __in      DWORD dwMaximumSizeHigh,
      __in      DWORD dwMaximumSizeLow,
      __in_opt  LPCTSTR lpName
    );
    '''
    #-----------------------------------------------------
    def post_CreateFileMappingW(self, event, retval):

        caller = self.__getcaller(event, 6)
        if caller == None or caller in knownmods:
            return

        tid = event.get_tid()
        params = event.hook.get_params(tid)

        map_name = event.get_process().peek_string(params[5], fUnicode=True)
        map_name = self.__filter(map_name)

        protect = self.__get_flags(page_protect, params[2])
        hFile = params[0]

        if hFile == __INVALID_HANDLE_VALUE__:
            file_name = "N/A (uses paging file)"
        else:
            file_name = self.__lookup_handle("File", hFile)

        if retval != 0:
            self.__add_handle("Mapping", retval, file_name)
            css = 'ok'
        else:
            css = 'fail'

        if not self.__matches(file_name, file_whitelist):
            self.__log(event, caller, file_name,
                "MapName: %s, Protection: %s" % (map_name, protect),
                retval, css)

    #-----------------------------------------------------
    '''
    HANDLE WINAPI OpenFileMapping(
      __in  DWORD dwDesiredAccess,
      __in  BOOL bInheritHandle,
      __in  LPCTSTR lpName
    );
    '''
    #-----------------------------------------------------
    def post_OpenFileMappingW(self, event, retval):

        caller = self.__getcaller(event, 3)
        if caller == None or caller in knownmods:
            return

        tid = event.get_tid()
        params = event.hook.get_params(tid)

        map_name = event.get_process().peek_string(params[2], fUnicode=True)
        map_name = self.__filter(map_name)

        access   = self.__get_flags(map_access, params[0])

        if retval != None:
            self.__add_handle("Mapping", retval, map_name)
            css = 'ok'
        else:
            css = 'fail'

        if not self.__matches(map_name, file_whitelist):
            self.__log(event, caller, map_name, "Access: %s" % access, retval, css)

    #-----------------------------------------------------
    '''
    LPVOID WINAPI MapViewOfFileEx(
      __in      HANDLE hFileMappingObject,
      __in      DWORD dwDesiredAccess,
      __in      DWORD dwFileOffsetHigh,
      __in      DWORD dwFileOffsetLow,
      __in      SIZE_T dwNumberOfBytesToMap,
      __in_opt  LPVOID lpBaseAddress
    );
    '''
    #-----------------------------------------------------
    def post_MapViewOfFileEx(self, event, retval):

        caller = self.__getcaller(event, 6)
        if caller == None or caller in knownmods:
            return

        tid = event.get_tid()
        params = event.hook.get_params(tid)
        access = self.__get_flags(map_access, params[1])

        name = self.__lookup_handle("Mapping", params[0])

        if retval != None:
            css = 'ok'
        else:
            css = 'fail'

        if not self.__matches(name, file_whitelist):
            self.__log(event, caller, name, "Access: %s" % access, retval, css)

    #-----------------------------------------------------
    '''
    BOOL WINAPI FlushViewOfFile(
      __in  LPCVOID lpBaseAddress,
      __in  SIZE_T dwNumberOfBytesToFlush
    );
    '''
    #-----------------------------------------------------
    def post_FlushViewOfFile(self, event, retval):

        caller = self.__getcaller(event, 2)
        if caller == None or caller in knownmods:
            return

        tid = event.get_tid()
        params = event.hook.get_params(tid)

        self.__log(event, caller, "Address: 0x%x" % params[0], "", retval,
            'ok' if retval == True else 'fail')

    #-----------------------------------------------------
    '''
    BOOL WINAPI UnmapViewOfFile(
      __in  LPCVOID lpBaseAddress
    );
    '''
    #-----------------------------------------------------
    def post_UnmapViewOfFile(self, event, retval):

        caller = self.__getcaller(event, 1)
        if caller == None or caller in knownmods:
            return

        tid = event.get_tid()
        params = event.hook.get_params(tid)

        self.__log(event, caller, "Address: 0x%x" % params[0], "",
            retval, 'ok' if retval == True else 'fail')

    #-----------------------------------------------------
    '''
    BOOL WINAPI CreatePipe(
      __out     PHANDLE hReadPipe,
      __out     PHANDLE hWritePipe,
      __in_opt  LPSECURITY_ATTRIBUTES lpPipeAttributes,
      __in      DWORD nSize
    );
    '''
    #-----------------------------------------------------

    def post_CreatePipe(self, event, retval):

        caller = self.__getcaller(event, 4)
        if caller == None or caller in knownmods:
            return

        tid = event.get_tid()
        params = event.hook.get_params(tid)

        pread  = params[0]
        pwrite = params[1]

        if retval == True:

            self.__log(event, caller, "", "", retval)

            if pread != None:
                read_handle = event.get_process().read_uint(pread)
                self.__add_handle("Pipe", read_handle, "<Anonymous>")
            else:
                read_handle = 0

            if pwrite != None:
                write_handle = event.get_process().read_uint(pwrite)
                self.__add_handle("Pipe", write_handle, "<Anonymous>")
            else:
                write_handle = 0

            self.__log(event, caller, 
                "Read handle: 0x%x; Write handle: 0x%x" % (read_handle, write_handle),
                "", 0, 'after')
        else:
            self.__log(event, caller, "", "", retval, 'fail')

    #-----------------------------------------------------
    '''
    HANDLE WINAPI CreateNamedPipe(
      __in      LPCTSTR lpName,
      __in      DWORD dwOpenMode,
      __in      DWORD dwPipeMode,
      __in      DWORD nMaxInstances,
      __in      DWORD nOutBufferSize,
      __in      DWORD nInBufferSize,
      __in      DWORD nDefaultTimeOut,
      __in_opt  LPSECURITY_ATTRIBUTES lpSecurityAttributes
    );
    '''
    #-----------------------------------------------------
    def post_CreateNamedPipeW(self, event, retval):

        caller = self.__getcaller(event, 8)
        if caller == None or caller in knownmods:
            return

        tid = event.get_tid()
        params = event.hook.get_params(tid)

        pipe_name = event.get_process().peek_string(params[0], fUnicode=True)
        pipe_name = self.__filter(pipe_name)

        pipe_mode = params[2]
        open_mode = params[1]

        if retval != __INVALID_HANDLE_VALUE__:
            self.__add_handle("Pipe", retval, pipe_name)
            css = 'ok'
        else:
            css = 'fail'

        self.__log(event, caller, pipe_name,
            "Pipe mode: 0x%x; Open mode: 0x%x" % (pipe_mode, open_mode),
            retval, css)

    #-----------------------------------------------------
    '''
    BOOL WINAPI ConnectNamedPipe(
      __in         HANDLE hNamedPipe,
      __inout_opt  LPOVERLAPPED lpOverlapped
    );
    '''
    #-----------------------------------------------------
    def post_ConnectNamedPipe(self, event, retval):

        caller = self.__getcaller(event, 2)
        if caller == None or caller in knownmods:
            return

        tid = event.get_tid()
        params = event.hook.get_params(tid)
        pipe_name = self.__lookup_handle("Pipe", params[0])

        self.__log(event, caller, pipe_name, "",
            retval, 'ok' if retval == True else 'fail')

    #-----------------------------------------------------
    '''
    DWORD WINAPI ResumeThread(
      __in  HANDLE hThread
    );
    '''
    #-----------------------------------------------------
    def post_ResumeThread(self, event, retval):

        caller = self.__getcaller(event, 1)
        if caller == None or caller in knownmods:
            return

        tid = event.get_tid()
        params = event.hook.get_params(tid)

        thread_name = self.__lookup_handle("Thread", params[0])

        self.__log(event, caller, thread_name, "", retval,
            'ok' if retval != -1 else 'fail')

    #-----------------------------------------------------
    '''
    DWORD WINAPI SuspendThread(
      __in  HANDLE hThread
    );
    '''
    #-----------------------------------------------------

    def post_SuspendThread(self, event, retval):

        caller = self.__getcaller(event, 1)
        if caller == None or caller in knownmods:
            return

        tid = event.get_tid()
        params = event.hook.get_params(tid)
        thread_name = self.__lookup_handle("Thread", params[0])

        self.__log(event, caller, thread_name, "", retval,
            'ok' if retval != -1 else 'fail')

    #-----------------------------------------------------
    '''
    HANDLE WINAPI OpenThread(
      __in  DWORD dwDesiredAccess,
      __in  BOOL bInheritHandle,
      __in  DWORD dwThreadId
    );
    '''
    #-----------------------------------------------------
    def post_OpenThread(self, event, retval):

        caller = self.__getcaller(event, 3)
        if caller == None or caller in knownmods:
            return

        tid = event.get_tid()
        params = event.hook.get_params(tid)

        the_list = thread_access.copy()
        the_list.update(std_access)

        access = self.__get_flags(the_list, params[0])
        thread_id = params[2]

        if retval != NULL:
            self.__add_handle("Thread", retval, "Tid: %d" % thread_id)
            css = 'ok'
        else:
            css = 'fail'

        self.__log(event, caller, "ThreadId: %d" % thread_id,
            "Access: %s" % access, retval, css)

    #-----------------------------------------------------
    '''
    BOOL WINAPI GetExitCodeThread(
      __in   HANDLE hThread,
      __out  LPDWORD lpExitCode
    );
    '''
    #-----------------------------------------------------
    def post_GetExitCodeThread(self, event, retval):

        caller = self.__getcaller(event, 2)
        if caller == None or caller in knownmods:
            return

        tid = event.get_tid()
        params = event.hook.get_params(tid)
        exit_ptr = params[1]
        thread_name = self.__lookup_handle("Thread", params[0])

        if retval == True:
            self.__log(event, caller, thread_name, "", retval)
            if exit_ptr != None:
                exit_code = event.get_process().read_uint(exit_ptr)
                if exit_code == __STILL_ACTIVE__:
                    self.__log(event, caller, "Exit Code: STILL_ACTIVE", "", 0, 'after')
                else:
                    self.__log(event, caller, "Exit Code: 0x%x" % exit_code, "", 0, 'after')
        else:
            self.__log(event, thread_name, "", retval, 'fail')

    #-----------------------------------------------------
    '''
    BOOL WINAPI WritePrivateProfileString(
      __in  LPCTSTR lpAppName,
      __in  LPCTSTR lpKeyName,
      __in  LPCTSTR lpString,
      __in  LPCTSTR lpFileName
    );
    '''
    #-----------------------------------------------------
    def post_WritePrivateProfileStringW(self, event, retval):

        caller = self.__getcaller(event, 4)
        if caller == None or caller in knownmods:
            return

        tid = event.get_tid()
        params = event.hook.get_params(tid)

        str1 = event.get_process().peek_string(params[0], fUnicode = True)
        str2 = event.get_process().peek_string(params[1], fUnicode = True)
        str3 = event.get_process().peek_string(params[2], fUnicode = True)
        str4 = event.get_process().peek_string(params[3], fUnicode = True)

        self.__log(event, caller, str4,
            "Application: %s; Key: %s; String: %s" % (str1, str2, str3),
            retval,
            'ok' if retval == True else 'fail')

    def post_WritePrivateProfileStringA(self, event, retval):

        caller = self.__getcaller(event, 4)
        if caller == None or caller in knownmods:
            return

        tid = event.get_tid()
        params = event.hook.get_params(tid)

        str1 = event.get_process().peek_string(params[0])
        str2 = event.get_process().peek_string(params[1])
        str3 = event.get_process().peek_string(params[2])
        str4 = event.get_process().peek_string(params[3])

        self.__log(event, caller, str4,
            "Application: %s; Key: %s; String: %s" % (str1, str2, str3),
            retval,
            'ok' if retval == True else 'fail')

    #-----------------------------------------------------
    '''
    BOOL WINAPI CreateProcess(
      __in_opt     LPCTSTR lpApplicationName,
      __inout_opt  LPTSTR lpCommandLine,
      __in_opt     LPSECURITY_ATTRIBUTES lpProcessAttributes,
      __in_opt     LPSECURITY_ATTRIBUTES lpThreadAttributes,
      __in         BOOL bInheritHandles,
      __in         DWORD dwCreationFlags,
      __in_opt     LPVOID lpEnvironment,
      __in_opt     LPCTSTR lpCurrentDirectory,
      __in         LPSTARTUPINFO lpStartupInfo,
      __out        LPPROCESS_INFORMATION lpProcessInformation
    );
    '''
    #-----------------------------------------------------
    def pre_CreateProcessA(self, event, ra, lpApplicationName, lpCommandLine,
                                    lpProcessAttributes, lpThreadAttributes,
                                    bInheritHandles, dwCreationFlags,
                                    lpEnvironment, lpCurrentDirectory,
                                    lpStartupInfo, lpProcessInformation):

        pass

    def post_CreateProcessA(self, event, retval):

        caller = self.__getcaller(event, 10)
        if caller == None or caller in knownmods:
            return

        tid = event.get_tid()
        params = event.hook.get_params(tid)

        flags = self.__get_flags(create_flags, params[5])

        app = event.get_process().peek_string(params[0])
        cmd = event.get_process().peek_string(params[1])

        # If neither are empty, use both...otherwise just use the one that's non empty
        if (app != "" and app != None) and (cmd != "" and cmd != None):
            the_string = "%s; %s" % (app, cmd)
        elif (app != "" and app != None):
            the_string = app
        elif (cmd != "" and cmd != None):
            the_string = cmd
        else:
            the_string = ""

        struct_ptr = params[9]

        css = 'suspicious'

        if retval == True:
            self.__log(event, caller, the_string, flags, retval, css)

            if struct_ptr != None:
                pi = event.get_process().read_structure(struct_ptr, kernel32.PROCESS_INFORMATION)

                self.__add_handle("Process", pi.dwProcessId, the_string)
                self.__add_handle("Thread", pi.dwThreadId, the_string)

                self.__log(event, caller, 
                    "hProcess: 0x%x; dwProcessId: 0x%x; hThread: 0x%x; dwThreadId: 0x%x" % \
                    (pi.hProcess, pi.dwProcessId, pi.hThread, pi.dwThreadId), "", 0, 'after')
        else:
            self.__log(event, caller, the_string, flags, retval, css)

    def pre_CreateProcessW(self, event, ra, lpApplicationName, lpCommandLine,
                                    lpProcessAttributes, lpThreadAttributes,
                                    bInheritHandles, dwCreationFlags,
                                    lpEnvironment, lpCurrentDirectory,
                                    lpStartupInfo, lpProcessInformation):

        pass

    def post_CreateProcessW(self, event, retval):

        caller = self.__getcaller(event, 10)
        if caller == None or caller in knownmods:
            return

        tid = event.get_tid()
        params = event.hook.get_params(tid)

        flags = self.__get_flags(create_flags, params[5])

        app = event.get_process().peek_string(params[0], fUnicode=True)
        cmd = event.get_process().peek_string(params[1], fUnicode=True)

        # If neither are empty, use both...otherwise just use the one that's non empty
        if (app != "" and app != None) and (cmd != "" and cmd != None):
            the_string = "%s; %s" % (app, cmd)
        elif (app != "" and app != None):
            the_string = app
        elif (cmd != "" and cmd != None):
            the_string = cmd
        else:
            the_string = ""

        struct_ptr = params[9]

        css = 'suspicious'

        if retval == True:
            self.__log(event, the_string, flags, retval, css)

            if struct_ptr != NULL:
                pi = event.get_process().read_structure(struct_ptr, kernel32.PROCESS_INFORMATION)

                self.__add_handle("Process", pi.dwProcessId, the_string)
                self.__add_handle("Thread", pi.dwThreadId, the_string)

                self.__log(event, caller, 
                    "hProcess: 0x%x; dwProcessId: 0x%x; hThread: 0x%x; dwThreadId: 0x%x" % \
                    (pi.hProcess, pi.dwProcessId, pi.hThread, pi.dwThreadId), "", 0, 'after')
        else:
            self.__log(event, caller, the_string, flags, retval, css)

    #-----------------------------------------------------
    '''
    HANDLE WINAPI OpenEvent(
      __in  DWORD dwDesiredAccess,
      __in  BOOL bInheritHandle,
      __in  LPCTSTR lpName
    );
    '''
    #-----------------------------------------------------
    def post_OpenEventW(self, event, retval):

        caller = self.__getcaller(event, 3)
        if caller == None or caller in knownmods:
            return

        tid = event.get_tid()
        params = event.hook.get_params(tid)

        the_list = event_access.copy()
        the_list.update(std_access)

        event_name = event.get_process().peek_string(params[2], fUnicode=True)
        event_name = self.__filter(event_name)
        access = self.__get_flags(the_list, params[0])

        # Ignore the creation of un-named events
        if len(event_name) == 0:
            return

        if retval != NULL:
            css = 'ok'
            self.__add_handle("Event", retval, event_name)
        else:
            css = 'fail'

        # Offending sample SHA1: cc4384b10a251d50a5c516968e90d49a4a6a41a2
        # It sends invalid Unicode characters which cause an error when converting to ascii

        if event_name != "":
            try:
                self.__log(event, caller, event_name, "Access: %s" % access, retval, css)
            except:
                pass

    def post_OpenEventA(self, event, retval):

        caller = self.__getcaller(event, 3)
        if caller == None or caller in knownmods:
            return

        tid = event.get_tid()
        params = event.hook.get_params(tid)

        the_list = event_access.copy()
        the_list.update(std_access)

        event_name = event.get_process().peek_string(params[2])
        event_name = self.__filter(event_name)
        access = self.__get_flags(the_list, params[0])

        # Ignore the creation of un-named events
        if len(event_name) == 0:
            return

        if retval != NULL:
            css = 'ok'
            self.__add_handle("Event", retval, event_name)
        else:
            css = 'fail'

        # Offending sample SHA1: cc4384b10a251d50a5c516968e90d49a4a6a41a2
        # It sends invalid Unicode characters which cause an error when converting to ascii

        if event_name != "":
            try:
                self.__log(event, caller, event_name, "Access: %s" % access, retval, css)
            except:
                pass

    #-----------------------------------------------------
    '''
    HANDLE WINAPI CreateEvent(
      __in_opt  LPSECURITY_ATTRIBUTES lpEventAttributes,
      __in      BOOL bManualReset,
      __in      BOOL bInitialState,
      __in_opt  LPCTSTR lpName
    );
    '''
    #-----------------------------------------------------
    def post_CreateEventW(self, event, retval):

        caller = self.__getcaller(event, 4)
        if caller == None or caller in knownmods:
            return
            
        tid = event.get_tid()
        params = event.hook.get_params(tid)

        event_name = event.get_process().peek_string(params[3], fUnicode=True)
        event_name = self.__filter(event_name)
        state = params[2]

        if retval != 0:
            css = 'ok'
            self.__add_handle("Event", retval, event_name)
        else:
            css = 'fail'

        # Preference - ignore un-named events
        if event_name != "":
            try:
                self.__log(event, caller, event_name,
                    "Initial state: 0x%x" % state, retval, css)
            except:
                pass

    def post_CreateEventA(self, event, retval):

        caller = self.__getcaller(event, 4)
        if caller == None or caller in knownmods:
            return
            
        tid = event.get_tid()
        params = event.hook.get_params(tid)

        event_name = event.get_process().peek_string(params[3])
        event_name = self.__filter(event_name)
        state = params[2]

        if retval != 0:
            css = 'ok'
            self.__add_handle("Event", retval, event_name)
        else:
            css = 'fail'

        # Preference - ignore un-named events
        if event_name != "":
            try:
                self.__log(event, caller, event_name,
                    "Initial state: 0x%x" % state, retval, css)
            except:
                pass

    #-----------------------------------------------------
    '''
    HANDLE WINAPI OpenMutex(
      __in  DWORD dwDesiredAccess,
      __in  BOOL bInheritHandle,
      __in  LPCTSTR lpName
    );
    '''
    #-----------------------------------------------------
    def post_OpenMutexW(self, event, retval):

        caller = self.__getcaller(event, 3)
        if caller == None or caller in knownmods:
            return

        tid = event.get_tid()
        params = event.hook.get_params(tid)

        the_list = mutex_access.copy()
        the_list.update(std_access)

        access = self.__get_flags(the_list, params[0])
        name = event.get_process().peek_string(params[2], fUnicode=True)
        name = self.__filter(name)

        if retval != NULL:
            self.__add_handle("Mutex", retval, name)
            css = 'ok'
        else:
            css = 'fail'

        # Ignore un-named mutexes
        if name != "":
            if self.__matches(name, alert_mutex_access):
                css = 'suspicious'
            self.__log(event, caller, name, "Access: %s" % access, retval, css)

    def post_OpenMutexA(self, event, retval):

        caller = self.__getcaller(event, 3)
        if caller == None or caller in knownmods:
            return

        tid = event.get_tid()
        params = event.hook.get_params(tid)

        the_list = mutex_access.copy()
        the_list.update(std_access)

        access = self.__get_flags(the_list, params[0])
        name = event.get_process().peek_string(params[2])
        name = self.__filter(name)

        if retval != NULL:
            self.__add_handle("Mutex", retval, name)
            css = 'ok'
        else:
            css = 'fail'

        # Ignore un-named mutexes
        if name != "":
            if self.__matches(name, alert_mutex_access):
                css = 'suspicious'
            self.__log(event, caller, name, "Access: %s" % access, retval, css)

    #-----------------------------------------------------
    '''
    HANDLE WINAPI CreateMutex(
      __in_opt  LPSECURITY_ATTRIBUTES lpMutexAttributes,
      __in      BOOL bInitialOwner,
      __in_opt  LPCTSTR lpName
    );
    '''
    #-----------------------------------------------------
    def post_CreateMutexW(self, event, retval):

        caller = self.__getcaller(event, 3)
        if caller == None or caller in knownmods:
            return

        tid = event.get_tid()
        params = event.hook.get_params(tid)

        name = event.get_process().peek_string(params[2], fUnicode=True)
        name = self.__filter(name)

        if retval != 0:
            self.__add_handle("Mutex", retval, name)
            css = 'ok'
        else:
            css = 'fail'

        if self.__matches(name, alert_mutex_access):
            css = 'suspicious'

        # Preference - ignore un-named mutexes
        if name != "":
            self.__log(event, caller, name, "", retval, css)

    def post_CreateMutexA(self, event, retval):

        caller = self.__getcaller(event, 3)
        if caller == None or caller in knownmods:
            return

        tid = event.get_tid()
        params = event.hook.get_params(tid)

        name = event.get_process().peek_string(params[2])
        name = self.__filter(name)

        if retval != 0:
            self.__add_handle("Mutex", retval, name)
            css = 'ok'
        else:
            css = 'fail'

        if self.__matches(name, alert_mutex_access):
            css = 'suspicious'

        # Preference - ignore un-named mutexes
        if name != "":
            self.__log(event, caller, name, "", retval, css)

    #-----------------------------------------------------
    '''
    UINT WINAPI WinExec(
      __in  LPCSTR lpCmdLine,
      __in  UINT uCmdShow
    );
    '''
    #-----------------------------------------------------
    def post_WinExec(self, event, retval):

        caller = self.__getcaller(event, 2)
        if caller == None or caller in knownmods:
            return

        tid = event.get_tid()
        params = event.hook.get_params(tid)

        cmdline = event.get_process().peek_string(params[0])
        flags = params[1]

        self.__log(event, caller, cmdline, "Flags: %s" % flags, retval, 'suspicious')

    #-----------------------------------------------------
    '''
    BOOL WINAPI WriteProcessMemory(
      __in   HANDLE hProcess,
      __in   LPVOID lpBaseAddress,
      __in   LPCVOID lpBuffer,
      __in   SIZE_T nSize,
      __out  SIZE_T *lpNumberOfBytesWritten
    );
    '''
    #-----------------------------------------------------
    def post_WriteProcessMemory(self, event, retval):

        caller = self.__getcaller(event, 5)
        if caller == None or caller in knownmods:
            return

        tid = event.get_tid()
        params = event.hook.get_params(tid)

        proc_name = self.__lookup_handle("Process", params[0])

        size = params[3]
        pbuf = params[2]
        addr = params[1]

        css = 'suspicious'

        if retval == True:
            self.__log(event, caller, 
                proc_name, "Address: 0x%x; Size: 0x%x" % (addr, size), retval, css)
            if pbuf != NULL:
                buf = event.get_process().read(pbuf, size)
                self.__loghex(buf)
        else:
            self.__log(event, caller, 
                proc_name, "Address: 0x%x; Size: 0x%x" % (addr, size), retval, css)

    #-----------------------------------------------------
    '''
    BOOL WINAPI ReadProcessMemory(
      __in   HANDLE hProcess,
      __in   LPCVOID lpBaseAddress,
      __out  LPVOID lpBuffer,
      __in   SIZE_T nSize,
      __out  SIZE_T *lpNumberOfBytesRead
    );
    '''
    #-----------------------------------------------------
    def post_ReadProcessMemory(self, event, retval):

        caller = self.__getcaller(event, 5)
        if caller == None or caller in knownmods:
            return

        tid = event.get_tid()
        params = event.hook.get_params(tid)

        base  = params[1]
        pbuf  = params[2]
        size  = params[3]

        proc_name = self.__lookup_handle("Process", params[0])

        if retval == True:
            self.__log(event, caller, 
                proc_name, "Address: 0x%x; Size: 0x%x" % (base, size), retval)

            # Try to use lpNumberOfBytesRead first, and then try nSize
            size_ptr =params[4]

            if size_ptr:
                size = event.get_process().read_uint(size_ptr)

            if (pbuf != None) and (size != 0):
                data = event.get_process().read(pbuf, size)
                self.__loghex(data)
        else:
            self.__log(event, caller, 
                proc_name, "Address: 0x%x; Size: 0x%x" % (base, size), retval, 'fail')

    #-----------------------------------------------------
    '''
    HANDLE WINAPI CreateRemoteThread(
      __in   HANDLE hProcess,
      __in   LPSECURITY_ATTRIBUTES lpThreadAttributes,
      __in   SIZE_T dwStackSize,
      __in   LPTHREAD_START_ROUTINE lpStartAddress,
      __in   LPVOID lpParameter,
      __in   DWORD dwCreationFlags,
      __out  LPDWORD lpThreadId
    );
    '''
    #-----------------------------------------------------
    def post_CreateRemoteThread(self, event, retval):

        caller = self.__getcaller(event, 7)
        if caller == None or caller in knownmods:
            return

        tid = event.get_tid()
        params = event.hook.get_params(tid)
        hproc = params[0]

        # Ignore follow-through calls from CreateThread
        if hproc == 0xffffffff:
            return

        start_addr = params[3]
        thread_param = params[4]
        flags = self.__get_flags(create_flags, params[5])
        ptid = params[6]

        proc_name = self.__lookup_handle("Process", hproc)

        self.__log(event, caller, proc_name,
            "Start: 0x%x; Parameter: 0x%x; Flags: %s" % (start_addr, thread_param, flags),
            retval,
            'suspicious')

        if retval != None:
            if ptid != None:
                tid = event.get_process().read_uint(ptid)
                self.__log(event, caller, "Tid: 0x%x" % tid, "", 0, 'after')
                self.__add_handle("Thread", retval, "Tid: %d" % tid)

    # Functions in advapi32.dll

    #-----------------------------------------------------
    '''
    LONG WINAPI RegCreateKey(
      __in          HKEY hKey,
      __in          LPCTSTR lpSubKey,
      __out         PHKEY phkResult
    );
    '''
    #-----------------------------------------------------
    def post_RegCreateKeyA(self, event, retval):

        caller = self.__getcaller(event, 3)
        if caller == None or caller in knownmods:
            return

        tid = event.get_tid()
        params = event.hook.get_params(tid)
        hKey = params[0]

        key_name = reg_hkey[hKey] if reg_hkey.has_key(hKey) else hex(hKey)
        sub_key = event.get_process().peek_string(params[1])
        phk = params[2]

        key_name = "%s\\%s" % (key_name, sub_key)

        if retval == __ERROR_SUCCESS__:
            if phk != None:
                hkey = event.get_process().read_uint(phk)
                reg_hkey[hkey] = key_name
            css = 'ok'
        else:
            css = 'fail'

        if not self.__matches(key_name, reg_whitelist):
            self.__log(event, caller, key_name, "", retval, css)

    def post_RegCreateKeyW(self, event, retval):

        caller = self.__getcaller(event, 3)
        if caller == None or caller in knownmods:
            return

        tid = event.get_tid()
        params = event.hook.get_params(tid)
        hKey = params[0]

        key_name = reg_hkey[hKey] if reg_hkey.has_key(hKey) else hex(hKey)
        sub_key = event.get_process().peek_string(params[1], fUnicode=True)
        phk = params[2]

        key_name = "%s\\%s" % (key_name, sub_key)

        if retval == __ERROR_SUCCESS__:
            if phk != None:
                hkey = event.get_process().read_uint(phk)
                reg_hkey[hkey] = key_name
            css = 'ok'
        else:
            css = 'fail'

        if not self.__matches(key_name, reg_whitelist):
            self.__log(event, caller, key_name, "", retval, css)

    #-----------------------------------------------------
    '''
    LONG WINAPI RegCreateKeyEx(
      __in        HKEY hKey,
      __in        LPCTSTR lpSubKey,
      __reserved  DWORD Reserved,
      __in_opt    LPTSTR lpClass,
      __in        DWORD dwOptions,
      __in        REGSAM samDesired,
      __in_opt    LPSECURITY_ATTRIBUTES lpSecurityAttributes,
      __out       PHKEY phkResult,
      __out_opt   LPDWORD lpdwDisposition
    );
    '''
    #-----------------------------------------------------
    def post_RegCreateKeyExA(self, event, retval):

        caller = self.__getcaller(event, 9)
        if caller == None or caller in knownmods:
            return

        tid = event.get_tid()
        params = event.hook.get_params(tid)
        hKey = params[0]

        key_name = reg_hkey[hKey] if reg_hkey.has_key(hKey) else hex(hKey)
        sub_key = event.get_process().peek_string(params[1])
        access = self.__get_flags(key_access, params[5])
        phk = params[7]

        key_name = "%s\\%s" % (key_name, sub_key)

        if retval == __ERROR_SUCCESS__:
            if phk != None:
                hkey = event.get_process().read_uint(phk)
                reg_hkey[hkey] = key_name
            css = 'ok'
        else:
            css = 'fail'

        if not self.__matches(key_name, reg_whitelist):
            self.__log(event, caller, key_name, "Access: %s" % access, retval, css)

    def post_RegCreateKeyExW(self, event, retval):

        caller = self.__getcaller(event, 9)
        if caller == None or caller in knownmods:
            return

        tid = event.get_tid()
        params = event.hook.get_params(tid)
        hKey = params[0]

        key_name = reg_hkey[hKey] if reg_hkey.has_key(hKey) else hex(hKey)
        sub_key = event.get_process().peek_string(params[1], fUnicode=True)
        access = self.__get_flags(key_access, params[5])

        if retval == __ERROR_SUCCESS__:
            hkey = event.get_process().read_uint(params[7])
            reg_hkey[hkey] = "%s\\%s" % (key_name, sub_key)
            css = 'ok'
        else:
            css = 'fail'

        if not self.__matches(key_name, reg_whitelist):
            self.__log(event, caller, key_name, "Access: %s" % access, retval, css)

    #-----------------------------------------------------
    '''
    SC_HANDLE WINAPI CreateService(
      __in       SC_HANDLE hSCManager,
      __in       LPCTSTR lpServiceName,
      __in_opt   LPCTSTR lpDisplayName,
      __in       DWORD dwDesiredAccess,
      __in       DWORD dwServiceType,
      __in       DWORD dwStartType,
      __in       DWORD dwErrorControl,
      __in_opt   LPCTSTR lpBinaryPathName,
      __in_opt   LPCTSTR lpLoadOrderGroup,
      __out_opt  LPDWORD lpdwTagId,
      __in_opt   LPCTSTR lpDependencies,
      __in_opt   LPCTSTR lpServiceStartName,
      __in_opt   LPCTSTR lpPassword
    );
    '''
    #-----------------------------------------------------
    def post_CreateServiceA(self, event, retval):

        caller = self.__getcaller(event, 13)
        if caller == None or caller in knownmods:
            return

        tid = event.get_tid()
        params = event.hook.get_params(tid)

        service_name = event.get_process().peek_string(params[1])
        display_name = event.get_process().peek_string(params[2])

        the_list = svc_access.copy()
        the_list.update(generic_access)
        the_list.update(std_access)

        access = self.__get_flags(the_list, params[3])
        types  = self.__get_flags(svc_types, params[4])
        start  = self.__get_flags(svc_start, params[5])
        binary_path = event.get_process().peek_string(params[7])
        start_name  = event.get_process().peek_string(params[11])

        if retval != None:
            self.__add_handle("Service", retval, display_name)

        self.__log(event, caller, 
            "%s -> %s" % (binary_path, service_name),  \
            "Display Name: %s; Access: %s; Service Type: %s; Start Type: %s" % (display_name, access, types, start),\
            retval,
            'suspicious')

    def post_CreateServiceW(self, event, retval):

        caller = self.__getcaller(event, 13)
        if caller == None or caller in knownmods:
            return

        tid = event.get_tid()
        params = event.hook.get_params(tid)

        service_name = event.get_process().peek_string(params[1], fUnicode=True)
        display_name = event.get_process().peek_string(params[2], fUnicode=True)

        the_list = svc_access.copy()
        the_list.update(generic_access)
        the_list.update(std_access)

        access = self.__get_flags(the_list, params[3])
        types  = self.__get_flags(svc_types, params[4])
        start  = self.__get_flags(svc_start, params[5])
        binary_path = event.get_process().peek_string(params[7], fUnicode=True)
        start_name  = event.get_process().peek_string(params[11], fUnicode=True)

        if retval != None:
            self.__add_handle("Service", retval, display_name)

        self.__log(event, caller, 
            "%s -> %s" % (binary_path, service_name),  \
            "Display Name: %s; Access: %s; Service Type: %s; Start Type: %s" % (display_name, access, types, start),\
            retval,
            'suspicious')

    #-----------------------------------------------------
    '''
    BOOL WINAPI QueryServiceConfig(
      __in       SC_HANDLE hService,
      __out_opt  LPQUERY_SERVICE_CONFIG lpServiceConfig,
      __in       DWORD cbBufSize,
      __out      LPDWORD pcbBytesNeeded
    );
    '''
    #-----------------------------------------------------
    def post_QueryServiceConfigA(self, event, retval):

        caller = self.__getcaller(event, 4)
        if caller == None or caller in knownmods:
            return

        tid = event.get_tid()
        params = event.hook.get_params(tid)

        svc_name = self.__lookup_handle("Service", params[0])
        lpconfig = params[1]
        bufsize = params[2]

        if retval == True:
            self.__log(event, caller, svc_name, "", retval)
            if (lpconfig != None) and (bufsize != 0):
                conf = event.get_process().read_structure(lpconfig, QUERY_SERVICE_CONFIG)
                self.__log(event, caller, "Details: 0x%x" % conf.dwStartType, "", 0, 'after')
        else:
            self.__log(event, caller, svc_name, "", retval, 'fail')

    def post_QueryServiceConfigW(self, event, retval):

        caller = self.__getcaller(event, 4)
        if caller == None or caller in knownmods:
            return

        tid = event.get_tid()
        params = event.hook.get_params(tid)
        svc_name = self.__lookup_handle("Service", params[0])

        lpconfig = params[1]
        bufsize = params[2]

        if retval == True:
            self.__log(event, caller, svc_name, "", retval)
            if (lpconfig != None) and (bufsize != 0):
                conf = event.get_process().read_structure(lpconfig, QUERY_SERVICE_CONFIG)
                self.__log(event, caller, "Details: 0x%x" % conf.dwStartType, "", 0, 'after')
        else:
            self.__log(event, caller, svc_name, "", retval, 'fail')

    #-----------------------------------------------------
    '''
    BOOL WINAPI ChangeServiceConfig(
      __in       SC_HANDLE hService,
      __in       DWORD dwServiceType,
      __in       DWORD dwStartType,
      __in       DWORD dwErrorControl,
      __in_opt   LPCTSTR lpBinaryPathName,
      __in_opt   LPCTSTR lpLoadOrderGroup,
      __out_opt  LPDWORD lpdwTagId,
      __in_opt   LPCTSTR lpDependencies,
      __in_opt   LPCTSTR lpServiceStartName,
      __in_opt   LPCTSTR lpPassword,
      __in_opt   LPCTSTR lpDisplayName
    );
    '''
    #-----------------------------------------------------
    def post_ChangeServiceConfigA(self, event, retval):

        caller = self.__getcaller(event, 11)
        if caller == None or caller in knownmods:
            return

        tid = event.get_tid()
        params = event.hook.get_params(tid)
        svc_name = self.__lookup_handle("Service", params[0])

        display_name = event.get_process().peek_string(params[10])
        types  = self.__get_flags(svc_types, params[1])
        start  = self.__get_flags(svc_start, params[2])
        binary_path = event.get_process().peek_string(params[4])
        start_name  = event.get_process().peek_string(params[8])

        self.__log(event, caller, svc_name, \
            "Display Name: %s; Service Type: %s; Start Type: %s; Binary: %s" % (display_name, types, start, binary_path), \
            retval,
            'suspicious')

    def post_ChangeServiceConfigW(self, event, retval):

        caller = self.__getcaller(event, 11)
        if caller == None or caller in knownmods:
            return

        tid = event.get_tid()
        params = event.hook.get_params(tid)
        svc_name = self.__lookup_handle("Service", params[0])

        display_name = event.get_process().peek_string(params[10], fUnicode=True)
        types  = self.__get_flags(svc_types, params[1])
        start  = self.__get_flags(svc_start, params[2])
        binary_path = event.get_process().peek_string(params[4], fUnicode=True)
        start_name  = event.get_process().peek_string(params[8], fUnicode=True)

        self.__log(event, caller, svc_name, \
            "Display Name: %s; Service Type: %s; Start Type: %s; Binary: %s" % (display_name, types, start, binary_path), \
            retval,
            'suspicious')

    #-----------------------------------------------------
    '''
    SC_HANDLE WINAPI OpenService(
      __in  SC_HANDLE hSCManager,
      __in  LPCTSTR lpServiceName,
      __in  DWORD dwDesiredAccess
    );
    '''
    #-----------------------------------------------------
    def post_OpenServiceA(self, event, retval):

        caller = self.__getcaller(event, 3)
        if caller == None or caller in knownmods:
            return

        tid = event.get_tid()
        params = event.hook.get_params(tid)

        the_list = svc_access.copy()
        the_list.update(generic_access)
        the_list.update(std_access)

        access = self.__get_flags(the_list, params[2])
        service_name = event.get_process().peek_string(params[1])

        if retval != None:
            self.__add_handle("Service", retval, service_name)
            css = 'ok'
        else:
            css = 'fail'

        self.__log(event, caller, 
            service_name, "Access: %s" % access, retval, css)

    def post_OpenServiceW(self, event, retval):

        caller = self.__getcaller(event, 3)
        if caller == None or caller in knownmods:
            return

        tid = event.get_tid()
        params = event.hook.get_params(tid)

        the_list = svc_access.copy()
        the_list.update(generic_access)
        the_list.update(std_access)

        access = self.__get_flags(the_list, params[2])
        svc_name = event.get_process().peek_string(params[1], fUnicode=True)

        if retval != NULL:
            self.__add_handle("Service", retval, svc_name)
            css = 'ok'
        else:
            css = 'fail'

        self.__log(event, caller, 
            svc_name, "Access: %s" % access, retval, css)

    #-----------------------------------------------------
    '''
    SC_HANDLE WINAPI OpenSCManager(
      __in_opt  LPCTSTR lpMachineName,
      __in_opt  LPCTSTR lpDatabaseName,
      __in      DWORD dwDesiredAccess
    );
    '''
    #-----------------------------------------------------
    def post_OpenSCManagerA(self, event, retval):

        caller = self.__getcaller(event, 3)
        if caller == None or caller in knownmods:
            return

        tid = event.get_tid()
        params = event.hook.get_params(tid)

        machine_name = event.get_process().peek_string(params[0])
        if machine_name == "":
            machine_name = "<Local Machine>"

        db_name = event.get_process().peek_string(params[1])
        if db_name == "":
            db_name = __SERVICES_ACTIVE_DATABASE__

        the_list = svc_access.copy()
        the_list.update(generic_access)
        the_list.update(std_access)

        access = self.__get_flags(the_list, params[2])

        if retval != NULL:
            self.__add_handle("Service", retval, "<Top level SC_HANDLE for database: %s>" % db_name)
            css = 'ok'
        else:
            css = 'fail'

        self.__log(event, caller, 
            "Machine: %s; Database: %s" % (machine_name, db_name), 
            "Access: %s" % access, retval, css)

    def post_OpenSCManagerW(self, event, retval):

        caller = self.__getcaller(event, 3)
        if caller == None or caller in knownmods:
            return
            
        tid = event.get_tid()
        params = event.hook.get_params(tid)

        machine_name = event.get_process().peek_string(params[0], fUnicode=True)
        if machine_name == "":
            machine_name = "<Local Machine>"

        db_name = event.get_process().peek_string(params[1], fUnicode=True)
        if db_name == "":
            db_name = __SERVICES_ACTIVE_DATABASE__

        the_list = svc_access.copy()
        the_list.update(generic_access)
        the_list.update(std_access)

        access = self.__get_flags(the_list, params[2])

        if retval != NULL:
            self.__add_handle("Service", retval, "<Top level SC_HANDLE for database: %s>" % db_name)
            css = 'ok'
        else:
            css = 'fail'

        self.__log(event, caller, 
            "Machine: %s; Database: %s" % (machine_name, db_name), 
            "Access: %s" % access, retval, css)

    #-----------------------------------------------------
    '''
    BOOL WINAPI StartService(
      __in      SC_HANDLE hService,
      __in      DWORD dwNumServiceArgs,
      __in_opt  LPCTSTR *lpServiceArgVectors
    );
    '''
    #-----------------------------------------------------
    def post_StartServiceA(self, event, retval):

        caller = self.__getcaller(event, 3)
        if caller == None or caller in knownmods:
            return

        tid = event.get_tid()
        params = event.hook.get_params(tid)
        svc_name = self.__lookup_handle("Service", params[0])
        num_args = params[1]

        self.__log(event, caller, svc_name,
            "Number of arguments: %d" % num_args,
            retval, 'suspicious')

    def post_StartServiceW(self, event, retval):

        caller = self.__getcaller(event, 3)
        if caller == None or caller in knownmods:
            return

        tid = event.get_tid()
        params = event.hook.get_params(tid)
        svc_name = self.__lookup_handle("Service", params[0])
        num_args = params[1]

        self.__log(event, caller, svc_name,
            "Number of arguments: %d" % num_args,
            retval, 'suspicious')

    #-----------------------------------------------------
    '''
    BOOL WINAPI OpenProcessToken(
      __in   HANDLE ProcessHandle,
      __in   DWORD DesiredAccess,
      __out  PHANDLE TokenHandle
    );
    '''
    #-----------------------------------------------------
    def post_OpenProcessToken(self, event, retval):

        caller = self.__getcaller(event, 3)
        if caller == None or caller in knownmods:
            return

        tid = event.get_tid()
        params = event.hook.get_params(tid)

        # Use the token-specific flags and pre-defined standard access types
        c = token_access.copy()
        c.update(std_access)

        phandle = params[0]
        ptoken  = params[2]
        access = self.__get_flags(c, params[1])

        if phandle == 0xffffffff:
            proc_name = "<Current Process>"
        else:
            proc_name = self.__lookup_handle("Process", phandle)

        if retval == True:
            css = 'ok'
            if ptoken != 0:
                token = event.get_process().read_uint(ptoken)
                self.__add_handle("Token", token, proc_name)
        else:
            css = 'fail'

        self.__log(event, caller, proc_name, access, retval, css)

    #-----------------------------------------------------
    '''
    BOOL WINAPI OpenThreadToken(
      __in   HANDLE ThreadHandle,
      __in   DWORD DesiredAccess,
      __in   BOOL OpenAsSelf,
      __out  PHANDLE TokenHandle
    );
    '''
    #-----------------------------------------------------
    def post_OpenThreadToken(self, event, retval):

        caller = self.__getcaller(event, 4)
        if caller == None or caller in knownmods:
            return

        tid = event.get_tid()
        params = event.hook.get_params(tid)

        c = token_access.copy()
        c.update(std_access)

        hthread = params[0]
        access = self.__get_flags(c, params[1])
        ptoken  = params[3]
        thread_name = self.__lookup_handle("Thread", hthread)

        if retval == True:
            if ptoken != None:
                token = event.get_process().read_uint(ptoken)
                self.__add_handle("Token", token, thread_name)
            css = 'ok'
        else:
            css = 'fail'

        self.__log(event, caller, thread_name, "Access: %s" % access, retval, css)

    #-----------------------------------------------------
    '''
    BOOL WINAPI DuplicateToken(
      __in   HANDLE ExistingTokenHandle,
      __in   SECURITY_IMPERSONATION_LEVEL ImpersonationLevel,
      __out  PHANDLE DuplicateTokenHandle
    );
    '''
    #-----------------------------------------------------
    def post_DuplicateToken(self, event, retval):

        caller = self.__getcaller(event, 3)
        if caller == None or caller in knownmods:
            return

        tid = event.get_tid()
        params = event.hook.get_params(tid)
        orig_token = params[0]
        pdup_token  = params[2]
        level = self.__get_flags(sec_level, params[1])
        the_id = self.__lookup_handle("Token", orig_token)

        if retval == True:
            if pdup_token != NULL:
                dup_token = event.get_process().read_uint(pdup_token)
                #self.__log(event, "", "DuplicateHandle: 0x%x" % dup_token, "", "", css = 'after')

            css = 'ok'
        else:
            css = 'fail'

        self.__log(event, caller, \
                "ExistingTokenHandle: 0x%x; Object: %s" % (orig_token, the_id), \
                "Impersonation: %s" % level, \
                retval, css)

    #-----------------------------------------------------
    '''
    LONG WINAPI RegDeleteKey(
      __in  HKEY hKey,
      __in  LPCTSTR lpSubKey
    );
    '''
    #-----------------------------------------------------
    def post_RegDeleteKeyA(self, event, retval):

        caller = self.__getcaller(event, 2)
        if caller == None or caller in knownmods:
            return

        tid = event.get_tid()
        params = event.hook.get_params(tid)
        hKey = params[0]

        sub_key = event.get_process().peek_string(params[1]);
        key_name = reg_hkey[hKey] if reg_hkey.has_key(hKey) else hex(hKey)

        the_key = "%s\\%s" % (key_name, sub_key)

        if retval == __ERROR_SUCCESS__:
            css = 'ok'
        else:
            css = 'fail'

        self.__log(event, event, the_key, "", retval, css)

    def post_RegDeleteKeyW(self, event, retval):

        caller = self.__getcaller(event, 2)
        if caller == None or caller in knownmods:
            return

        tid = event.get_tid()
        params = event.hook.get_params(tid)
        hKey = params[0]

        sub_key = event.get_process().peek_string(params[1], fUnicode=True);
        key_name = reg_hkey[hKey] if reg_hkey.has_key(hKey) else hex(hKey)

        the_key = "%s\\%s" % (key_name, sub_key)

        if retval == __ERROR_SUCCESS__:
            css = 'ok'
        else:
            css = 'fail'

        self.__log(event, caller, the_key, "", retval, css)

    #-----------------------------------------------------
    '''
    LONG WINAPI RegDeleteValue(
      __in      HKEY hKey,
      __in_opt  LPCTSTR lpValueName
    );
    '''
    #-----------------------------------------------------
    def post_RegDeleteValueA(self, event, retval):

        caller = self.__getcaller(event, 2)
        if caller == None or caller in knownmods:
            return

        tid = event.get_tid()
        params = event.hook.get_params(tid)
        hKey = params[0]

        value_name = event.get_process().peek_string(params[1])
        key_name = reg_hkey[hKey] if reg_hkey.has_key(hKey) else hex(hKey)

        the_key = "%s\\%s" % (key_name, value_name)

        if retval == __ERROR_SUCCESS__:
            css = 'ok'
        else:
            css = 'fail'

        if self.__matches(the_key, alert_reg_write):
            css = 'suspicious'

        self.__log(event, event, the_key, "", retval, css)

    def post_RegDeleteValueW(self, event, retval):

        caller = self.__getcaller(event, 2)
        if caller == None or caller in knownmods:
            return

        tid = event.get_tid()
        params = event.hook.get_params(tid)
        hKey = params[0]

        value_name = event.get_process().peek_string(params[1], fUnicode=True)
        key_name = reg_hkey[hKey] if reg_hkey.has_key(hKey) else hex(hKey)

        the_key = "%s\\%s" % (key_name, value_name)

        if retval == __ERROR_SUCCESS__:
            css = 'ok'
        else:
            css = 'fail'

        if self.__matches(the_key, alert_reg_write):
            css = 'suspicious'

        self.__log(event, caller, the_key, "", retval, css)

    #-----------------------------------------------------
    '''
    LONG WINAPI RegOpenKey(
      __in          HKEY hKey,
      __in          LPCTSTR lpSubKey,
      __out         PHKEY phkResult
    );
    '''
    #-----------------------------------------------------
    def post_RegOpenKeyA(self, event, retval):
    
        caller = self.__getcaller(event, 3)
        if caller == None or caller in knownmods:
            return

        tid = event.get_tid()
        params = event.hook.get_params(tid)
        
        hKey = params[0]
        sub_key = event.get_process().peek_string(params[1])
        hkey_str = reg_hkey[hKey] if reg_hkey.has_key(hKey) else hex(hKey)
        key_name = "%s\\%s" % (hkey_str, sub_key)
        
        if retval == __ERROR_SUCCESS__:
            new_hkey = event.get_process().read_uint(params[2])
            reg_hkey[new_hkey] = key_name
            css = 'ok'
        else:
            css = 'fail'

        if not self.__matches(key_name, reg_whitelist):
            self.__log(event, caller, key_name, "", retval, css)
        
    def post_RegOpenKeyW(self, event, retval):
    
        caller = self.__getcaller(event, 3)
        if caller == None or caller in knownmods:
            return

        tid = event.get_tid()
        params = event.hook.get_params(tid)
        
        hKey = params[0]
        sub_key = event.get_process().peek_string(params[1], fUnicode=True)
        hkey_str = reg_hkey[hKey] if reg_hkey.has_key(hKey) else hex(hKey)
        key_name = "%s\\%s" % (hkey_str, sub_key)
        
        if retval == __ERROR_SUCCESS__:
            new_hkey = event.get_process().read_uint(params[2])
            reg_hkey[new_hkey] = key_name
            css = 'ok'
        else:
            css = 'fail'

        if not self.__matches(key_name, reg_whitelist):
            self.__log(event, caller, key_name, "", retval, css)

    #-----------------------------------------------------
    '''
    LONG WINAPI RegOpenKeyEx(
      __in        HKEY hKey,
      __in_opt    LPCTSTR lpSubKey,
      __reserved  DWORD ulOptions,
      __in        REGSAM samDesired,
      __out       PHKEY phkResult
    );
    '''
    #-----------------------------------------------------
    def post_RegOpenKeyExA(self, event, retval):

        caller = self.__getcaller(event, 5)
        if caller == None or caller in knownmods:
            return

        tid = event.get_tid()
        params = event.hook.get_params(tid)
        
        hKey = params[0]
        sub_key = event.get_process().peek_string(params[1])
        hkey_str = reg_hkey[hKey] if reg_hkey.has_key(hKey) else hex(hKey)
        access = self.__get_flags(key_access, params[3])
        new_hkey = event.get_process().read_uint(params[4])
        key_name = "%s\\%s" % (hkey_str, sub_key)
        
        if retval == __ERROR_SUCCESS__:
            reg_hkey[new_hkey] = key_name
            css = 'ok'
        else:
            css = 'fail'

        if not self.__matches(key_name, reg_whitelist):
            self.__log(event, caller, key_name, access, retval, css)

    def post_RegOpenKeyExW(self, event, retval):

        caller = self.__getcaller(event, 5)
        if caller == None or caller in knownmods:
            return

        tid = event.get_tid()
        params = event.hook.get_params(tid)
        
        hKey = params[0]
        sub_key = event.get_process().peek_string(params[1], fUnicode=True)
        hkey_str = reg_hkey[hKey] if reg_hkey.has_key(hKey) else hex(hKey)
        access = self.__get_flags(key_access, params[3])
        new_hkey = event.get_process().read_uint(params[4])
        key_name = "%s\\%s" % (hkey_str, sub_key)
        
        if retval == __ERROR_SUCCESS__:
            reg_hkey[new_hkey] = key_name
            css = 'ok'
        else:
            css = 'fail'

        if not self.__matches(key_name, reg_whitelist):
            self.__log(event, caller, key_name, access, retval, css)

    #-----------------------------------------------------
    '''
    LONG WINAPI RegQueryValueEx(
      __in         HKEY hKey,
      __in_opt     LPCTSTR lpValueName,
      __reserved   LPDWORD lpReserved,
      __out_opt    LPDWORD lpType,
      __out_opt    LPBYTE lpData,
      __inout_opt  LPDWORD lpcbData
    );
    '''
    #-----------------------------------------------------
    def post_RegQueryValueExA(self, event, retval):

        caller = self.__getcaller(event, 6)
        if caller == None or caller in knownmods:
            return

        tid = event.get_tid()
        params = event.hook.get_params(tid)

        hKey = params[0]
        value_name = event.get_process().peek_string(params[1])
        key_name = reg_hkey[hKey] if reg_hkey.has_key(hKey) else hex(hKey)

        if retval == __ERROR_SUCCESS__:
            css = 'ok'
        else:
            css = 'fail'

        if not self.__matches(key_name, reg_whitelist):
            self.__log(event, caller, key_name, "Value: %s" % value_name, retval, css)

    def post_RegQueryValueExW(self, event, retval):

        caller = self.__getcaller(event, 6)
        if caller == None or caller in knownmods:
            return

        tid = event.get_tid()
        params = event.hook.get_params(tid)

        hKey = params[0]
        value_name = event.get_process().peek_string(params[1], fUnicode=True)
        key_name = reg_hkey[hKey] if reg_hkey.has_key(hKey) else hex(hKey)

        if retval == __ERROR_SUCCESS__:
            css = 'ok'
        else:
            css = 'fail'

        if not self.__matches(key_name, reg_whitelist):
            self.__log(event, caller, key_name, "Value: %s" % value_name, retval, css)

    #-----------------------------------------------------
    '''
    LONG WINAPI RegSetValueEx(
      __in        HKEY hKey,
      __in_opt    LPCTSTR lpValueName,
      __reserved  DWORD Reserved,
      __in        DWORD dwType,
      __in_opt    const BYTE *lpData,
      __in        DWORD cbData
    );
    '''
    #-----------------------------------------------------
    def post_RegSetValueExA(self, event, retval):

        caller = self.__getcaller(event, 6)
        if caller == None or caller in knownmods:
            return

        tid = event.get_tid()
        params = event.hook.get_params(tid)

        hKey = params[0]
        key_name  = reg_hkey[hKey] if reg_hkey.has_key(hKey) else hex(hKey)
        value_name = event.get_process().peek_string(params[1])
        dwType = params[3]
        types = reg_types[dwType] if reg_types.has_key(dwType) else hex(dwType)
        cbData = params[5]

        if cbData > 128:
            size = 128
        else:
            size = cbData

        data = event.get_process().read(params[4], size)

        if self.__matches(key_name, alert_reg_write):
            css = 'suspicious'
        elif self.__matches(data, alert_reg_content_write):
            css = 'suspicious'
        else:
            css = 'ok'

        self.__log(event, caller,
            key_name,
            "Value: %s; Type: %s; Size: 0x%x" % (value_name, types, cbData),
            retval, css)

        if retval == __ERROR_SUCCESS__:
            self.__loghex(data)

    def post_RegSetValueExW(self, event, retval):

        caller = self.__getcaller(event, 6)
        if caller == None or caller in knownmods:
            return

        tid = event.get_tid()
        params = event.hook.get_params(tid)
        hKey = params[0]
        dwType = params[3]

        key_name = reg_hkey[hKey] if reg_hkey.has_key(hKey) else hex(hKey)
        value_name = event.get_process().peek_string(params[1], fUnicode=True)
        types = reg_types[dwType] if reg_types.has_key(dwType) else hex(dwType)

        cbData = params[5]
        if cbData > 128:
            size = 128
        else:
            size = cbData
        data = event.get_process().read(params[4], size)

        if self.__matches(key_name, alert_reg_write):
            css = 'suspicious'
        elif self.__matches(data, alert_reg_content_write):
            css = 'suspicious'
        else:
            css = 'ok'

        self.__log(event, caller, key_name,
            "Value: %s; Type: %s; Size: 0x%x" % (value_name, types, cbData),
            retval, css)

        if retval == __ERROR_SUCCESS__:
            self.__loghex(data)

    #-----------------------------------------------------
    '''
    BOOL WINAPI CryptAcquireContext(
      __out  HCRYPTPROV *phProv,
      __in   LPCTSTR pszContainer,
      __in   LPCTSTR pszProvider,
      __in   DWORD dwProvType,
      __in   DWORD dwFlags
    );
    '''
    #-----------------------------------------------------
    def post_CryptAcquireContextA(self, event, retval):

        caller = self.__getcaller(event, 5)
        if caller == None or caller in knownmods:
            return

        tid = event.get_tid()
        params = event.hook.get_params(tid)

        container = event.get_process().peek_string(params[1])
        provider = event.get_process().peek_string(params[2])

        if container == "":
            container = "<Default>"

        if provider == "":
            provider = "<Default>"

        dwProvType = params[3]
        types = prov_types[dwProvType] if prov_types.has_key(dwProvType) else hex(dwProvType)
        flags = self.__get_flags(context_flags, params[4])

        self.__log(event, caller, 
            "Container: %s; Provider: %s" % (container, provider),
            "Type: %s; Flags: %s" % (types, flags),
            retval,
            'ok' if retval == True else 'fail')

    #-----------------------------------------------------
    '''
    BOOL WINAPI CryptEncrypt(
      __in     HCRYPTKEY hKey,
      __in     HCRYPTHASH hHash,
      __in     BOOL Final,
      __in     DWORD dwFlags,
      __inout  BYTE *pbData,
      __inout  DWORD *pdwDataLen,
      __in     DWORD dwBufLen
    );
    '''
    #-----------------------------------------------------
    def post_CryptEncrypt(self, event, retval):

        caller = self.__getcaller(event, 7)
        if caller == None or caller in knownmods:
            return

        tid = event.get_tid()
        params = event.hook.get_params(tid)

        hkey = params[0]
        pbdata = params[4]
        pbdatalen = params[5]
        dwbuflen = params[6]

        if (pbdata != None) and (dwbuflen > 0):
            input_data = event.get_process().read(pbdata, dwbuflen)
        else:
            input_data = ""

        if retval == True:
            self.__log(event, caller, 
                "hKey: 0x%x" % hkey, "Input Length: 0x%x" % len(input_data), retval)
            if input_data != "":
                self.__loghex(input_data)
            if pbdatalen != None:
                dlen = event.get_process().read_uint(pdatalen)
                if pbdata != None:
                    data = event.get_process().read(pbdata, dlen)
                    self.__log(event, caller, "Crypted Length: 0x%x" % dlen, "", 0, 'after')
                    self.__loghex(data)
        else:
            self.__log(event, caller, "hKey: 0x%x" % hkey,
                "Input Length: 0x%x" % len(input_data),
                retval, 'fail')

    #-----------------------------------------------------
    '''
    BOOL WINAPI CryptHashData(
      __in  HCRYPTHASH hHash,
      __in  BYTE *pbData,
      __in  DWORD dwDataLen,
      __in  DWORD dwFlags
    );
    '''
    #-----------------------------------------------------
    def post_CryptHashData(self, event, retval):

        caller = self.__getcaller(event, 4)
        if caller == None or caller in knownmods:
            return

        tid = event.get_tid()
        params = event.hook.get_params(tid)

        hhash = params[0]
        pbdata = params[1]
        dwdatalen = params[2]

        if (pbdata != NULL) and (dwdatalen > 0):
            hash_data = event.get_process().read(pbdata, dwdatalen)
        else:
            hash_data = ""

        if retval == True:
            self.__log(event, caller, 
                "hHash: 0x%x" % hhash, "Length: 0x%x" % len(hash_data), retval)
            if hash_data != "":
                self.__loghex(hash_data)
        else:
            self.__log(event, caller, 
                "hHash: 0x%x" % hhash,
                "Length: 0x%x" % len(hash_data),
                retval, 'fail')

    #-----------------------------------------------------
    '''
    BOOL WINAPI CryptCreateHash(
      __in   HCRYPTPROV hProv,
      __in   ALG_ID Algid,
      __in   HCRYPTKEY hKey,
      __in   DWORD dwFlags,
      __out  HCRYPTHASH *phHash
    );
    '''
    #-----------------------------------------------------
    def post_CryptCreateHash(self, event, retval):

        caller = self.__getcaller(event, 5)
        if caller == None or caller in knownmods:
            return

        tid = event.get_tid()
        params = event.hook.get_params(tid)

        hprov = params[0]
        algid = params[1]
        hkey  = params[2]
        flags = params[3]

        self.__log(event, caller, 
            "hProv: 0x%x" % hprov,
            "Algorithm: %s; hKey: 0x%x; Flags: 0x%x" % (algid, hkey, flags),
            retval,
            'ok' if retval == True else 'fail')


    def __add_handle(self, type, val, name):
        if name.startswith("Handle") and name.find("Name:") != -1:
            name = name[name.find("Name:")+5:].rstrip(")")
        # If a handle already exists for the same type, overwrite it
        c = 0
        done = False
        for (t, v, n) in self.handles:
            if (t==type) and (v==val):
                print "**", self.handles[c]
                self.handles[c] = ((type, val, name))
                print "**", self.handles[c]
                done = True
                break
            c += 1
        if not done:
            self.handles.append((type, val, name))
        print "**NEW %s Handle(Value:0x%x; Name:%s)" % (type, val, name)

    def __get_name(self, type, val):
        for (t, v, n) in self.handles:
            if (t==type) and (v==val):
                if n.startswith("Handle") and n.find("Name:") != -1:
                    return n[n.find("Name:")+5:].rstrip(")")
        return ""

    def __lookup_handle(self, type, val):
        for (t, v, n) in self.handles:
            if ((type==None) or (t==type)) and (v==val):
                return "Handle(Value:0x%x; Type:%s; Name:%s)" % (v, t, n)
        return "Handle(Value:0x%x; Type:%s)" % (val, type)



    def __get_flags(self, flags, val):
        if flags.has_key(val):
            return flags[val]
        else:
            return '|'.join([flags[f] for f in flags if (val | f == val)])
       
    def __getcaller(self, event, argc):
        ra = event.get_thread().read_stack_dwords(1, offset = -(4*(argc+1)))[0]
        proc = event.get_process()
        proc.scan_modules()
        mod = proc.get_module_at_address(ra)
        if mod != None:
            return os.path.basename(mod.fileName).lower()
        else:
            return None


    ############################################################################


    # This needs changing so it accepts UNICODE strings and hex byte arrays

    def __matches(self, needle, haystack):
        for i in haystack:
            # Try to normalize paths a bit
            i = i.replace('\\\\', '\\')
            i = i.replace('/', '\\')
            try:
                if ( (i.lower() == needle.lower()) or (i.lower() in needle.lower()) ):
                    return True
            except:
                pass
        return False

    def __archive(self, fname):
        basename = os.path.basename(fname)
        basename = "%d_%s" % (self.copyid, basename)
        try:
            shutil.copy(fname, "%s/%s" % (self.dir, basename))
        except:
            pass
        self.copyid += 1

    def __read_blob(self, event, pBlob):

        if pBlob == None:
            return None, 0

        b = event.get_process().read_structure(pBlob, DATA_BLOB)

        if (b.pbData != None) and (b.cbData != 0):

            buf = event.get_process().read(b.pbData, b.cbData)
            return buf, b.cbData

        return None, 0

    def get_context_flags(self, event, context_ptr):

        Ctx = event.get_process().read_structure(context_ptr, kernel32.CONTEXT)

        flags = self.__get_flags(ctx_flags, Ctx.ContextFlags)

        ret = "Flags: %s" % flags

        if 'CONTEXT_FULL' in flags or 'CONTEXT_ALL' in flags or 'CONTEXT_INTEGER' in flags:
            ret += "; EDI: 0x%x" % Ctx.Edi
            ret += "; ESI: 0x%x" % Ctx.Esi
            ret += "; EBX: 0x%x" % Ctx.Ebx
            ret += "; EDX: 0x%x" % Ctx.Edx
            ret += "; ECX: 0x%x" % Ctx.Ecx
            ret += "; EAX: 0x%x" % Ctx.Eax

        if 'CONTEXT_FULL' in flags or 'CONTEXT_ALL' in flags or 'CONTEXT_CONTROL' in flags:
            ret += "; EBP: 0x%x" % Ctx.Ebp
            ret += "; EIP: 0x%x" % Ctx.Eip
            ret += "; EFlags: 0x%x" % Ctx.EFlags
            ret += "; ESP: 0x%x" % Ctx.Esp

        if 'CONTEXT_ALL' in flags or 'CONTEXT_DEBUG_REGISTERS' in flags:
            ret += "; DR0: 0x%x" % Ctx.Dr0
            ret += "; DR1: 0x%x" % Ctx.Dr1
            ret += "; DR2: 0x%x" % Ctx.Dr2
            ret += "; DR3: 0x%x" % Ctx.Dr3
            ret += "; DR4: 0x%x" % Ctx.Dr4
            ret += "; DR5: 0x%x" % Ctx.Dr5
            ret += "; DR6: 0x%x" % Ctx.Dr6
            ret += "; DR7: 0x%x" % Ctx.Dr7

        return ret

    def __nameof(self, pid):

        fileName = ""

        if pid == 0:
            fileName = "System process"
        elif pid == 4:
            fileName = "System"
        else:
            s = System()
            s.request_debug_privileges()
            s.scan_processes()
            pid_list = s.get_process_ids()

            if pid in pid_list:
                p = s.get_process(pid)
                fileName = PathOperations.pathname_to_filename(p.get_filename())

        return fileName

    def __filter(self, str1):
        if len(str1) == 0: return ''
        l = [i for i in str1 if ord(i) < 0x7f and ord(i) > 0x19]
        return ''.join(l)

    def __log(self, event, caller, item, details, rval, css='ok'):
    
        cid = "%s:%s" % (event.get_pid(), event.get_tid())
        func = inspect.stack()[1][3]
        func = func[func.find('_')+1:]
        t = time()

        log_entry = "++ %s %s %s %s %s %s" % (caller, cid, func, item, rval, details)

        try:
            print log_entry
#            self.report.write(log_entry)
#            self.report.flush()
            os.fsync(self.report.fileno())
        except:
            pass

    def __dump2(self, src, length=16):

        FILTER=''.join([(len(repr(chr(x)))==3) and chr(x) or '.' for x in range(256)])
        result=[]

        for i in xrange(0, len(src), length):
           s = src[i:i+length]
           hexa = ' '.join(["%02x"%ord(x) for x in s])
           printable = s.translate(FILTER)
           result.append("%08x   %-*s   %s<br>" % (i, length*3, hexa, cgi.escape(printable)))
        return ''.join(result)

    def __format_time(self, time):
        return strftime("%a %b %d %H:%M:%S %Y", gmtime(time))

    def __windows_to_unix_time(self, windows_time):

        if(windows_time == 0):
            unix_time =0
        else:
            unix_time = windows_time / 10000000
            unix_time = unix_time - 11644473600

        if unix_time < 0:
            unix_time = 0

        return unix_time

    def __loghex(self, data):

        size = 128 if (len(data) > 128) else len(data)
        log_entry = self.__dump2(data[0:size])

        print log_entry
        self.report.write(log_entry)
        os.fsync(self.report.fileno())

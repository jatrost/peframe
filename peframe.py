#!/usr/bin/env python

##############################################################
#
## PEFrame: Portable Executable Framework
##
## Gianni 'guelfoweb' Amato - guelfoweb@gmail.com - 2012
##
## http://code.google.com/p/peframe/
##
## Licence: GNU GPL v.2.0
##
## This program is free software; you can redistribute it and/or modify
## it under the terms of the GNU General Public License as published by
## the Free Software Foundation; either version 2 of the License, or
## (at your option) any later version.
##
## This program is distributed in the hope that it will be useful,
## but WITHOUT ANY WARRANTY; without even the implied warranty of
## MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
## GNU General Public License for more details.
##
## Credit to: Ero Carrera for 'pefile' module
#
##############################################################

# ToDo:
# [ ] Virus Total Check
# [X] Search File Path
# [ ] Assembly
# [X] Anti VM
# [X] API Anti-Debug
# [X] Hash for sections

import re
import sys
import string
import os
import math
import time
import datetime
import subprocess
import hashlib
import json
import codecs
import traceback

sys.stdout = codecs.getwriter('UTF-8')(sys.stdout)
sys.stderr = codecs.getwriter('UTF-8')(sys.stderr)

pathname = os.path.abspath(os.path.dirname(sys.argv[0]))
sys.path.append(pathname + '/modules')

try:
    import pefile
    import peutils
except ImportError:
    sys.stderr.write('pefile not installed, see http://code.google.com/p/pefile/\n')

##############################################################
## PEFrame Information
NAME="peframe"
VERSION="0.4"
DATE="02/10/2012"
SITE="http://code.google.com/p/peframe/"
AUTHOR="Gianni 'guelfoweb' Amato"
SPONSOR="http://www.securityside.it"

##############################################################
## Print HASH MD5 & SHA1
def HASH():
    return {
        "md5": hashlib.md5(filebytes).hexdigest(),
        "sha1": hashlib.sha1(filebytes).hexdigest()
    }

##############################################################
## Print PE file attributes
def INFO():
    return {
        "name": os.path.basename(exename),
        "size": len(filebytes), 
        "compile_time": "%s"%datetime.datetime.fromtimestamp(pe.FILE_HEADER.TimeDateStamp),
        "dll": unicode(pe.FILE_HEADER.IMAGE_FILE_DLL),
        "sections":pe.FILE_HEADER.NumberOfSections
    }

##############################################################
## Check for version info & metadata
def META():
    # TODO: should this be a dict instead?
    res = []    
    if hasattr(pe, 'VS_VERSIONINFO'):
        if hasattr(pe, 'FileInfo'):
            for entry in pe.FileInfo:
                if hasattr(entry, 'StringTable'):
                    for st_entry in entry.StringTable:
                        for str_entry in st_entry.entries.items():
                            res.append([str_entry[0], str_entry[1]])
                elif hasattr(entry, 'Var'):
                    for var_entry in entry.Var:
                        if hasattr(var_entry, 'entry'):
                            res.append( [var_entry.entry.keys()[0], var_entry.entry.values()[0]] )
    return res

##############################################################
## Extract Strings
printable = set(string.printable)

def process(data):
    found_str = ""
    for char in data:
        if char in printable:
            found_str += char
        elif len(found_str) >= 4:
            yield found_str
            found_str = ""
        else:
            found_str = ""

def STRINGS():
    return [s for s in process(filebytes)]

##############################################################
## Section analyzer
def SECTIONS():
    sections = []
    for section in pe.sections:
        section.get_entropy()
        if section.SizeOfRawData == 0 or (section.get_entropy() > 0 and section.get_entropy() < 1) or section.get_entropy() > 7:
            suspicious = True
        else:
            suspicious = False

        sections.append({
            'name': unicode(section.Name.encode("string_escape")),
            'virt_address':hex(section.VirtualAddress),
            'virt_size':hex(section.Misc_VirtualSize),
            'raw_data_size':section.SizeOfRawData,
            'entropy': section.get_entropy(),
            'suspicious': suspicious,
            'md5': section.get_hash_md5(),
            'sha1': section.get_hash_sha1()
        })
    return {
        "num_sections": pe.FILE_HEADER.NumberOfSections,
        "sections":sections
    }

##############################################################
## Load PEID userdb.txt database and scan file
def PEID():
    signatures = peutils.SignatureDatabase(pathname + '/modules/userdb.txt')
    matches = signatures.match_all(pe,ep_only = True)
    if matches and len(matches) > 0 and len(matches[0]) > 0:
        return {"packer": unicode(matches[0][0])}
    else:
        return {}

##############################################################
## Check for Anti VM
def CHECKANTIVM():
    VM_Sign = {
        "Red Pill":"\x0f\x01\x0d\x00\x00\x00\x00\xc3",
        "VirtualPc trick":"\x0f\x3f\x07\x0b",
        "VMware trick":"VMXh",
        "VMCheck.dll":"\x45\xC7\x00\x01",
        "VMCheck.dll for VirtualPC":"\x0f\x3f\x07\x0b\xc7\x45\xfc\xff\xff\xff\xff",
        "Xen":"XenVMM",
        "Bochs & QEmu CPUID Trick":"\x44\x4d\x41\x63",
        "Torpig VMM Trick": "\xE8\xED\xFF\xFF\xFF\x25\x00\x00\x00\xFF\x33\xC9\x3D\x00\x00\x00\x80\x0F\x95\xC1\x8B\xC1\xC3",
        "Torpig (UPX) VMM Trick": "\x51\x51\x0F\x01\x27\x00\xC1\xFB\xB5\xD5\x35\x02\xE2\xC3\xD1\x66\x25\x32\xBD\x83\x7F\xB7\x4E\x3D\x06\x80\x0F\x95\xC1\x8B\xC1\xC3"
        }
    
    tricks = []
    for name, signature in VM_Sign.items():
        if filebytes.find(signature[::-1]) > -1:
            tricks.append(name)

    return {
        'antivm_tricks':tricks
    }

##############################################################
## Url Check
def URL(strings):
    files = []
    urls = []

    for found_str in strings:
        fname = re.findall("(\w*\.(exe|dll|com|bat|pdf|swf|jpg|php|asp|aspx|cgi|js|htm|html|css))+", found_str, re.IGNORECASE | re.MULTILINE)
        url = re.findall("((http|ftp|mailto|telnet|ssh)(s){0,1}\:\/\/[\w|\/|\.|\#|\?|\&|\=|\-|\%]+)+", found_str, re.IGNORECASE | re.MULTILINE)
        if url:
            U = url[0][0]
            urls.append(U)
        else:
            U = ""
        if fname:
            P = fname[0][0]
            if not P in U:
                files.append(P)
    return {
        "files":files,
        "urls":urls
    }

##############################################################
## Dump Entry instances

#
# Code taken from pefile and modified....
#
def dump(obj, indentation=0):
    """Returns a string representation of the structure."""

    dump = []
    res = {'name':obj.name, 'objects':dump}
    
    # Refer to the __set_format__ method for an explanation
    # of the following construct.
    for keys in obj.__keys__:
        for key in keys:
            val = getattr(obj, key)
            if isinstance(val, int) or isinstance(val, long):
                val_str = '0x%X' % (val)
                if key == 'TimeDateStamp' or key == 'dwTimeStamp':
                    try:
                        val_str = '%s UTC' % time.asctime(time.gmtime(val))
                    except exceptions.ValueError, e:
                        val_str = 'INVALID TIME'
            else:
                val_str = ''.join(filter(lambda c:c != '\0', str(val)))
            
            dump.append( {
                key: val_str, 
                'address': '0x%X'%(obj.__field_offsets__[key] + obj.__file_offset__),
                'offset':  '0x%X'%(obj.__field_offsets__[key])
            })

    return res

def IMPORT():
    try:
        return dump(pe.DIRECTORY_ENTRY_IMPORT[0].struct)
    except:
        try:
            return dump(pe.DIRECTORY_ENTRY_IMPORT.struct)
        except:
            return {}

def EXPORT():
    try:
        return dump(pe.DIRECTORY_ENTRY_EXPORT[0].struct)
    except:
        try:
            return dump(pe.DIRECTORY_ENTRY_EXPORT.struct)
        except:
            return {}

def RESOURCE():
    try:
        return dump(pe.DIRECTORY_ENTRY_RESOURCE[0].struct)
    except:
        try:
            return dump(pe.DIRECTORY_ENTRY_RESOURCE.struct)
        except:
            return {}

def DEBUG():
    try:
        return dump(pe.DIRECTORY_ENTRY_DEBUG[0].struct)
    except:
        try:
            return dump(pe.DIRECTORY_ENTRY_DEBUG.struct)
        except:
            return {}

##############################################################
## Imports DLLs and API
def FUNCTIONS():
    res = {}
    try:
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            res[entry.dll] = {}
            for imp in entry.imports:
                res[entry.dll][imp.address] = imp.name
    except:
        pass
    return res

##############################################################
## Suspicious Functions API and Sections
alerts = ['accept', 'AddCredentials', 'bind', 'CertDeleteCertificateFromStore', 'CheckRemoteDebuggerPresent', 
'closesocket', 'connect', 'ConnectNamedPipe', 'CopyFile', 'CreateFile', 'CreateProcess', 'CreateToolhelp32Snapshot', 
'CreateFileMapping', 'CreateRemoteThread', 'CreateDirectory', 'CreateService', 'CreateThread', 'CryptEncrypt', 'DeleteFile', 
'DeviceIoControl', 'DisconnectNamedPipe', 'DNSQuery', 'EnumProcesses', 'ExitThread', 'FindWindow', 'FindResource', 
'FindFirstFile', 'FindNextFile', 'FltRegisterFilter', 'FtpGetFile', 'FtpOpenFile', 'GetCommandLine', 'GetThreadContext', 
'GetDriveType', 'GetFileSize', 'GetFileAttributes', 'GetHostByAddr', 'GetHostByName', 'GetHostName', 'GetModuleHandle', 
'GetProcAddress', 'GetTempFileName', 'GetTempPath', 'GetTickCount', 'GetUpdateRect', 'GetUpdateRgn', 'GetUserNameA', 
'GetUrlCacheEntryInfo', 'GetComputerName', 'GetVersionEx', 'GetModuleFileName', 'GetStartupInfo', 'GetWindowThreadProcessId',
'HttpSendRequest', 'HttpQueryInfo', 'IcmpSendEcho', 'IsDebuggerPresent', 'InternetCloseHandle', 'InternetConnect', 
'InternetCrackUrl', 'InternetQueryDataAvailable', 'InternetGetConnectedState', 'InternetOpen', 'InternetQueryDataAvailable', 
'InternetQueryOption', 'InternetReadFile', 'InternetWriteFile', 'LdrLoadDll', 'LoadLibrary', 'LoadLibraryA', 'LockResource', 
'listen', 'MapViewOfFile', 'OutputDebugString', 'OpenFileMapping', 'OpenProcess', 'Process32First', 'Process32Next', 
'recv', 'ReadProcessMemory', 'RegCloseKey', 'RegCreateKey', 'RegDeleteKey', 'RegDeleteValue', 'RegEnumKey', 'RegOpenKey', 
'send', 'sendto', 'SetKeyboardState', 'SetWindowsHook', 'ShellExecute', 'Sleep', 'socket', 'StartService', 'TerminateProcess',
'UnhandledExceptionFilter', 'URLDownload', 'VirtualAlloc', 'VirtualProtect', 'VirtualAllocEx', 'WinExec', 'WriteProcessMemory', 
'WriteFile', 'WSASend', 'WSASocket', 'WSAStartup', 'ZwQueryInformation']

antidbgs = ['CheckRemoteDebuggerPresent', 'FindWindow', 'GetWindowThreadProcessId', 'IsDebuggerPresent', 
'OutputDebugString', 'Process32First', 'Process32Next', 'TerminateProcess',  'UnhandledExceptionFilter', 'ZwQueryInformation']

def APIALERT():
    suspicious_functions = []
    try:
        for lib in pe.DIRECTORY_ENTRY_IMPORT:
            for imp in lib.imports:
                if (imp.name != None) and (imp.name != ""):
                    for alert in alerts:
                        if imp.name.startswith(alert):
                            suspicious_functions.append(imp.name)
    except:
        pass

    return suspicious_functions

def APIANTIDBG():
    antidebugs = []
    try:
        for lib in pe.DIRECTORY_ENTRY_IMPORT:
            for imp in lib.imports:
                if (imp.name != None) and (imp.name != ""):
                    for antidbg in antidbgs:
                        if imp.name.startswith(antidbg):
                                antidebugs.append(imp.name)
    except:
        pass

    return antidebugs

def SUSPICIOUS():
    return {
        'api_alert':APIALERT(),
        'api_antidebug':APIANTIDBG()
    }

results = {}
exename = sys.argv[1]
filebytes = open(exename, 'rb').read()

try:
	results['hash'] = HASH()
	#results['strings'] = STRINGS()
	#results['urls'] = URL(results['strings'])

	pe = pefile.PE(data=filebytes)
	results['info'] = INFO()
	results['suspicious'] = SUSPICIOUS()
	results['peid'] = PEID()
	results['meta'] = META()
	results['sections'] = SECTIONS()
	results['import'] = IMPORT()
	results['export'] = EXPORT()
	results['resource'] = RESOURCE()
	results['debug'] = DEBUG()
except pefile.PEFormatError, pe_err:
    results['error'] = unicode(pe_err) 
except Exception, e:
	traceback.print_exc()

print json.dumps(results)
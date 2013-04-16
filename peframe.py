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

pathname = os.path.abspath(os.path.dirname(sys.argv[0]))
sys.path.append(pathname + '/modules')

try:
		import pefile
		import peutils
except ImportError:
		print 'pefile not installed, see http://code.google.com/p/pefile/'

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
		# Thank to Christophe Monniez for patched hash function
		fh = open(exename, 'rb')
		m = hashlib.md5()
		s = hashlib.sha1()
		while True:
			data = fh.read(8192)
			if not data:
				break
			m.update(data)
			s.update(data)
		print "MD5   hash:\t", m.hexdigest()
		print "SHA-1 hash:\t", s.hexdigest()

##############################################################
## Print PE file attributes
def INFO():
		print "File Name:\t", os.path.basename(exename)
		print "File Size:\t", os.path.getsize(exename), "byte"
		#print "Optional Header:\t\t", hex(pe.OPTIONAL_HEADER.ImageBase)
		#print "Address Of Entry Point:\t\t", hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint)
		print "Compile Time:\t", datetime.datetime.fromtimestamp(pe.FILE_HEADER.TimeDateStamp)
		#print "Subsystem:\t\t\t", pefile.SUBSYSTEM_TYPE[pe.OPTIONAL_HEADER.Subsystem]
		#machine = 0
		#machine = pe.FILE_HEADER.Machine
		#print "Required CPU type:\t\t", pefile.MACHINE_TYPE[machine]
		#print "Number of RVA and Sizes:\t", pe.OPTIONAL_HEADER.NumberOfRvaAndSizes
		dll = pe.FILE_HEADER.IMAGE_FILE_DLL
		print "DLL:\t\t", dll
		print "Sections:\t", pe.FILE_HEADER.NumberOfSections

##############################################################
## Check for version info & metadata
def META():
		ret = []
		
		if hasattr(pe, 'VS_VERSIONINFO'):
		    if hasattr(pe, 'FileInfo'):
		        for entry in pe.FileInfo:
		            if hasattr(entry, 'StringTable'):
		                for st_entry in entry.StringTable:
		                    for str_entry in st_entry.entries.items():
		                        print str_entry[0] + ': ' + str_entry[1]
		            elif hasattr(entry, 'Var'):
		                for var_entry in entry.Var:
		                    if hasattr(var_entry, 'entry'):
		                        print var_entry.entry.keys()[0] + ': ' + var_entry.entry.values()[0]

##############################################################
## Extract Strings
printable = set(string.printable)

def process(stream):
    found_str = ""
    while True:
        data = stream.read(1024*4)
        if not data:
            break
        for char in data:
            if char in printable:
                found_str += char
            elif len(found_str) >= 4:
                yield found_str
                found_str = ""
            else:
                found_str = ""

def STRINGS():
		PEtoStr = open(exename, 'rb')
		for found_str in process(PEtoStr):
			print found_str
		PEtoStr.close()

##############################################################
## Section analyzer
def SECTIONS():
        print "Number of Sections:", pe.FILE_HEADER.NumberOfSections
        print
        print "Section\tVirtualAddress\tVirtualSize\tSizeofRawData\tSuspicious"
        for section in pe.sections:
			section.get_entropy()
			if section.SizeOfRawData == 0 or (section.get_entropy() > 0 and section.get_entropy() < 1) or section.get_entropy() > 7:
				suspicious = "YES"
			else:
				suspicious = "NO"

			if len(section.Name) < 7:
				sepName="\t\t"
			else:
				sepName="\t"
			if len(hex(section.VirtualAddress)) < 7:
				sepVA="\t\t"
			else:
				sepVA="\t"
			if len(hex(section.Misc_VirtualSize)) < 7:
				sepVS="\t\t"
			else:
				sepVS="\t"
			if len(str(section.SizeOfRawData)) < 7: # integer to string
				sepSD="\t\t"
			else:
				sepSD="\t"

			print section.Name,sepName,hex(section.VirtualAddress),sepVA,hex(section.Misc_VirtualSize),sepVS,section.SizeOfRawData,sepSD,suspicious

			print "MD5     hash:",section.get_hash_md5()
			print "SHA-1   hash:",section.get_hash_sha1()
			#print "SHA-256 hash:",section.get_hash_sha256()
			#print "SHA-512 hash:",section.get_hash_sha512()
			print

##############################################################
## Load PEID userdb.txt database and scan file
def PEID():
        signatures = peutils.SignatureDatabase(pathname + '/modules/userdb.txt')
        matches = signatures.match_all(pe,ep_only = True)
        print "Packer:\t\t", matches[0][0]

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
	CountTricks = 0
	with open(exename, "rb") as f:
		buf = f.read()
		for trick in VM_Sign:
			if buf.find(VM_Sign[trick][::-1]) > -1:
				print "Anti VM:\t", trick
				CountTricks = CountTricks +1

	if CountTricks == 0:
		print "Anti VM:\tNone"

##############################################################
## Url Check
def URL():
		PEtoStr = open(exename, 'rb')
		countU = 0
		countF = 0
		for found_str in process(PEtoStr):
			fname = re.findall("(\w*\.(exe|dll|com|bat|pdf|swf|jpg|php|asp|aspx|cgi|js|htm|html|css))+", found_str, re.IGNORECASE | re.MULTILINE)
			url = re.findall("((http|ftp|mailto|telnet|ssh)(s){0,1}\:\/\/[\w|\/|\.|\#|\?|\&|\=|\-|\%]+)+", found_str, re.IGNORECASE | re.MULTILINE)
			if url:
				U = url[0][0]
				print "URL:\t\t", U
				countU = countU + 1
			else:
				U = ""
			if fname:
				P = fname[0][0]
				#if (P != U):
				if not P in U:
					print "FILE:\t\t", P
					countF = countF + 1 
		PEtoStr.close()
		if countU == 0:
			print "URL:\t\tNone"
		if countF == 0:
			print "FILE:\t\tNone"


##############################################################
## Dump Entry instances
def IMPORT():
		try:
			print pe.DIRECTORY_ENTRY_IMPORT[0].struct
		except:
			try:
				print pe.DIRECTORY_ENTRY_IMPORT.struct
			except:
				print "none"

def EXPORT():
		try:
			print pe.DIRECTORY_ENTRY_EXPORT[0].struct
		except:
			try:
				print pe.DIRECTORY_ENTRY_EXPORT.struct
			except:
				print "none"

def RESOURCE():
		try:
			print pe.DIRECTORY_ENTRY_RESOURCE[0].struct
		except:
			try:
				print pe.DIRECTORY_ENTRY_RESOURCE.struct
			except:
				print "none"

def DEBUG():
		try:
			print pe.DIRECTORY_ENTRY_DEBUG[0].struct
		except:
			try:
				print pe.DIRECTORY_ENTRY_DEBUG.struct
			except:
				print "none"

##############################################################
## Imports DLLs and API
def FUNCTIONS():
        print "Imported DLLs and API:"
        i = 1
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
                bool = 1 ## For Formattting 
                print "%2s" % [i], "%-17s" % entry.dll
                print "\t",
                for imp in entry.imports:
                        if bool:
                                print "%-1s" % hex(imp.address),imp.name,
                                bool = 0
                        else:
                                sys.stdout.write("%s%s%s%s" % ("\n\t",hex(imp.address)," ", imp.name)) # Python Print adds a blank space 
                i += 1
		print

##############################################################
## Suspicious Functions API and Sections
alerts = ['accept', 'AddCredentials', 'bind', 'CertDeleteCertificateFromStore', 'CheckRemoteDebuggerPresent', 'closesocket', 'connect', 'ConnectNamedPipe', 'CopyFile', 'CreateFile', 'CreateProcess', 'CreateToolhelp32Snapshot', 'CreateFileMapping', 'CreateRemoteThread', 'CreateDirectory', 'CreateService', 'CreateThread', 'CryptEncrypt', 'DeleteFile', 'DeviceIoControl', 'DisconnectNamedPipe', 'DNSQuery', 'EnumProcesses', 'ExitThread', 'FindWindow', 'FindResource', 'FindFirstFile', 'FindNextFile', 'FltRegisterFilter', 'FtpGetFile', 'FtpOpenFile', 'GetCommandLine', 'GetThreadContext', 'GetDriveType', 'GetFileSize', 'GetFileAttributes', 'GetHostByAddr', 'GetHostByName', 'GetHostName', 'GetModuleHandle', 'GetProcAddress', 'GetTempFileName', 'GetTempPath', 'GetTickCount', 'GetUpdateRect', 'GetUpdateRgn', 'GetUserNameA', 'GetUrlCacheEntryInfo', 'GetComputerName', 'GetVersionEx', 'GetModuleFileName', 'GetStartupInfo', 'GetWindowThreadProcessId', 'HttpSendRequest', 'HttpQueryInfo', 'IcmpSendEcho', 'IsDebuggerPresent', 'InternetCloseHandle', 'InternetConnect', 'InternetCrackUrl', 'InternetQueryDataAvailable', 'InternetGetConnectedState', 'InternetOpen', 'InternetQueryDataAvailable', 'InternetQueryOption', 'InternetReadFile', 'InternetWriteFile', 'LdrLoadDll', 'LoadLibrary', 'LoadLibraryA', 'LockResource', 'listen', 'MapViewOfFile', 'OutputDebugString', 'OpenFileMapping', 'OpenProcess', 'Process32First', 'Process32Next', 'recv', 'ReadProcessMemory', 'RegCloseKey', 'RegCreateKey', 'RegDeleteKey', 'RegDeleteValue', 'RegEnumKey', 'RegOpenKey', 'send', 'sendto', 'SetKeyboardState', 'SetWindowsHook', 'ShellExecute', 'Sleep', 'socket', 'StartService', 'TerminateProcess', 'UnhandledExceptionFilter', 'URLDownload', 'VirtualAlloc', 'VirtualProtect', 'VirtualAllocEx', 'WinExec', 'WriteProcessMemory', 'WriteFile', 'WSASend', 'WSASocket', 'WSAStartup', 'ZwQueryInformation']

antidbgs = ['CheckRemoteDebuggerPresent', 'FindWindow', 'GetWindowThreadProcessId', 'IsDebuggerPresent', 'OutputDebugString', 'Process32First', 'Process32Next', 'TerminateProcess',  'UnhandledExceptionFilter', 'ZwQueryInformation']

def APIALERT():
		if not hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
				print "No suspicious API"
		for lib in pe.DIRECTORY_ENTRY_IMPORT:
				for imp in lib.imports:
					if (imp.name != None) and (imp.name != ""):
						for alert in alerts:
							if imp.name.startswith(alert):
								print "Func. Name:\t", imp.name

def APIANTIDBG(out):
		countantidbg = 0
		if not hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
				print "No suspicious API Anti Debug"
		for lib in pe.DIRECTORY_ENTRY_IMPORT:
				for imp in lib.imports:
					if (imp.name != None) and (imp.name != ""):
						for antidbg in antidbgs:
							if imp.name.startswith(antidbg):
								if out == 1:
									print "Anti Debug:\t", imp.name
								else:
									countantidbg = countantidbg + 1
		if out == 0:
			if countantidbg > 0:
				print "Anti Debug:\tYes"
			else:
				print "Anti Debug:\tNone"

def SECTIONSALERT():
        for section in pe.sections:
				section.get_entropy()
				if section.SizeOfRawData == 0 or (section.get_entropy() > 0 and section.get_entropy() < 1) or section.get_entropy() > 7:
						print "Sect. Name:\t", section.Name
						print "MD5   hash:\t",section.get_hash_md5()
						print "SHA-1 hash:\t",section.get_hash_sha1()

def SUSPICIOUS():
		print "Suspicious API Functions:"
		APIALERT()
		print "\nSuspicious API Anti-Debug:"
		APIANTIDBG(1)
		print "\nSuspicious Sections:"
		SECTIONSALERT()

##############################################################
## Dumping all the information
def DUMP():
		print pe.dump_info()

##############################################################
## Hexdump
def ascii(x):
		"""Determine how to show a byte in ascii."""
		if 32 <= x <= 126:
		    return chr(x)
		elif 160 <= x <= 255:
		    return '.'
		else:
		    return '.'

def HEXDUMP(width=16, verbose=0, start=0):		
		pos = 0
		f = open(exename, 'rb')
		ascmap = [ ascii(x) for x in range(256) ]
		
		lastbuf = ''
		lastline = ''
		nStarLen = 0

		if width > 4:
		    spaceCol = width//2
		else:
		    spaceCol = -1

		hexwidth = 3 * width 
		if spaceCol != -1:
		    hexwidth += 1                

		if start:
		    f.seek(start)
		    pos = start
		    
		while 1:
		    buf = f.read(width)

		    length = len(buf)
		    if length == 0:
		        if nStarLen:
		            if nStarLen > 1:
		                print "* %d" % (nStarLen-1)
		            print lastline
		        return

		    bShowBuf = 1
		    
		    if not verbose and buf == lastbuf:
		        nStarLen += 1
		        bShowBuf = 0
		    else:
		        if nStarLen:
		            if nStarLen == 1:
		                print lastline
		            else:
		                print "* %d" % nStarLen
		        nStarLen = 0
          
		    hex = ""
		    asc = ""
		    for i in range(length):
		        c = buf[i]
		        if i == spaceCol:
		            hex = hex + " "
		        hex = hex + ("%02x" % ord(c)) + " "
		        asc = asc + ascmap[ord(c)]
		    line = "%06x: %-*s %s" % (pos, hexwidth, hex, asc)

		    if bShowBuf:
		        print line
		        
		    pos = pos + length
		    lastbuf = buf
		    lastline = line

		f.close()

##############################################################
## Help
def HELP():
		print NAME, VERSION, "by", AUTHOR
		print SITE
		print
		print "USAGE:"
		print "\t", NAME, "<opt> <file>"
		print
		print "OPTIONS:"
		print "\t-h\t--help\t\tThis help"
		print "\t-a\t--auto\t\tShow Auto analysis"
		print "\t-i\t--info\t\tPE file attributes"
		print "\t\t--hash\t\tHash MD5 & SHA1"
		print "\t\t--meta\t\tVersion info & metadata"
		print "\t\t--peid\t\tPE Identifier Signature"
		print "\t\t--antivm\tAnti Virtual Machine"
		print "\t\t--antidbg\tAnti Debug | Disassembler"
		print "\t\t--sections\tSection analyzer"
		print "\t\t--functions\tImported DLLs & API functions"
		print "\t\t--suspicious\tSearch for suspicious API & sections"
		print "\t\t--dump\t\tDumping all the information"
		print "\t\t--strings\tExtract all the string"
		print "\t\t--url\t\tExtract File Name and Url"
		print "\t\t--hexdump\tReverse Hex dump"
		print "\t\t--import\tList Entry Import instances"
		print "\t\t--export\tList Entry Export instances"
		print "\t\t--resource\tList Entry Resource instances"
		print "\t\t--debug\t\tList Entry DebugData instances"

##############################################################
## Main Menu
if len(sys.argv) < 3:
		HELP()
		sys.exit
elif len(sys.argv) == 3:
		opt = sys.argv[1]
		exename = sys.argv[2]
		try:
			pe = pefile.PE(exename)
			if opt == '-h' or opt == '--help':
				HELP()
			elif opt == '-a' or opt == '--auto':
				INFO()
				HASH()
				try:
					PEID()
				except:
					print "None"
				APIANTIDBG(0)
				try:
					CHECKANTIVM()
				except:
					print "Anti VM:\tError"
				print
				print "File and URL:"
				URL()
				print
				SUSPICIOUS()
				print
				META()
			elif opt == '--hash':
				HASH()
			elif opt == '-i' or opt == '--info':
				INFO()
			elif opt == '--meta':
				META()
			elif opt == '--peid':
				try:
					PEID()
				except:
					print "None"
			elif opt == '--antivm':
				try:
					CHECKANTIVM()
				except:
					print "Anti VM:\tError"
			elif opt == '--antidbg':
				APIANTIDBG(0)
			elif opt == '--sections':
				SECTIONS()
			elif opt == '--functions':
				FUNCTIONS()
			elif opt == '--strings':
				STRINGS()
			elif opt == '--url':
				URL()
			elif opt == '--suspicious':
				SUSPICIOUS()
			elif opt == '--dump':
				DUMP()
			elif opt == '--hexdump':
				HEXDUMP()
			elif opt == '--import':
				IMPORT()
			elif opt == '--export':
				EXPORT()
			elif opt == '--resource':
				RESOURCE()
			elif opt == '--debug':
				DEBUG()
			else:
				HELP()
				sys.exit
		except:
			print "No Portable Executable"
else:
		exename = sys.argv[1]
		if exename == "--help":
			HELP()
			sys.exit

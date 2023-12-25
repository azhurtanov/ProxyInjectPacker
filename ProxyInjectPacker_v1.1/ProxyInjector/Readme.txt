TODO:
	- restore proxy process

Functions:
	- " mov qword ptr [rbp+0x10], rax ;" # Save CreateFile address for later usage
	- " mov qword ptr [rbp+0x18], rax ;" # Save CreateProcessA address for later usage
	- " mov qword ptr [rbp+0x20], rax ;" # Save CloseHandle address for later usage
	- " mov qword ptr [rbp+0x28], rax ;" # Save CreateRemoteThread address for later usage
	- " mov qword ptr [rbp+0x30], rax ;" # Save ExitProcess address for later usage
	- " mov qword ptr [rbp+0x38], rax ;" # Save OpenProcess address for later usage
	- " mov qword ptr [rbp+0x40], rax ;" # Save ReadFile address for later usage
	- " mov qword ptr [rbp+0x48], rax ;" # Save ResumeThread address for later usage
	- " mov qword ptr [rbp+0x50], rax ;" # Save VirtualAlloc address for later usage
	- " mov qword ptr [rbp+0x58], rax ;" # Save VirtualAllocEx address for later usage
	- " mov qword ptr [rbp+0x60], rax ;" # Save VirtualFree address for later usage
	- " mov qword ptr [rbp+0x68], rax ;" # Save VirtualQueryEx address for later usage
	- " mov qword ptr [rbp+0x70], rax ;" # Save WriteFile address for later usage
	- " mov qword ptr [rbp+0x78], rax ;" # Save WaitForSingleObject address for later usage
	- " mov qword ptr [rbp+0x80], rax ;" # Save WriteProcessMemory address for later usage

Locals:
	- 0x88: Pipe handle
	- 0x90: return 1 (Allocated memory 1 / hProcess)
	- 0x98: return 2 (Allocated memory 2 / hThread)
	- 0xA0: return 3 (Allocated memory 3 / allocated memory (proxy2))
	- 0xA8: Target thread handle
	- 0xB0: Proxy allocated memory
	- 0xB8: Target process Handle
	- 0xC0: Return to the agent 
	- 0xC8: PagesCount
	- 0xD0: Shellcode location
	- 0xE0: Shellcode size
	- 0xE8: Granularities Count
	- 0xF0: Temp
	- 0xF8: Entrypoint

Access rights:
	- CreateThread: PROCESS_VM_WRITE (0x020), PROCESS_QUERY_INFORMATION (0x0400), PROCESS_VM_OPERATION (0x0008), PROCESS_CREATE_THREAD (0x0002) = 0x042A
	- VirtualAllocEx:

Shellcode variables:
	- Shellcode size: 0x4141414141414141
	- PID: 0x4242424242424242
	- Required granularities: 0x4343434343434343
	- Required pages: 0x44444444
	
	

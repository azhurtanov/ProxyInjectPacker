from keystone import *
import ctypes, struct

CODE = (
    " start: "
        " mov rax, 0x4141414141414141;"
        " mov r10, rcx; "
        " push r10; "
        " push r9; "
        " push r8; "
        " push rdx; "
        " push rcx; "        
)


ks = Ks(KS_ARCH_X86, KS_MODE_64)
encoding, count = ks.asm(CODE)
instructions = ""
i=1
for dec in encoding: 
    if(i % 20 == 0):
        instructions += "\\x{0:02x}".format(int(dec)).rstrip("\n")
        instructions += "\"\r\n\""
    else:
        instructions += "\\x{0:02x}".format(int(dec)).rstrip("\n")
    i+=1
print("unsigned char syscall[] = (\r\n\"" + instructions + "\");\r\n")
print("Size = " + str(i-1) + ";\r\n")
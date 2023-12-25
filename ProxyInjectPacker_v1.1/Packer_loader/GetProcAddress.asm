PUBLIC _GetProcAddress

.code
_GetProcAddress PROC


push rbp;
sub rsp, 20h;
mov rbp, rsp;
sub rsp, 40h;
mov rbx, rcx;
mov qword ptr[rbp + 10h], rdx;

xor rcx, rcx;  rcx = 0
mov rsi, gs: [rcx + 60h] ;  ESI = &(PEB)([FS:60])
mov rsi, [rsi + 18h];  ESI = PEB->Ldr
mov rsi, [rsi + 30h];  ESI = PEB->Ldr.InInitOrder
next_module:
cmp rbx, [rsi+10h];
mov rdi, [rsi+ 40h] ;  EDI = InInitOrder[X].module_name
mov rsi, [rsi] ; ESI = InInitOrder[X].flink (next)

jne next_module


find_function_shorten :
jmp find_function_shorten_bnc;  Short jump

find_function_ret :
pop rsi;  POP the return address from the stack
mov[rbp + 08h], rsi;  Save find_function address for later usage
jmp resolve_symbols;

find_function_shorten_bnc:
call find_function_ret;  Relative CALL with negative offset

find_function :
push rsp;
push rax;  Save all registers
push rcx;  Save all registers
push rdx;  Save all registers
push rbx;  Save all registers
push rbp;  Save all registers
push rsi;  Save all registers
push rdi;  Save all registers
mov eax, [rbx + 3ch];  Offset to PE Signature
mov edi, [rbx + rax + 88h];  Export Table Directory RVA
add rdi, rbx;  Export Table Directory VMA
mov ecx, [rdi + 14h];  NumberOfNames
xor rax, rax;
mov eax, [rdi + 20h];  AddressOfNames RVA
add rax, rbx;  AddressOfNames VMA
mov[rbp - 8h], rax;  Save AddressOfNames VMA for later


find_function_loop :
jecxz find_function_finished;  Jump to the end if rcx is 0
dec rcx;  Decrement our names counter
mov rax, [rbp - 8];  Restore AddressOfNames VMA
mov esi, [rax + rcx * 4];  Get the RVA of the symbol name
add rsi, rbx;

compute_hash:
xor eax, eax;  NULL EAX
cdq;  NULL EDX
cld;  Clear direction

compute_hash_again :
lodsb;  Load the next byte from esi into al
test al, al;  Check for NULL terminator
jz compute_hash_finished;  If the ZF is set, we've hit the NULL term
ror edx, 0dh;  Rotate edx 13 bits to the right
add edx, eax;  Add the new byte to the accumulator
jmp compute_hash_again;  Next iteration
compute_hash_finished :



find_function_compare:

cmp rdx, [rsp + 48h];  Compare the computed hash with the requested hash
jnz find_function_loop;  If it doesn't match go back to find_function_loop
mov edx, [rdi + 24h];  AddressOfNameOrdinals RVA
add rdx, rbx;  AddressOfNameOrdinals VMA
mov cx, [rdx + 2 * rcx];  Extrapolate the function's ordinal
mov edx, [rdi + 1ch];  AddressOfFunctions RVA
add rdx, rbx;  AddressOfFunctions VMA
mov eax, [rdx + 4 * rcx];  Get the function RVA
add rax, rbx;  Get the function VMA
mov[rsp + 30h], rax;



find_function_finished:

pop rdi;  Restore registers
pop rsi;  Restore registers
pop rbp;  Restore registers
pop rbx;  Restore registers
pop rdx;  Restore registers
pop rcx;  Restore registers
pop rax;  Restore registers
pop rsp;  Restore registers
ret;

resolve_symbols:

mov rax, [rbp + 10h];
push rax;
call qword ptr[rbp + 08];  Call find_function
pop r8;

exit:

add rsp, 40h;
add rsp, 20h
pop rbp;
ret; ; Resolve function hash into syscall number and make the call
_GetProcAddress ENDP
END
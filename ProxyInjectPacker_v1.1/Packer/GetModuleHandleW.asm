PUBLIC _GetModuleHandleW
.code
EXTERN mystrcmp: PROC

_GetModuleHandleW PROC

push rbp;
mov rbp, rsp;
sub rsp, 10h;
push rcx; 


xor rcx, rcx;  rcx = 0
mov rsi, gs: [rcx + 60h] ;  ESI = &(PEB)([FS:60])
mov rsi, [rsi + 18h];  ESI = PEB->Ldr
mov rsi, [rsi + 30h];  ESI = PEB->Ldr.InInitOrder
next_module :
mov rbx, [rsi + 10h];  rbx = InInitOrder[X].base_address
mov rdi, [rsi + 40h];  EDI = InInitOrder[X].module_name
mov rsi, [rsi];  ESI = InInitOrder[X].flink(next)
pop rcx; 
mov rdx, rdi;
push rdx; 
push rcx;
call mystrcmp;
pop rcx; 
pop rdx; 
cmp rax, 1; 
jne next_module;  No: try next module

add rsp, 10h; 
pop rbp; 
mov rax, rbx
ret; ; Resolve function hash into syscall number and make the call
_GetModuleHandleW ENDP
END
;RCX: 1st integer argument
;RDX: 2nd integer argument
;R8: 3rd integer argument
;R9: 4th integer argument

;I should probably start converting to inrinsics

_TEXT SEGMENT 'CODE'



PUBLIC asmInt3
asmInt3:
	int 3
	ret

PUBLIC getCS
getCS:
	mov ax,cs
	ret

PUBLIC getSS
getSS:
	mov ax,ss
	ret
	
PUBLIC getDS
getDS:
	mov ax,ds
	ret
	
PUBLIC getES
getES:
	mov ax,es
	ret	
	
PUBLIC getFS
getFS:
	mov ax,fs
	ret
	
PUBLIC getGS
getGS:
	mov ax,gs
	ret	
	
PUBLIC GetTR
GetTR:
	STR AX
	ret	
	
PUBLIC GetLDT
GetLDT:
	SLDT ax
	ret
	
PUBLIC GetGDT
GetGDT:
	SGDT [rcx]
	ret
	
PUBLIC _fxsave
_fxsave:
    fxsave [rcx]
    ret
	
PUBLIC getRSP
getRSP:
	mov rax,rsp
	add rax,8 ;undo the call push
	ret	
	
PUBLIC getRBP
getRBP:
    push rbp
    pop rax	
	ret	
	
PUBLIC getRAX
getRAX:	
	ret							
	
PUBLIC getRBX
getRBX:
	mov rax,rbx
	ret	
	
PUBLIC getRCX
getRCX:
	mov rax,rcx
	ret	
	
PUBLIC getRDX
getRDX:
	mov rax,rdx
	ret		
	
PUBLIC getRSI
getRSI:
	mov rax,rsi
	ret		
	
PUBLIC getRDI
getRDI:
	mov rax,rdi
	ret		
	
PUBLIC getR8
getR8:
	mov rax,r8
	ret		
	
PUBLIC getR9
getR9:
	mov rax,r9
	ret		
	
PUBLIC getR10
getR10:
	mov rax,r10
	ret		
	
PUBLIC getR11
getR11:
	mov rax,r11
	ret		
	
PUBLIC getR12
getR12:
	mov rax,r12
	ret		
	
PUBLIC getR13
getR13:
	mov rax,r13
	ret		
	
PUBLIC getR14
getR14:
	mov rax,r14
	ret		
	
PUBLIC getR15
getR15:
	mov rax,r15
	ret				
	
PUBLIC getAccessRights										
getAccessRights:
  xor rax,rax
  lar rax,rcx
  jnz getAccessRights_invalid
  shr rax,8
  and rax,0f0ffh
  ret
  getAccessRights_invalid:
  mov rax,010000h
  ret


PUBLIC getSegmentLimit										
getSegmentLimit:
  xor rax,rax
  lsl rax,rcx
  ret



;---------------------------;
;void spinlock(int *lockvar);
;---------------------------;

asm_spinlock proc
push rbx
mov rbx,rcx ;ebx now contains the address of the lock

spinlock_loop:
;serialize
; ±£´æ¼Ä´æÆ÷×´Ì¬
push rax
push rbx
push rcx
push rdx
push rsi
push rdi
push rbp
push r8
push r9
push r10
push r11
push r12
push r13
push r14
push r15

xor rax,rax
cpuid ;serialize

; »Ö¸´¼Ä´æÆ÷×´Ì¬
pop r15
pop r14
pop r13
pop r12
pop r11
pop r10
pop r9
pop r8
pop rbp
pop rdi
pop rsi
pop rdx
pop rcx
pop rbx
pop rax

;check lock
cmp qword ptr [rbx],0
je spinlock_getlock
pause
jmp spinlock_loop

spinlock_getlock:
mov rax,1
xchg rax,[rbx] ;try to lock
cmp rax,0 ;test if successful
jne spinlock_loop

pop rbx

ret ;4
asm_spinlock endp;
;-----------------------------------------;
;void outportb(short int port, char value);
;-----------------------------------------;
outportb proc
mov eax,edx ;value
mov edx,ecx  ;port
out dx,al
ret ;8
outportb endp;


;-----------------;
;inportb(int port); returns a byte from the given port
;-----------------;
inportb proc
mov edx,ecx
in al,dx
ret ;4 ; (no params, in cdecl frees the caller)
inportb endp;





_TEXT   ENDS
        END


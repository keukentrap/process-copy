mov r12, 0;
mov rbx, rcx;
mov r13, rdx;
mov rsp, r8;
mark:
	inc r12;
	mov rcx, 0;
	mov rdx, r13;
	call rbx;
	jmp mark;
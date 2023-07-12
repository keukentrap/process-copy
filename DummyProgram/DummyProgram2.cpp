#include<Windows.h>
#include<stdio.h>

const char payload[] = "\x49\xc7\xc4\x0\x0\x0\x0\x48\x89\xcb\x49\x89\xd5\x4c\x89\xc4\x49\xff\xc4\x48\xc7\xc1\x0\x0\x0\x0\x4c\x89\xea\xff\xd3\xeb\xef";
/* x86-64bit ASM 
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
*/

int main()
{
	void* buf = VirtualAlloc(NULL, sizeof(payload) + 0x20 + 0x20, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (!buf) {
		return 1;
	}
	memcpy(buf, payload, sizeof(payload));

	HMODULE ntdll = LoadLibraryA("ntdll.dll");
	FARPROC ZwDelayExecution = GetProcAddress(ntdll, "ZwDelayExecution");

	LONGLONG* p = (LONGLONG*)((CHAR*)buf + 0x30); // This has to be 8 byte aligned
	*p = -50000000LL; // 5 seconds
	
	void* stack = (void*)((CHAR*)buf + 0x30 + 0x20);

	 (*(void (*)(void*,LONGLONG*,void*)) buf)(ZwDelayExecution,p, stack);
	return 0;
}

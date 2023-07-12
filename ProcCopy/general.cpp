#include"general.h"
#include <DbgHelp.h>

boolean isExecutable(DWORD ap) {
	return (ap == PAGE_EXECUTE || ap == PAGE_EXECUTE_READWRITE || ap == PAGE_EXECUTE_READ || ap == PAGE_EXECUTE_WRITECOPY);
}

void ErrorExit(LPTSTR lpszFunction)
{
	// Retrieve the system error message for the last-error code
	LPVOID lpMsgBuf;
	LPVOID lpDisplayBuf;
	DWORD dw = GetLastError();

	FormatMessage(
		FORMAT_MESSAGE_ALLOCATE_BUFFER |
		FORMAT_MESSAGE_FROM_SYSTEM |
		FORMAT_MESSAGE_IGNORE_INSERTS,
		NULL,
		dw,
		MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
		(LPTSTR)&lpMsgBuf,
		0, NULL);

	// Display the error message and exit the process
	wprintf(L"(%s) err #%u: %s\n", lpszFunction, dw, (LPTSTR)lpMsgBuf);
}

HANDLE ProcessByExeName(const WCHAR fname[], PROCESSENTRY32* processEntry) {
	processEntry->dwSize = sizeof(PROCESSENTRY32);
	HANDLE process;
	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	Process32First(snapshot, processEntry);
	do
	{
		process = OpenProcess(MAXIMUM_ALLOWED, 0, processEntry->th32ProcessID);
		if (!process)
		{
			CloseHandle(process);
			continue;
		}
		if (_wcsicmp(processEntry->szExeFile, fname) != 0) {
			CloseHandle(process);
			continue;
		}
		CloseHandle(snapshot);
		return process;
	} while (Process32Next(snapshot, processEntry));
	CloseHandle(snapshot);
	return NULL;
}

void debugShowProcess(HANDLE process) {
	if (!process) {
		return;
	}
	MEMORY_BASIC_INFORMATION mbi;
	PLOADED_IMAGE pImage;
	unsigned char* image;
	LPVOID offset = 0;

	printf("Showing all memory allocations:\n");
	while (VirtualQueryEx(process, offset, &mbi, sizeof(mbi))) {
		if ((mbi.Protect == PAGE_EXECUTE || mbi.Protect == PAGE_READWRITE || mbi.Protect == PAGE_READONLY || mbi.Protect == PAGE_EXECUTE_READWRITE || mbi.Protect == PAGE_EXECUTE_READ || mbi.Protect == PAGE_EXECUTE_WRITECOPY) &&
			(mbi.State == MEM_COMMIT) &&
			(mbi.Type == MEM_PRIVATE || mbi.Type == MEM_IMAGE || mbi.Type == MEM_MAPPED))
		{
			DWORD64 diff = (DWORD64)mbi.BaseAddress + mbi.RegionSize;
			printf("%p-%p\tAP: %x\tP: %x\tstate:%x\ttype:%x\tsize:%x\n", mbi.BaseAddress, (PVOID)diff, mbi.AllocationProtect, mbi.Protect, mbi.State, mbi.Type, mbi.RegionSize);
		}
		offset = (LPVOID)((UINT64)mbi.BaseAddress + mbi.RegionSize);
	}
}

void printRegisters(const PCONTEXT t) {
	printf("----REGISTERS----\n");
	printf("RAX %p\n", (void*)t->Rax);
	printf("RCX %p\n", (void*)t->Rcx);
	printf("RDX %p\n", (void*)t->Rdx);
	printf("RBX %p\n", (void*)t->Rbx);
	printf("RSP %p\n", (void*)t->Rsp);
	printf("RBP %p\n", (void*)t->Rbp);
	printf("RSI %p\n", (void*)t->Rsi);
	printf("RDI %p\n", (void*)t->Rdi);
	printf("RIP %p\n", (void*)t->Rip);
	printf("-----------------\n");
	return;
}
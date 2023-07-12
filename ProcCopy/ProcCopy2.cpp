
#include <stdio.h>
#include <Windows.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <processthreadsapi.h>
#include <strsafe.h>

#include "internals.h"
#include "PE.h"
#include "general.h"

#define MIN(x, y) (((x) < (y)) ? (x) : (y))

typedef struct Memory_ {
	MEMORY_BASIC_INFORMATION mbi;
	LPVOID offset;
	unsigned char* buf;
	struct Memory_* next;
} Memory;

typedef struct ProcessState_ {
	PROCESSENTRY32 processEntry;
	PPEB PEB;
	PLOADED_IMAGE pImage;
	unsigned char* image;
	LPCONTEXT* threads;
	LPCONTEXT thread;
	Memory* mem;
} ProcessState;

//WCHAR fname[] = L"DummyProgram.exe";

void RestartProcess(const ProcessState* s) {
	printf("Creating process\r\n");

	LPSTARTUPINFOA pStartupInfo = new STARTUPINFOA;
	LPPROCESS_INFORMATION pProcessInfo = new PROCESS_INFORMATION;
	if (!pStartupInfo || !pProcessInfo) {
		printf("pStartupInfo or pProcessInfo malloc failed.\n");
		return;
	}

	memset(pStartupInfo, 0, sizeof(STARTUPINFOA));
	pStartupInfo->cb = sizeof(STARTUPINFOA);
	memset(pProcessInfo, 0, sizeof(PROCESS_INFORMATION));

	if (!CreateProcessA
	(
		0,//s->processEntry.szExeFile,
		(LPSTR)"C:\\Users\\Someone\\Documents\\Thesis\\ProcCopy\\x64\\Debug\\Empty", /*(LPSTR)"notepad", //*/
		0,
		0,
		0,
		CREATE_SUSPENDED,
		0,
		0,
		pStartupInfo,
		pProcessInfo
	))
	{
		printf("Error creating process\r\n");
		ErrorExit((LPTSTR)TEXT("CreateProcessA"));
		return;
	}
	printf("PID: %d", pProcessInfo->dwProcessId);
	debugShowProcess(pProcessInfo->hProcess);

	PPEB pPEB = ReadRemotePEB(pProcessInfo->hProcess);
	//PLOADED_IMAGE pImage = ReadRemoteImage(pProcessInfo->hProcess, pPEB->ImageBaseAddress);

	printf("Allocating memory\r\n");

	UINT64 delta = (UINT64)pPEB->ImageBaseAddress - (UINT64)s->PEB->ImageBaseAddress;
	printf("old: %p\tnew: %p\tdelta: %x\n", s->PEB->ImageBaseAddress, pPEB->ImageBaseAddress, delta);

	DWORD64 rip = s->thread->Rip;

	Memory* curmem = s->mem;
	do {
		PVOID offset = curmem->mbi.BaseAddress;
		if (s->PEB->ImageBaseAddress == curmem->mbi.AllocationBase) {
			delta = (DWORD64)curmem->mbi.BaseAddress - (DWORD64)s->PEB->ImageBaseAddress;
			offset = (PVOID)((DWORD64)pPEB->ImageBaseAddress + delta);
			printf("!!!%p\n", offset);
		}
		PVOID pRemoteImage;

		MEMORY_BASIC_INFORMATION mbi;
		SIZE_T Size = VirtualQueryEx
		(
			pProcessInfo->hProcess,
			offset,
			&mbi,
			sizeof(mbi)
		);
		DWORD64 end = (DWORD64)mbi.BaseAddress + mbi.RegionSize;
		printf("mbi: %p-%p\t%x\t%x\t%x\t%x ", mbi.BaseAddress, end, mbi.Type, mbi.State, mbi.AllocationProtect, mbi.Protect);
		if (mbi.State == MEM_FREE) {
			pRemoteImage = VirtualAllocEx
			(
				pProcessInfo->hProcess,
				offset,
				curmem->mbi.RegionSize,
				MEM_RESERVE | MEM_COMMIT,
				PAGE_EXECUTE_READWRITE //curmem->mbi.AllocationProtect
			);
			if (curmem->mbi.BaseAddress != pRemoteImage) {
				printf("old: %p\tnew: %p\tsize: %x\t", curmem->mbi.BaseAddress, pRemoteImage, curmem->mbi.RegionSize);
			}
			else {
				printf("new: %p\t", pRemoteImage);
			}
			if (!pRemoteImage)
			{
				printf("VirtualAllocEx call failed\r\n");
				ErrorExit((LPTSTR)TEXT("VirtualAllocEx"));
			}
		}
		else {
			DWORD OldProtect = NULL;
			if (!VirtualProtectEx
			(
				pProcessInfo->hProcess,
				offset,
				mbi.RegionSize,
				PAGE_READWRITE,
				&OldProtect
			))
			{
				printf("Error setting allocation protect\r\n");
				ErrorExit((LPTSTR)TEXT("VirtualProtectEx"));
				curmem = curmem->next;
				continue;
			}
			pRemoteImage = offset;
		}
		if (!WriteProcessMemory
		(
			pProcessInfo->hProcess,
			pRemoteImage,
			curmem->buf,
			curmem->mbi.RegionSize,
			0
		))
		{
			printf("Error writing process memory\r\n");
			ErrorExit((LPTSTR)TEXT("WriteProcessMemory"));
			return;
		}
		DWORD OldProtect = NULL;
		printf(" %x", curmem->mbi.Protect);
		if (!VirtualProtectEx
		(
			pProcessInfo->hProcess,
			pRemoteImage,
			curmem->mbi.RegionSize,
			curmem->mbi.Protect,
			&OldProtect
		))
		{
			printf("Error setting allocation protect\r\n");
			ErrorExit((LPTSTR)TEXT("VirtualProtectEx"));
			return;
		}
		printf("\n");
		if (s->thread->Rip >= (DWORD64)curmem->mbi.BaseAddress && (s->thread->Rip <= (DWORD64)curmem->mbi.BaseAddress + curmem->mbi.RegionSize)) {
			rip = (DWORD64)pRemoteImage | (s->thread->Rip & 0xffff);
			printf("RIP: old %p\tnew: %p\n", s->thread->Rip, rip);

		}

		curmem = curmem->next;
	} while (curmem != NULL);

	debugShowProcess(pProcessInfo->hProcess);


	printf("Resuming thread\r\n");
	if (!ResumeThread(pProcessInfo->hThread))
	{
		printf("Error resuming thread\r\n");
		return;
	}
	printf("Waiting for the program to be ready\r\n");
	Sleep(4000);

	printf("Suspending thread again\r\n");
	// TODO error only if result is (DWORD) -1
	if (!SuspendThread(pProcessInfo->hThread))
	{
		printf("Error suspending thread\r\n");
		//ErrorExit((LPTSTR)TEXT("SuspendThread"));
		//return;
	}

	CONTEXT* pContext = new CONTEXT;
	if (!pContext) {
		printf("malloc failed");
		return;
	}
	memset(pContext, 0, sizeof(CONTEXT));
	pContext->ContextFlags = CONTEXT_ALL;
	printf("Getting thread context\r\n");
	if (!GetThreadContext(pProcessInfo->hThread, pContext))
	{
		printf("Error getting context\r\n");
		return;
	}
	printRegisters(pContext);
	pContext = s->thread;
	
	//pContext->Rax = s->thread->Rax;
	//pContext->Rbx = s->thread->Rbx;
	//pContext->Rcx = s->thread->Rcx;
	//pContext->Rdx = s->thread->Rdx;
	////pContext->R8  = s->thread->R8;
	////pContext->R9  = s->thread->R9;
	////pContext->R10 = s->thread->R10;
	////pContext->R11 = s->thread->R11;
	//pContext->R12 = s->thread->R12;
	//pContext->R13 = s->thread->R13;
	////pContext->R14 = s->thread->R14;
	////pContext->R15 = s->thread->R15;
	//pContext->Rip = s->thread->Rip;
	//pContext->Rsp = s->thread->Rsp;

	printRegisters(pContext);

	printf("Setting thread context\r\n");
	if (!SetThreadContext(pProcessInfo->hThread, pContext))
	{
		printf("Error setting context\r\n");
		return;
	}

	printf("Resuming thread again\r\n");
	if (!ResumeThread(pProcessInfo->hThread))
	{
		printf("Error resuming thread\r\n");
		return;
	}

	CloseHandle(pProcessInfo->hProcess);
	delete pStartupInfo;
	delete pProcessInfo;
	delete pContext;
}

int ThreadContextByProcess(DWORD th32ProcessID, PCONTEXT context) {
	HANDLE hThreadSnap = INVALID_HANDLE_VALUE;
	THREADENTRY32 te32;
	DWORD cntThreads = 1;
	DWORD c = 0;

	// Take a snapshot of all running threads  
	hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	if (hThreadSnap == INVALID_HANDLE_VALUE)
		return 0;

	// Fill in the size of the structure before using it. 
	te32.dwSize = sizeof(THREADENTRY32);

	// Retrieve information about the first thread,
	// and exit if unsuccessful
	if (!Thread32First(hThreadSnap, &te32))
	{
		CloseHandle(hThreadSnap);     // Must clean up the snapshot object!
		ErrorExit((LPTSTR)TEXT("Thread32First"));  // Show cause of failure
		return 0;
	}

	// Now walk the thread list of the system, and display information about each thread
	// associated with the specified process
	do
	{
		if (te32.th32OwnerProcessID == th32ProcessID && c < cntThreads)
		{
			HANDLE thread = OpenThread(THREAD_ALL_ACCESS, 0, te32.th32ThreadID);
			if (!thread) {
				ErrorExit((LPTSTR)L"OpenThread");
			}
			SuspendThread(thread);
			memset(context, 0, sizeof(CONTEXT));
			context->ContextFlags = CONTEXT_ALL;
			if (!GetThreadContext(thread, context)) {
				ErrorExit((LPTSTR)L"GetThreadContext");
			}
			ResumeThread(thread);
			CloseHandle(thread);
			CloseHandle(hThreadSnap);
			return 1;
		}
	} while (Thread32Next(hThreadSnap, &te32));
	CloseHandle(hThreadSnap);
	return 0;
}

int ReadState(WCHAR fname[], ProcessState* state) {
	PROCESSENTRY32 processEntry;
	HANDLE process = ProcessByExeName(fname, &processEntry);
	if (!process) {
		return 0;
	}
	state->processEntry = processEntry;

	state->thread = new CONTEXT;
	if (!state->thread) {
		printf("state->thread malloc failed.\n");
		return 0;
	}
	ThreadContextByProcess(processEntry.th32ProcessID, state->thread);
	printf("RIP: %p\n", state->thread->Rip);

	state->PEB = ReadRemotePEB(process);
	if (state->PEB == NULL) {
		ErrorExit((LPTSTR)TEXT("ReadProcessMemory"));
	}

	debugShowProcess(process);

	MEMORY_BASIC_INFORMATION mbi;
	LPVOID offset = 0;
	Memory* curmem = new Memory;
	if (!curmem) {
		return 0;
	}
	while (VirtualQueryEx(process, offset, &mbi, sizeof(mbi)))
	{
		//if ((mbi.Protect == PAGE_EXECUTE || mbi.Protect == PAGE_READWRITE || mbi.Protect == PAGE_READONLY || mbi.Protect == PAGE_EXECUTE_READWRITE || mbi.Protect == PAGE_EXECUTE_READ || mbi.Protect == PAGE_EXECUTE_WRITECOPY) &&
		if ((mbi.Protect == PAGE_EXECUTE_READWRITE) &&
			(mbi.State == MEM_COMMIT) &&
			(mbi.Type == MEM_PRIVATE || mbi.Type == MEM_IMAGE || mbi.Type == MEM_MAPPED))
		{
			if (state->mem == NULL) {
				state->mem = curmem;
			}
			else {
				curmem->next = new Memory;
				if (!curmem->next) {
					printf("curmem->next malloc failed.\n");
					return 0;
				}
				curmem = curmem->next;
			}

			curmem->offset = offset;
			curmem->mbi = mbi;
			curmem->next = 0;
			curmem->buf = new BYTE[mbi.RegionSize];
			//curmem->buf = malloc(sizeof(unsigned char) * mbi.RegionSize);
			if (!curmem->buf) {
				printf("curmem->buf malloc failed.\n");
				return 0;
			}
			ReadProcessMemory(process, mbi.BaseAddress, curmem->buf, mbi.RegionSize, NULL);
		}
		offset = (LPVOID)((UINT64)mbi.BaseAddress + mbi.RegionSize);
	}
	CloseHandle(process);
	return 1;
}

int main()
{
	ProcessState state = { 0 };
	if (!ReadState((WCHAR*)L"DummyProgram.exe", &state)) {
		printf("Could not find program.\n");
		return 1;
	}
	//dumpState(&state);
	RestartProcess(&state);
	printf("Done!");

	Memory* curmem = state.mem;
	Memory* next;
	while (!curmem) {
		next = curmem->next;
		delete curmem;
		curmem = next;
	}
	return 0;
}

#include <stdio.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <Windows.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <tchar.h>
#include <strsafe.h>
#include <psapi.h>

// Need to link with Ws2_32.lib
#pragma comment (lib, "Ws2_32.lib")
// #pragma comment (lib, "Mswsock.lib")

#include "internals.h"
#include "PE.h"
#include "general.h"

#include<iostream>
#include<vector>
#include <fstream>
#include<filesystem>

#define MIN(x, y) (((x) < (y)) ? (x) : (y))

using NtAllocateVirtualMemory = NTSTATUS (WINAPI*)(HANDLE ProcessHandle,
	PVOID* BaseAddress,
	ULONG ZeroBits,
	PULONG RegionSize,
	ULONG AllocationType,
	ULONG Protect);


typedef struct Memory_ {
	MEMORY_BASIC_INFORMATION mbi;
	LPVOID offset;
	unsigned char* buf;
	struct Memory_* next;
} Memory;

#define OBJECT_FILE L"File"
#define OBJECT_EVENT L"Event"
#define OBJECT_MUTEX L"Mutex"
#define OBJECT_SEMAPHORE L"Semaphore"
#define OBJECT_KEY L"Key"
#define OBJECT_DESKTOP L"Desktop"

typedef struct Object_ {
	ULONG addr;
	WCHAR type[30];
	WCHAR name[MAX_PATH+1];
	DWORD ftype;
	LARGE_INTEGER fpos;
	unsigned char* buf;
} Object;

typedef struct ProcessState_ {
	PROCESSENTRY32 processEntry;
	ULONG objLength;
	Object* objs;
	PVOID PebBaseAddress;
	PPEB PEB;
	PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
	PTEB TEB;
	ULONG threadLength;
	CONTEXT* threads;
	Memory* mem;
} ProcessState;

void printMemory(const Memory* m) {
	while (m != NULL) {
		printf("%p\t%p-%p\t%x\n",m->mbi.AllocationBase,m->mbi.BaseAddress,(DWORD64)m->mbi.BaseAddress+m->mbi.RegionSize,m->mbi.State,m->mbi.Protect);
		m = m->next;
	}
}

void Marshal(ProcessState* s, FILE *buf) {
	fwrite(&(s->processEntry), sizeof(PROCESSENTRY32), 1, buf);
	fwrite(&(s->PebBaseAddress), sizeof(PVOID), 1, buf);
	fwrite(s->PEB, sizeof(PEB), 1, buf);
	fwrite(s->ProcessParameters, sizeof(RTL_USER_PROCESS_PARAMETERS), 1, buf);
	fwrite(s->TEB, sizeof(TEB), 1, buf);
	fwrite(&(s->threadLength), sizeof(ULONG), 1, buf);
	fwrite(s->threads, sizeof(CONTEXT), s->threadLength, buf);
	//fwrite(s->mem, sizeof(Memory), 1, buf); // Note this is just the first memory page
	Memory* curmem = s->mem;
	while (curmem != NULL) {
		fwrite(&(curmem->mbi), sizeof(MEMORY_BASIC_INFORMATION), 1, buf);
		fwrite(&(curmem->offset), sizeof(LPCVOID), 1, buf);
		auto n = fwrite(curmem->buf, sizeof(unsigned char), (DWORD64)curmem->mbi.RegionSize, buf);
		fwrite(&(curmem->next), sizeof(Memory*), 1, buf);
		curmem = curmem->next;
	}
	fwrite(&(s->objLength), sizeof(ULONG), 1, buf);
	fwrite(s->objs, sizeof(Object), s->objLength, buf);
}

void UnMarshal(ProcessState* s, FILE* buf) {
	
	memset(s, 0, sizeof(ProcessState));

	fread(&(s->processEntry), sizeof(PROCESSENTRY32), 1, buf);
	fread(&(s->PebBaseAddress), sizeof(PVOID), 1, buf);
	s->PEB = new PEB();
	fread(s->PEB, sizeof(PEB), 1, buf);
	s->ProcessParameters = new RTL_USER_PROCESS_PARAMETERS();
	fread(s->ProcessParameters, sizeof(RTL_USER_PROCESS_PARAMETERS), 1, buf);
	s->TEB = new TEB();
	fread(s->TEB, sizeof(TEB), 1, buf);
	fread(&(s->threadLength), sizeof(ULONG), 1, buf);
	s->threads = new CONTEXT[s->threadLength]();
	fread(s->threads, sizeof(CONTEXT), s->threadLength, buf);
	s->mem = NULL;
	Memory* curmem = NULL;
	do {
		if (curmem) {
			curmem->next = new Memory();
			curmem = curmem->next;
		}
		else {
			curmem = new Memory();
			s->mem = curmem;
		} 
		fread(&(curmem->mbi), sizeof(MEMORY_BASIC_INFORMATION), 1, buf);
		fread(&(curmem->offset), sizeof(LPCVOID), 1, buf);
		curmem->buf = new unsigned char[(DWORD64)curmem->mbi.RegionSize]();
		auto n = fread(curmem->buf, sizeof(unsigned char), (DWORD64)curmem->mbi.RegionSize, buf);
		auto e = ferror(buf);
		auto eof = feof(buf);
		fread(&curmem->next, sizeof(Memory*), 1, buf);
	} while (curmem->next != NULL);
	fread(&(s->objLength), sizeof(ULONG), 1, buf);
	s->objs = new Object[s->objLength]();
	fread(s->objs, sizeof(Object), s->objLength, buf);
	return ;
}

DWORD64 getRegionsize(const Memory* m) {
	DWORD64 rs = 0;
	PVOID ab = m->mbi.AllocationBase;
	while (m->next != NULL && m->next->mbi.AllocationBase == ab) {
		m  = m->next;
	}
	rs = (DWORD64)m->mbi.BaseAddress - (DWORD64)m->mbi.AllocationBase + m->mbi.RegionSize;
	return rs;
}

std::vector<HANDLE> ThreadsByProcess(DWORD th32ProcessID) {
	std::vector<HANDLE> ts = {};
	HANDLE hThreadSnap = INVALID_HANDLE_VALUE;
	THREADENTRY32 te32;
	DWORD cntThreads = 1;
	DWORD c = 0;

	// Take a snapshot of all running threads  
	hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	if (hThreadSnap == INVALID_HANDLE_VALUE)
		return {};

	// Fill in the size of the structure before using it. 
	te32.dwSize = sizeof(THREADENTRY32);

	// Retrieve information about the first thread,
	// and exit if unsuccessful
	if (!Thread32First(hThreadSnap, &te32))
	{
		CloseHandle(hThreadSnap);     // Must clean up the snapshot object!
		ErrorExit((LPTSTR)TEXT("Thread32First"));  // Show cause of failure
		return {};
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
				return {};
			}
			ts.push_back(thread);
		}
	} while (Thread32Next(hThreadSnap, &te32));
	CloseHandle(hThreadSnap);
	return ts;
}

BOOL CloseThreadHandles(std::vector<HANDLE> ts) {
	for (HANDLE t : ts) {
		if (!CloseHandle(t)) {
			return false;
		}
	}
	return true;
}

BOOL SuspendThreads(const std::vector<HANDLE> ts) {
	for (HANDLE t : ts) {
		if (SuspendThread(t) == (DWORD)-1) {
			ErrorExit((LPTSTR)L"SuspendThread");
			return false;
		}
	}
	return true;
}

BOOL ResumeThreads(const std::vector<HANDLE> ts) {
	for (HANDLE t : ts) {
		if (!ResumeThread(t)) {
			ErrorExit((LPTSTR)L"ResumeThread");
			return false;
		}
	}
	return true;
}

void PrintThreads(const std::vector<HANDLE> ts) {
	printf("No. Threads: %d\n", ts.size());
	for (HANDLE t : ts) {
		printf("THREAD HANDLE: %p\n", t);
	}
}

#ifndef MAKEULONGLONG
#define MAKEULONGLONG(ldw, hdw) ((ULONGLONG(hdw) << 32) | ((ldw) & 0xFFFFFFFF))
#endif

HANDLE MainThread(const std::vector<HANDLE> ts) {
	HANDLE mt = 0;
	ULONGLONG ullMinCreateTime = ((ULONGLONG)~((ULONGLONG)0));

	for (HANDLE t : ts) {
		FILETIME afTimes[4] = { 0 };
		if (GetThreadTimes(t,
			&afTimes[0], &afTimes[1], &afTimes[2], &afTimes[3])) {
			ULONGLONG ullTest = MAKEULONGLONG(afTimes[0].dwLowDateTime,
				afTimes[0].dwHighDateTime);
			if (ullTest && ullTest < ullMinCreateTime) {
				ullMinCreateTime = ullTest;
				mt = t;
			}
		}
	}
	printf("MAIN THREAD: %p\n", mt);
	return mt;
}

BOOL ThreadContexts(const std::vector<HANDLE> ts, PCONTEXT contexts) {
	HANDLE mt = MainThread(ts);
	contexts->ContextFlags = CONTEXT_ALL;

	if (!GetThreadContext(mt, contexts)) {
		ErrorExit((LPTSTR)L"GetThreadContext");
		return false;
	}

	int i = 1;
	for (HANDLE t : ts) {
		if (t == mt) continue;
		contexts[i].ContextFlags = CONTEXT_ALL;
		if (!GetThreadContext(t, &(contexts[i]))) {
			ErrorExit((LPTSTR)L"GetThreadContext");
			return false;
		}
		i++;
	}
	return true;
}

PVOID GetLibraryProcAddress(LPCSTR LibraryName, LPCSTR ProcName)
{
	return GetProcAddress(GetModuleHandleA(LibraryName), ProcName);
}

void RestartProcess(const ProcessState* s, const LPSTR program) {
	printf("Creating process\r\n");

	LPSTARTUPINFOA pStartupInfo = new STARTUPINFOA();
	LPPROCESS_INFORMATION pProcessInfo = new PROCESS_INFORMATION();
	PVOID offset = 0;
	MEMORY_BASIC_INFORMATION mbi = {};

	pStartupInfo->cb = sizeof(STARTUPINFOA);

	if (!CreateProcessA
	(
		0,//s->processEntry.szExeFile,
		program, /*(LPSTR)"notepad", //*/
		0,
		0,
		0,
		CREATE_SUSPENDED, // | CREATE_NEW_CONSOLE, // | CREATE_NO_WINDOW,
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
	printf("PID: %d\n", pProcessInfo->dwProcessId);

	printf("Setting handles\r\n");

	HANDLE h;
	Object o;
	USHORT ctr = 0x04;
	for (int i = 0; i < s->objLength; i++) {
		o = s->objs[i];
		printf("Handle [%#x] : ctr: %#x %S %S\n", o.addr, ctr, o.type,o.name);

		// Skip inherited console handles
		if (ctr <= 0x10) { //TODO maybe check how many handle have been inherited?
			if (o.addr != 0 && !(wcscmp(o.type, OBJECT_FILE) == 0 && (o.ftype == 2))) {
				printf("WARNING: handle [%#x] will be a console handle instead of %S (%S)\n", o.addr, o.type, o.name);
			}
			ctr += 4;
			continue;
		}

		//If handle was nonexistant, create 'filler' handle
		if (o.addr == 0) {
			h = CreateMutex(0, 0, L"");
			DuplicateHandle(GetCurrentProcess(), h, pProcessInfo->hProcess, 0, 0, FALSE, DUPLICATE_SAME_ACCESS);
			ctr += 4;
			continue;
		}

		if (wcscmp(o.type, OBJECT_FILE) == 0) {
			printf("[%#x] File detected: %S (type:%x)\n", o.addr, o.name,o.ftype);

			if (o.ftype == 2 || wcscmp(o.name, L"\\Device\\ConDrv") == 0) {
				if ((HANDLE) ctr == s->ProcessParameters->StdInputHandle) {
					h = (HANDLE) 0x08;
					printf("INPUT: ");
				}
				else if ((HANDLE)ctr == s->ProcessParameters->StdOutputHandle) {
					h = (HANDLE)0x0C;
					printf("OUPUT: ");
				}
				else if ((HANDLE)ctr == s->ProcessParameters->StdErrorHandle) {
					h = (HANDLE)0x10;
					printf("ERROR: ");
				}
				else {
					printf("%x\n");
					h = (HANDLE) 0x4;
				}
				
				printf("Handle for console @%x: %x\n", ctr, (DWORD64) h);
				
				DuplicateHandle(pProcessInfo->hProcess, h, pProcessInfo->hProcess, 0, 0, TRUE, DUPLICATE_SAME_ACCESS);
				ctr += 4;
			}
			else {
				h = CreateFileW(o.name, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, 0, OPEN_ALWAYS, 0, 0);
				
				if (h == INVALID_HANDLE_VALUE) {
					ErrorExit((LPTSTR)TEXT("CreateFileW"));
					h = CreateFileW(L"C:\\Users\\Someone\\Desktop\\Test.txt", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, 0, OPEN_ALWAYS, 0, 0);
				}
				LARGE_INTEGER p{};
				SetFilePointerEx(h, o.fpos, &p, FILE_BEGIN);
				printf("File handle %x (pos: %d)\n", h, o.fpos);

				DuplicateHandle(GetCurrentProcess(), h, pProcessInfo->hProcess, 0, 0, 0, DUPLICATE_SAME_ACCESS);
				ctr += 4;
				CloseHandle(h);
			}
		}
		else if (wcscmp(o.type, OBJECT_EVENT) == 0) {
			if (*o.name) {
				h = CreateEventW(0, 0, 0, L"EVENT");
			}
			else {
				h = CreateEventW(0, 0, 0, 0);
			}
			

			if (DuplicateHandle(GetCurrentProcess(), h, pProcessInfo->hProcess, 0, 0, 0, DUPLICATE_SAME_ACCESS)) {
				ctr += 4;
			}
			else {
				printf("Handle [%#x] : %p %8S ERRR\n", o.addr, (void*) h, o.type, ctr);
			}
			
		}
		else if (wcscmp(o.type, OBJECT_KEY) == 0) {
			//RegCreateKeyW(HKEY_CLASSES_ROOT, o.name, (PHKEY) &h);
			h = h = CreateEventW(0, 0, 0, L"KEY");

			if (DuplicateHandle(GetCurrentProcess(), h, pProcessInfo->hProcess, 0, 0, 0, DUPLICATE_SAME_ACCESS)) {
				ctr += 4;
			}
			else {
				printf("Handle [%#x] : %p %8S ERRR : %S\n", o.addr, (void*)h, o.type, o.name);
			}
		}
		/*else if (wcscmp(o.type, OBJECT_DESKTOP) == 0) {
			h = (HANDLE) GetDesktopWindow();

			if (DuplicateHandle(GetCurrentProcess(), h, pProcessInfo->hProcess, 0, 0, 0, DUPLICATE_SAME_ACCESS)) {
				ctr += 4;
			}
			else {
				printf("Handle [%#x] : %p %8S ERRR\n", o.addr, (void*)h, o.type, ctr);
			}
		} */ else {
			//printf("%S\n", o.name);
			h = CreateSemaphore(0, 0, 1, 0);

			if (DuplicateHandle(GetCurrentProcess(), h, pProcessInfo->hProcess, 0, 0, 0, DUPLICATE_SAME_ACCESS)) {
				ctr += 4;
			}
			else {
				printf("Handle [%#x] : %p %8S ERRR\n", o.addr, (void*)h, o.type, ctr);
			}
		}
	}

	printf("Resuming thread\r\n");
	if (!ResumeThread(pProcessInfo->hThread))
	{
		printf("Error resuming thread\r\n");
		return;
	}
	printf("Waiting for the program to be ready\r\n");
	Sleep(4000);
	printf("Suspending thread again\r\n");
	if (SuspendThread(pProcessInfo->hThread) == (DWORD)-1)
	{
		printf("Error suspending thread\r\n");
		ErrorExit((LPTSTR)TEXT("SuspendThread"));
		//return;
	}

	std::vector<HANDLE> ts = ThreadsByProcess(pProcessInfo->dwProcessId);
	HANDLE mt = MainThread(ts);

	for (HANDLE t : ts) {
		if (t == mt) {
			continue;
		}
		TerminateThread(t, 0);
	}

	/*
	for (int i = 1; i < s->threadLength; i++) {
		auto hThread = CreateRemoteThread(pProcessInfo->hProcess, 0, 0, (LPTHREAD_START_ROUTINE)0, 0, CREATE_SUSPENDED, 0);
		SetThreadContext(hThread, &(s->threads[i]));
	}
	*/
	/*
	const char* buffer = "C:driversdllinject.dll";
	LPVOID arg = (LPVOID)VirtualAllocEx(pProcessInfo->hProcess, NULL, strnlen(buffer, 50), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	//int n = WriteProcessMemory(pProcessInfo->hProcess, arg, buffer, strnlen(buffer, 50), NULL);
	auto hThread = CreateRemoteThread(pProcessInfo->hProcess, 0, 0, (LPTHREAD_START_ROUTINE)MessageBoxA, arg, 0, 0);
	if (hThread == NULL) {
		printf("Error: the remote thread could not be created.\n");
	}
	else {
		printf("Running MessageBoxA...\n");
	}
	while (WaitForSingleObject(hThread, 200)) {};
	*/

	printf("Allocating memory\r\n");
	//UINT64 delta = (UINT64)pPEB->ImageBaseAddress - (UINT64)s->PEB->ImageBaseAddress;
	//printf("old: %p\tnew: %p\tdelta: %x\n", s->PEB->ImageBaseAddress, pPEB->ImageBaseAddress, delta);

	DWORD64 rip = s->threads[0].Rip;
	DWORD64 rsp = s->threads[0].Rsp;

	HMODULE ntdll = GetModuleHandleA("ntdll.dll");
	NtAllocateVirtualMemory myNtAllocateVirtualMemory = (NtAllocateVirtualMemory) GetProcAddress(ntdll, "NtAllocateVirtualMemory");

	Memory* curmem = s->mem;
	do {
		PVOID offset = curmem->mbi.AllocationBase;
		PVOID pRemoteImage;

		MEMORY_BASIC_INFORMATION mbi;
		SIZE_T Size = VirtualQueryEx
		(
			pProcessInfo->hProcess,
			curmem->mbi.BaseAddress,
			&mbi,
			sizeof(mbi)
		);
		
		DWORD64 end = (DWORD64)mbi.BaseAddress + mbi.RegionSize;
		printf("mem: (%p) %p (%6x)\t", curmem->mbi.AllocationBase, curmem->mbi.BaseAddress, curmem->mbi.RegionSize);
		printf("mbi:  %p-%p\t%x\t%x\t%x\t%x ", mbi.BaseAddress, end, mbi.Type, mbi.State, mbi.AllocationProtect, mbi.Protect);

		// Allocate full region if pages are free
		if (mbi.State == MEM_FREE) {
			SIZE_T rs = getRegionsize(curmem);
			NTSTATUS a = myNtAllocateVirtualMemory
			(
				pProcessInfo->hProcess,
				&offset,
				0,
				(PULONG) & (rs),
				MEM_RESERVE,
				PAGE_READWRITE
			);
			if (a != 0) {
				printf("myNtAllocateVirtualMemory: error code %x\n", a);
				curmem = curmem->next;
				continue;
			}
			printf("Allocated memory: %p (%x)\n", offset, rs);
		}
		offset = (PVOID)((DWORD64)offset + ((DWORD64)curmem->mbi.BaseAddress - (DWORD64)curmem->mbi.AllocationBase));
		pRemoteImage = offset;

		DWORD OldProtect = NULL;

		if (mbi.State != MEM_COMMIT) {
			pRemoteImage = VirtualAllocEx
			(
				pProcessInfo->hProcess,
				offset,
				curmem->mbi.RegionSize,
				MEM_COMMIT,
				PAGE_EXECUTE_READWRITE //curmem->mbi.AllocationProtect
			);
			if (!pRemoteImage)
			{
				printf("VirtualAllocEx to commit call failed, %p (%x)\r\n",offset, curmem->mbi.RegionSize);
				ErrorExit((LPTSTR)TEXT("VirtualAllocEx"));
				curmem = curmem->next;
				continue;
			}
			if (curmem->mbi.BaseAddress != pRemoteImage) {
				printf("old: %p\tnew: %p\tsize: %x\t", curmem->mbi.BaseAddress, pRemoteImage, curmem->mbi.RegionSize);
			}
			else {
				printf("new: %p (%x)\t", pRemoteImage, curmem->mbi.RegionSize);
			}
		} else {
			if (!VirtualProtectEx
			(
				pProcessInfo->hProcess,
				pRemoteImage,
				curmem->mbi.RegionSize,
				PAGE_EXECUTE_READWRITE,
				&OldProtect
			))
			{
				printf("Error setting allocation protect to READWRITE (%p, %x)\r\n", offset, curmem->mbi.RegionSize);
				ErrorExit((LPTSTR)TEXT("VirtualProtectEx"));
				curmem = curmem->next;
				continue;
			}
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
		}
		
		// Setting to original protection
		if (curmem->mbi.Protect == PAGE_WRITECOPY || curmem->mbi.Protect == PAGE_EXECUTE_WRITECOPY) {
			curmem->mbi.Protect = PAGE_READWRITE;
		}
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
			printf("Error setting allocation protect (%x\r\n");
			ErrorExit((LPTSTR)TEXT("VirtualProtectEx"));
			return;
		}
		printf("\n");

		/*if (s->thread->Rip >= (DWORD64)curmem->mbi.BaseAddress && (s->thread->Rip <= (DWORD64)curmem->mbi.BaseAddress + curmem->mbi.RegionSize)) {
			LONGLONG delta = (DWORD64)pRemoteImage - (DWORD64)curmem->mbi.BaseAddress;
			rip = s->thread->Rip + delta;
			printf("RIP: old %p\tnew: %p\n", s->thread->Rip, rip);

		}
		if (s->thread->Rsp >= (DWORD64)curmem->mbi.BaseAddress && (s->thread->Rsp <= (DWORD64)curmem->mbi.BaseAddress + curmem->mbi.RegionSize)) {
			LONGLONG delta = (DWORD64)pRemoteImage - (DWORD64)curmem->mbi.BaseAddress;
			rsp = s->thread->Rsp + delta;
			printf("RSP: old %p\tnew: %p\n", s->thread->Rsp, rip);

		}*/
		curmem = curmem->next;
	} while (curmem != NULL);

	
	printf("Adjusting PEB\r\n");

	PPEB PebBaseAddress = FindRemotePEB(pProcessInfo->hProcess);
	PPEB pPEB = ReadRemotePEB(pProcessInfo->hProcess);

	PVOID TebBaseAddress = FindRemoteTEB(pProcessInfo->hThread);
	PTEB pTEB = ReadRemoteTEB(pProcessInfo->hProcess, pProcessInfo->hThread);

	//PLOADED_IMAGE pImage = ReadRemoteImage(pProcessInfo->hProcess, pPEB->ImageBaseAddress);

	printf("ProcessParameters: %p -> %p\n", pPEB->ProcessParameters, s->PEB->ProcessParameters);
	PRTL_USER_PROCESS_PARAMETERS params = new _RTL_USER_PROCESS_PARAMETERS;
	if (!ReadProcessMemory(pProcessInfo->hProcess, pPEB->ProcessParameters, params, sizeof(_RTL_USER_PROCESS_PARAMETERS), 0)) {
		ErrorExit((LPTSTR)TEXT("ReadProcessMemory"));
	}

	PRTL_USER_PROCESS_PARAMETERS donorparams = new _RTL_USER_PROCESS_PARAMETERS;
	
	if (!ReadProcessMemory(pProcessInfo->hProcess, s->PEB->ProcessParameters, donorparams, sizeof(_RTL_USER_PROCESS_PARAMETERS), 0)) {
		ErrorExit((LPTSTR)TEXT("ReadProcessMemory"));
	}

	printf("%p - %p\n", params->StdInputHandle , donorparams->StdInputHandle);
	printf("%p - %p\n", params->StdOutputHandle, donorparams->StdOutputHandle);
	printf("%p - %p\n", params->StdErrorHandle, donorparams->StdErrorHandle);
	printf("%p - %p\n", params->ConsoleHandle, donorparams->ConsoleHandle);

	//params->StdInputHandle = donorparams->StdInputHandle;
	//params->StdOutputHandle = donorparams->StdOutputHandle;
	//params->StdErrorHandle = donorparams->StdErrorHandle;
	//params->ConsoleHandle = donorparams->ConsoleHandle;
	
	params->WindowTitle.Buffer        = donorparams->WindowTitle.Buffer;
	params->WindowTitle.Length        = donorparams->WindowTitle.Length;
	params->WindowTitle.MaximumLength = donorparams->WindowTitle.MaximumLength;

	params->Environment = donorparams->Environment;

	params->ImagePathName.Buffer        = donorparams->ImagePathName.Buffer;
	params->ImagePathName.Length        = donorparams->ImagePathName.Length;
	params->ImagePathName.MaximumLength = donorparams->ImagePathName.MaximumLength;

	params->CommandLine.Buffer        = donorparams->CommandLine.Buffer;
	params->CommandLine.Length        = donorparams->CommandLine.Length;
	params->CommandLine.MaximumLength = donorparams->CommandLine.MaximumLength;

	params->DesktopName.Buffer        = donorparams->DesktopName.Buffer;
	params->DesktopName.Length        = donorparams->DesktopName.Length;
	params->DesktopName.MaximumLength = donorparams->DesktopName.MaximumLength;
	
	if (!WriteProcessMemory(pProcessInfo->hProcess, pPEB->ProcessParameters, params, sizeof(_RTL_USER_PROCESS_PARAMETERS), 0)) {
		ErrorExit((LPTSTR)TEXT("WriteProcessMemory"));
	}

	pPEB->LoaderData = s->PEB->LoaderData;

	pPEB->ProcessHeap = s->PEB->ProcessHeap;
	
	pPEB->HeapSegmentReserve = s->PEB->HeapSegmentReserve;
	pPEB->HeapSegmentCommit = s->PEB->HeapSegmentCommit;
	pPEB->HeapDeCommitTotalFreeThreshold = s->PEB->HeapDeCommitTotalFreeThreshold;
	pPEB->HeapDeCommitFreeBlockThreshold = s->PEB->HeapDeCommitFreeBlockThreshold;
	pPEB->NumberOfHeaps = s->PEB->NumberOfHeaps;

	pPEB->ProcessHeaps = s->PEB->ProcessHeaps;

	pPEB->ImageBaseAddress = s->PEB->ImageBaseAddress;

	printf("PebBaseAddress: %p\n", PebBaseAddress);
	if (!WriteProcessMemory(pProcessInfo->hProcess, PebBaseAddress, pPEB, sizeof(PEB), 0)) {
		ErrorExit((LPTSTR)TEXT("WriteProcessMemory"));
	}
	
	printf("Adjusting TEB\r\n");
	pTEB->NtTib = s->TEB->NtTib;
	pTEB->EnvironmentPointer = s->TEB->EnvironmentPointer;
	pTEB->ThreadLocalStoragePointer = s->TEB->ThreadLocalStoragePointer;
	//CurrentLocale?

	printf("TebBaseAddress: %p\n", TebBaseAddress);
	if (!WriteProcessMemory(pProcessInfo->hProcess, TebBaseAddress, pTEB, sizeof(TEB), 0)) {
		ErrorExit((LPTSTR)TEXT("WriteProcessMemory"));
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
	pContext = &(s->threads[0]);
	//pContext->Rip = s->thread->Rip;
	//pContect->Eax = s->thread->Eax;

	printRegisters(pContext);

	printf("Setting thread context\r\n");
	if (!SetThreadContext(pProcessInfo->hThread, pContext))
	{
		printf("Error setting context\r\n");
		return;
	}
	
	FlushInstructionCache(pProcessInfo->hProcess, 0, 0);
	printf("Resuming thread again\r\n");
	
	//hThread = CreateRemoteThread(pProcessInfo->hProcess, 0, 0, (LPTHREAD_START_ROUTINE)puts, (PVOID)params->WindowTitle.Buffer, 0, 0);
	//while (WaitForSingleObject(hThread, 200)) {};
	
	printf("This is the moment you can attach a debugger.\nWaiting for input:");
	char cs[20];
	std::cin >> cs;

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

#define BUFSIZE 512

BOOL GetFileNameFromHandle(HANDLE hFile, TCHAR* pszFilename, TCHAR* fname)
{
	BOOL bSuccess = FALSE;
	HANDLE hFileMap;



	// Translate path with device name to drive letters.
	TCHAR szTemp[BUFSIZE];
	szTemp[0] = '\0';

	if (GetLogicalDriveStrings(BUFSIZE - 1, szTemp))
	{
		TCHAR szName[MAX_PATH];
		TCHAR szDrive[3] = TEXT(" :");
		BOOL bFound = FALSE;
		TCHAR* p = szTemp;

		do
		{
			// Copy the drive letter to the template string
			*szDrive = *p;

			// Look up each device name
			if (QueryDosDevice(szDrive, szName, MAX_PATH))
			{
				size_t uNameLen = _tcslen(szName);

				if (uNameLen < MAX_PATH)
				{
					bFound = _tcsnicmp(pszFilename, szName, uNameLen) == 0
						&& *(pszFilename + uNameLen) == _T('\\');

					if (bFound)
					{
						// Reconstruct pszFilename using szTempFile
						// Replace device path with DOS path
						TCHAR szTempFile[MAX_PATH];
						StringCchPrintf(szTempFile,
							MAX_PATH,
							TEXT("%s%s"),
							szDrive,
							pszFilename + uNameLen);
						StringCchCopyN(pszFilename, MAX_PATH + 1, szTempFile, _tcslen(szTempFile));
					}
				}
			}

			// Go to the next NULL character.
			while (*p++);
		} while (!bFound && *p); // end of string
	}
	_tprintf(TEXT("File name is %s\n"), pszFilename);
	memcpy(fname, pszFilename, sizeof(TCHAR) * (MAX_PATH + 1));
	return(bSuccess);
}

ULONG ReadHandles(HANDLE processHandle, ProcessState* state) {

	_NtQuerySystemInformation NtQuerySystemInformation =
		(_NtQuerySystemInformation) GetLibraryProcAddress("ntdll.dll", "NtQuerySystemInformation");
	_NtDuplicateObject NtDuplicateObject =
		(_NtDuplicateObject) GetLibraryProcAddress("ntdll.dll", "NtDuplicateObject");
	_NtQueryObject NtQueryObject =
		(_NtQueryObject) GetLibraryProcAddress("ntdll.dll", "NtQueryObject");
	NTSTATUS status;
	PSYSTEM_HANDLE_INFORMATION handleInfo;
	ULONG handleInfoSize = 0x10000;
	ULONG i;
	ULONG pid;
	ULONG length = 0;

	pid = GetProcessId(processHandle);

	handleInfo = (PSYSTEM_HANDLE_INFORMATION)malloc(handleInfoSize);

	/* NtQuerySystemInformation won't give us the correct buffer size,
		so we guess by doubling the buffer size. */
	while ((status = NtQuerySystemInformation(
		SystemHandleInformation,
		handleInfo,
		handleInfoSize,
		NULL
	)) == STATUS_INFO_LENGTH_MISMATCH)
		handleInfo = (PSYSTEM_HANDLE_INFORMATION)realloc(handleInfo, handleInfoSize *= 2);

	/* NtQuerySystemInformation stopped giving us STATUS_INFO_LENGTH_MISMATCH. */
	if (!NT_SUCCESS(status))
	{
		printf("NtQuerySystemInformation failed!\n");
		return 0;
	}

	state->objs = new Object[handleInfo->HandleCount]();

	for (i = 0; i < handleInfo->HandleCount; i++)
	{
		SYSTEM_HANDLE handle = handleInfo->Handles[i];
		HANDLE dupHandle = NULL;
		POBJECT_TYPE_INFORMATION objectTypeInfo;
		PVOID objectNameInfo;
		UNICODE_STRING objectName;
		ULONG returnLength;
		Object* o;

		/* Check if this handle belongs to the PID the user specified. */
		if (handle.ProcessId != pid)
			continue;

		/* Duplicate the handle so we can query it. */
		status = NtDuplicateObject(
			processHandle,
			(HANDLE)handle.Handle,
			GetCurrentProcess(),
			&dupHandle,
			0,
			0,
			0
		);

		if (!NT_SUCCESS(status))
		{
			printf("[%#x] Error! Could not duplicate handle\n", handle.Handle);
			continue;
		}

		/* Query the object type. */
		objectTypeInfo = (POBJECT_TYPE_INFORMATION)malloc(0x1000);
		if (!NT_SUCCESS(NtQueryObject(
			dupHandle,
			ObjectTypeInformation,
			objectTypeInfo,
			0x1000,
			NULL
		)))
		{
			printf("[%#x] Error! - %#x\n", handle.Handle, status);
			CloseHandle(dupHandle);
			continue;
		}


		o = new Object();
		o->addr = (ULONG)handle.Handle;
		wcscpy_s(o->type, min(objectTypeInfo->Name.Length / 2 + 1,30), objectTypeInfo->Name.Buffer);

		/* Query the object name (unless it has an access of
			0x0012019f, on which NtQueryObject could hang. */
		
		if (handle.GrantedAccess == 0x0012019f)
		{
			// We have the type, so display that.
			printf(
				"[%#x] %.*S: (did not get name )\n",
				handle.Handle,
				objectTypeInfo->Name.Length / 2,
				objectTypeInfo->Name.Buffer
			);
		}
		else {
			objectNameInfo = malloc(0x1000);
			if (!NT_SUCCESS(NtQueryObject(
				dupHandle,
				ObjectNameInformation,
				objectNameInfo,
				0x1000,
				&returnLength
			)))
			{
				/* Reallocate the buffer and try again. */
				objectNameInfo = realloc(objectNameInfo, returnLength);
				if (!NT_SUCCESS(NtQueryObject(
					dupHandle,
					ObjectNameInformation,
					objectNameInfo,
					returnLength,
					NULL
				)))
				{
					/* We have the type name, so just display that. */
					printf(
						"[%#x] %.*S: (could not get name)\n",
						handle.Handle,
						objectTypeInfo->Name.Length / 2,
						objectTypeInfo->Name.Buffer
					);
				}
			}
			else {
				/* Cast our buffer into an UNICODE_STRING. */
				objectName = *(PUNICODE_STRING)objectNameInfo;

				
				if (objectName.Length > 0) {
					//o->name = new wchar_t[objectName.Length + 1]();
					//o->name_length = objectName.Length + 1;
					wcscpy_s(o->name, min(objectName.Length/2+1,255), objectName.Buffer);
				}
				/*
				else {
					o->name = (PWSTR)L"";
				}*/
			}
			free(objectNameInfo);
		}

		if (wcscmp(o->type, L"File") == 0) {
			o->ftype = GetFileType(dupHandle);

			if (o->ftype == FILE_TYPE_DISK) {
				// SetFilePointex with offset=0 to get the current offset
				SetFilePointerEx(dupHandle, LARGE_INTEGER(), &(o->fpos), FILE_CURRENT);

				TCHAR buf[MAX_PATH + 1];
				GetFileNameFromHandle(dupHandle, o->name, buf);
				memcpy(o->name, buf, sizeof(TCHAR) * (MAX_PATH + 1));

				//HANDLE h = CreateFileW(o->name, GENERIC_READ, 0, 0, 0, OPEN_ALWAYS,0);
				//rewind((FILE*)dupHandle);
				//CHAR buf2[1000]{};
				//DWORD nread;

				auto path = std::filesystem::path(o->name);
				auto desktop = std::filesystem::path("C:\\Users\\Someone\\Desktop\\checkpoint");
				
				if (is_regular_file(path)) {
					auto dest = desktop / path.filename();
					//std::filesystem::copy(path, dest);
					auto fs = std::filesystem::file_size(path);
					std::unique_ptr<char[]> pData = std::make_unique<char[]>(fs);
					
					std::ifstream(path).read(pData.get(), fs);
					std::cout << pData.get() << "\n\n";
				}
				
				//ReadFile(h, buf2, 1000, &nread, 0);
				//ErrorExit((LPTSTR)TEXT("ReadFile"));
				
			}
			else if (o->ftype == FILE_TYPE_PIPE) {
				int buf{};
				int namelen = sizeof(buf);
				getsockopt((SOCKET)dupHandle, SOL_SOCKET, SO_ACCEPTCONN, (char*) buf, &namelen);
				printf(">>>> SOCKET: %d\n", buf);
			}
		}
		else if (wcscmp(o->type, L"Key") == 0) {
			// https://github.com/winsiderss/systeminformer/blob/master/phlib/hndlinfo.c#L739
		}

		o->buf = 0;
		state->objs[o->addr / 4 - 1] = *o;

		length = o->addr / 4;


		free(objectTypeInfo);
		
		CloseHandle(dupHandle);
	}

	free(handleInfo);
	state->objLength = length;
	return length;
}

int ReadState(WCHAR fname[], ProcessState* state) {
	PROCESSENTRY32 processEntry;
	HANDLE process = ProcessByExeName(fname, &processEntry);
	if (!process) {
		return 0;
	}
	state->processEntry = processEntry;

	std::vector<HANDLE> ts = ThreadsByProcess(processEntry.th32ProcessID);
	if (ts.size() == 0) {
		printf("Opening threads failed.\n");
		CloseThreadHandles(ts);
		return 0;
	}
	PrintThreads(ts);

	state->threadLength = ts.size();
	state->threads = new CONTEXT[state->threadLength]();
	if (!state->threads) {
		printf("state->thread malloc failed.\n");
		return 0;
	}

	HANDLE mt = MainThread(ts);

	if (!SuspendThreads(ts)) {
		printf("Suspending thread failed.\n");
		CloseThreadHandles(ts);
		return 0;
	}
	ThreadContexts(ts, state->threads);

	// printf("RIP: %p\n", state->thread->Rip);
	for (int i = 0; i < state->threadLength; i++) {
		printf("RIP #%d: %p\n", i, state->threads[i].Rip);
	}
	//printRegisters(&(state->threads[3]));

	state->PebBaseAddress = FindRemotePEB(process);

	state->TEB = ReadRemoteTEB(process, mt);
	printf("Stack: %p\n\n\n", state->TEB->NtTib.StackBase);

	
	state->objLength = ReadHandles(process, state);

	for (int i=0; i < state->objLength;i++) {
		Object o = state->objs[i];
		if (o.addr == 0) {
			continue;
		}
		printf("[%#x] %S %S %d %d\n", o.addr, o.type, o.name, o.ftype, o.fpos);
	}

	state->PEB = ReadRemotePEB(process);
	if (state->PEB == NULL) {
		ErrorExit((LPTSTR)TEXT("ReadProcessMemory"));
	}

	state->ProcessParameters = ReadRemoteProcessParameters(process, state->PEB);
	if (state->ProcessParameters == NULL) {
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
		if ( ( //(mbi.Protect == PAGE_EXECUTE || mbi.Protect == PAGE_READWRITE || mbi.Protect == PAGE_READONLY || mbi.Protect == PAGE_EXECUTE_READWRITE || mbi.Protect == PAGE_EXECUTE_READ || mbi.Protect == PAGE_EXECUTE_WRITECOPY) &&
		//if (  ((mbi.Protect == PAGE_EXECUTE_READWRITE) &&
			  (mbi.State == MEM_COMMIT)// &&
			  //(mbi.Type == MEM_PRIVATE || mbi.Type == MEM_IMAGE)
			) 
			||
			  (state->threads[0].Rsp >= (DWORD64)mbi.BaseAddress && state->threads[0].Rsp <= (DWORD64)mbi.BaseAddress + mbi.RegionSize)
		   )
		{
			if (state->mem == NULL) {
				state->mem = curmem;
			}
			else {
				curmem->next = new Memory();
				if (!curmem->next) {
					printf("curmem->next malloc failed.\n");
					return 0;
				}
				curmem = curmem->next;
			}
			curmem->offset = offset;
			curmem->mbi = mbi;
			curmem->next = 0;
			curmem->buf = new BYTE[mbi.RegionSize]();

			if (!curmem->buf) {
				printf("curmem->buf malloc failed.\n");
				return 0;
			}
			ReadProcessMemory(process, mbi.BaseAddress, curmem->buf, mbi.RegionSize, NULL);
		}
		offset = (LPVOID)((UINT64)mbi.BaseAddress + mbi.RegionSize);
	}
	
	if (!ResumeThreads(ts)) {
		printf("Resuming threads failed.\n");
		CloseThreadHandles(ts);
		return 0;
	}
	CloseThreadHandles(ts);

	CloseHandle(process);

	return 1;
}

int main()
{
	LPSTR program = (LPSTR)"Empty.exe";
	WCHAR* processname_to_copy = (WCHAR*)L"dummyprogram.exe";
	const CHAR* checkpoint_file = "checkpoint.dat";

	ProcessState state = { 0 };
	if (!ReadState(processname_to_copy, &state)) {
		printf("Could not find program.\n");

		FILE* temp2;
		fopen_s(&temp2, "checkpoint.dat", "r+b");
		//rewind(temp);
		ProcessState state2 = {};
		UnMarshal(&state2, temp2);
		fclose(temp2);

		RestartProcess(&state2, program);

		return 1;
	}

	printf("Testing marshal\n");

	FILE* temp;
	fopen_s(&temp, checkpoint_file, "w+b");
	  //tmpfile_s(&temp);
	Marshal(&state, temp);
	fclose(temp);

	  //rewind(temp);
	FILE* temp2;
	fopen_s(&temp2, checkpoint_file, "r+b");

	ProcessState state2 = {};
	UnMarshal(&state2, temp2);
	fclose(temp2);
	
	RestartProcess(&state2, program);
	printf("Done!\n\n");

	return 0;
}
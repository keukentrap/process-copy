
#include "windows.h"
#include "internals.h"
#include "PE.h"
#include "stdio.h"

PPEB  FindRemotePEB(HANDLE hProcess)
{
	HMODULE hNTDLL = LoadLibraryA("ntdll");

	if (!hNTDLL)
		return NULL;

	FARPROC fpNtQueryInformationProcess = GetProcAddress
	(
		hNTDLL,
		"NtQueryInformationProcess"
	);

	if (!fpNtQueryInformationProcess)
		return NULL;

	_NtQueryInformationProcess ntQueryInformationProcess =
		(_NtQueryInformationProcess)fpNtQueryInformationProcess;

	PROCESS_BASIC_INFORMATION* pBasicInfo = new PROCESS_BASIC_INFORMATION;
	if (!pBasicInfo) return 0;

	DWORD dwReturnLength = 0;

	NTSTATUS res = ntQueryInformationProcess
	(
		hProcess,
		0,
		pBasicInfo,
		sizeof(PROCESS_BASIC_INFORMATION),
		&dwReturnLength
	);
	if (res){
		return NULL;
	}
	return pBasicInfo->PebBaseAddress;
}

PEB* ReadRemotePEB(HANDLE hProcess)
{
	PVOID dwPEBAddress = (PVOID)FindRemotePEB(hProcess);
	printf("dwPEBAddress: %p\n", dwPEBAddress);

	PEB* pPEB = new PEB();
	if (!pPEB) return 0;
	//PEB* pPEB = dwPEBAddress;

	BOOL bSuccess = ReadProcessMemory
	(
		hProcess,
		(LPCVOID)dwPEBAddress,
		pPEB,
		sizeof(PEB),
		0
	);
	if (!bSuccess) return 0;

	return pPEB;
}

PRTL_USER_PROCESS_PARAMETERS ReadRemoteProcessParameters(HANDLE hProcess,PPEB peb) {
	PVOID dwProcessParametersAddress = (PVOID)peb->ProcessParameters;

	PRTL_USER_PROCESS_PARAMETERS pParams = new RTL_USER_PROCESS_PARAMETERS();

	BOOL bSuccess = ReadProcessMemory
	(
		hProcess,
		(LPCVOID)dwProcessParametersAddress,
		pParams,
		sizeof(RTL_USER_PROCESS_PARAMETERS),
		0
	);
	if (!bSuccess) return 0;

	return pParams;
}

PTEB  FindRemoteTEB(HANDLE hThread)
{
	HMODULE hNTDLL = LoadLibraryA("ntdll");

	if (!hNTDLL)
		return NULL;

	FARPROC fpNtQueryInformationThread = GetProcAddress
	(
		hNTDLL,
		"NtQueryInformationThread"
	);

	if (!fpNtQueryInformationThread)
		return NULL;

	_NtQueryInformationThread ntQueryInformationThread =
		(_NtQueryInformationThread)fpNtQueryInformationThread;

	THREAD_BASIC_INFORMATION* pBasicInfo = new THREAD_BASIC_INFORMATION;
	if (!pBasicInfo) return 0;

	DWORD dwReturnLength = 0;

	NTSTATUS res = ntQueryInformationThread
	(
		hThread,
		0,
		pBasicInfo,
		sizeof(THREAD_BASIC_INFORMATION),
		&dwReturnLength
	);
	printf("Result ntQueryInformationThread: %x\n", res);
	if (res) {
		return NULL;
	}
	return pBasicInfo->TebBaseAddress;
}

TEB* ReadRemoteTEB(HANDLE hProcess, HANDLE hThread)
{
	PVOID dwTEBAddress = (PVOID)FindRemoteTEB(hThread);
	printf("dwTEBAddress: %p\n", dwTEBAddress);
	if (dwTEBAddress == NULL) {
		return 0;
	}

	TEB* pTEB = new TEB;
	if (!pTEB) return 0;

	BOOL bSuccess = ReadProcessMemory
	(
		hProcess,
		(LPCVOID)dwTEBAddress,
		pTEB,
		sizeof(TEB),
		0
	);
	if (!bSuccess) return 0;

	return pTEB;
}

PLOADED_IMAGE ReadRemoteImage(HANDLE hProcess, LPCVOID lpImageBaseAddress)
{
	BYTE* lpBuffer = new BYTE[BUFFER_SIZE];
	if (!lpBuffer) return 0;

	BOOL bSuccess = ReadProcessMemory
	(
		hProcess,
		lpImageBaseAddress,
		lpBuffer,
		BUFFER_SIZE,
		0
	);

	if (!bSuccess)
		return 0;

	PIMAGE_DOS_HEADER pDOSHeader = (PIMAGE_DOS_HEADER)lpBuffer;

	PLOADED_IMAGE pImage = new LOADED_IMAGE;
	if (!pImage) return 0;
	memset(pImage, 0, sizeof(pImage));

	pImage->FileHeader =
		(PIMAGE_NT_HEADERS64)(lpBuffer + pDOSHeader->e_lfanew);

	pImage->NumberOfSections =
		pImage->FileHeader->FileHeader.NumberOfSections;

	pImage->Sections =
		(PIMAGE_SECTION_HEADER)(lpBuffer + pDOSHeader->e_lfanew +
			sizeof(IMAGE_NT_HEADERS64));


	return pImage;
}



//struct PROCESS_BASIC_INFORMATION {
//	PVOID Reserved1;
//	DWORD PebBaseAddress;
//	PVOID Reserved2[2];
//	DWORD UniqueProcessId;
//	PVOID Reserved3;
//};



typedef NTSTATUS(WINAPI* _NtUnmapViewOfSection)(
	HANDLE ProcessHandle,
	PVOID BaseAddress
	);

typedef NTSTATUS(WINAPI* _NtQueryInformationProcess)(
	HANDLE ProcessHandle,
	DWORD ProcessInformationClass,
	PVOID ProcessInformation,
	DWORD ProcessInformationLength,
	PDWORD ReturnLength
	);

typedef NTSTATUS(WINAPI* _NtQuerySystemInformation)(
	DWORD SystemInformationClass,
	PVOID SystemInformation,
	ULONG SystemInformationLength,
	PULONG ReturnLength
	);

typedef enum x_THREAD_INFORMATION_CLASS {
	ThreadBasicInformation,
	ThreadTimes,
	ThreadPriority,
	ThreadBasePriority,
	ThreadAffinityMask,
	ThreadImpersonationToken,
	ThreadDescriptorTableEntry,
	ThreadEnableAlignmentFaultFixup,
	ThreadEventPair,
	ThreadQuerySetWin32StartAddress,
	ThreadZeroTlsCell,
	ThreadPerformanceCount,
	ThreadAmILastThread,
	ThreadIdealProcessor,
	ThreadPriorityBoost,
	ThreadSetTlsArrayAddress,
	ThreadIsIoPending,
	ThreadHideFromDebugger


} xTHREAD_INFORMATION_CLASS, * xPTHREAD_INFORMATION_CLASS;

typedef NTSTATUS(WINAPI* _NtQueryInformationThread)(
	HANDLE               ThreadHandle,
	DWORD ThreadInformationClass,
	PVOID               ThreadInformation,
	ULONG                ThreadInformationLength,
	PULONG              ReturnLength
	);
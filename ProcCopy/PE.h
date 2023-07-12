#pragma once


#include <Ntsecapi.h>
#include <DbgHelp.h>

#define BUFFER_SIZE 0x2000

typedef struct _RTL_DRIVE_LETTER_CURDIR {
	USHORT                  Flags;
	USHORT                  Length;
	ULONG                   TimeStamp;
	UNICODE_STRING          DosPath;
} RTL_DRIVE_LETTER_CURDIR, * PRTL_DRIVE_LETTER_CURDIR;

typedef struct _LDR_MODULE {
	LIST_ENTRY              InLoadOrderModuleList;
	LIST_ENTRY              InMemoryOrderModuleList;
	LIST_ENTRY              InInitializationOrderModuleList;
	PVOID                   BaseAddress;
	PVOID                   EntryPoint;
	ULONG                   SizeOfImage;
	UNICODE_STRING          FullDllName;
	UNICODE_STRING          BaseDllName;
	ULONG                   Flags;
	SHORT                   LoadCount;
	SHORT                   TlsIndex;
	LIST_ENTRY              HashTableEntry;
	ULONG                   TimeDateStamp;
} LDR_MODULE, * PLDR_MODULE;

typedef struct _PEB_LDR_DATA {
	ULONG                   Length;
	BOOLEAN                 Initialized;
	PVOID                   SsHandle;
	LIST_ENTRY              InLoadOrderModuleList;
	LIST_ENTRY              InMemoryOrderModuleList;
	LIST_ENTRY              InInitializationOrderModuleList;
} PEB_LDR_DATA, * PPEB_LDR_DATA;

typedef struct _RTL_USER_PROCESS_PARAMETERS {
	ULONG                   MaximumLength;
	ULONG                   Length;
	ULONG                   Flags;
	ULONG                   DebugFlags;
	PVOID                   ConsoleHandle;
	ULONG                   ConsoleFlags;
	HANDLE                  StdInputHandle;
	HANDLE                  StdOutputHandle;
	HANDLE                  StdErrorHandle;
	UNICODE_STRING          CurrentDirectoryPath;
	HANDLE                  CurrentDirectoryHandle;
	UNICODE_STRING          DllPath;
	UNICODE_STRING          ImagePathName;
	UNICODE_STRING          CommandLine;
	PVOID                   Environment;
	ULONG                   StartingPositionLeft;
	ULONG                   StartingPositionTop;
	ULONG                   Width;
	ULONG                   Height;
	ULONG                   CharWidth;
	ULONG                   CharHeight;
	ULONG                   ConsoleTextAttributes;
	ULONG                   WindowFlags;
	ULONG                   ShowWindowFlags;
	UNICODE_STRING          WindowTitle;
	UNICODE_STRING          DesktopName;
	UNICODE_STRING          ShellInfo;
	UNICODE_STRING          RuntimeData;
	RTL_DRIVE_LETTER_CURDIR DLCurrentDirectory[0x20];
} RTL_USER_PROCESS_PARAMETERS, * PRTL_USER_PROCESS_PARAMETERS;

typedef struct  PEB_FREE_BLOCK _PEB_FREE_BLOCK;
typedef struct  PEB_FREE_BLOCK* PPEB_FREE_BLOCK;

struct PEB_FREE_BLOCK {
	_PEB_FREE_BLOCK* Next;
	ULONG                   Size;
} ;

typedef void (*PPEBLOCKROUTINE)(
	PVOID PebLock
	);

typedef PVOID* PPVOID;

typedef struct _PEB {
	BOOLEAN                 InheritedAddressSpace;
	BOOLEAN                 ReadImageFileExecOptions;
	BOOLEAN                 BeingDebugged;
	BOOLEAN                 Spare;
	HANDLE                  Mutant;
	PVOID                   ImageBaseAddress;
	PPEB_LDR_DATA           LoaderData;
	PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
	PVOID                   SubSystemData;
	PVOID                   ProcessHeap;
	PVOID                   FastPebLock;
	PPEBLOCKROUTINE         FastPebLockRoutine;
	PPEBLOCKROUTINE         FastPebUnlockRoutine;
	ULONG                   EnvironmentUpdateCount;
	PPVOID                  KernelCallbackTable;
	PVOID                   EventLogSection;
	PVOID                   EventLog;
	PPEB_FREE_BLOCK         FreeList;
	ULONG                   TlsExpansionCounter;
	PVOID                   TlsBitmap;
	ULONG                   TlsBitmapBits[0x2];
	PVOID                   ReadOnlySharedMemoryBase;
	PVOID                   ReadOnlySharedMemoryHeap;
	PPVOID                  ReadOnlyStaticServerData;
	PVOID                   AnsiCodePageData;
	PVOID                   OemCodePageData;
	PVOID                   UnicodeCaseTableData;
	ULONG                   NumberOfProcessors;
	ULONG                   NtGlobalFlag;
	BYTE                    Spare2[0x4];
	LARGE_INTEGER           CriticalSectionTimeout;
	ULONG                   HeapSegmentReserve;
	ULONG                   HeapSegmentCommit;
	ULONG                   HeapDeCommitTotalFreeThreshold;
	ULONG                   HeapDeCommitFreeBlockThreshold;
	ULONG                   NumberOfHeaps;
	ULONG                   MaximumNumberOfHeaps;
	PPVOID* ProcessHeaps;
	PVOID                   GdiSharedHandleTable;
	PVOID                   ProcessStarterHelper;
	PVOID                   GdiDCAttributeList;
	PVOID                   LoaderLock;
	ULONG                   OSMajorVersion;
	ULONG                   OSMinorVersion;
	ULONG                   OSBuildNumber;
	ULONG                   OSPlatformId;
	ULONG                   ImageSubSystem;
	ULONG                   ImageSubSystemMajorVersion;
	ULONG                   ImageSubSystemMinorVersion;
	ULONG                   GdiHandleBuffer[0x22];
	ULONG                   PostProcessInitRoutine;
	ULONG                   TlsExpansionBitmap;
	BYTE                    TlsExpansionBitmapBits[0x80];
	ULONG                   SessionId;

} PEB, * PPEB;

typedef struct _PROCESS_BASIC_INFORMATION {
	NTSTATUS ExitStatus;
	PPEB PebBaseAddress;
	ULONG_PTR AffinityMask;
	PVOID BasePriority;
	ULONG_PTR UniqueProcessId;
	ULONG_PTR InheritedFromUniqueProcessId;
} PROCESS_BASIC_INFORMATION;

typedef struct BASE_RELOCATION_BLOCK {
	DWORD PageAddress;
	DWORD BlockSize;
} BASE_RELOCATION_BLOCK, * PBASE_RELOCATION_BLOCK;

typedef struct BASE_RELOCATION_ENTRY {
	USHORT Offset : 12;
	USHORT Type : 4;
} BASE_RELOCATION_ENTRY, * PBASE_RELOCATION_ENTRY;

#define CountRelocationEntries(dwBlockSize)		\
	(dwBlockSize -								\
	sizeof(BASE_RELOCATION_BLOCK)) /			\
	sizeof(BASE_RELOCATION_ENTRY)

//inline PEB* GetPEB()
//{
//	__asm mov eax, dword ptr fs : 0x30;
//}

inline PIMAGE_NT_HEADERS GetNTHeaders(DWORD64 dwImageBase)
{
	return (PIMAGE_NT_HEADERS)(dwImageBase +
		((PIMAGE_DOS_HEADER)dwImageBase)->e_lfanew);
}

inline PLOADED_IMAGE GetLoadedImage(DWORD64 dwImageBase)
{
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)dwImageBase;
	//PIMAGE_NT_HEADERS pNTHeaders = GetNTHeaders(dwImageBase);

	PLOADED_IMAGE pImage = (PLOADED_IMAGE) malloc(sizeof(pImage));
	if (!pImage) return 0;

	pImage->FileHeader =
		(PIMAGE_NT_HEADERS)(dwImageBase + pDosHeader->e_lfanew);

	pImage->NumberOfSections =
		pImage->FileHeader->FileHeader.NumberOfSections;

	pImage->Sections =
		(PIMAGE_SECTION_HEADER)(dwImageBase + pDosHeader->e_lfanew +
			sizeof(IMAGE_NT_HEADERS32));

	return pImage;
}

inline char* GetDLLName(DWORD dwImageBase,
	IMAGE_IMPORT_DESCRIPTOR ImageImportDescriptor)
{
	return (char*)(dwImageBase + ImageImportDescriptor.Name);
}

inline IMAGE_DATA_DIRECTORY GetImportDirectory(PIMAGE_NT_HEADERS32 pFileHeader)
{
	return pFileHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
}

inline PIMAGE_IMPORT_DESCRIPTOR GetImportDescriptors(PIMAGE_NT_HEADERS32 pFileHeader,
	IMAGE_DATA_DIRECTORY ImportDirectory)
{
	return (PIMAGE_IMPORT_DESCRIPTOR)(pFileHeader->OptionalHeader.ImageBase +
		ImportDirectory.VirtualAddress);
}

inline PIMAGE_THUNK_DATA32 GetILT(DWORD dwImageBase,
	IMAGE_IMPORT_DESCRIPTOR ImageImportDescriptor)
{
	return (PIMAGE_THUNK_DATA32)(dwImageBase + ImageImportDescriptor.OriginalFirstThunk);
}

inline PIMAGE_THUNK_DATA32 GetIAT(DWORD dwImageBase,
	IMAGE_IMPORT_DESCRIPTOR ImageImportDescriptor)
{
	return (PIMAGE_THUNK_DATA32)(dwImageBase + ImageImportDescriptor.FirstThunk);
}

inline PIMAGE_IMPORT_BY_NAME GetImportByName(DWORD dwImageBase,
	IMAGE_THUNK_DATA32 itdImportLookup)
{
	return (PIMAGE_IMPORT_BY_NAME)(dwImageBase + itdImportLookup.u1.AddressOfData);
}


//extern std::map<PWSTR, std::vector<DWORD>> gCodeChecksums;

void WalkLoadOrderModules(void (*pLdrModuleFunction)(PLDR_MODULE, DWORD, PVOID), PVOID pParameters);

//void GenerateCodeChecksums(PLDR_MODULE pLdrModule, std::vector<DWORD>* pChecksums);

void SetInitialLdrCodeChecksums(PLDR_MODULE pLdrModule, DWORD dwIndex, PVOID pParams);

void ValidateLdrCodeChecksums(PLDR_MODULE pLdrModule, DWORD dwIndex, PVOID pParams);

typedef struct _IAT_BACKUP_INFO {
	DWORD BackupLength;
	DWORD*** IATBackup;
} IAT_BACKUP_INFO, * PIAT_BACKUP_INFO;

DWORD** BackupIAT(DWORD dwImageBase);

void RepairIAT(DWORD dwImageBase, DWORD** pIATBackup);

PPEB FindRemotePEB(HANDLE hProcess);

PEB* ReadRemotePEB(HANDLE hProcess);

PRTL_USER_PROCESS_PARAMETERS ReadRemoteProcessParameters(HANDLE hProcess, PPEB peb);

PLOADED_IMAGE ReadRemoteImage(HANDLE hProcess, LPCVOID lpImageBaseAddress);

typedef struct _CLIENT_ID
{
	PVOID UniqueProcess;
	PVOID UniqueThread;
} CLIENT_ID, * PCLIENT_ID;

typedef struct _RTL_ACTIVATION_CONTEXT_STACK_FRAME
{
	_RTL_ACTIVATION_CONTEXT_STACK_FRAME* Previous;
	_ACTIVATION_CONTEXT* ActivationContext;
	ULONG Flags;
} RTL_ACTIVATION_CONTEXT_STACK_FRAME, * PRTL_ACTIVATION_CONTEXT_STACK_FRAME;


typedef struct _ACTIVATION_CONTEXT_STACK
{
	PRTL_ACTIVATION_CONTEXT_STACK_FRAME ActiveFrame;
	LIST_ENTRY FrameListCache;
	ULONG Flags;
	ULONG NextCookieSequenceNumber;
	ULONG StackId;
} ACTIVATION_CONTEXT_STACK, * PACTIVATION_CONTEXT_STACK;

typedef struct _GDI_TEB_BATCH
{
	ULONG Offset;
	ULONG HDC;
	ULONG Buffer[310];
} GDI_TEB_BATCH, * PGDI_TEB_BATCH;

typedef struct _TEB_ACTIVE_FRAME_CONTEXT
{
	ULONG Flags;
	CHAR* FrameName;
} TEB_ACTIVE_FRAME_CONTEXT, * PTEB_ACTIVE_FRAME_CONTEXT;

typedef struct _TEB_ACTIVE_FRAME
{
	ULONG Flags;
	_TEB_ACTIVE_FRAME* Previous;
	PTEB_ACTIVE_FRAME_CONTEXT Context;
} TEB_ACTIVE_FRAME, * PTEB_ACTIVE_FRAME;


typedef struct _TEB
{
	NT_TIB NtTib;
	PVOID EnvironmentPointer;
	CLIENT_ID ClientId;
	PVOID ActiveRpcHandle;
	PVOID ThreadLocalStoragePointer;
	PPEB ProcessEnvironmentBlock;
	ULONG LastErrorValue;
	ULONG CountOfOwnedCriticalSections;
	PVOID CsrClientThread;
	PVOID Win32ThreadInfo;
	ULONG User32Reserved[26];
	ULONG UserReserved[5];
	PVOID WOW32Reserved;
	ULONG CurrentLocale;
	ULONG FpSoftwareStatusRegister;
	VOID* SystemReserved1[54];
	LONG ExceptionCode;
	PACTIVATION_CONTEXT_STACK ActivationContextStackPointer;
	UCHAR SpareBytes1[36];
	ULONG TxFsContext;
	GDI_TEB_BATCH GdiTebBatch;
	CLIENT_ID RealClientId;
	PVOID GdiCachedProcessHandle;
	ULONG GdiClientPID;
	ULONG GdiClientTID;
	PVOID GdiThreadLocalInfo;
	ULONG Win32ClientInfo[62];
	VOID* glDispatchTable[233];
	ULONG glReserved1[29];
	PVOID glReserved2;
	PVOID glSectionInfo;
	PVOID glSection;
	PVOID glTable;
	PVOID glCurrentRC;
	PVOID glContext;
	ULONG LastStatusValue;
	UNICODE_STRING StaticUnicodeString;
	WCHAR StaticUnicodeBuffer[261];
	PVOID DeallocationStack;
	VOID* TlsSlots[64];
	LIST_ENTRY TlsLinks;
	PVOID Vdm;
	PVOID ReservedForNtRpc;
	VOID* DbgSsReserved[2];
	ULONG HardErrorMode;
	VOID* Instrumentation[9];
	GUID ActivityId;
	PVOID SubProcessTag;
	PVOID EtwLocalData;
	PVOID EtwTraceData;
	PVOID WinSockData;
	ULONG GdiBatchCount;
	UCHAR SpareBool0;
	UCHAR SpareBool1;
	UCHAR SpareBool2;
	UCHAR IdealProcessor;
	ULONG GuaranteedStackBytes;
	PVOID ReservedForPerf;
	PVOID ReservedForOle;
	ULONG WaitingOnLoaderLock;
	PVOID SavedPriorityState;
	ULONG SoftPatchPtr1;
	PVOID ThreadPoolData;
	VOID** TlsExpansionSlots;
	ULONG ImpersonationLocale;
	ULONG IsImpersonating;
	PVOID NlsCache;
	PVOID pShimData;
	ULONG HeapVirtualAffinity;
	PVOID CurrentTransactionHandle;
	PTEB_ACTIVE_FRAME ActiveFrame;
	PVOID FlsData;
	PVOID PreferredLanguages;
	PVOID UserPrefLanguages;
	PVOID MergedPrefLanguages;
	ULONG MuiImpersonation;
	WORD CrossTebFlags;
	ULONG SpareCrossTebBits : 16;
	WORD SameTebFlags;
	ULONG DbgSafeThunkCall : 1;
	ULONG DbgInDebugPrint : 1;
	ULONG DbgHasFiberData : 1;
	ULONG DbgSkipThreadAttach : 1;
	ULONG DbgWerInShipAssertCode : 1;
	ULONG DbgRanProcessInit : 1;
	ULONG DbgClonedThread : 1;
	ULONG DbgSuppressDebugMsg : 1;
	ULONG SpareSameTebBits : 8;
	PVOID TxnScopeEnterCallback;
	PVOID TxnScopeExitCallback;
	PVOID TxnScopeContext;
	ULONG LockCount;
	ULONG ProcessRundown;
	UINT64 LastSwitchTime;
	UINT64 TotalSwitchOutTime;
	LARGE_INTEGER WaitReasonBitMap;
} TEB, * PTEB;

typedef struct {
	ULONG PriorityClass;
	ULONG PrioritySubClass;
} KSPRIORITY, * PKSPRIORITY;

typedef struct _THREAD_BASIC_INFORMATION {
	NTSTATUS                ExitStatus;
	PTEB                   TebBaseAddress;
	CLIENT_ID               ClientId;
	KAFFINITY               AffinityMask;
	LONG                    Priority;       // KPRIORITY in ntexapi.h
	LONG                    BasePriority;   // KPRIORITY in ntexapi.h
} THREAD_BASIC_INFORMATION, * PTHREAD_BASIC_INFORMATION;

PTEB FindRemoteTEB(HANDLE hThread);

TEB* ReadRemoteTEB(HANDLE hProcess, HANDLE hThread);


// ==== HANDLES =====

#define NT_SUCCESS(x) ((x) >= 0)
#define STATUS_INFO_LENGTH_MISMATCH 0xc0000004

#define SystemHandleInformation 16
#define ObjectBasicInformation 0
#define ObjectNameInformation 1
#define ObjectTypeInformation 2

typedef NTSTATUS(NTAPI* _NtQuerySystemInformation)(
	ULONG SystemInformationClass,
	PVOID SystemInformation,
	ULONG SystemInformationLength,
	PULONG ReturnLength
	);
typedef NTSTATUS(NTAPI* _NtDuplicateObject)(
	HANDLE SourceProcessHandle,
	HANDLE SourceHandle,
	HANDLE TargetProcessHandle,
	PHANDLE TargetHandle,
	ACCESS_MASK DesiredAccess,
	ULONG Attributes,
	ULONG Options
	);
typedef NTSTATUS(NTAPI* _NtQueryObject)(
	HANDLE ObjectHandle,
	ULONG ObjectInformationClass,
	PVOID ObjectInformation,
	ULONG ObjectInformationLength,
	PULONG ReturnLength
	);

typedef struct _OBJECT_ATTRIBUTES {
	ULONG           Length;
	HANDLE          RootDirectory;
	PUNICODE_STRING ObjectName;
	ULONG           Attributes;
	PVOID           SecurityDescriptor;
	PVOID           SecurityQualityOfService;
} OBJECT_ATTRIBUTES, * POBJECT_ATTRIBUTES;

typedef struct _IO_STATUS_BLOCK {
	union {
		NTSTATUS Status;
		PVOID    Pointer;
	};
	ULONG_PTR Information;
} IO_STATUS_BLOCK, * PIO_STATUS_BLOCK;

typedef NTSTATUS(NTAPI* _NtOpenFile)(
	PHANDLE            FileHandle,
	ACCESS_MASK        DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes,
	PIO_STATUS_BLOCK   IoStatusBlock,
	ULONG              ShareAccess,
	ULONG              OpenOptions
);



typedef struct _SYSTEM_HANDLE
{
	ULONG ProcessId;
	BYTE ObjectTypeNumber;
	BYTE Flags;
	USHORT Handle;
	PVOID Object;
	ACCESS_MASK GrantedAccess;
} SYSTEM_HANDLE, * PSYSTEM_HANDLE;

typedef struct _SYSTEM_HANDLE_INFORMATION
{
	ULONG HandleCount;
	SYSTEM_HANDLE Handles[1];
} SYSTEM_HANDLE_INFORMATION, * PSYSTEM_HANDLE_INFORMATION;

typedef enum _POOL_TYPE
{
	NonPagedPool,
	PagedPool,
	NonPagedPoolMustSucceed,
	DontUseThisType,
	NonPagedPoolCacheAligned,
	PagedPoolCacheAligned,
	NonPagedPoolCacheAlignedMustS
} POOL_TYPE, * PPOOL_TYPE;

typedef struct _OBJECT_TYPE_INFORMATION
{
	UNICODE_STRING Name;
	ULONG TotalNumberOfObjects;
	ULONG TotalNumberOfHandles;
	ULONG TotalPagedPoolUsage;
	ULONG TotalNonPagedPoolUsage;
	ULONG TotalNamePoolUsage;
	ULONG TotalHandleTableUsage;
	ULONG HighWaterNumberOfObjects;
	ULONG HighWaterNumberOfHandles;
	ULONG HighWaterPagedPoolUsage;
	ULONG HighWaterNonPagedPoolUsage;
	ULONG HighWaterNamePoolUsage;
	ULONG HighWaterHandleTableUsage;
	ULONG InvalidAttributes;
	GENERIC_MAPPING GenericMapping;
	ULONG ValidAccess;
	BOOLEAN SecurityRequired;
	BOOLEAN MaintainHandleCount;
	USHORT MaintainTypeList;
	POOL_TYPE PoolType;
	ULONG PagedPoolUsage;
	ULONG NonPagedPoolUsage;
} OBJECT_TYPE_INFORMATION, * POBJECT_TYPE_INFORMATION;



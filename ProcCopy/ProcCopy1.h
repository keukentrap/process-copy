#include <Windows.h>
#include <TlHelp32.h>
#include <strsafe.h>
#include "internals.h"
#include "PE.h"

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
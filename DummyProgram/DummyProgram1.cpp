// DummyProgram.cpp : This file contains the 'main' function. Program execution begins and ends there.
//
#include<Windows.h>
#include<stdio.h>

extern void __fastcall  loop_func();

// start:
//   inc eax    ; FF C0
//   jmp start  ; EB FC
const char payload[] = "\xff\xc0\xeb\xfc";

int main()
{
    void *buf = VirtualAlloc(NULL, sizeof(payload), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

    if (!buf) {
        printf("ALLOC FAILED\n");
        return 1;
    }
    memcpy(buf, payload, sizeof(payload));
    (*(void (*)()) buf)();
    return 0;
}

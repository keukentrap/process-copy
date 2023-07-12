#pragma once

#include <Windows.h>
#include <TlHelp32.h>

#include <stdio.h>

#define MIN(x, y) (((x) < (y)) ? (x) : (y))

boolean isExecutable(DWORD ap);

void ErrorExit(LPTSTR lpszFunction);

HANDLE ProcessByExeName(const WCHAR fname[], PROCESSENTRY32* processEntry);

void debugShowProcess(HANDLE process);

void printRegisters(const PCONTEXT t);

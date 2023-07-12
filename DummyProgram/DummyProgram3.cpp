#include<Windows.h>
#include<stdio.h>
#include<Dll1.h>

int g = 1;
LPWCH l;

int foo(int a, void*ph) {
	a += g;
	g++;
	
	Sleep(500);
	void* p = HeapAlloc(ph, 0, 0x40);
	HeapFree(ph, 0, p);
	ShowMsg();
	return a;
}

int main()
{
	
	//SetStdHandle(STD_ERROR_HANDLE, (HANDLE)STD_OUTPUT_HANDLE);
	void* ph = GetProcessHeap();
	int a = 0;
	while (1) { a = foo(a,ph); }

	printf("a: %d",a);
}

// crt_ftell.c
// This program opens a file named CRT_FTELL.C
// for reading and tries to read 100 characters. It
// then uses ftell to determine the position of the
// file pointer and displays this position.

#include <Windows.h>
#include <stdio.h>
#include <iostream>

FILE* stream;

int main(void)
{
    HWND h = GetDesktopWindow();
    long position;
    char list[105]{};
    if (fopen_s(&stream, "C:\\Users\\Someone\\Desktop\\Test2.txt", "rb") == 0)
    {
        while (1) {
            // Move the pointer by reading data:
            ZeroMemory(list, 100);
            fread(list, sizeof(char), 100, stream);
            for (int i = 0; i < 100; i++) {
                printf("%c", list[i]);
            }
            printf("\n");
            // Get position after read:
            //position = ftell(stream);
            //printf("Position after trying to read 100 bytes: %ld\n", position);
            
            /*
            fclose(stream);

            errno_t err{};
            if ( (err = fopen_s(&stream, "C:\\Users\\Someone\\Desktop\\Test.txt", "rb")) && err) {
                printf(":( %d\n",err);
                Sleep(5000);
                return 1;
            }
            */
            HANDLE e = CreateEvent(0, 0, 0, L"Meme");
            Sleep(700);
            //char c[20]{};
            //scanf_s("%8s", &c, 19);
            fseek(stream, rand()%200, SEEK_SET);
        }
        
        fclose(stream);
    }
}

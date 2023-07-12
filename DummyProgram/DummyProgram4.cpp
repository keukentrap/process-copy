#include<Windows.h>
#include<stdio.h>
#include<conio.h>

int main()
{
	char pw[20];
	printf("enter secret code: ");
	int i = 0;
	while ((pw[i] = _getch()) != '\n' && pw[i] != '\r' && i < 19)
	{
		putchar('*');
		i++;
	}
	pw[i] = '\0';
	printf("\n");
	if (strncmp(pw, "stonksonlygoup",20) != 0) {
		printf("ACCESS DENIED\n");
		return 1;
	}
	printf("ACCESS GRANTED\n");
	int j = rand() % 100;
	i = 0;
	while (1) { 
		printf("#%04d %2d Jet fuel can't melt steel memes\n",i,j);
		Sleep(690);
		j = rand() % 100;
		i++;
	}
}

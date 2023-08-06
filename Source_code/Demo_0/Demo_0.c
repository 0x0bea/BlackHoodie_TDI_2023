#include <stdio.h>
#include <stdlib.h>
#include <string.h>

char encrypted[] = "Boffe*Mbcnxk";

int main(void)
{
	size_t length = sizeof(encrypted) / sizeof(encrypted[0]);
	int key = 0x0a;

	for (int i = 0; i < length; i++)
	{
		encrypted[i] = encrypted[i] ^ key;
		printf("%c", encrypted[i]);
	}

	printf("Press ENTER to Continue\n");
	getchar();

	return 0;
}
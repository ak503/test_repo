#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <syslog.h>

#define MAX_SIZE 50

static void printMAS(char* mas, int size) {
	int i;
	for (i = 0; i < size; i++)
		printf("%c",  mas[i]);
	printf("\n");
	return;
}

static void  sortBubb (char *mas, int size)
{
	char curretn,t;
	int i,j;
	for ( i = 0; i < size ; i++) {
		for (j = 1; j < size-i ; j++) {
			if (mas[j] < mas[j-1]){
				t=mas[j];
				mas[j] = mas[j-1];
				mas[j-1] = t;
			}
		}
	}
	//printMAS(mas, 3);
	return;
}


int main(int argc, char **argv)
{
	char mas[MAX_SIZE] = "wefwqejihgfedcbawefqwfeadcadsaeaecadcqecaeacdscsadcwqe";
	int i = 0;
	
	printMAS(mas, MAX_SIZE);
	sortBubb(mas, MAX_SIZE);
	printf("------------\n");
	printMAS(mas, MAX_SIZE);
	
	return 0;
}

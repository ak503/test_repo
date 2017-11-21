#include <stdio.h>
#include <string.h>

int cnt=0;
void print_mas(char * mas, int size)
{
	int i;
	for (i = 0; i < size; i ++  )
		printf("%c", mas[i]);
	printf("\n");
	return;
}

void sort_mas_BOOBLE(char * mas, int size) {
	int i,j;
	char t;
	int swap = 0;
	
	for ( i = 0 ; i < size; i++) {
		for ( j = 1 ; j < size-i ; j++) {
			if (mas[j] < mas[j-1]) {
				t = mas[j];
				mas[j] = mas[j-1];
				mas[j-1] = t;
			} 
			cnt++;
		}
	}
	return;
}

void sort_mas_SELECT(char * mas, int size) {
	int i,j, num;
	char t, min;
	int swap = 0;
	
	for ( i = 0 ; i < size-1; i++) {
		swap = 0;
		t = mas[i];
		num = i;
		for ( j = i+1 ; j < size ; j++) {
			if (t > mas[j]) {
				t = mas[j];
				num = j;
				swap = 1;
			}
			cnt++;
		}
		if (swap ==1){
			mas[num] = mas[i];
			mas[i] = t;
		}
	}
	return;
}

int binary_search(char *items, int count, char key)
{
int low, high, mid;
low = 0; high = count-1;
while(low <= high) {
mid = (low+high)/2;
if(key < items[mid]) high = mid-1;
else if(key > items[mid]) low = mid+1;
else return mid; /* ключ найден */
}return -1;
}

int bin_search (char *mas, int size,char key) {


	int fst, last, mid;
	fst = 0;
	last = size-1;
	while (fst <= last) {
		mid = (last + fst)/2;
		if  (key > mas[mid])
			fst = mid + 1;
		else if( key < mas[mid])
			last = mid - 1;
		else return mid;
	}

}


void * main () {
	char mas[] = "aabbcdefghijklmnopqrstuvwxyz";
	int MAS_SIZE = strlen(mas);
	print_mas(mas, MAS_SIZE);
	//sort_mas_BOOBLE (mas, MAS_SIZE);
	//sort_mas_SELECT (mas, MAS_SIZE);
	//select (mas, MAS_SIZE);
	//print_mas(mas, MAS_SIZE);
	//printf("cnt: %d\n", cnt);
	int n=0;
	n = bin_search (mas,MAS_SIZE, 'c');
	printf("key2: %d\n", n);
	return 0;
}

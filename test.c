#include <string.h>
#include <stdlib.h>
#include <stdio.h>

int main(int argc, char **argv)
{
	//int rc = 1;
	printf("Main\n");

	fflush(stdin);
	fflush(stdout);
	FILE * f;
	//f = fdopen(0, "r");
	char *buf;
	while(1){
		f = fdopen(1, "r");
		if( f )
	{		fread(buf, 256, 1, f);
			printf("%s", buf);
			fclose(f);
		
	}	//return 0;

	}
	return 0;
}

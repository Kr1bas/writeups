
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char *argv[])
{
	if (argc<2){ return -1;}
	char* ptr;
	int seed = strtol(argv[1], &ptr,10);
	srand(seed);
	for( int i = 10 ; i < 1000000000 ; i*=10 ) {
		printf("%d,", rand() % i + 1);
	}
	printf("0");
	return 0;
}

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define SIZE 3


int func(int a, int b, int c){
	if(a<5)
		if(b+a>10)
			if(a+c-5 == 3)
				printf("Success! %d %d %d\n",a,b,c);
}

int main(int argc, char** argv){	
	char buffer[SIZE];
	read(STDIN_FILENO, buffer, SIZE);
	int a = buffer[0] - '0';
	int b = buffer[1] - '0';
	int c = buffer[2] - '0';
	func(a,b,c);	
	return 0;
}

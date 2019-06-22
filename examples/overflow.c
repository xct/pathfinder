#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>


int func(){
	char buffer[100];
	int len = read(STDIN_FILENO, buffer, 200);	
	printf("Read %d bytes.\n",len);
}

int main(int argc, char** argv){	
	func();	
	return 0;
}

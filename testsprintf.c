#include <stdio.h>
#include <string.h>

int main(int argc, char *argv[]) {
    int size = snprintf(NULL, 0, "1234567890%s", argv[1]);
    printf("got size of %d\n", size);
    return 0;
}
    

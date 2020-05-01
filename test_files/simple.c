#include <stdio.h>
#include <stdlib.h>
#include <time.h>

u_int32_t arr[10][10];

int main(int argc, char **argv)
{
    u_int32_t row = atoi(argv[1]);
    u_int32_t col = atoi(argv[2]);

    for (u_int32_t i = 0; i < 10; ++i) {
        arr[i] = 0;
    }

    if (index >= 0 && index < 10) {
        arr[index] = 8;
    }

    if (arr[2] == 8) {
        printf("Correct Input\n");
    }   


    return 0;
}
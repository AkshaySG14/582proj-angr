#include <stdio.h>
#include <stdlib.h>
#include <time.h>

u_int32_t arr[10][10];

int main(int argc, char **argv)
{
    u_int32_t row = atoi(argv[1]);
    u_int32_t col = atoi(argv[2]);

    for (u_int32_t i = 0; i < 10; ++i) {
        for (u_int32_t j = 0; j < 10; ++j) {
            arr[i][j] = 0; 
        }
    }

    if (row >= 0 && row < 10) {
        if (col >= 0 && col < 10) {
            arr[row][col] = 5;
        }
    }

    if (arr[5][7] == 5) {
        printf("Correct Input\n");
    }   


    return 0;
}
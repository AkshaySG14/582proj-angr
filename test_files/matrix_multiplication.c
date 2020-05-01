#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#define SIZE 1000

u_int32_t m1[SIZE][SIZE];
u_int32_t m2[SIZE][SIZE];

int main(int argc, char **argv)
{
    const u_int32_t MAX = __UINT32_MAX__ >> 2;
    u_int32_t prod[SIZE][SIZE];
    srand(time(NULL));
    
    u_int32_t row_begin = atoi(argv[1]);
    u_int32_t row_end = atoi(argv[2]);
    u_int32_t col_begin = atoi(argv[3]);
    u_int32_t col_end = atoi(argv[4]);

    for (u_int32_t i = 0; i < SIZE; ++i) {
        for (u_int32_t j = 0; j < SIZE; ++j) {
            m1[i][j] = 1;
            m2[i][j] = 1;
        }
    }

    for (u_int32_t i = row_begin; i < row_end; ++i) {
        for (u_int32_t j = col_begin; j < col_end; ++j) {
            m1[i][j] = rand() % MAX;
            m2[i][j] = rand() % MAX;
        }
    }

    
    for (u_int32_t i = 0; i < SIZE; ++i) {
        for (u_int32_t j = 0; j < SIZE; ++j) {
            u_int32_t cp = 0;
            for (u_int32_t k = 0; k < SIZE; ++k) {
                cp += m1[i][k] * m2[k][j];
            }
            prod[i][j] = cp;
        }
    }

    return 0;
}
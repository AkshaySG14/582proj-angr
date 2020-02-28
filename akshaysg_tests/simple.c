#include <stdio.h>
#include <stdlib.h>
#include <time.h>

static int boo = 5, goo = 19, doo = 21;

int arr[10];

int main(int argc, char **argv)
{
    int test = atoi(argv[1]);
    int index = atoi(argv[2]);

    if (test > 0) {
        if (index < 10) {
            arr[index] = 8;
        }
    }
    if (arr[2] == 8) {
        printf("Woah\n");
    }
    return 0;
}
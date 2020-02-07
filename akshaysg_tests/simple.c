#include <stdio.h>
#include <stdlib.h>
#include <time.h>

static int boo = 5, goo = 19, doo = 21;

int main(int argc, char **argv)
{
    printf("Hello World\n");

    int arr[10];
    int test = atoi(argv[1]);
    int length = atoi(argv[2]);

    if (test > 0) {
        if (length <= 10) {
            printf("Woah\n");
            for (int i = 0; i < length; ++i) {
                arr[i] = i;
                printf("%d\n", i);
            }
        }
        printf("Test\n");
    } else {
        printf("Second Branch\n");
    }
    return 0;
}
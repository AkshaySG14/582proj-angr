#include <stdio.h>
#include <stdlib.h>

static int boo = 5, goo = 19, doo = 21;

int main(int argc, char **argv)
{
    printf("Hello World\n");
    int arr[10];
    int test = atoi(argv[1]);
    int length = atoi(argv[2]);
    if (argc < 2) {
        printf("Error\n");
        return 0;
    }
    if (test > 0 && length <= 10) {
        for (int i = 0; i < length; ++i) {
            arr[i] = 5;
            printf("%d\n", i);
        }
        printf("Test");
    } else {
        printf("Second Branch");
    }
    return 0;
}
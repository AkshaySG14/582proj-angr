#import <stdlib.h>
#import <string.h>
#import <stdio.h>

struct Statistics {
    double mass;
    double height;
    int legs;
    int canFly;
};

const int value[] = {7, 2, 6, 3, 10, 2};

const struct Statistics stats[] = {
    { 0.0001, 0.002, 6, 1 },
    {  350.0,   2.4, 4, 0 },
    {   0.28,  0.46, 4, 0 },
    {   27.0,   0.8, 4, 1 },
    {   10.0,  0.36, 4, 0 }
};

int getIndex(const char* name) {

    if (*name++ != 'b') return -1;
    if (*name++ != 'e') return -1;
    if (*name   == 'e') return 0; 
    if (*name++ != 'a') return -1;

    switch (*name++) {
        case 'r': 
            if (!*name) return 1;
            if (strcmp(name, "ded dragon") == 0) return 2;
        case 'v':
            if (strcmp(name, "er") == 0) return 3;
        case 'g':
            if (strcmp(name, "le") == 0) return 4;
        default: 
            return -1;
    }

}

void printStats(const struct Statistics* s) {
    printf("mass: %fkg\nheight: %fm\nhas %d legs\ncan%sfly\n",
           s->mass,
           s->height,
           s->legs, 
           s->canFly ? " " : " not ");
} 

int main(int argc, char** argv) {
    if (argc != 3) return 1;
    int index = getIndex(argv[2]);
    if (strcmp(argv[1], "stats") == 0) {
        const struct Statistics* s = stats + index;
        printStats(s);
    }
    else if (strcmp(argv[1], "value") == 0)
        printf("value = %d\n", value[index]);
    else return -1;
    return 0;
}

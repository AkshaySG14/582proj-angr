#include <stdio.h>

int main(int argc, char** argv) {
    const char* text = argv[1];
    char tape[30000] = { 0 };
    char* p = tape;
    int depth = 0;
    while (*text) {
        switch (*text) {
            case '>':
                p++;
                break;
            case '<':
                p--;
                break;
            case '+':
                ++*p;
                break;
            case '-':
                --*p;
                break;
            case '.':
                putchar(*p);
                break;
            case ',':
                *p = getchar();
                break;
            case '[':
                if (!*p) {
                    depth = 0;
                    while (!(*text == ']' && depth == 0)) {
                        if (*text == '[') depth++;
                        if (*text == ']') depth--;
                        text++;
                    }
                }
                break;
            case ']':
                if (*p) {
                    depth = 0;
                    while (*text != '[' && depth != 0) {
                        if (*text == ']') depth++;
                        if (*text == '[') depth--;
                        text--;
                    }
                    text--;
                }
        }
        text++;
    }
}
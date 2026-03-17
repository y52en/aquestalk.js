#include <stddef.h>

int stricmp(const char *s1, const char *s2) {
    unsigned char c1, c2;
    do {
        c1 = (unsigned char)*s1++;
        c2 = (unsigned char)*s2++;
        if (c1 >= 'A' && c1 <= 'Z') c1 += 'a' - 'A';
        if (c2 >= 'A' && c2 <= 'Z') c2 += 'a' - 'A';
        if (c1 == '\0') break;
    } while (c1 == c2);
    return c1 - c2;
}

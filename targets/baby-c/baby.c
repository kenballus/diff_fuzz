#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

// Reads an 8-bit signed integer from stdin
static int8_t read_i8(void) {
    int const gc_result = getchar();
    if (gc_result == EOF) {
        exit(255);
    }
    return gc_result;
}

int main(void) {
    int8_t const age = read_i8();
    if (age > 1) {
        exit(1);
    }
    return 0;
}

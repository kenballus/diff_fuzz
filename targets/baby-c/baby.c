#include <stdio.h> // for getchar, printf
#include <stdint.h> // for uint32_t, uint8_t
#include <limits.h> // for CHAR_BIT
#include <stdlib.h> // for exit

// Reads a little-endian 32-bit unsigned integer from stdin
uint32_t read_u32(void) {
    uint32_t result = 0;
    for (uint8_t place = 0; place < sizeof(uint32_t) * CHAR_BIT; place += CHAR_BIT) {
        int gc_result = getchar();
        if (gc_result == -1) {
            exit(1);
        }
        result += gc_result << place;
    }

    return result;
}

int main(void) {
    uint age = read_u32();
    if (age != 1) {
        return 1;
    }
    uint32_t weight = read_u32();
    printf("Age: %u\n", age);
    printf("Weight: %u\n", weight);
    return 0;
}

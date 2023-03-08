#include <iostream>
#include <cstdint>

using std::uint8_t;
using std::exit;

// Reads an 8-bit unsigned integer from stdin
static uint8_t read_u8() {
    uint8_t result = 0;
    std::cin.read((char *)&result, 1);
    if (std::cin.gcount() != 1) {
        exit(255);
    }
    return result;
}

int main() {
    uint8_t const age = read_u8();
    if (age > 1) {
        exit(1);
    }
    return 0;
}

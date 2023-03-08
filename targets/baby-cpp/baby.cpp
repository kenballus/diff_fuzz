#include <iostream>
#include <limits>
#include <cstdint>

using std::uint8_t;
using std::uint32_t;

// Reads a little-endian 32-bit unsigned integer from stdin
uint32_t read_u32() {
    uint32_t result = 0;
    std::cin.read((char *)&result, sizeof(result));
    return result;
}

int main() {
    uint32_t age = read_u32();
    if (age != 1) {
        return 1;
    }
    uint32_t weight = read_u32();
    if (weight == 0) {
        return 2;
    }
    std::cout << "Age: " << age << "\n";
    std::cout << "Weight: " << weight << "\n";
    return 0;
}

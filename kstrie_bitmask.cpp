#include "kstrie_bitmask.hpp"
#include "kstrie_memory.hpp"
#include <iostream>

using namespace gteitelbaum;

int main() {
    std::cout << "kstrie_bitmask tests:\n";
    std::cout << "  (all methods are stubs)\n";
    std::cout << "  layout constants compile: PASS\n";
    // Verify BITMAP_U64 is correct
    static_assert(kstrie_bitmask<int, identity_char_map,
                  std::allocator<uint64_t>>::BITMAP_U64 == 4);
    std::cout << "ALL PASSED\n";
    return 0;
}

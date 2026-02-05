#include "kstrie_memory.hpp"
#include <cassert>
#include <iostream>

using namespace gteitelbaum;

void test_alloc_free() {
    kstrie_memory<std::allocator<uint64_t>> mem;
    uint64_t* p = mem.alloc_node(4);
    assert(p != nullptr);
    assert(hdr(p).alloc_u64 == 4);
    mem.free_node(p);
    std::cout << "  alloc/free: PASS\n";
}

void test_sentinel() {
    kstrie_memory<std::allocator<uint64_t>> mem;
    // Sentinel has alloc_u64=0, free_node should not crash
    uint64_t* sentinel = const_cast<uint64_t*>(EMPTY_NODE_STORAGE.data());
    mem.free_node(sentinel);  // should be no-op
    std::cout << "  sentinel: PASS\n";
}

int main() {
    std::cout << "kstrie_memory tests:\n";
    test_alloc_free();
    test_sentinel();
    std::cout << "ALL PASSED\n";
    return 0;
}

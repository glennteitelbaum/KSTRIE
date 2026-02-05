#include "kstrie_memory.hpp"
#include "kstrie_skip_eos.hpp"
#include <cassert>
#include <iostream>

using namespace gteitelbaum;
using mem_t = kstrie_memory<std::allocator<uint64_t>>;
using seo   = kstrie_skip_eos<int, std::allocator<uint64_t>>;

void test_find_lcp() {
    const uint8_t a[] = "hello world";
    const uint8_t b[] = "hello there";
    assert(seo::find_lcp(a, 11, b, 11) == 6);
    assert(seo::find_lcp(a, 5, b, 5) == 5);
    assert(seo::find_lcp(a, 0, b, 5) == 0);
    std::cout << "  find_lcp: PASS\n";
}

void test_create_leaf() {
    mem_t mem;
    const uint8_t suffix[] = "test";
    uint64_t* node = seo::create_leaf(suffix, 4, 42, mem);
    assert(node != nullptr);
    assert(hdr(node).is_compact());
    assert(hdr(node).has_eos());
    assert(hdr(node).skip == 4);
    assert(hdr(node).count == 0);
    assert(seo::load_eos(node, 4) == 42);
    mem.free_node(node);
    std::cout << "  create_leaf: PASS\n";
}

void test_create_eos_only() {
    mem_t mem;
    uint64_t* node = seo::create_eos_only(99, mem);
    assert(hdr(node).has_eos());
    assert(hdr(node).skip == 0);
    assert(seo::load_eos(node, 0) == 99);
    mem.free_node(node);
    std::cout << "  create_eos_only: PASS\n";
}

void test_match_prefix() {
    mem_t mem;
    const uint8_t suffix[] = "abcd";
    uint64_t* node = seo::create_leaf(suffix, 4, 1, mem);
    node_header h = hdr(node);

    // Full match
    const uint8_t key1[] = "abcdXYZ";
    const uint64_t* cnode = node;
    auto r1 = seo::match_prefix(cnode, h, key1, 7, 0);
    assert(r1.status == seo::match_status::MATCHED);
    assert(r1.consumed == 4);

    // Mismatch
    h = hdr(node);
    cnode = node;
    const uint8_t key2[] = "abXX";
    auto r2 = seo::match_prefix(cnode, h, key2, 4, 0);
    assert(r2.status == seo::match_status::MISMATCH);
    assert(r2.match_len == 2);

    // Key exhausted
    h = hdr(node);
    cnode = node;
    const uint8_t key3[] = "ab";
    auto r3 = seo::match_prefix(cnode, h, key3, 2, 0);
    assert(r3.status == seo::match_status::KEY_EXHAUSTED);

    mem.free_node(node);
    std::cout << "  match_prefix: PASS\n";
}

int main() {
    std::cout << "kstrie_skip_eos tests:\n";
    test_find_lcp();
    test_create_leaf();
    test_create_eos_only();
    test_match_prefix();
    std::cout << "ALL PASSED\n";
    return 0;
}

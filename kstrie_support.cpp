#include "kstrie_support.hpp"
#include <cassert>
#include <iostream>

using namespace gteitelbaum;

void test_padded_size() {
    assert(padded_size(1) == 1);
    assert(padded_size(4) == 4);
    assert(padded_size(5) == 6);   // lower=4, mid=6, upper=8
    assert(padded_size(7) == 8);
    assert(padded_size(9) == 12);  // lower=8, mid=12, upper=16
    std::cout << "  padded_size: PASS\n";
}

void test_bitmap_n() {
    bitmap_n<4> bm;
    assert(!bm.has_bit(42));
    bm.set_bit(42);
    assert(bm.has_bit(42));
    assert(bm.popcount() == 1);
    assert(bm.find_slot(42) == 0);
    bm.set_bit(10);
    assert(bm.popcount() == 2);
    assert(bm.find_slot(10) == 0);
    assert(bm.find_slot(42) == 1);
    bm.clear_bit(10);
    assert(!bm.has_bit(10));
    assert(bm.popcount() == 1);
    std::cout << "  bitmap_n: PASS\n";
}

void test_e_es_cvt() {
    es s;
    s.setkey("hello", 5);
    s.setoff(42);
    e entry = cvt(s);
    assert(e_offset(entry) == 42);

    e search = make_search_key(reinterpret_cast<const uint8_t*>("hello"), 5);
    assert(e_prefix_only(entry) == e_prefix_only(search));
    std::cout << "  e/es/cvt: PASS\n";
}

void test_layout() {
    assert(idx_count(0) == 0);
    assert(idx_count(1) == 1);
    assert(idx_count(8) == 1);
    assert(idx_count(9) == 2);
    assert(align8(0) == 0);
    assert(align8(1) == 8);
    assert(align8(8) == 8);
    assert(align8(9) == 16);
    std::cout << "  layout: PASS\n";
}

void test_eytzinger() {
    // Simple test with 8 idx entries
    e idx[8];
    for (int i = 0; i < 8; ++i) {
        es s; s.setkey("", 0); s.setoff(i);
        idx[i] = cvt(s);
    }
    e hot[8];
    int ec = build_eyt(idx, 8, hot);
    assert(ec > 0);
    std::cout << "  eytzinger: PASS\n";
}

void test_kstrie_values() {
    // Test int packing
    static_assert(kstrie_values<int>::PACK_COUNT == 2);
    static_assert(kstrie_values<int>::IS_PACKED);
    static_assert(kstrie_values<int>::array_u64(1) == 1);
    static_assert(kstrie_values<int>::array_u64(2) == 1);
    static_assert(kstrie_values<int>::array_u64(3) == 2);

    // Test char packing
    static_assert(kstrie_values<char>::PACK_COUNT == 8);
    static_assert(kstrie_values<char>::array_u64(8) == 1);
    static_assert(kstrie_values<char>::array_u64(9) == 2);

    // Test uint64_t (no packing)
    static_assert(kstrie_values<uint64_t>::PACK_COUNT == 1);
    static_assert(!kstrie_values<uint64_t>::IS_PACKED);

    // Runtime store/load
    uint64_t buf[4] = {};
    kstrie_values<int>::store_at(buf, 0, 42);
    kstrie_values<int>::store_at(buf, 1, 99);
    assert(*kstrie_values<int>::ptr_at(buf, 0) == 42);
    assert(*kstrie_values<int>::ptr_at(buf, 1) == 99);

    // EOS
    uint64_t eos[1] = {};
    kstrie_values<int>::store_single(eos, 7);
    assert(kstrie_values<int>::load_single(eos) == 7);

    std::cout << "  kstrie_values: PASS\n";
}

int main() {
    std::cout << "kstrie_support tests:\n";
    test_padded_size();
    test_bitmap_n();
    test_e_es_cvt();
    test_layout();
    test_eytzinger();
    test_kstrie_values();
    std::cout << "ALL PASSED\n";
    return 0;
}

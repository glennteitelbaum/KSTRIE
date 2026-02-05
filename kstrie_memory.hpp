#pragma once

#include "kstrie_support.hpp"

namespace gteitelbaum {

// ============================================================================
// kstrie_memory -- node allocation and deallocation
// ============================================================================

template <typename ALLOC>
struct kstrie_memory {
    ALLOC alloc_{};

    kstrie_memory() = default;
    explicit kstrie_memory(const ALLOC& a) : alloc_(a) {}

    // Allocate node with padded size, zeroed, header.alloc_u64 set
    uint64_t* alloc_node(std::size_t needed_u64) {
        std::size_t au = padded_size(static_cast<uint16_t>(needed_u64));
        uint64_t* p = std::allocator_traits<ALLOC>::allocate(alloc_, au);
        std::memset(p, 0, au * 8);
        hdr(p).alloc_u64 = static_cast<uint16_t>(au);
        return p;
    }

    // Free node using size stored in header. Skips sentinel (alloc_u64 == 0).
    void free_node(uint64_t* p) {
        if (p && !hdr(p).is_sentinel()) {
            std::allocator_traits<ALLOC>::deallocate(alloc_, p, hdr(p).alloc_u64);
        }
    }
};

} // namespace gteitelbaum

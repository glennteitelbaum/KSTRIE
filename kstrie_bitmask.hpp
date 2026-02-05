#pragma once

#include "kstrie_support.hpp"

namespace gteitelbaum {

// ============================================================================
// kstrie_bitmask -- bitmap dispatch node operations
// ============================================================================

template <typename VALUE, typename CHARMAP, typename ALLOC>
struct kstrie_bitmask {
    using memory_type  = kstrie_memory<ALLOC>;
    using vals         = kstrie_values<VALUE>;
    using bitmap_type  = typename CHARMAP::bitmap_type;
    using skip_eos     = kstrie_skip_eos<VALUE, ALLOC>;
    using compact_type = kstrie_compact<VALUE, CHARMAP, ALLOC>;

    static constexpr size_t BITMAP_U64 = CHARMAP::BITMAP_WORDS;

    // ------------------------------------------------------------------
    // Layout accessors (implemented -- pure pointer arithmetic)
    // ------------------------------------------------------------------

    static const bitmap_type& bm_bitmap(const uint64_t* n, uint8_t skip,
                                         bool has_eos) noexcept {
        return *reinterpret_cast<const bitmap_type*>(
            n + data_offset_u64<VALUE>(skip, has_eos));
    }

    static bitmap_type& bm_bitmap_mut(uint64_t* n, uint8_t skip,
                                       bool has_eos) noexcept {
        return *reinterpret_cast<bitmap_type*>(
            n + data_offset_u64<VALUE>(skip, has_eos));
    }

    static const uint64_t* bm_children(const uint64_t* n, uint8_t skip,
                                        bool has_eos) noexcept {
        return n + data_offset_u64<VALUE>(skip, has_eos) + BITMAP_U64;
    }

    static uint64_t* bm_children_mut(uint64_t* n, uint8_t skip,
                                      bool has_eos) noexcept {
        return const_cast<uint64_t*>(bm_children(n, skip, has_eos));
    }

    // Data region size in bytes for a bitmap node
    static std::size_t data_size_bytes(const uint64_t* node,
                                        node_header h) noexcept {
        int top_count = bm_bitmap(node, h.skip, h.has_eos()).popcount();
        return (BITMAP_U64 + top_count) * 8;
    }

    // ------------------------------------------------------------------
    // Reading
    // ------------------------------------------------------------------

    // Find child for byte. Returns nullptr if byte not in bitmap.
    static const uint64_t* find_child(const uint64_t* node, node_header h,
                                       uint8_t byte) noexcept {
        const bitmap_type& bm = bm_bitmap(node, h.skip, h.has_eos());
        int slot = bm.find_slot(byte);
        if (slot < 0) return nullptr;
        const uint64_t* children = bm_children(node, h.skip, h.has_eos());
        return reinterpret_cast<const uint64_t*>(children[slot]);
    }

    static uint64_t* find_child_mut(uint64_t* node, node_header h,
                                     uint8_t byte) noexcept {
        return const_cast<uint64_t*>(
            find_child(const_cast<const uint64_t*>(node), h, byte));
    }

    // ------------------------------------------------------------------
    // Creation -- STUB
    // ------------------------------------------------------------------

    // Create bitmap node from pre-built children.
    // dispatch_bytes and children are parallel vectors.
    static uint64_t* create(const uint8_t* skip_prefix, uint8_t skip_len,
                            bool has_eos, const uint64_t* eos_data,
                            const std::vector<uint8_t>& dispatch_bytes,
                            const std::vector<uint64_t*>& children,
                            memory_type& mem) {
        (void)skip_prefix; (void)skip_len; (void)has_eos; (void)eos_data;
        (void)dispatch_bytes; (void)children; (void)mem;
        assert(false && "kstrie_bitmask::create not yet implemented");
        return nullptr;
    }

    // ------------------------------------------------------------------
    // Insert -- STUB
    // ------------------------------------------------------------------

    // Add new child for a byte not yet in bitmap. Returns new node.
    static uint64_t* insert_child(uint64_t* node, node_header h,
                                   uint8_t byte, uint64_t* child,
                                   memory_type& mem) {
        (void)node; (void)h; (void)byte; (void)child; (void)mem;
        assert(false && "kstrie_bitmask::insert_child not yet implemented");
        return nullptr;
    }

    // Insert into bitmap node (dispatch byte, recurse or add child)
    static insert_result insert(uint64_t* node, node_header h,
                                const uint8_t* key_data, uint32_t key_len,
                                const VALUE& value, uint32_t consumed,
                                insert_mode mode, memory_type& mem) {
        (void)node; (void)h; (void)key_data; (void)key_len;
        (void)value; (void)consumed; (void)mode; (void)mem;
        assert(false && "kstrie_bitmask::insert not yet implemented");
        return {nullptr, insert_outcome::FOUND};
    }

    // ------------------------------------------------------------------
    // Iteration -- STUB
    // ------------------------------------------------------------------

    // next(node, header, byte) -> {next_byte, child}
    // prev(node, header, byte) -> {prev_byte, child}

    // ------------------------------------------------------------------
    // Erase -- STUB
    // ------------------------------------------------------------------

    static uint64_t* erase_child(uint64_t* node, node_header h,
                                  uint8_t byte, memory_type& mem) {
        (void)node; (void)h; (void)byte; (void)mem;
        assert(false && "kstrie_bitmask::erase_child not yet implemented");
        return nullptr;
    }

    // ------------------------------------------------------------------
    // Split / Combine -- STUB
    // ------------------------------------------------------------------
};

} // namespace gteitelbaum

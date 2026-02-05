#pragma once

#include "kstrie_support.hpp"

namespace gteitelbaum {

// ============================================================================
// kstrie_compact -- compact sorted-array node operations
// ============================================================================

template <typename VALUE, typename CHARMAP, typename ALLOC>
struct kstrie_compact {
    using memory_type  = kstrie_memory<ALLOC>;
    using vals         = kstrie_values<VALUE>;
    using skip_eos     = kstrie_skip_eos<VALUE, ALLOC>;
    using bitmask_type = kstrie_bitmask<VALUE, CHARMAP, ALLOC>;

    // ------------------------------------------------------------------
    // Layout helpers (implemented -- pure arithmetic)
    // ------------------------------------------------------------------

    // Data region size in bytes for a compact node
    static std::size_t data_size_bytes(node_header h) noexcept {
        if (h.count == 0) return 0;
        int ic = idx_count(h.count);
        int W  = calc_W(ic);
        int ec = W > 0 ? W - 1 : 0;
        return values_off(h.count, h.keys_bytes, ec) +
               vals::array_u64(h.count) * 8;
    }

    // ------------------------------------------------------------------
    // Reading -- STUB
    // ------------------------------------------------------------------

    // Search compact node for suffix. Returns pointer to value or nullptr.
    static const VALUE* find(const uint64_t* node, node_header h,
                             const uint8_t* mapped_suffix,
                             uint32_t suffix_len) noexcept {
        (void)node; (void)h; (void)mapped_suffix; (void)suffix_len;
        // STUB: not yet implemented
        return nullptr;
    }

    static VALUE* find_mut(uint64_t* node, node_header h,
                           const uint8_t* mapped_suffix,
                           uint32_t suffix_len) noexcept {
        return const_cast<VALUE*>(
            find(const_cast<const uint64_t*>(node), h,
                 mapped_suffix, suffix_len));
    }

    // Find insert position for suffix
    static search_result search_position(uint64_t* node, node_header h,
                                          const uint8_t* mapped_suffix,
                                          uint32_t suffix_len) {
        (void)node; (void)h; (void)mapped_suffix; (void)suffix_len;
        // STUB
        return {false, 0, 0};
    }

    // ------------------------------------------------------------------
    // Insert -- STUB
    // ------------------------------------------------------------------

    // Insert into compact node. May split to bitmap if needed.
    static insert_result insert(uint64_t* node, node_header h,
                                const uint8_t* key_data, uint32_t key_len,
                                const VALUE& value, uint32_t consumed,
                                insert_mode mode, memory_type& mem) {
        (void)node; (void)h; (void)key_data; (void)key_len;
        (void)value; (void)consumed; (void)mode; (void)mem;
        assert(false && "kstrie_compact::insert not yet implemented");
        return {nullptr, insert_outcome::FOUND};
    }

    // Update value at known position
    static void update_value(uint64_t* node, node_header h, int pos,
                             const VALUE& value) {
        (void)node; (void)h; (void)pos; (void)value;
        assert(false && "kstrie_compact::update_value not yet implemented");
    }

    // Insert at position (low-level). Returns nullptr if split needed.
    static uint64_t* insert_at(uint64_t*& node, node_header h,
                                const uint8_t* suffix, uint32_t suffix_len,
                                const VALUE& value, int pos,
                                memory_type& mem) {
        (void)node; (void)h; (void)suffix; (void)suffix_len;
        (void)value; (void)pos; (void)mem;
        assert(false && "kstrie_compact::insert_at not yet implemented");
        return nullptr;
    }

    // Force insert (no limit checks, used before split)
    static uint64_t* force_insert(uint64_t* node, node_header h,
                                   const uint8_t* suffix, uint32_t suffix_len,
                                   const VALUE& value, int pos,
                                   memory_type& mem) {
        (void)node; (void)h; (void)suffix; (void)suffix_len;
        (void)value; (void)pos; (void)mem;
        assert(false && "kstrie_compact::force_insert not yet implemented");
        return nullptr;
    }

    // ------------------------------------------------------------------
    // Split -- STUB
    // ------------------------------------------------------------------

    // Split compact node into bitmap node
    static uint64_t* split_to_bitmask(uint64_t* node, node_header h,
                                       memory_type& mem) {
        (void)node; (void)h; (void)mem;
        assert(false && "kstrie_compact::split_to_bitmask not yet implemented");
        return nullptr;
    }

    // Split compact node at prefix mismatch (stays compact if possible)
    static insert_result split_on_prefix(uint64_t* node, node_header h,
                                          const uint8_t* key_data,
                                          uint32_t key_len,
                                          const VALUE& value,
                                          uint32_t consumed,
                                          uint32_t match_len,
                                          memory_type& mem) {
        (void)node; (void)h; (void)key_data; (void)key_len;
        (void)value; (void)consumed; (void)match_len; (void)mem;
        assert(false && "kstrie_compact::split_on_prefix not yet implemented");
        return {nullptr, insert_outcome::INSERTED};
    }

    // ------------------------------------------------------------------
    // Create from entries -- STUB
    // ------------------------------------------------------------------

    struct bucket_entry {
        const uint8_t* suffix;
        uint32_t       len;
        // Value stored as raw uint64_t (EOS_U64 wide)
    };

    static uint64_t* create_from_entries(const std::vector<bucket_entry>& entries,
                                          const uint64_t* eos_data,
                                          memory_type& mem) {
        (void)entries; (void)eos_data; (void)mem;
        assert(false && "kstrie_compact::create_from_entries not yet implemented");
        return nullptr;
    }

    // ------------------------------------------------------------------
    // Validation -- STUB
    // ------------------------------------------------------------------

    static void check_compress([[maybe_unused]] const uint64_t* node) {
#ifdef KSTRIE_DEBUG
        // TODO: implement compact invariant validation
#endif
    }

    static int32_t check_compact_insert(uint16_t current_alloc, uint8_t old_skip,
                                         uint8_t new_skip, bool has_eos,
                                         uint16_t old_count,
                                         uint32_t old_keys_bytes,
                                         uint32_t suffix_len) noexcept {
        (void)current_alloc; (void)old_skip; (void)new_skip; (void)has_eos;
        (void)old_count; (void)old_keys_bytes; (void)suffix_len;
        // STUB: return -1 to force split
        return -1;
    }

    static bool needs_split(const uint64_t* node) noexcept {
        (void)node;
        return false;
    }

    // ------------------------------------------------------------------
    // Iteration -- STUB
    // ------------------------------------------------------------------

    // next(node, header, pos) -> {key, value}
    // prev(node, header, pos) -> {key, value}

    // ------------------------------------------------------------------
    // Erase -- STUB
    // ------------------------------------------------------------------

    // ------------------------------------------------------------------
    // Combine -- STUB
    // ------------------------------------------------------------------
};

} // namespace gteitelbaum

#pragma once

#include "kstrie_support.hpp"

namespace gteitelbaum {

// ============================================================================
// kstrie_bitmask -- bitmap (internal fanout) node operations
//
// Node layout:  [header 8B] [skip] [bitmap] [slots]
//
// Index region = bitmap_type (8, 16, or 32 bytes depending on CHARMAP)
// Slots region = [eos_value?] [child_ptr_0] [child_ptr_1] ...
//   - child pointers are ordered by bitmap popcount position
//   - eos slot (if present) is always slot[0]
//
// Owns: bitmap lookup, child insert/remove, eos management, node creation
// Does NOT own: prefix matching (kstrie_skip), value storage details (kstrie_slots)
// ============================================================================

template <typename VALUE, typename CHARMAP, typename ALLOC>
struct kstrie_bitmask {
    using hdr_type    = node_header<VALUE, CHARMAP, ALLOC>;
    using bitmap_type = typename CHARMAP::bitmap_type;
    using slots       = kstrie_slots<VALUE>;
    using mem_type    = kstrie_memory<ALLOC>;

    static constexpr size_t BITMAP_BYTES = sizeof(bitmap_type);

    // ------------------------------------------------------------------
    // Index size (called by node_header::index_size)
    // ------------------------------------------------------------------

    static constexpr size_t index_size(const hdr_type& /*h*/) noexcept {
        return BITMAP_BYTES;
    }

    // ------------------------------------------------------------------
    // Bitmap access
    // ------------------------------------------------------------------

    static bitmap_type* get_bitmap(uint64_t* node, const hdr_type& h) noexcept {
        return reinterpret_cast<bitmap_type*>(h.get_index(node));
    }

    static const bitmap_type* get_bitmap(const uint64_t* node, const hdr_type& h) noexcept {
        return reinterpret_cast<const bitmap_type*>(
            h.get_index(const_cast<uint64_t*>(node)));
    }

    // ------------------------------------------------------------------
    // Child lookup
    // ------------------------------------------------------------------

    // Find child node for mapped character index.
    // Returns child pointer, or nullptr if no child for this index.
    static uint64_t* find_child(const uint64_t* node, const hdr_type& h,
                                uint8_t idx) noexcept {
        const bitmap_type* bm = get_bitmap(node, h);
        int slot = bm->find_slot(idx);
        if (slot < 0) return nullptr;
        const uint64_t* sb = h.get_slots(const_cast<uint64_t*>(node));
        return slots::load_child(sb, h.has_eos() + slot);
    }

    // ------------------------------------------------------------------
    // EOS value access
    // ------------------------------------------------------------------

    // Returns pointer to EOS value, or nullptr if no EOS.
    static VALUE* find_eos(uint64_t* node, const hdr_type& h) noexcept {
        if (!h.has_eos()) return nullptr;
        uint64_t* sb = h.get_slots(node);
        return &slots::load_eos(sb);
    }

    static const VALUE* find_eos(const uint64_t* node, const hdr_type& h) noexcept {
        if (!h.has_eos()) return nullptr;
        const uint64_t* sb = h.get_slots(const_cast<uint64_t*>(node));
        return &slots::load_eos(sb);
    }

    // ------------------------------------------------------------------
    // Node size computation
    // ------------------------------------------------------------------

    // Compute required u64 units for a bitmask node.
    static size_t needed_u64(uint8_t skip_len, uint16_t child_count,
                             bool has_eos) noexcept {
        size_t bytes = hdr_type::header_size();                          // 8
        if (skip_len > 0) bytes += (skip_len + 7) & ~size_t(7);         // skip
        bytes += BITMAP_BYTES;                                           // bitmap
        uint16_t total = child_count + (has_eos ? 1 : 0);
        bytes += slots::size_bytes(total);                               // slots
        return (bytes + 7) / 8;
    }

    // ------------------------------------------------------------------
    // Node creation
    // ------------------------------------------------------------------

    // Create a new bitmask node with optional skip prefix and optional EOS.
    // Caller is responsible for populating children afterward.
    static uint64_t* create(mem_type& mem,
                            uint8_t skip_len, const uint8_t* skip_data,
                            bool has_eos, const VALUE* eos_val) {
        size_t nu = needed_u64(skip_len, 0, has_eos);
        uint64_t* node = mem.alloc_node(nu);
        hdr_type& h = hdr_type::from_node(node);
        h.set_compact(false);
        h.skip       = skip_len;
        h.count      = 0;
        h.keys_bytes = 0;
        h.set_eos(has_eos);

        if (skip_len > 0 && skip_data)
            std::memcpy(hdr_type::get_skip(node), skip_data, skip_len);

        if (has_eos && eos_val)
            slots::store_eos(h.get_slots(node), *eos_val);

        return node;
    }

    // Create a bitmask node pre-populated with children from buckets.
    // bucket_idx[i] = mapped character index for child i (must be sorted by idx).
    // bucket_child[i] = child node pointer.
    // n_buckets = number of children.
    static uint64_t* create_with_children(
            mem_type& mem,
            uint8_t skip_len, const uint8_t* skip_data,
            bool has_eos, const VALUE* eos_val,
            const uint8_t* bucket_idx, uint64_t* const* bucket_child,
            uint16_t n_buckets) {
        size_t nu = needed_u64(skip_len, n_buckets, has_eos);
        uint64_t* node = mem.alloc_node(nu);
        hdr_type& h = hdr_type::from_node(node);
        h.set_compact(false);
        h.skip       = skip_len;
        h.count      = n_buckets;
        h.keys_bytes = 0;
        h.set_eos(has_eos);

        if (skip_len > 0 && skip_data)
            std::memcpy(hdr_type::get_skip(node), skip_data, skip_len);

        if (has_eos && eos_val)
            slots::store_eos(h.get_slots(node), *eos_val);

        // Populate bitmap and child slots
        bitmap_type* bm = get_bitmap(node, h);
        uint64_t* sb = h.get_slots(node);
        size_t data_start = has_eos ? 1 : 0;

        for (uint16_t i = 0; i < n_buckets; ++i) {
            bm->set_bit(bucket_idx[i]);
            slots::store_child(sb, data_start + i, bucket_child[i]);
        }

        return node;
    }

    // ------------------------------------------------------------------
    // Child insertion
    // ------------------------------------------------------------------

    // Insert a child pointer for mapped character index idx.
    // idx must NOT already be present in the bitmap.
    // Returns (possibly reallocated) node pointer.
    static uint64_t* insert_child(uint64_t* node, hdr_type& h, mem_type& mem,
                                  uint8_t idx, uint64_t* child) {
        bitmap_type* bm = get_bitmap(node, h);
        assert(!bm->has_bit(idx) && "insert_child: index already present");

        int pos = bm->slot_for_insert(idx);
        uint16_t old_count = h.count;
        uint16_t new_count = old_count + 1;
        bool eos = h.has_eos();
        size_t data_start = eos ? 1 : 0;

        size_t new_nu = needed_u64(h.skip, new_count, eos);

        if (new_nu <= h.alloc_u64) {
            // Fits in place: shift slots right, insert
            uint64_t* sb = h.get_slots(node);
            slots::move_slots(sb, data_start + pos + 1,
                              sb, data_start + pos,
                              old_count - pos);
            slots::store_child(sb, data_start + pos, child);
            bm->set_bit(idx);
            h.count = new_count;
            return node;
        }

        // Reallocate
        uint64_t* new_node = mem.alloc_node(new_nu);
        hdr_type& nh = hdr_type::from_node(new_node);
        nh.copy_from(h);
        nh.count = new_count;

        // Copy skip
        if (h.skip > 0)
            std::memcpy(hdr_type::get_skip(new_node),
                        hdr_type::get_skip(node), h.skip_bytes());

        // Copy bitmap and set new bit
        bitmap_type* new_bm = get_bitmap(new_node, nh);
        *new_bm = *bm;
        new_bm->set_bit(idx);

        // Copy slots with insertion gap
        const uint64_t* old_sb = h.get_slots(node);
        uint64_t* new_sb = nh.get_slots(new_node);

        // EOS slot
        if (eos)
            new_sb[0] = old_sb[0];

        // Children before insertion point
        slots::copy_slots(new_sb, data_start,
                          old_sb, data_start, pos);
        // New child
        slots::store_child(new_sb, data_start + pos, child);
        // Children after insertion point
        slots::copy_slots(new_sb, data_start + pos + 1,
                          old_sb, data_start + pos,
                          old_count - pos);

        mem.free_node(node);
        return new_node;
    }

    // Replace existing child pointer at mapped character index idx.
    // idx must already be present.
    static void replace_child(uint64_t* node, const hdr_type& h,
                              uint8_t idx, uint64_t* new_child) noexcept {
        const bitmap_type* bm = get_bitmap(node, h);
        int slot = bm->find_slot(idx);
        assert(slot >= 0 && "replace_child: index not found");
        uint64_t* sb = h.get_slots(node);
        slots::store_child(sb, h.has_eos() + slot, new_child);
    }

    // ------------------------------------------------------------------
    // EOS insertion / update
    // ------------------------------------------------------------------

    // Set or update the EOS value on a bitmask node.
    // Returns (possibly reallocated) node pointer and whether it was an update.
    struct eos_result {
        uint64_t* node;
        bool      was_update;
    };

    static eos_result set_eos(uint64_t* node, hdr_type& h, mem_type& mem,
                              const VALUE& val) {
        if (h.has_eos()) {
            // Update existing EOS value
            uint64_t* sb = h.get_slots(node);
            slots::destroy_eos(sb);
            slots::store_eos(sb, val);
            return {node, true};
        }

        // Adding EOS: need one more slot
        uint16_t child_count = h.count;
        size_t new_nu = needed_u64(h.skip, child_count, true);

        if (new_nu <= h.alloc_u64) {
            // Recompute slot base BEFORE setting eos flag (layout changes)
            // The index region doesn't change, but slots start at the same place.
            // We just need to shift children right by 1 to make room for eos at slot 0.
            uint64_t* sb = h.get_slots(node);
            slots::move_slots(sb, 1, sb, 0, child_count);
            slots::store_eos(sb, val);
            h.set_eos(true);
            return {node, false};
        }

        // Reallocate
        uint64_t* new_node = mem.alloc_node(new_nu);
        hdr_type& nh = hdr_type::from_node(new_node);
        nh.copy_from(h);
        nh.set_eos(true);

        // Copy skip
        if (h.skip > 0)
            std::memcpy(hdr_type::get_skip(new_node),
                        hdr_type::get_skip(node), h.skip_bytes());

        // Copy bitmap
        bitmap_type* new_bm = get_bitmap(new_node, nh);
        const bitmap_type* old_bm = get_bitmap(node, h);
        *new_bm = *old_bm;

        // Slots: eos at [0], then copy children
        uint64_t* new_sb = nh.get_slots(new_node);
        const uint64_t* old_sb = h.get_slots(node);
        slots::store_eos(new_sb, val);
        slots::copy_slots(new_sb, 1, old_sb, 0, child_count);

        mem.free_node(node);
        return {new_node, false};
    }

    // ------------------------------------------------------------------
    // Child removal
    // ------------------------------------------------------------------

    // Remove child at mapped character index idx.
    // Does NOT free the child node (caller's responsibility).
    // Returns (possibly same) node pointer.
    static uint64_t* remove_child(uint64_t* node, hdr_type& h,
                                  uint8_t idx) noexcept {
        bitmap_type* bm = get_bitmap(node, h);
        int pos = bm->find_slot(idx);
        assert(pos >= 0 && "remove_child: index not found");

        uint16_t old_count = h.count;
        size_t data_start = h.has_eos() ? 1 : 0;
        uint64_t* sb = h.get_slots(node);

        // Shift children left to close the gap
        slots::move_slots(sb, data_start + pos,
                          sb, data_start + pos + 1,
                          old_count - pos - 1);

        bm->clear_bit(idx);
        h.count = old_count - 1;

        // Clear the now-unused last slot
        sb[data_start + old_count - 1] = 0;

        return node;
    }

    // Remove EOS value (does not reallocate, just shifts children left).
    static void remove_eos(uint64_t* node, hdr_type& h) noexcept {
        if (!h.has_eos()) return;

        uint64_t* sb = h.get_slots(node);
        slots::destroy_eos(sb);

        // Shift children left by 1
        slots::move_slots(sb, 0, sb, 1, h.count);
        // Clear last slot
        sb[h.count] = 0;

        h.set_eos(false);
    }

    // ------------------------------------------------------------------
    // Iteration helpers
    // ------------------------------------------------------------------

    // Get the first set bit in the bitmap (-1 if empty).
    static int first_child_idx(const uint64_t* node, const hdr_type& h) noexcept {
        const bitmap_type* bm = get_bitmap(node, h);
        return bm->find_next_set(0);
    }

    // Get the next set bit after prev (-1 if none).
    static int next_child_idx(const uint64_t* node, const hdr_type& h,
                              int prev) noexcept {
        const bitmap_type* bm = get_bitmap(node, h);
        return bm->find_next_set(prev + 1);
    }

    // Get child pointer by dense slot position (not by character index).
    static uint64_t* child_by_slot(const uint64_t* node, const hdr_type& h,
                                   uint16_t slot) noexcept {
        const uint64_t* sb = h.get_slots(const_cast<uint64_t*>(node));
        return slots::load_child(sb, h.has_eos() + slot);
    }

    // ------------------------------------------------------------------
    // Memory usage (recursive)
    // ------------------------------------------------------------------

    static size_t memory_usage(const uint64_t* node) noexcept {
        const hdr_type& h = hdr_type::from_node(node);
        if (h.is_sentinel()) return 0;

        size_t total = static_cast<size_t>(h.alloc_u64) * 8;

        const uint64_t* sb = h.get_slots(const_cast<uint64_t*>(node));
        size_t data_start = h.has_eos() ? 1 : 0;

        for (uint16_t i = 0; i < h.count; ++i) {
            uint64_t* child = slots::load_child(sb, data_start + i);
            if (child) {
                const hdr_type& ch = hdr_type::from_node(child);
                if (ch.is_sentinel()) continue;
                if (ch.is_bitmap())
                    total += memory_usage(child);
                else
                    total += static_cast<size_t>(ch.alloc_u64) * 8;
            }
        }

        return total;
    }

    // ------------------------------------------------------------------
    // Destroy (recursive)
    // ------------------------------------------------------------------

    static void destroy(uint64_t* node, mem_type& mem) {
        hdr_type& h = hdr_type::from_node(node);
        if (h.is_sentinel()) return;

        uint64_t* sb = h.get_slots(node);
        size_t data_start = h.has_eos() ? 1 : 0;

        // Destroy EOS value if present
        if (h.has_eos())
            slots::destroy_eos(sb);

        // Recursively destroy children
        for (uint16_t i = 0; i < h.count; ++i) {
            uint64_t* child = slots::load_child(sb, data_start + i);
            if (child) {
                const hdr_type& ch = hdr_type::from_node(child);
                if (ch.is_sentinel()) continue;
                if (ch.is_bitmap())
                    destroy(child, mem);
                else {
                    // Compact node: destroy its values, then free
                    // Caller (kstrie) handles compact destruction
                    // We just free the node here
                }
                mem.free_node(child);
            }
        }
    }

    // ------------------------------------------------------------------
    // Debug / diagnostics
    // ------------------------------------------------------------------

    static uint16_t child_count(const uint64_t* node, const hdr_type& h) noexcept {
        return h.count;
    }

    static uint16_t popcount(const uint64_t* node, const hdr_type& h) noexcept {
        const bitmap_type* bm = get_bitmap(node, h);
        return static_cast<uint16_t>(bm->popcount());
    }
};

} // namespace gteitelbaum

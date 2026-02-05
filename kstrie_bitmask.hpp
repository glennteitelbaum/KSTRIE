#pragma once

#include "kstrie_support.hpp"

namespace gteitelbaum {

// ============================================================================
// kstrie_bitmask -- bitmap (internal fanout) node operations
//
// Node layout:  [header 8B] [skip] [bitmap] [slots]
//
// Index region = bitmap_type (8, 16, or 32 bytes depending on CHARMAP)
// Slots region = [sentinel] [child_ptr_0 .. child_ptr_{count-1}] [eos_child]
//   - slot[0]       = sentinel (always points to EMPTY_NODE_STORAGE)
//   - slot[1..count] = child pointers ordered by bitmap popcount position
//   - slot[count+1]  = eos_child (sentinel if no EOS, compact leaf if EOS)
//
// All slots are child pointers. No values stored directly.
// EOS is represented as a compact leaf child with skip=0, one zero-length key.
//
// Branchless lookup: do_find_pop returns 0 (→ sentinel) or 1-based slot index.
// ============================================================================

template <typename VALUE, typename CHARMAP, typename ALLOC>
struct kstrie_bitmask {
    using hdr_type    = node_header<VALUE, CHARMAP, ALLOC>;
    using bitmap_type = typename CHARMAP::bitmap_type;
    using slots       = kstrie_slots<VALUE>;
    using mem_type    = kstrie_memory<ALLOC>;

    static constexpr size_t BITMAP_BYTES = sizeof(bitmap_type);
    static constexpr size_t BITMAP_WORDS = CHARMAP::BITMAP_WORDS;

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
    // Branchless bitmap probe
    //
    // Returns 0 if idx not present (→ slot[0] = sentinel).
    // Returns 1-based slot index if present (popcount including target bit).
    // ------------------------------------------------------------------

    static int do_find_pop(const uint64_t* search, uint8_t v) noexcept {
        constexpr size_t W = BITMAP_WORDS;
        const int word = v >> 6;
        const int bit  = v & 63;

        uint64_t before = search[word] << (63 - bit);

        int pc0 = 0, pc1 = 0, pc2 = 0;
        if constexpr (W > 1) pc0 = std::popcount(search[0]);
        if constexpr (W > 2) pc1 = std::popcount(search[1]);
        if constexpr (W > 3) pc2 = std::popcount(search[2]);

        int count = std::popcount(before);
        if constexpr (W > 1) count += pc0 & -int(word > 0);
        if constexpr (W > 2) count += pc1 & -int(word > 1);
        if constexpr (W > 3) count += pc2 & -int(word > 2);

        bool found = before & (1ULL << 63);
        count &= -uint64_t(found);

        return count;
    }

    // ------------------------------------------------------------------
    // Child lookup (branchless)
    // ------------------------------------------------------------------

    // Returns slot index: 0 = not found (sentinel), 1+ = child position.
    static int find_slot(const uint64_t* node, const hdr_type& h,
                         uint8_t idx) noexcept {
        const bitmap_type* bm = get_bitmap(node, h);
        return do_find_pop(bm->words, idx);
    }

    // Returns child pointer. Sentinel if not found (never null).
    static uint64_t* find_child(const uint64_t* node, const hdr_type& h,
                                uint8_t idx) noexcept {
        int slot = find_slot(node, h, idx);
        const uint64_t* sb = h.get_slots(const_cast<uint64_t*>(node));
        return slots::load_child(sb, slot);
    }

    // ------------------------------------------------------------------
    // EOS child access — slot[count + 1]
    // ------------------------------------------------------------------

    static uint64_t* eos_child(const uint64_t* node, const hdr_type& h) noexcept {
        const uint64_t* sb = h.get_slots(const_cast<uint64_t*>(node));
        return slots::load_child(sb, h.count + 1);
    }

    static void set_eos_child(uint64_t* node, const hdr_type& h,
                              uint64_t* child) noexcept {
        uint64_t* sb = h.get_slots(node);
        slots::store_child(sb, h.count + 1, child);
    }

    // ------------------------------------------------------------------
    // Node size computation
    // ------------------------------------------------------------------

    static size_t needed_u64(uint8_t skip_len, uint16_t child_count) noexcept {
        size_t bytes = hdr_type::header_size();                          // 8
        if (skip_len > 0) bytes += (skip_len + 7) & ~size_t(7);         // skip
        bytes += BITMAP_BYTES;                                           // bitmap
        uint16_t total = child_count + 2;                                // sentinel + children + eos
        bytes += slots::size_bytes(total);                               // slots
        return (bytes + 7) / 8;
    }

    // ------------------------------------------------------------------
    // Slot initialization — fill sentinel and eos_child with sentinel_ptr
    // ------------------------------------------------------------------

    static void init_slots(uint64_t* sb, uint16_t child_count) noexcept {
        slots::store_child(sb, 0, sentinel_ptr());
        slots::store_child(sb, child_count + 1, sentinel_ptr());
    }

    // ------------------------------------------------------------------
    // Node creation
    // ------------------------------------------------------------------

    // Create a new empty bitmask node with optional skip prefix.
    static uint64_t* create(mem_type& mem,
                            uint8_t skip_len, const uint8_t* skip_data) {
        size_t nu = needed_u64(skip_len, 0);
        uint64_t* node = mem.alloc_node(nu);
        hdr_type& h = hdr_type::from_node(node);
        h.set_bitmask(true);
        h.skip       = skip_len;
        h.count      = 0;
        h.keys_bytes = 0;

        if (skip_len > 0 && skip_data)
            std::memcpy(hdr_type::get_skip(node), skip_data, skip_len);

        init_slots(h.get_slots(node), 0);
        return node;
    }

    // Create a bitmask node pre-populated with children from buckets.
    // bucket_idx[i] = mapped character index for child i.
    // bucket_child[i] = child node pointer.
    // n_buckets = number of children.
    static uint64_t* create_with_children(
            mem_type& mem,
            uint8_t skip_len, const uint8_t* skip_data,
            const uint8_t* bucket_idx, uint64_t* const* bucket_child,
            uint16_t n_buckets) {
        size_t nu = needed_u64(skip_len, n_buckets);
        uint64_t* node = mem.alloc_node(nu);
        hdr_type& h = hdr_type::from_node(node);
        h.set_bitmask(true);
        h.skip       = skip_len;
        h.count      = n_buckets;
        h.keys_bytes = 0;

        if (skip_len > 0 && skip_data)
            std::memcpy(hdr_type::get_skip(node), skip_data, skip_len);

        bitmap_type* bm = get_bitmap(node, h);
        uint64_t* sb = h.get_slots(node);

        // sentinel at slot[0]
        slots::store_child(sb, 0, sentinel_ptr());

        // children at slot[1..n_buckets]
        for (uint16_t i = 0; i < n_buckets; ++i) {
            bm->set_bit(bucket_idx[i]);
            slots::store_child(sb, i + 1, bucket_child[i]);
        }

        // eos_child at slot[n_buckets + 1]
        slots::store_child(sb, n_buckets + 1, sentinel_ptr());

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

        // 1-based position among children (slot_for_insert is 0-based count_below)
        int pos = bm->slot_for_insert(idx) + 1;
        uint16_t old_count = h.count;
        uint16_t new_count = old_count + 1;

        size_t new_nu = needed_u64(h.skip, new_count);

        if (new_nu <= h.alloc_u64) {
            uint64_t* sb = h.get_slots(node);
            // Save eos_child from slot[old_count + 1]
            uint64_t eos_tmp = sb[old_count + 1];
            // Shift slot[pos..old_count] right by 1
            slots::move_slots(sb, pos + 1, sb, pos, old_count - (pos - 1));
            slots::store_child(sb, pos, child);
            // Restore eos_child at slot[new_count + 1]
            sb[new_count + 1] = eos_tmp;
            bm->set_bit(idx);
            h.count = new_count;
            return node;
        }

        // Reallocate
        uint64_t* new_node = mem.alloc_node(new_nu);
        hdr_type& nh = hdr_type::from_node(new_node);
        nh.copy_from(h);
        nh.count = new_count;

        if (h.skip > 0)
            std::memcpy(hdr_type::get_skip(new_node),
                        hdr_type::get_skip(node), h.skip_bytes());

        bitmap_type* new_bm = get_bitmap(new_node, nh);
        *new_bm = *bm;
        new_bm->set_bit(idx);

        const uint64_t* old_sb = h.get_slots(node);
        uint64_t* new_sb = nh.get_slots(new_node);

        // slot[0] = sentinel
        slots::store_child(new_sb, 0, sentinel_ptr());
        // Children before insertion point: slot[1..pos-1]
        if (pos > 1)
            slots::copy_slots(new_sb, 1, old_sb, 1, pos - 1);
        // New child at slot[pos]
        slots::store_child(new_sb, pos, child);
        // Children after insertion point: old slot[pos..old_count]
        slots::copy_slots(new_sb, pos + 1, old_sb, pos,
                          old_count - (pos - 1));
        // eos_child at slot[new_count + 1]
        new_sb[new_count + 1] = old_sb[old_count + 1];

        mem.free_node(node);
        return new_node;
    }

    // Replace existing child pointer at mapped character index idx.
    // idx must already be present.
    static void replace_child(uint64_t* node, const hdr_type& h,
                              uint8_t idx, uint64_t* new_child) noexcept {
        int slot = find_slot(node, h, idx);
        assert(slot > 0 && "replace_child: index not found");
        uint64_t* sb = h.get_slots(node);
        slots::store_child(sb, slot, new_child);
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
        int pos = bm->find_slot(idx) + 1;   // 1-based
        assert(pos > 0 && "remove_child: index not found");

        uint16_t old_count = h.count;
        uint64_t* sb = h.get_slots(node);

        // Save eos_child
        uint64_t eos_tmp = sb[old_count + 1];

        // Shift slot[pos+1..old_count] left by 1
        slots::move_slots(sb, pos, sb, pos + 1, old_count - pos);

        bm->clear_bit(idx);
        h.count = old_count - 1;

        // Restore eos_child at slot[new_count + 1] = slot[old_count]
        sb[old_count] = eos_tmp;

        // Clear unused last slot
        sb[old_count + 1] = 0;

        return node;
    }

    // ------------------------------------------------------------------
    // Iteration helpers
    // ------------------------------------------------------------------

    static int first_child_idx(const uint64_t* node, const hdr_type& h) noexcept {
        const bitmap_type* bm = get_bitmap(node, h);
        return bm->find_next_set(0);
    }

    static int next_child_idx(const uint64_t* node, const hdr_type& h,
                              int prev) noexcept {
        const bitmap_type* bm = get_bitmap(node, h);
        return bm->find_next_set(prev + 1);
    }

    // Get child pointer by dense slot position (0-based among children).
    static uint64_t* child_by_slot(const uint64_t* node, const hdr_type& h,
                                   uint16_t slot) noexcept {
        const uint64_t* sb = h.get_slots(const_cast<uint64_t*>(node));
        return slots::load_child(sb, slot + 1);  // +1 to skip sentinel
    }

    // ------------------------------------------------------------------
    // Memory usage (recursive)
    // ------------------------------------------------------------------

    static size_t memory_usage(const uint64_t* node) noexcept {
        const hdr_type& h = hdr_type::from_node(node);
        if (h.is_sentinel()) return 0;

        size_t total = static_cast<size_t>(h.alloc_u64) * 8;

        const uint64_t* sb = h.get_slots(const_cast<uint64_t*>(node));

        // Iterate slot[1..count] (children) and slot[count+1] (eos_child)
        // slot[0] is sentinel — skip it
        for (uint16_t i = 1; i <= static_cast<uint16_t>(h.count + 1); ++i) {
            uint64_t* child = slots::load_child(sb, i);
            const hdr_type& ch = hdr_type::from_node(child);
            if (ch.is_sentinel()) continue;
            if (ch.is_bitmap())
                total += memory_usage(child);
            else
                total += static_cast<size_t>(ch.alloc_u64) * 8;
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

        // Destroy all children and eos_child (slot[1..count+1])
        // slot[0] is sentinel — don't touch
        for (uint16_t i = 1; i <= static_cast<uint16_t>(h.count + 1); ++i) {
            uint64_t* child = slots::load_child(sb, i);
            const hdr_type& ch = hdr_type::from_node(child);
            if (ch.is_sentinel()) continue;
            if (ch.is_bitmap())
                destroy(child, mem);
            mem.free_node(child);
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

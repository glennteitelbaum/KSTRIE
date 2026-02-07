#pragma once

#include "kstrie_support.hpp"

namespace gteitelbaum {

template <typename VALUE, typename CHARMAP, typename ALLOC>
struct kstrie_bitmask {
    using hdr_type    = node_header<VALUE, CHARMAP, ALLOC>;
    using bitmap_type = typename CHARMAP::bitmap_type;
    using slots       = kstrie_slots<VALUE>;
    using mem_type    = kstrie_memory<ALLOC>;

    static constexpr size_t BITMAP_BYTES = sizeof(bitmap_type);
    static constexpr size_t BITMAP_WORDS = CHARMAP::BITMAP_WORDS;
    static constexpr size_t BITMAP_U64   = BITMAP_BYTES / 8;

    static constexpr size_t index_size(const hdr_type& /*h*/) noexcept {
        return BITMAP_BYTES;
    }

    // Compute bitmask slots_off in u64 units
    static uint16_t compute_slots_off(uint8_t skip_len) noexcept {
        size_t skip_aligned = skip_len > 0 ? ((skip_len + 7) & ~size_t(7)) : 0;
        return static_cast<uint16_t>((8 + skip_aligned + BITMAP_BYTES) / 8);
    }

    static bitmap_type* get_bitmap(uint64_t* node, const hdr_type& h) noexcept {
        return reinterpret_cast<bitmap_type*>(h.get_index(node));
    }

    static const bitmap_type* get_bitmap(const uint64_t* node, const hdr_type& h) noexcept {
        return reinterpret_cast<const bitmap_type*>(
            h.get_index(const_cast<uint64_t*>(node)));
    }

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

    static int find_slot(const uint64_t* node, const hdr_type& h,
                         uint8_t idx) noexcept {
        const uint64_t* bm = h.get_bitmap_index(node);
        return do_find_pop(bm, idx);
    }

    // Read-path: branchless bitmap probe + slot load
    static uint64_t* find_child(const uint64_t* node, const hdr_type& h,
                                uint8_t idx) noexcept {
        const uint64_t* bm = h.get_bitmap_index(node);
        int slot = do_find_pop(bm, idx);
        const uint64_t* sb = h.get_bitmap_slots(node);
        return slots::load_child(sb, slot);
    }

    // ------------------------------------------------------------------
    // EOS value — inline in slot[count + 1] when has_eos flag is set
    // ------------------------------------------------------------------

    static const VALUE* eos_value(const uint64_t* node, const hdr_type& h) noexcept {
        if (!h.has_eos()) return nullptr;
        const uint64_t* sb = h.get_bitmap_slots(node);
        return slots::load_value(sb, h.count + 1);
    }

    // Store eos value on a node that doesn't have one yet. May realloc.
    static uint64_t* set_eos_value(uint64_t* node, hdr_type& h, mem_type& mem,
                                   const VALUE& value) {
        assert(!h.has_eos());
        size_t need = needed_u64(h.skip, h.count, true);
        if (need <= h.alloc_u64) {
            h.set_has_eos(true);
            hdr_type::from_node(node).set_has_eos(true);
            uint64_t* sb = h.get_bitmap_slots(node);
            slots::store_value(sb, h.count + 1, value);
            return node;
        }
        // Realloc
        uint64_t* nn = mem.alloc_node(need);
        hdr_type& nh = hdr_type::from_node(nn);
        nh.copy_from(h);
        nh.set_has_eos(true);
        nh.slots_off = compute_slots_off(h.skip);
        if (h.skip > 0)
            std::memcpy(hdr_type::get_skip(nn), hdr_type::get_skip(node), h.skip_bytes());
        const uint64_t* old_bm = h.get_bitmap_index(node);
        uint64_t* new_bm = nh.get_bitmap_index(nn);
        std::memcpy(new_bm, old_bm, BITMAP_BYTES);
        const uint64_t* old_sb = h.get_bitmap_slots(node);
        uint64_t* new_sb = nh.get_bitmap_slots(nn);
        slots::copy_slots(new_sb, 0, old_sb, 0, h.count + 1); // sentinel + children
        slots::store_value(new_sb, h.count + 1, value);
        mem.free_node(node);
        return nn;
    }

    // Update existing eos value (node already has_eos).
    static void update_eos_value(uint64_t* node, const hdr_type& h,
                                 const VALUE& value) {
        assert(h.has_eos());
        uint64_t* sb = h.get_bitmap_slots(node);
        slots::destroy_value(sb, h.count + 1);
        slots::store_value(sb, h.count + 1, value);
    }

    // Write raw eos slot (used by split_node to move values without create/destroy).
    // May realloc. Caller must NOT have already set has_eos.
    static uint64_t* add_eos_raw(uint64_t* node, hdr_type& h, mem_type& mem,
                                 uint64_t raw) {
        assert(!h.has_eos());
        size_t need = needed_u64(h.skip, h.count, true);
        if (need <= h.alloc_u64) {
            h.set_has_eos(true);
            hdr_type::from_node(node).set_has_eos(true);
            uint64_t* sb = h.get_bitmap_slots(node);
            sb[h.count + 1] = raw;
            return node;
        }
        uint64_t* nn = mem.alloc_node(need);
        hdr_type& nh = hdr_type::from_node(nn);
        nh.copy_from(h);
        nh.set_has_eos(true);
        nh.slots_off = compute_slots_off(h.skip);
        if (h.skip > 0)
            std::memcpy(hdr_type::get_skip(nn), hdr_type::get_skip(node), h.skip_bytes());
        const uint64_t* old_bm = h.get_bitmap_index(node);
        uint64_t* new_bm = nh.get_bitmap_index(nn);
        std::memcpy(new_bm, old_bm, BITMAP_BYTES);
        const uint64_t* old_sb = h.get_bitmap_slots(node);
        uint64_t* new_sb = nh.get_bitmap_slots(nn);
        slots::copy_slots(new_sb, 0, old_sb, 0, h.count + 1);
        new_sb[h.count + 1] = raw;
        mem.free_node(node);
        return nn;
    }

    static size_t needed_u64(uint8_t skip_len, uint16_t child_count,
                             bool has_eos = false) noexcept {
        size_t bytes = hdr_type::header_size();
        if (skip_len > 0) bytes += (skip_len + 7) & ~size_t(7);
        bytes += BITMAP_BYTES;
        uint16_t total = child_count + 1 + (has_eos ? 1 : 0);
        bytes += slots::size_bytes(total);
        return (bytes + 7) / 8;
    }

    static void init_slots(uint64_t* sb) noexcept {
        slots::store_child(sb, 0, sentinel_ptr());
    }

    static uint64_t* create(mem_type& mem,
                            uint8_t skip_len, const uint8_t* skip_data) {
        size_t nu = needed_u64(skip_len, 0);
        uint64_t* node = mem.alloc_node(nu);
        hdr_type& h = hdr_type::from_node(node);
        h.set_bitmask(true);
        h.skip      = skip_len;
        h.count     = 0;
        h.slots_off = compute_slots_off(skip_len);
        if (skip_len > 0 && skip_data)
            std::memcpy(hdr_type::get_skip(node), skip_data, skip_len);
        init_slots(h.get_slots(node));
        return node;
    }

    static uint64_t* create_with_children(
            mem_type& mem,
            uint8_t skip_len, const uint8_t* skip_data,
            const uint8_t* bucket_idx, uint64_t* const* bucket_child,
            uint16_t n_buckets) {
        size_t nu = needed_u64(skip_len, n_buckets);
        uint64_t* node = mem.alloc_node(nu);
        hdr_type& h = hdr_type::from_node(node);
        h.set_bitmask(true);
        h.skip      = skip_len;
        h.count     = n_buckets;
        h.slots_off = compute_slots_off(skip_len);
        if (skip_len > 0 && skip_data)
            std::memcpy(hdr_type::get_skip(node), skip_data, skip_len);
        bitmap_type* bm = get_bitmap(node, h);
        uint64_t* sb = h.get_slots(node);
        slots::store_child(sb, 0, sentinel_ptr());
        for (uint16_t i = 0; i < n_buckets; ++i) {
            bm->set_bit(bucket_idx[i]);
            slots::store_child(sb, i + 1, bucket_child[i]);
        }
        return node;
    }

    static uint64_t* insert_child(uint64_t* node, hdr_type& h, mem_type& mem,
                                  uint8_t idx, uint64_t* child) {
        bitmap_type* bm = get_bitmap(node, h);
        assert(!bm->has_bit(idx) && "insert_child: index already present");
        int pos = bm->slot_for_insert(idx) + 1;
        uint16_t old_count = h.count;
        uint16_t new_count = old_count + 1;
        bool eos = h.has_eos();
        size_t new_nu = needed_u64(h.skip, new_count, eos);
        if (new_nu <= h.alloc_u64) {
            uint64_t* sb = h.get_slots(node);
            uint64_t eos_tmp = 0;
            if (eos) eos_tmp = sb[old_count + 1];
            slots::move_slots(sb, pos + 1, sb, pos, old_count - (pos - 1));
            slots::store_child(sb, pos, child);
            if (eos) sb[new_count + 1] = eos_tmp;
            bm->set_bit(idx);
            h.count = new_count;
            hdr_type::from_node(node).count = new_count;
            return node;
        }
        uint64_t* new_node = mem.alloc_node(new_nu);
        hdr_type& nh = hdr_type::from_node(new_node);
        nh.copy_from(h);
        nh.count     = new_count;
        nh.slots_off = compute_slots_off(h.skip);
        if (h.skip > 0)
            std::memcpy(hdr_type::get_skip(new_node),
                        hdr_type::get_skip(node), h.skip_bytes());
        bitmap_type* new_bm = get_bitmap(new_node, nh);
        *new_bm = *bm;
        new_bm->set_bit(idx);
        const uint64_t* old_sb = h.get_slots(node);
        uint64_t* new_sb = nh.get_slots(new_node);
        slots::store_child(new_sb, 0, sentinel_ptr());
        if (pos > 1) slots::copy_slots(new_sb, 1, old_sb, 1, pos - 1);
        slots::store_child(new_sb, pos, child);
        slots::copy_slots(new_sb, pos + 1, old_sb, pos, old_count - (pos - 1));
        if (eos) new_sb[new_count + 1] = old_sb[old_count + 1];
        mem.free_node(node);
        return new_node;
    }

    static uint64_t* reskip(uint64_t* node, hdr_type& h, mem_type& mem,
                            uint8_t new_skip_len,
                            const uint8_t* new_skip_data) {
        size_t nu = needed_u64(new_skip_len, h.count, h.has_eos());
        uint64_t* nn = mem.alloc_node(nu);
        hdr_type& nh = hdr_type::from_node(nn);
        nh.copy_from(h);
        nh.skip      = new_skip_len;
        nh.slots_off = compute_slots_off(new_skip_len);
        if (new_skip_len > 0 && new_skip_data)
            std::memcpy(hdr_type::get_skip(nn), new_skip_data, new_skip_len);
        *get_bitmap(nn, nh) = *get_bitmap(node, h);
        const uint64_t* old_sb = h.get_slots(node);
        uint64_t* new_sb = nh.get_slots(nn);
        slots::copy_slots(new_sb, 0, old_sb, 0, h.total_slots());
        mem.free_node(node);
        return nn;
    }

    static void replace_child(uint64_t* node, const hdr_type& h,
                              uint8_t idx, uint64_t* new_child) noexcept {
        int slot = find_slot(node, h, idx);
        assert(slot > 0 && "replace_child: index not found");
        uint64_t* sb = h.get_slots(node);
        slots::store_child(sb, slot, new_child);
    }

    static uint64_t* remove_child(uint64_t* node, hdr_type& h,
                                  uint8_t idx) noexcept {
        bitmap_type* bm = get_bitmap(node, h);
        int pos = bm->find_slot(idx) + 1;
        assert(pos > 0 && "remove_child: index not found");
        uint16_t old_count = h.count;
        bool eos = h.has_eos();
        uint64_t* sb = h.get_slots(node);
        uint64_t eos_tmp = 0;
        if (eos) eos_tmp = sb[old_count + 1];
        slots::move_slots(sb, pos, sb, pos + 1, old_count - pos);
        bm->clear_bit(idx);
        h.count = old_count - 1;
        hdr_type::from_node(node).count = old_count - 1;
        if (eos) sb[old_count] = eos_tmp;
        return node;
    }

    static int first_child_idx(const uint64_t* node, const hdr_type& h) noexcept {
        const bitmap_type* bm = get_bitmap(node, h);
        return bm->find_next_set(0);
    }

    static int next_child_idx(const uint64_t* node, const hdr_type& h, int prev) noexcept {
        const bitmap_type* bm = get_bitmap(node, h);
        return bm->find_next_set(prev + 1);
    }

    static uint64_t* child_by_slot(const uint64_t* node, const hdr_type& h,
                                   uint16_t slot) noexcept {
        const uint64_t* sb = h.get_slots(const_cast<uint64_t*>(node));
        return slots::load_child(sb, slot + 1);
    }

    static size_t memory_usage(const uint64_t* node) noexcept {
        if (node == sentinel_ptr()) return 0;
        const hdr_type& h = hdr_type::from_node(node);
        size_t total = static_cast<size_t>(h.alloc_u64) * 8;
        const uint64_t* sb = h.get_slots(const_cast<uint64_t*>(node));
        for (uint16_t i = 1; i <= h.count; ++i) {
            uint64_t* child = slots::load_child(sb, i);
            if (child == sentinel_ptr()) continue;
            const hdr_type& ch = hdr_type::from_node(child);
            if (ch.is_bitmap()) total += memory_usage(child);
            else total += static_cast<size_t>(ch.alloc_u64) * 8;
        }
        // eos value is inline — no extra allocation
        return total;
    }

    static void destroy(uint64_t* node, mem_type& mem) {
        if (node == sentinel_ptr()) return;
        hdr_type& h = hdr_type::from_node(node);
        uint64_t* sb = h.get_slots(node);
        for (uint16_t i = 1; i <= h.count; ++i) {
            uint64_t* child = slots::load_child(sb, i);
            if (child == sentinel_ptr()) continue;
            if (hdr_type::from_node(child).is_bitmap()) destroy(child, mem);
            mem.free_node(child);
        }
        // Destroy inline eos value if present
        if (h.has_eos())
            slots::destroy_value(sb, h.count + 1);
    }

    static uint16_t child_count(const uint64_t* node, const hdr_type& h) noexcept {
        return h.count;
    }

    static uint16_t popcount(const uint64_t* node, const hdr_type& h) noexcept {
        const bitmap_type* bm = get_bitmap(node, h);
        return static_cast<uint16_t>(bm->popcount());
    }
};

} // namespace gteitelbaum

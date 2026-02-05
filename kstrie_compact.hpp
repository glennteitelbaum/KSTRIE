#pragma once

#include "kstrie_support.hpp"
#include <vector>

namespace gteitelbaum {

// ============================================================================
// kstrie_compact -- compact (leaf) node operations
//
// Node layout:  [header 8B] [skip] [index] [slots]
//
// Index region = [hot] [idx] [keys]
//   hot[0..ec]:  Eytzinger tree of boundary e values (hot[0] unused)
//   idx[0..ic-1]: one e per 8 keys (prefix + byte offset into keys)
//   keys[]:       packed keys as [u16 len][bytes...]
//
// Slots region = [eos_value?] [value_0] [value_1] ... [value_{count-1}]
//
// Search: Eytzinger → idx scan (≤4) → key scan (≤8) = O(log N + 12)
//
// Owns: search, insert, create, extract, value access
// Does NOT own: prefix matching (kstrie_skip), split to bitmap (caller)
// ============================================================================

template <typename VALUE, typename CHARMAP, typename ALLOC>
struct kstrie_compact {
    using hdr_type    = node_header<VALUE, CHARMAP, ALLOC>;
    using slots       = kstrie_slots<VALUE>;
    using mem_type    = kstrie_memory<ALLOC>;

    // ------------------------------------------------------------------
    // Entry descriptor (for building nodes from sorted entries)
    // ------------------------------------------------------------------

    struct entry_desc {
        const uint8_t* suffix;
        uint32_t       suffix_len;
    };

    // ------------------------------------------------------------------
    // Index size (called by node_header::index_size)
    // ------------------------------------------------------------------

    static size_t index_size(const hdr_type& h) noexcept {
        return compact_index_size(h.count, h.keys_bytes);
    }

    // ------------------------------------------------------------------
    // Index region view
    // ------------------------------------------------------------------

    struct index_view {
        const e*       hot;
        const e*       idx;
        const uint8_t* keys;
        int            ic, ec, W;
    };

    static index_view view_index(const uint64_t* node, const hdr_type& h) noexcept {
        const uint8_t* base = h.get_index(const_cast<uint64_t*>(node));
        int ic = idx_count(h.count);
        int W  = calc_W(ic);
        int ec = W > 0 ? W - 1 : 0;
        return {
            reinterpret_cast<const e*>(base + hot_off()),
            reinterpret_cast<const e*>(base + idx_off(ec)),
            base + keys_off(h.count, ec),
            ic, ec, W
        };
    }

    // Mutable version for build operations
    struct index_ptrs {
        e*       hot;
        e*       idx;
        uint8_t* keys;
        int      ic, ec, W;
    };

    static index_ptrs get_index_ptrs(uint64_t* node, const hdr_type& h) noexcept {
        uint8_t* base = h.get_index(node);
        int ic = idx_count(h.count);
        int W  = calc_W(ic);
        int ec = W > 0 ? W - 1 : 0;
        return {
            reinterpret_cast<e*>(base + hot_off()),
            reinterpret_cast<e*>(base + idx_off(ec)),
            base + keys_off(h.count, ec),
            ic, ec, W
        };
    }

    // ------------------------------------------------------------------
    // Search position
    //
    // Returns: found (exact match), pos (position or insertion point),
    //          block_offset (byte offset of the block in keys region)
    // ------------------------------------------------------------------

    static search_result find_position(const uint64_t* node, const hdr_type& h,
                                       const uint8_t* suffix,
                                       uint32_t suffix_len) noexcept {
        uint16_t count = h.count;
        if (count == 0) return {false, 0, 0};

        auto vi = view_index(node, h);
        e skey_prefix = e_prefix_only(make_search_key(suffix, suffix_len));

        // ---- Phase 1: Eytzinger → narrow idx range ----
        int idx_lo = 0, idx_hi = vi.ic;
        if (vi.ec > 0) {
            int i = 1;
            while (i <= vi.ec)
                i = 2 * i + (e_prefix_only(vi.hot[i]) <= skey_prefix);

            int window = i - vi.ec - 1;
            idx_lo = window * vi.ic / vi.W;
            idx_hi = std::min((window + 1) * vi.ic / vi.W + 1, vi.ic);
            // Expand by 1 on the low side for safety at boundaries
            if (idx_lo > 0) --idx_lo;
        }

        // ---- Phase 2: Scan idx entries → find block ----
        int block = idx_lo;
        for (int k = idx_lo + 1; k < idx_hi; ++k) {
            if (e_prefix_only(vi.idx[k]) > skey_prefix) break;
            block = k;
        }

        // ---- Phase 3: Scan packed keys in block ----
        int key_start = block * 8;
        // Scan up to 16 keys when prefix matches the next block boundary
        // (handles keys > 14 bytes that share the same e prefix)
        bool prefix_match = (block + 1 < vi.ic &&
                             e_prefix_only(vi.idx[block + 1]) == skey_prefix);
        int scan_end = std::min(key_start + (prefix_match ? 16 : 8),
                                static_cast<int>(count));

        uint32_t block_offset = e_offset(vi.idx[block]);
        const uint8_t* kp = vi.keys + block_offset;

        for (int pos = key_start; pos < scan_end; ++pos) {
            int cmp = key_cmp(kp, suffix, suffix_len);
            if (cmp == 0) return {true,  pos, block_offset};
            if (cmp > 0)  return {false, pos, block_offset};
            kp = key_next(kp);
        }

        return {false, scan_end, block_offset};
    }

    // ------------------------------------------------------------------
    // Value lookup
    // ------------------------------------------------------------------

    static VALUE* find_value(uint64_t* node, const hdr_type& h,
                             const uint8_t* suffix, uint32_t suffix_len) noexcept {
        auto sr = find_position(node, h, suffix, suffix_len);
        if (!sr.found) return nullptr;
        uint64_t* sb = h.get_slots(node);
        return &slots::load_value(sb, h.has_eos() + sr.pos);
    }

    static const VALUE* find_value(const uint64_t* node, const hdr_type& h,
                                   const uint8_t* suffix,
                                   uint32_t suffix_len) noexcept {
        auto sr = find_position(node, h, suffix, suffix_len);
        if (!sr.found) return nullptr;
        const uint64_t* sb = h.get_slots(const_cast<uint64_t*>(node));
        return &slots::load_value(sb, h.has_eos() + sr.pos);
    }

    // ------------------------------------------------------------------
    // EOS value access
    // ------------------------------------------------------------------

    static VALUE* find_eos(uint64_t* node, const hdr_type& h) noexcept {
        if (!h.has_eos()) return nullptr;
        return &slots::load_eos(h.get_slots(node));
    }

    static const VALUE* find_eos(const uint64_t* node, const hdr_type& h) noexcept {
        if (!h.has_eos()) return nullptr;
        const uint64_t* sb = h.get_slots(const_cast<uint64_t*>(node));
        return &slots::load_eos(sb);
    }

    // ------------------------------------------------------------------
    // Set / update EOS value
    // Returns (possibly reallocated) node and whether it was an update.
    // ------------------------------------------------------------------

    struct eos_result {
        uint64_t* node;
        bool      was_update;
    };

    static eos_result set_eos(uint64_t* node, hdr_type& h, mem_type& mem,
                              const VALUE& val) {
        if (h.has_eos()) {
            uint64_t* sb = h.get_slots(node);
            slots::destroy_eos(sb);
            slots::store_eos(sb, val);
            return {node, true};
        }

        // Adding EOS: need one more slot. Check if it fits.
        size_t new_nu = needed_u64(h.skip, h.count, h.keys_bytes, true);

        if (new_nu <= h.alloc_u64) {
            // Shift values right by 1 to make room for eos at slot 0
            uint64_t* sb = h.get_slots(node);
            slots::move_slots(sb, 1, sb, 0, h.count);
            slots::store_eos(sb, val);
            h.set_eos(true);
            return {node, false};
        }

        // Reallocate
        uint64_t* nn = mem.alloc_node(new_nu);
        hdr_type& nh = hdr_type::from_node(nn);
        nh.copy_from(h);
        nh.set_eos(true);

        // Copy skip
        if (h.skip > 0)
            std::memcpy(hdr_type::get_skip(nn),
                        hdr_type::get_skip(node), h.skip_bytes());

        // Copy index (identical layout since count/keys_bytes unchanged)
        if (h.count > 0)
            std::memcpy(nh.get_index(nn), h.get_index(node), h.index_size());

        // Slots: eos at [0], then copy old values
        uint64_t* new_sb = nh.get_slots(nn);
        const uint64_t* old_sb = h.get_slots(node);
        slots::store_eos(new_sb, val);
        slots::copy_slots(new_sb, 1, old_sb, 0, h.count);

        mem.free_node(node);
        return {nn, false};
    }

    // ------------------------------------------------------------------
    // Remove EOS value
    // ------------------------------------------------------------------

    static void remove_eos(uint64_t* node, hdr_type& h) noexcept {
        if (!h.has_eos()) return;
        uint64_t* sb = h.get_slots(node);
        slots::destroy_eos(sb);
        slots::move_slots(sb, 0, sb, 1, h.count);
        sb[h.count] = 0;
        h.set_eos(false);
    }

    // ------------------------------------------------------------------
    // Node size computation
    // ------------------------------------------------------------------

    static size_t needed_u64(uint8_t skip_len, uint16_t count,
                             uint16_t keys_bytes, bool has_eos) noexcept {
        size_t bytes = hdr_type::header_size();
        if (skip_len > 0) bytes += (skip_len + 7) & ~size_t(7);
        bytes += compact_index_size(count, keys_bytes);
        uint16_t total = count + (has_eos ? 1 : 0);
        bytes += slots::size_bytes(total);
        return (bytes + 7) / 8;
    }

    // ------------------------------------------------------------------
    // Exceeds compact limits?
    // Caller should split to bitmap when this returns true.
    // ------------------------------------------------------------------

    static bool exceeds_limits(uint16_t count, uint16_t keys_bytes) noexcept {
        return count > COMPACT_MAX || keys_bytes > COMPACT_MAX_BYTES;
    }

    // ------------------------------------------------------------------
    // Build index: populate hot[], idx[], keys[] in an allocated node
    //
    // entries must be sorted. Returns actual keys_bytes written.
    // ------------------------------------------------------------------

    static uint16_t build_index(uint8_t* index_base, uint16_t count,
                                const entry_desc* entries) noexcept {
        if (count == 0) return 0;

        int ic = idx_count(count);
        int W  = calc_W(ic);
        int ec = W > 0 ? W - 1 : 0;

        e*       hot  = reinterpret_cast<e*>(index_base + hot_off());
        e*       idx  = reinterpret_cast<e*>(index_base + idx_off(ec));
        uint8_t* keys = index_base + keys_off(count, ec);

        // Pack keys and build idx entries (one per 8 keys)
        uint8_t* kp = keys;
        for (uint16_t i = 0; i < count; ++i) {
            if (i % 8 == 0) {
                es s;
                s.setkey(reinterpret_cast<const char*>(entries[i].suffix),
                         static_cast<int>(entries[i].suffix_len));
                s.setoff(static_cast<uint16_t>(kp - keys));
                idx[i / 8] = cvt(s);
            }
            write_u16(kp, static_cast<uint16_t>(entries[i].suffix_len));
            std::memcpy(kp + 2, entries[i].suffix, entries[i].suffix_len);
            kp += 2 + entries[i].suffix_len;
        }

        uint16_t keys_bytes = static_cast<uint16_t>(kp - keys);

        // Build Eytzinger tree from idx
        if (ec > 0)
            build_eyt(idx, ic, hot);

        return keys_bytes;
    }

    // ------------------------------------------------------------------
    // Compute keys_bytes for a set of entries
    // ------------------------------------------------------------------

    static uint16_t compute_keys_bytes(const entry_desc* entries,
                                       uint16_t count) noexcept {
        uint16_t total = 0;
        for (uint16_t i = 0; i < count; ++i)
            total += 2 + static_cast<uint16_t>(entries[i].suffix_len);
        return total;
    }

    // ------------------------------------------------------------------
    // Create node from sorted entries
    //
    // entries: sorted key suffixes (after skip stripped)
    // values:  parallel array of values
    // ------------------------------------------------------------------

    static uint64_t* create_from_entries(
            mem_type& mem,
            uint8_t skip_len, const uint8_t* skip_data,
            bool has_eos, const VALUE* eos_val,
            const entry_desc* entries, const VALUE* values,
            uint16_t count) {
        uint16_t kb = compute_keys_bytes(entries, count);
        size_t nu = needed_u64(skip_len, count, kb, has_eos);

        uint64_t* node = mem.alloc_node(nu);
        hdr_type& h = hdr_type::from_node(node);
        h.set_compact(true);
        h.skip       = skip_len;
        h.count      = count;
        h.keys_bytes = kb;
        h.set_eos(has_eos);

        if (skip_len > 0 && skip_data)
            std::memcpy(hdr_type::get_skip(node), skip_data, skip_len);

        if (count > 0)
            build_index(h.get_index(node), count, entries);

        uint64_t* sb = h.get_slots(node);
        if (has_eos && eos_val)
            slots::store_eos(sb, *eos_val);
        size_t val_start = has_eos ? 1 : 0;
        for (uint16_t i = 0; i < count; ++i)
            slots::store_value(sb, val_start + i, values[i]);

        return node;
    }

    // Variant: create from entries with raw slot transfer (avoids VALUE copy).
    // old_slots: pointer to value slot array (eos slot NOT included).
    // Raw uint64_t values are memcpy'd, transferring pointer ownership.
    static uint64_t* create_from_entries_raw(
            mem_type& mem,
            uint8_t skip_len, const uint8_t* skip_data,
            bool has_eos, const uint64_t* eos_raw,
            const entry_desc* entries, uint16_t count,
            const uint64_t* old_value_slots) {
        uint16_t kb = compute_keys_bytes(entries, count);
        size_t nu = needed_u64(skip_len, count, kb, has_eos);

        uint64_t* node = mem.alloc_node(nu);
        hdr_type& h = hdr_type::from_node(node);
        h.set_compact(true);
        h.skip       = skip_len;
        h.count      = count;
        h.keys_bytes = kb;
        h.set_eos(has_eos);

        if (skip_len > 0 && skip_data)
            std::memcpy(hdr_type::get_skip(node), skip_data, skip_len);

        if (count > 0)
            build_index(h.get_index(node), count, entries);

        uint64_t* sb = h.get_slots(node);
        if (has_eos && eos_raw)
            sb[0] = *eos_raw;  // raw transfer
        size_t val_start = has_eos ? 1 : 0;
        if (count > 0)
            slots::copy_slots(sb, val_start, old_value_slots, 0, count);

        return node;
    }

    // ------------------------------------------------------------------
    // Insert entry (rebuild approach)
    //
    // Searches for suffix, inserts at the correct position.
    // Returns new node pointer and outcome.
    // Old node is freed (value slots transferred, not destroyed).
    //
    // Caller should check exceeds_limits() after insert and split if needed.
    // ------------------------------------------------------------------

    static insert_result insert_entry(
            uint64_t* old_node, hdr_type& old_h, mem_type& mem,
            const uint8_t* suffix, uint32_t suffix_len,
            const VALUE& value, insert_mode mode) {
        // Search for position
        auto sr = find_position(old_node, old_h, suffix, suffix_len);

        if (sr.found) {
            if (mode == insert_mode::UPDATE) {
                uint64_t* sb = old_h.get_slots(old_node);
                size_t slot_idx = old_h.has_eos() + sr.pos;
                slots::destroy_value(sb, slot_idx);
                slots::store_value(sb, slot_idx, value);
                return {old_node, insert_outcome::UPDATED};
            }
            return {old_node, insert_outcome::FOUND};
        }

        uint16_t old_count = old_h.count;
        uint16_t new_count = old_count + 1;
        int insert_pos = sr.pos;

        // Build entry descriptor array with new entry spliced in.
        // Entries point into the old node (which stays alive until we free it).
        std::vector<entry_desc> entries(new_count);
        {
            const uint8_t* kp = nullptr;
            if (old_count > 0) {
                auto vi = view_index(old_node, old_h);
                kp = vi.keys;
            }
            int dst = 0;
            for (uint16_t i = 0; i < old_count; ++i) {
                if (dst == insert_pos) {
                    entries[dst++] = {suffix, suffix_len};
                }
                entries[dst].suffix     = kp + 2;
                entries[dst].suffix_len = read_u16(kp);
                kp = key_next(kp);
                ++dst;
            }
            if (dst == insert_pos) {
                entries[dst] = {suffix, suffix_len};
            }
        }

        // Compute new sizes
        uint16_t new_kb = compute_keys_bytes(entries.data(), new_count);
        size_t new_nu = needed_u64(old_h.skip, new_count, new_kb, old_h.has_eos());

        // Allocate new node
        uint64_t* nn = mem.alloc_node(new_nu);
        hdr_type& nh = hdr_type::from_node(nn);
        nh.copy_from(old_h);
        nh.count      = new_count;
        nh.keys_bytes = new_kb;

        // Copy skip prefix
        if (old_h.skip > 0)
            std::memcpy(hdr_type::get_skip(nn),
                        hdr_type::get_skip(old_node), old_h.skip_bytes());

        // Build new index
        build_index(nh.get_index(nn), new_count, entries.data());

        // Transfer value slots from old node, insert new value
        uint64_t* new_sb = nh.get_slots(nn);
        const uint64_t* old_sb = old_h.get_slots(old_node);
        size_t eos_off = old_h.has_eos() ? 1 : 0;

        // Raw copy EOS slot if present
        if (old_h.has_eos())
            new_sb[0] = old_sb[0];

        // Values before insertion point (raw transfer)
        slots::copy_slots(new_sb, eos_off,
                          old_sb, eos_off,
                          insert_pos);
        // New value
        slots::store_value(new_sb, eos_off + insert_pos, value);
        // Values after insertion point (raw transfer)
        slots::copy_slots(new_sb, eos_off + insert_pos + 1,
                          old_sb, eos_off + insert_pos,
                          old_count - insert_pos);

        // Free old node (don't destroy values — ownership transferred)
        mem.free_node(old_node);

        return {nn, insert_outcome::INSERTED};
    }

    // ------------------------------------------------------------------
    // Extract all entries (for split to bitmap)
    //
    // Fills out_entries with suffix pointers into the node's keys region.
    // The node must remain alive while out_entries are in use.
    // ------------------------------------------------------------------

    static void extract_entries(const uint64_t* node, const hdr_type& h,
                                std::vector<entry_desc>& out) {
        out.resize(h.count);
        if (h.count == 0) return;

        auto vi = view_index(node, h);
        const uint8_t* kp = vi.keys;
        for (uint16_t i = 0; i < h.count; ++i) {
            out[i].suffix     = kp + 2;
            out[i].suffix_len = read_u16(kp);
            kp = key_next(kp);
        }
    }

    // ------------------------------------------------------------------
    // Get value by position index (for use after extract_entries)
    // ------------------------------------------------------------------

    static VALUE& value_at(uint64_t* node, const hdr_type& h,
                           uint16_t pos) noexcept {
        uint64_t* sb = h.get_slots(node);
        return slots::load_value(sb, h.has_eos() + pos);
    }

    static const VALUE& value_at(const uint64_t* node, const hdr_type& h,
                                 uint16_t pos) noexcept {
        const uint64_t* sb = h.get_slots(const_cast<uint64_t*>(node));
        return slots::load_value(sb, h.has_eos() + pos);
    }

    // Raw slot pointer for value region (excluding eos).
    // Used for raw slot transfer during split.
    static const uint64_t* value_slots(const uint64_t* node,
                                       const hdr_type& h) noexcept {
        const uint64_t* sb = h.get_slots(const_cast<uint64_t*>(node));
        return sb + (h.has_eos() ? 1 : 0);
    }

    // Raw EOS slot (or nullptr)
    static const uint64_t* eos_slot(const uint64_t* node,
                                    const hdr_type& h) noexcept {
        if (!h.has_eos()) return nullptr;
        return h.get_slots(const_cast<uint64_t*>(node));
    }

    // ------------------------------------------------------------------
    // Memory usage
    // ------------------------------------------------------------------

    static size_t memory_usage(const uint64_t* node) noexcept {
        const hdr_type& h = hdr_type::from_node(node);
        if (h.is_sentinel()) return 0;
        return static_cast<size_t>(h.alloc_u64) * 8;
    }

    // ------------------------------------------------------------------
    // Destroy all values in a compact node (does NOT free the node)
    // ------------------------------------------------------------------

    static void destroy_values(uint64_t* node, hdr_type& h) {
        uint64_t* sb = h.get_slots(node);
        if (h.has_eos())
            slots::destroy_eos(sb);
        size_t val_start = h.has_eos() ? 1 : 0;
        slots::destroy_values(sb, val_start, h.count);
    }

    // ------------------------------------------------------------------
    // Debug: walk all keys and verify sorted order
    // ------------------------------------------------------------------

    static bool verify_sorted(const uint64_t* node, const hdr_type& h) noexcept {
        if (h.count <= 1) return true;
        auto vi = view_index(node, h);
        const uint8_t* prev = vi.keys;
        const uint8_t* kp = key_next(prev);
        for (uint16_t i = 1; i < h.count; ++i) {
            uint16_t prev_len = read_u16(prev);
            uint16_t cur_len  = read_u16(kp);
            uint32_t min_len  = std::min<uint32_t>(prev_len, cur_len);
            int cmp = std::memcmp(prev + 2, kp + 2, min_len);
            if (cmp > 0 || (cmp == 0 && prev_len >= cur_len))
                return false;
            prev = kp;
            kp = key_next(kp);
        }
        return true;
    }
};

} // namespace gteitelbaum

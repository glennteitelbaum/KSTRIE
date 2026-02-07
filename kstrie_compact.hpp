#pragma once
#include "kstrie_support.hpp"
#include <algorithm>

namespace gteitelbaum {

template <typename VALUE, typename CHARMAP, typename ALLOC>
struct kstrie_bitmask;

// ============================================================================
// kstrie_compact -- compact (leaf) node operations
//
// Node layout:  [header 8B] [skip] [keys] [slots]
//
// Keys region = length-prefixed entries in sorted order:
//   [u16 len][key bytes] [u16 len][key bytes] ...
//
// Slots region = [value_0] ... [value_{count-1}]
//
// Search: linear scan with sorted-order early exit (cmp >= 0).
// Max COMPACT_MAX entries (32), so worst case 32 key_cmps.
//
// Insert strategy:
//   Always build the result node unconditionally, then finalize checks
//   count > COMPACT_MAX.  If violated, split into bitmask + compact children.
//
// VALUE ownership:
//   - T* created exactly once on insert (via slots::store_value)
//   - Moved between nodes by raw uint64_t memcpy
//   - Deleted only on erase or tree destruction
// ============================================================================

template <typename VALUE, typename CHARMAP, typename ALLOC>
struct kstrie_compact {
    using hdr_type     = node_header<VALUE, CHARMAP, ALLOC>;
    using slots        = kstrie_slots<VALUE>;
    using mem_type     = kstrie_memory<ALLOC>;
    using skip_type    = kstrie_skip<VALUE, CHARMAP, ALLOC>;
    using bitmask_ops  = kstrie_bitmask<VALUE, CHARMAP, ALLOC>;
    using match_result = typename skip_type::match_result;
    using match_status = typename skip_type::match_status;

    struct build_entry {
        const uint8_t* key;
        uint32_t       key_len;
        uint64_t       raw_slot;
    };

    // ------------------------------------------------------------------
    // Index size (called by node_header::index_size, write-path only)
    // ------------------------------------------------------------------

    static size_t index_size(const hdr_type& h) noexcept {
        size_t skip_sz = h.skip_size();
        return static_cast<size_t>(h.slots_off) * 8 - 8 - skip_sz;
    }

    // ------------------------------------------------------------------
    // Keys pointer (start of keys region = get_index)
    // ------------------------------------------------------------------

    static const uint8_t* keys_ptr(const uint64_t* node, const hdr_type& h) noexcept {
        return h.get_compact_index(node);
    }

    static uint8_t* keys_ptr(uint64_t* node, const hdr_type& h) noexcept {
        return h.get_compact_index(node);
    }

    // ------------------------------------------------------------------
    // Search -- linear scan with early exit
    // ------------------------------------------------------------------

    struct search_pos {
        bool found;
        int  pos;
    };

    static search_pos search(const uint8_t* keys, uint16_t N,
                             const uint8_t* suffix,
                             uint32_t suffix_len) noexcept {
        const uint8_t* kp = keys;
        for (int ki = 0; ki < N; ++ki) {
            int cmp = key_cmp(kp, suffix, suffix_len);
            if (cmp >= 0) [[unlikely]]
                return {(cmp == 0), ki};
            kp = key_next(kp);
        }
        return {false, N};
    }

    // ------------------------------------------------------------------
    // find
    // ------------------------------------------------------------------

    static const VALUE* find(const uint64_t* node, const hdr_type& h,
                             const uint8_t* suffix,
                             uint32_t suffix_len) noexcept {
        const uint8_t* keys = keys_ptr(node, h);
        auto [found, pos] = search(keys, h.count, suffix, suffix_len);
        if (!found) return nullptr;

        const uint64_t* sb = h.get_compact_slots(node);
        return slots::load_value(sb, pos);
    }

    // ------------------------------------------------------------------
    // collect_entries -- walk keys sequentially
    // ------------------------------------------------------------------

    static uint16_t collect_entries(const uint64_t* node, const hdr_type& h,
                                    build_entry* out,
                                    uint8_t* key_buf) noexcept {
        uint16_t N = h.count;
        if (N == 0) return 0;

        const uint8_t* keys = keys_ptr(node, h);
        const uint64_t* sb  = h.get_slots(node);

        const uint8_t* kp = keys;
        size_t buf_off = 0;
        for (uint16_t i = 0; i < N; ++i) {
            uint16_t klen = read_u16(kp);
            std::memcpy(key_buf + buf_off, kp + 2, klen);
            out[i].key      = key_buf + buf_off;
            out[i].key_len  = klen;
            out[i].raw_slot = sb[i];
            buf_off += klen;
            kp += 2 + klen;
        }
        return N;
    }

    // ------------------------------------------------------------------
    // build_compact
    // ------------------------------------------------------------------

    static uint64_t* build_compact(mem_type& mem,
                                    uint8_t skip_len,
                                    const uint8_t* skip_data,
                                    const build_entry* entries,
                                    uint16_t count) {
        uint16_t kb = 0;
        for (uint16_t i = 0; i < count; ++i)
            kb += 2 + static_cast<uint16_t>(entries[i].key_len);

        uint16_t soff = compute_compact_slots_off(skip_len, kb);
        size_t nu = static_cast<size_t>(soff) + count;

        uint64_t* node = mem.alloc_node(nu);
        hdr_type& h = hdr_type::from_node(node);
        h.set_compact(true);
        h.skip      = skip_len;
        h.count     = count;
        h.slots_off = soff;

        if (skip_len > 0 && skip_data)
            std::memcpy(hdr_type::get_skip(node), skip_data, skip_len);

        write_keys_and_slots(node, h, entries, count);
        return node;
    }

    // ------------------------------------------------------------------
    // write_keys_and_slots
    // ------------------------------------------------------------------

    static void write_keys_and_slots(uint64_t* node, const hdr_type& h,
                                      const build_entry* entries,
                                      uint16_t count) noexcept {
        uint8_t* key_dst = keys_ptr(node, h);
        uint16_t key_off = 0;
        for (uint16_t i = 0; i < count; ++i) {
            write_u16(key_dst + key_off,
                      static_cast<uint16_t>(entries[i].key_len));
            if (entries[i].key_len > 0)
                std::memcpy(key_dst + key_off + 2,
                            entries[i].key, entries[i].key_len);
            key_off += 2 + entries[i].key_len;
        }

        uint64_t* sb = h.get_slots(node);
        for (uint16_t i = 0; i < count; ++i)
            sb[i] = entries[i].raw_slot;
    }

    // ------------------------------------------------------------------
    // finalize -- free old node, post-check, split if needed
    // ------------------------------------------------------------------

    static insert_result finalize(uint64_t* old_node, uint64_t* new_node,
                                   mem_type& mem) {
        mem.free_node(old_node);
        hdr_type& h = hdr_type::from_node(new_node);
        if (h.count > COMPACT_MAX) [[unlikely]]
            return split_node(new_node, h, mem);
        return {new_node, insert_outcome::INSERTED};
    }

    // ------------------------------------------------------------------
    // insert -- main dispatch
    // ------------------------------------------------------------------

    static insert_result insert(uint64_t* node, hdr_type& h,
                                 const uint8_t* key_data, uint32_t key_len,
                                 const VALUE& value, uint32_t consumed,
                                 match_result mr, insert_mode mode,
                                 mem_type& mem) {
        if (mr.status == match_status::MATCHED) {
            uint32_t suffix_len = key_len - mr.consumed;
            const uint8_t* suffix = key_data + mr.consumed;

            const uint8_t* keys = keys_ptr(node, h);
            auto [found, pos] = search(keys, h.count, suffix, suffix_len);
            if (found) {
                if (mode == insert_mode::INSERT)
                    return {node, insert_outcome::FOUND};
                uint64_t* sb = h.get_slots(node);
                slots::destroy_value(sb, pos);
                slots::store_value(sb, pos, value);
                return {node, insert_outcome::UPDATED};
            }
        }

        if (mode == insert_mode::ASSIGN)
            return {node, insert_outcome::FOUND};

        return rebuild(node, h, key_data, key_len, value, consumed, mr, mem);
    }

    // ------------------------------------------------------------------
    // rebuild -- unified insert path
    // ------------------------------------------------------------------

    static insert_result rebuild(uint64_t* node, hdr_type& h,
                                  const uint8_t* key_data, uint32_t key_len,
                                  const VALUE& value, uint32_t consumed,
                                  match_result mr, mem_type& mem) {
        const uint8_t* skip_data = hdr_type::get_skip(node);
        uint32_t old_skip = h.skip_bytes();

        uint8_t new_skip;
        uint32_t tail;
        uint32_t suffix_off;

        if (mr.status == match_status::MATCHED) {
            new_skip   = h.skip;
            tail       = 0;
            suffix_off = consumed + old_skip;
        } else {
            new_skip   = static_cast<uint8_t>(mr.match_len);
            tail       = old_skip - mr.match_len;
            suffix_off = consumed + mr.match_len;
        }

        const uint8_t* prepend = skip_data + new_skip;
        const uint8_t* new_suffix = key_data + suffix_off;
        uint32_t new_suffix_len   = key_len - suffix_off;

        uint16_t new_count = h.count + 1;

        uint16_t approx_kb = approx_keys_bytes(h.slots_off, h.skip);
        size_t key_buf_size = approx_kb + h.count * tail + new_suffix_len + 256;
        uint8_t stack_keys[4096];
        uint8_t* key_buf = (key_buf_size <= sizeof(stack_keys))
                            ? stack_keys : new uint8_t[key_buf_size];

        build_entry stack_entries[65];
        build_entry* entries = (new_count <= 65)
                                ? stack_entries
                                : new build_entry[new_count];

        const uint8_t* keys = keys_ptr(node, h);
        const uint64_t* sb  = h.get_slots(node);

        size_t buf_off = 0;
        uint16_t ei = 0;
        const uint8_t* kp = keys;

        for (uint16_t i = 0; i < h.count; ++i) {
            uint16_t klen = read_u16(kp);

            uint8_t* dst = key_buf + buf_off;
            if (tail > 0) std::memcpy(dst, prepend, tail);
            std::memcpy(dst + tail, kp + 2, klen);

            entries[ei].key      = dst;
            entries[ei].key_len  = klen + tail;
            entries[ei].raw_slot = sb[i];
            buf_off += klen + tail;
            ei++;
            kp += 2 + klen;
        }

        uint64_t new_raw = 0;
        slots::store_value(&new_raw, 0, value);

        uint8_t* dst = key_buf + buf_off;
        if (new_suffix_len > 0)
            std::memcpy(dst, new_suffix, new_suffix_len);
        entries[ei].key      = dst;
        entries[ei].key_len  = new_suffix_len;
        entries[ei].raw_slot = new_raw;
        buf_off += new_suffix_len;
        ei++;

        assert(ei == new_count);

        std::sort(entries, entries + new_count,
                  [](const build_entry& a, const build_entry& b) {
                      uint32_t min_len = std::min(a.key_len, b.key_len);
                      int cmp = std::memcmp(a.key, b.key, min_len);
                      if (cmp != 0) return cmp < 0;
                      return a.key_len < b.key_len;
                  });

        uint64_t* result = build_compact(mem, new_skip, skip_data,
                                          entries, new_count);
        insert_result ir = finalize(node, result, mem);

        if (entries != stack_entries) delete[] entries;
        if (key_buf != stack_keys)   delete[] key_buf;

        return ir;
    }

    // ------------------------------------------------------------------
    // split_node -- split compact into bitmask parent + compact children
    // ------------------------------------------------------------------

    static insert_result split_node(uint64_t* node, hdr_type& h,
                                     mem_type& mem) {
        uint16_t N = h.count;

        uint16_t approx_kb = approx_keys_bytes(h.slots_off, h.skip);
        uint8_t* key_buf = new uint8_t[approx_kb + 256];
        build_entry* all = new build_entry[N];
        collect_entries(node, h, all, key_buf);

        // Zero-length key → becomes inline eos value on bitmask parent
        uint64_t eos_raw = 0;
        bool has_eos = false;
        uint16_t data_start = 0;

        if (N > 0 && all[0].key_len == 0) {
            eos_raw = all[0].raw_slot;
            has_eos = true;
            data_start = 1;
        }

        // Bucket by first byte
        uint8_t  bucket_bytes[256];
        uint16_t bucket_start[256];
        uint16_t bucket_count[256];
        int n_buckets = 0;

        uint8_t prev_byte = 0;
        bool first = true;
        for (uint16_t i = data_start; i < N; ++i) {
            assert(all[i].key_len > 0);
            uint8_t fb = all[i].key[0];
            if (first || fb != prev_byte) {
                bucket_bytes[n_buckets] = fb;
                bucket_start[n_buckets] = i;
                bucket_count[n_buckets] = 1;
                n_buckets++;
                prev_byte = fb;
                first = false;
            } else {
                bucket_count[n_buckets - 1]++;
            }
        }

        // Create child for each bucket
        uint64_t* children[256];
        for (int b = 0; b < n_buckets; ++b) {
            uint16_t start = bucket_start[b];
            uint16_t cnt   = bucket_count[b];

            build_entry* child_entries = new build_entry[cnt];
            for (uint16_t j = 0; j < cnt; ++j) {
                const build_entry& src = all[start + j];
                child_entries[j].key      = src.key + 1;
                child_entries[j].key_len  = src.key_len - 1;
                child_entries[j].raw_slot = src.raw_slot;
            }

            children[b] = build_compact(mem, 0, nullptr, child_entries, cnt);

            hdr_type& ch = hdr_type::from_node(children[b]);
            if (ch.count > COMPACT_MAX) {
                auto sr = split_node(children[b], ch, mem);
                children[b] = sr.node;
            }

            delete[] child_entries;
        }

        uint64_t* parent = bitmask_ops::create_with_children(
            mem,
            h.skip, hdr_type::get_skip(node),
            bucket_bytes, children,
            static_cast<uint16_t>(n_buckets));

        if (has_eos) {
            hdr_type& ph = hdr_type::from_node(parent);
            parent = bitmask_ops::add_eos_raw(parent, ph, mem, eos_raw);
        }

        mem.free_node(node);
        delete[] all;
        delete[] key_buf;

        return {parent, insert_outcome::INSERTED};
    }

    // ------------------------------------------------------------------
    // reskip -- rebuild compact with a new skip prefix
    // ------------------------------------------------------------------

    static uint64_t* reskip(uint64_t* node, hdr_type& h, mem_type& mem,
                            uint8_t new_skip_len,
                            const uint8_t* new_skip_data) {
        uint16_t approx_kb = approx_keys_bytes(h.slots_off, h.skip);
        uint8_t stack_keys[4096];
        uint8_t* key_buf = (approx_kb <= sizeof(stack_keys))
            ? stack_keys : new uint8_t[approx_kb];

        build_entry stack_entries[33];
        build_entry* entries = (h.count <= 33)
            ? stack_entries : new build_entry[h.count];

        collect_entries(node, h, entries, key_buf);
        uint64_t* result = build_compact(mem, new_skip_len, new_skip_data,
                                          entries, h.count);
        mem.free_node(node);

        if (entries != stack_entries) delete[] entries;
        if (key_buf != stack_keys)   delete[] key_buf;

        return result;
    }

    // ------------------------------------------------------------------
    // erase_in_place -- remove entry at pos, rewrite keys/slots in place
    //
    // Always fits (result is strictly smaller).
    // ------------------------------------------------------------------

    static void erase_in_place(uint64_t* node, hdr_type& h, int pos) {
        uint8_t* keys = keys_ptr(node, h);
        uint64_t* sb = h.get_compact_slots(node);

        slots::destroy_value(sb, pos);

        // Walk to key at pos
        uint8_t* kp = keys;
        for (int i = 0; i < pos; ++i)
            kp = const_cast<uint8_t*>(key_next(kp));

        uint16_t klen = read_u16(kp);
        uint8_t* after = kp + 2 + klen;

        // Shift remaining keys left (up to slots start)
        uint8_t* keys_end = reinterpret_cast<uint8_t*>(sb);
        ptrdiff_t remaining = keys_end - after;
        if (remaining > 0)
            std::memmove(kp, after, remaining);

        // Shift slots left
        if (pos < h.count - 1)
            slots::move_slots(sb, pos, sb, pos + 1, h.count - 1 - pos);

        hdr_type::from_node(node).count--;
    }
};

} // namespace gteitelbaum

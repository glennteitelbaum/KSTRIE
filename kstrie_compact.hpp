#pragma once
#include "kstrie_support.hpp"

namespace gteitelbaum {

template <typename VALUE, typename CHARMAP, typename ALLOC>
struct kstrie_bitmask;

template <typename VALUE, typename CHARMAP, typename ALLOC>
class kstrie;

// ============================================================================
// kstrie_compact -- compact (leaf) node operations
//
// Node layout:  [header 8B] [skip] [index] [slots]
//
// Index region = [hot: W*16 bytes] [idx: N*16 bytes] [keys: keys_bytes]
// Slots region = [value_0] ... [value_{N-1}]
//
// Compact nodes never use has_eos. A key that matches the skip prefix
// exactly is stored as a zero-length key entry in the index (sorts first).
//
// Insert strategy:
//   Always build the result node unconditionally, then finalize checks
//   constraints. If any violated, split into bitmask + compact children.
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
    using trie_type    = kstrie<VALUE, CHARMAP, ALLOC>;
    using match_result = typename skip_type::match_result;
    using match_status = typename skip_type::match_status;

    struct build_entry {
        const uint8_t* key;
        uint32_t       key_len;
        uint64_t       raw_slot;
    };

    // ------------------------------------------------------------------
    // Index size (called by node_header::index_size)
    // ------------------------------------------------------------------

    static size_t index_size(const hdr_type& h) noexcept {
        uint16_t N = h.count;
        if (N == 0 && h.keys_bytes == 0) return 0;
        int W = calc_W(N);
        return align8(static_cast<size_t>(W) * 16 +
                       static_cast<size_t>(N) * 16 +
                       h.keys_bytes);
    }

    // ------------------------------------------------------------------
    // Index region pointers
    // ------------------------------------------------------------------

    static e* hot_ptr(uint8_t* index) noexcept {
        return reinterpret_cast<e*>(index);
    }

    static const e* hot_ptr(const uint8_t* index) noexcept {
        return reinterpret_cast<const e*>(index);
    }

    static e* idx_ptr(uint8_t* index, int W) noexcept {
        return reinterpret_cast<e*>(index + W * 16);
    }

    static const e* idx_ptr(const uint8_t* index, int W) noexcept {
        return reinterpret_cast<const e*>(index + W * 16);
    }

    static uint8_t* keys_ptr(uint8_t* index, int W, int N) noexcept {
        return index + W * 16 + N * 16;
    }

    static const uint8_t* keys_ptr(const uint8_t* index, int W, int N) noexcept {
        return index + W * 16 + N * 16;
    }

    // ------------------------------------------------------------------
    // Search
    // ------------------------------------------------------------------

    struct search_pos {
        bool found;
        int  pos;
    };

    static search_pos search_in_index(const uint8_t* index, uint16_t N,
                                      const uint8_t* suffix,
                                      uint32_t suffix_len) noexcept {
        if (N == 0) return {false, 0};

        int W = calc_W(N);
        e search = make_search_key(suffix, suffix_len);

        int scan_start, scan_end;
        if (W == 0) {
            scan_start = 0;
            scan_end   = N;
        } else {
            const e* hot = hot_ptr(index);
            int i = 1;
            while (i < W)
                i = 2 * i + (search >= hot[i] ? 1 : 0);
            int group = i - W;
            scan_start = group * static_cast<int>(N) / W;
            scan_end   = (group + 1) * static_cast<int>(N) / W;
            if (scan_end > N) scan_end = N;
        }

        const e* idx    = idx_ptr(index, W);
        const uint8_t* keys = keys_ptr(index, W, N);
        e search_pfx = e_prefix_only(search);

        for (int i = scan_start; i < scan_end; ++i) {
            e entry_pfx = e_prefix_only(idx[i]);
            if (entry_pfx < search_pfx) continue;
            if (entry_pfx > search_pfx) return {false, i};

            uint16_t off = e_offset(idx[i]);
            int cmp = key_cmp(keys + off, suffix, suffix_len);
            if (cmp == 0) return {true, i};
            if (cmp > 0)  return {false, i};
        }

        if (W > 0 && scan_end < N) {
            e next_pfx = e_prefix_only(idx[scan_end]);
            if (next_pfx == search_pfx) {
                for (int i = scan_end; i < N; ++i) {
                    if (e_prefix_only(idx[i]) != search_pfx)
                        return {false, i};
                    uint16_t off = e_offset(idx[i]);
                    int cmp = key_cmp(keys + off, suffix, suffix_len);
                    if (cmp == 0) return {true, i};
                    if (cmp > 0)  return {false, i};
                }
                return {false, N};
            }
        }

        return {false, scan_end};
    }

    // ------------------------------------------------------------------
    // find
    // ------------------------------------------------------------------

    static const VALUE* find(const uint64_t* node, const hdr_type& h,
                             const uint8_t* suffix,
                             uint32_t suffix_len) noexcept {
        if (h.count == 0) return nullptr;

        const uint8_t* index = h.get_index(const_cast<uint64_t*>(node));
        auto [found, pos] = search_in_index(index, h.count, suffix, suffix_len);
        if (!found) return nullptr;

        const uint64_t* sb = h.get_slots(const_cast<uint64_t*>(node));
        return &slots::load_value(sb, pos);
    }

    // ------------------------------------------------------------------
    // collect_entries
    // ------------------------------------------------------------------

    static uint16_t collect_entries(const uint64_t* node, const hdr_type& h,
                                    build_entry* out,
                                    uint8_t* key_buf) noexcept {
        uint16_t N = h.count;
        if (N == 0) return 0;

        const uint8_t* index = h.get_index(const_cast<uint64_t*>(node));
        int W = calc_W(N);
        const e* idx          = idx_ptr(index, W);
        const uint8_t* keys   = keys_ptr(index, W, N);
        const uint64_t* sb    = h.get_slots(const_cast<uint64_t*>(node));

        size_t buf_off = 0;
        for (uint16_t i = 0; i < N; ++i) {
            uint16_t off  = e_offset(idx[i]);
            uint16_t klen = read_u16(keys + off);
            std::memcpy(key_buf + buf_off, keys + off + 2, klen);
            out[i].key      = key_buf + buf_off;
            out[i].key_len  = klen;
            out[i].raw_slot = sb[i];
            buf_off += klen;
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

        hdr_type th{};
        th.skip       = skip_len;
        th.count      = count;
        th.keys_bytes = kb;
        th.set_compact(true);
        th.set_eos(false);
        size_t nu = (th.node_size() + 7) / 8;

        uint64_t* node = mem.alloc_node(nu);
        hdr_type& h = hdr_type::from_node(node);
        h.set_compact(true);
        h.set_eos(false);
        h.skip       = skip_len;
        h.count      = count;
        h.keys_bytes = kb;

        if (skip_len > 0 && skip_data)
            std::memcpy(hdr_type::get_skip(node), skip_data, skip_len);

        write_index_and_slots(node, h, entries, count);
        return node;
    }

    // ------------------------------------------------------------------
    // write_index_and_slots
    // ------------------------------------------------------------------

    static void write_index_and_slots(uint64_t* node, const hdr_type& h,
                                       const build_entry* entries,
                                       uint16_t count) noexcept {
        if (count > 0) {
            uint8_t* index = h.get_index(node);
            int W = calc_W(count);
            e* idx_arr       = idx_ptr(index, W);
            uint8_t* key_dst = keys_ptr(index, W, count);

            uint16_t key_off = 0;
            for (uint16_t i = 0; i < count; ++i) {
                write_u16(key_dst + key_off,
                          static_cast<uint16_t>(entries[i].key_len));
                if (entries[i].key_len > 0)
                    std::memcpy(key_dst + key_off + 2,
                                entries[i].key, entries[i].key_len);

                es s;
                s.setkey(reinterpret_cast<const char*>(entries[i].key),
                         static_cast<int>(entries[i].key_len));
                s.setoff(key_off);
                idx_arr[i] = cvt(s);

                key_off += 2 + entries[i].key_len;
            }

            if (W > 0) {
                e* hot = hot_ptr(index);
                hot[0] = e{};
                build_eyt(idx_arr, count, hot);
            }
        }

        uint64_t* sb = h.get_slots(node);
        for (uint16_t i = 0; i < count; ++i)
            sb[i] = entries[i].raw_slot;
    }

    // ------------------------------------------------------------------
    // finalize -- free old node, post-check, split if needed
    // ------------------------------------------------------------------

    static insert_result finalize(uint64_t* old_node, uint64_t* new_node,
                                   uint32_t key_len, uint32_t consumed,
                                   trie_type& trie) {
        trie.memory().free_node(old_node);
        hdr_type& h = hdr_type::from_node(new_node);
        uint32_t added = key_len - consumed - h.skip;
        if (h.count > COMPACT_MAX ||
            h.alloc_u64 > COMPACT_MAX_ALLOC_U64 ||
            added > COMPACT_MAX_KEY_LEN)
            return split_node(new_node, h, trie);
        return {new_node, insert_outcome::INSERTED};
    }

    // ------------------------------------------------------------------
    // insert -- main dispatch
    // ------------------------------------------------------------------

    static insert_result insert(uint64_t* node, hdr_type& h,
                                 const uint8_t* key_data, uint32_t key_len,
                                 const VALUE& value, uint32_t consumed,
                                 match_result mr, insert_mode mode,
                                 trie_type& trie) {
        // MATCHED: check for existing entry (update/found short-circuits)
        if (mr.status == match_status::MATCHED) {
            uint32_t suffix_len = key_len - mr.consumed;
            const uint8_t* suffix = key_data + mr.consumed;

            const uint8_t* index = h.get_index(node);
            auto [found, pos] = search_in_index(index, h.count,
                                                 suffix, suffix_len);
            if (found) {
                if (mode == insert_mode::INSERT)
                    return {node, insert_outcome::FOUND};
                uint64_t* sb = h.get_slots(node);
                slots::destroy_value(sb, pos);
                slots::store_value(sb, pos, value);
                return {node, insert_outcome::UPDATED};
            }
        }

        return rebuild(node, h, key_data, key_len, value, consumed, mr, trie);
    }

    // ------------------------------------------------------------------
    // rebuild -- unified insert path
    //
    // Handles all three skip match outcomes:
    //   MATCHED:       no prepend, new entry added
    //   MISMATCH:      prepend skip[ml..] to all keys, new entry added
    //   KEY_EXHAUSTED: prepend skip[ml..] to all keys, new entry with len=0
    //
    // Steps:
    //   1. Collect existing entries with prepend applied
    //   2. Create new VALUE, add as entry
    //   3. Sort entries
    //   4. build_compact
    //   5. finalize
    // ------------------------------------------------------------------

    static insert_result rebuild(uint64_t* node, hdr_type& h,
                                  const uint8_t* key_data, uint32_t key_len,
                                  const VALUE& value, uint32_t consumed,
                                  match_result mr, trie_type& trie) {
        const uint8_t* skip_data = hdr_type::get_skip(node);
        uint32_t old_skip = h.skip_bytes();

        // Compute new skip and prepend length
        uint8_t new_skip;
        uint32_t tail;
        uint32_t suffix_off;  // offset into key_data where new suffix starts

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

        // Allocate buffers
        size_t key_buf_size = h.keys_bytes
                              + h.count * tail
                              + new_suffix_len + 256;
        uint8_t stack_keys[4096];
        uint8_t* key_buf = (key_buf_size <= sizeof(stack_keys))
                            ? stack_keys : new uint8_t[key_buf_size];

        build_entry stack_entries[65];
        build_entry* entries = (new_count <= 65)
                                ? stack_entries
                                : new build_entry[new_count];

        // Collect existing entries with prepend
        const uint8_t* index = h.get_index(node);
        int W = calc_W(h.count);
        const e* idx_arr    = idx_ptr(index, W);
        const uint8_t* keys = keys_ptr(index, W, h.count);
        const uint64_t* sb  = h.get_slots(node);

        size_t buf_off = 0;
        uint16_t ei = 0;

        for (uint16_t i = 0; i < h.count; ++i) {
            uint16_t off  = e_offset(idx_arr[i]);
            uint16_t klen = read_u16(keys + off);

            uint8_t* dst = key_buf + buf_off;
            if (tail > 0) std::memcpy(dst, prepend, tail);
            std::memcpy(dst + tail, keys + off + 2, klen);

            entries[ei].key      = dst;
            entries[ei].key_len  = klen + tail;
            entries[ei].raw_slot = sb[i];
            buf_off += klen + tail;
            ei++;
        }

        // New entry
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

        // Sort
        std::sort(entries, entries + new_count,
                  [](const build_entry& a, const build_entry& b) {
                      uint32_t min_len = std::min(a.key_len, b.key_len);
                      int cmp = std::memcmp(a.key, b.key, min_len);
                      if (cmp != 0) return cmp < 0;
                      return a.key_len < b.key_len;
                  });

        // Build
        uint64_t* result = build_compact(trie.memory(),
                                          new_skip, skip_data,
                                          entries, new_count);

        if (entries != stack_entries) delete[] entries;
        if (key_buf != stack_keys)   delete[] key_buf;

        return finalize(node, result, key_len, consumed, trie);
    }

    // ------------------------------------------------------------------
    // split_node -- split compact into bitmask parent + compact children
    //
    // Entry with key_len==0 (if present) becomes bitmask parent EOS.
    // All other entries bucketed by first key byte.
    // ------------------------------------------------------------------

    static insert_result split_node(uint64_t* node, hdr_type& h,
                                     trie_type& trie) {
        uint16_t N = h.count;

        uint8_t* key_buf = new uint8_t[h.keys_bytes + 256];
        build_entry* all = new build_entry[N];
        collect_entries(node, h, all, key_buf);

        // Check for zero-length key → bitmask parent EOS
        bool parent_has_eos = false;
        uint64_t parent_eos_raw = 0;
        uint16_t data_start = 0;

        if (N > 0 && all[0].key_len == 0) {
            parent_has_eos = true;
            parent_eos_raw = all[0].raw_slot;
            data_start = 1;
        }

        uint16_t data_count = N - data_start;

        // Bucket by first byte (entries are sorted, zero-len already handled)
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
            uint16_t data_cnt = 0;

            for (uint16_t j = 0; j < cnt; ++j) {
                const build_entry& src = all[start + j];
                child_entries[data_cnt].key      = src.key + 1;
                child_entries[data_cnt].key_len  = src.key_len - 1;
                child_entries[data_cnt].raw_slot = src.raw_slot;
                data_cnt++;
            }

            children[b] = build_compact(trie.memory(),
                                         0, nullptr,
                                         child_entries, data_cnt);

            // Recursive: child might still violate
            hdr_type& ch = hdr_type::from_node(children[b]);
            if (ch.count > COMPACT_MAX ||
                ch.alloc_u64 > COMPACT_MAX_ALLOC_U64) {
                auto sr = split_node(children[b], ch, trie);
                children[b] = sr.node;
            }

            delete[] child_entries;
        }

        // Create bitmask parent (nullptr for eos_val: raw transfer below)
        uint64_t* parent = bitmask_ops::create_with_children(
            trie.memory(),
            h.skip, hdr_type::get_skip(node),
            parent_has_eos, nullptr,
            bucket_bytes, children,
            static_cast<uint16_t>(n_buckets));

        // Raw-transfer EOS slot
        if (parent_has_eos) {
            hdr_type& ph = hdr_type::from_node(parent);
            uint64_t* sb = ph.get_slots(parent);
            sb[0] = parent_eos_raw;
        }

        trie.memory().free_node(node);
        delete[] all;
        delete[] key_buf;

        return {parent, insert_outcome::INSERTED};
    }

    // ------------------------------------------------------------------
    // create_from_entries -- bulk build from child_entry array
    // ------------------------------------------------------------------

    static uint64_t* create_from_entries(
            const typename trie_type::child_entry* entries,
            size_t count, trie_type& trie) {
        if (count == 0)
            return trie.memory().alloc_node(1);

        build_entry* be = new build_entry[count];
        for (size_t i = 0; i < count; ++i) {
            uint64_t raw = 0;
            slots::store_value(&raw, 0, *entries[i].value);
            be[i].key      = entries[i].suffix;
            be[i].key_len  = entries[i].suffix_len;
            be[i].raw_slot = raw;
        }

        uint64_t* node = build_compact(trie.memory(),
                                         0, nullptr,
                                         be, static_cast<uint16_t>(count));
        delete[] be;
        return node;
    }
};

} // namespace gteitelbaum

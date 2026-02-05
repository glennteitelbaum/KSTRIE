#pragma once
#include "kstrie_support.hpp"

namespace gteitelbaum {

// Forward declarations
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
//   - hot: Eytzinger tree of W-1 boundary entries (1-indexed, slot 0 unused)
//   - idx: N sorted e entries (14-byte key prefix + 2-byte keys-blob offset)
//   - keys: variable-length key blob ([u16 len][bytes] per key)
//   - W = calc_W(N): complete binary tree dividing N into groups of 3-4
//   - When N <= 4, W = 0 (no hot tree, just linear scan)
//
// Slots region = [eos_value?] [value_0] ... [value_{N-1}]
//
// Insert strategy:
//   Always perform the insert/prepend unconditionally to produce a complete
//   compact node, then post-check constraints. If any violated, split the
//   fully-built node into a bitmask parent with compact children.
//
// Post-check constraints:
//   - Any key in index > 14 bytes → KEY_TOO_BIG
//   - count > 4096              → TOO_MANY_ENTRIES
//   - alloc_u64 > MAX_ALLOC     → TOO_LARGE
//
// VALUE ownership:
//   - T* created exactly once on insert (via slots::store_value)
//   - Moved between nodes by raw uint64_t memcpy
//   - Deleted only on erase or tree destruction
//   - Node reallocation/splits never create or destroy T*
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

    static constexpr uint32_t MAX_KEY_LEN = 14;
    static constexpr uint32_t MAX_COUNT   = 4096;
    static constexpr uint32_t MAX_ALLOC   = 256 * 256;

    // ------------------------------------------------------------------
    // Build entry -- key data + raw slot value for node construction
    // ------------------------------------------------------------------

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
    // Search -- find position in compact index
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

        // Determine scan range via Eytzinger hot tree
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

            // Same 14-byte prefix -- disambiguate via keys blob
            uint16_t off = e_offset(idx[i]);
            int cmp = key_cmp(keys + off, suffix, suffix_len);
            if (cmp == 0) return {true, i};
            if (cmp > 0)  return {false, i};
        }

        // Check next group for duplicate prefix spanning boundary
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
    // find -- search compact node for a suffix
    // ------------------------------------------------------------------

    static const VALUE* find(const uint64_t* node, const hdr_type& h,
                             const uint8_t* suffix,
                             uint32_t suffix_len) noexcept {
        if (h.count == 0) return nullptr;

        const uint8_t* index = h.get_index(const_cast<uint64_t*>(node));
        auto [found, pos] = search_in_index(index, h.count, suffix, suffix_len);
        if (!found) return nullptr;

        const uint64_t* sb = h.get_slots(const_cast<uint64_t*>(node));
        return &slots::load_value(sb, h.has_eos() + pos);
    }

    // ------------------------------------------------------------------
    // Collect entries from a compact node into build_entry array
    //
    // key_buf receives raw key bytes (without u16 headers).
    // Must have room for sum of all key lengths.
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
        uint16_t data_start   = h.has_eos() ? 1 : 0;

        size_t buf_off = 0;
        for (uint16_t i = 0; i < N; ++i) {
            uint16_t off  = e_offset(idx[i]);
            uint16_t klen = read_u16(keys + off);
            std::memcpy(key_buf + buf_off, keys + off + 2, klen);
            out[i].key      = key_buf + buf_off;
            out[i].key_len  = klen;
            out[i].raw_slot = sb[data_start + i];
            buf_off += klen;
        }

        return N;
    }

    // ------------------------------------------------------------------
    // Max key length among all entries
    // ------------------------------------------------------------------

    static uint32_t max_key_len_in(const uint64_t* node,
                                    const hdr_type& h) noexcept {
        if (h.count == 0) return 0;
        const uint8_t* index = h.get_index(const_cast<uint64_t*>(node));
        int W = calc_W(h.count);
        const uint8_t* keys = keys_ptr(index, W, h.count);

        uint32_t max_kl = 0;
        const uint8_t* kp = keys;
        for (uint16_t i = 0; i < h.count; ++i) {
            uint16_t kl = read_u16(kp);
            if (kl > max_kl) max_kl = kl;
            kp = key_next(kp);
        }
        return max_kl;
    }

    // ------------------------------------------------------------------
    // build_compact -- create a compact node from sorted build_entries
    //
    // Raw slot values copied verbatim (no VALUE construction).
    // eos_raw: if non-null, its uint64_t is placed at slot[0].
    // ------------------------------------------------------------------

    static uint64_t* build_compact(mem_type& mem,
                                    uint8_t skip_len,
                                    const uint8_t* skip_data,
                                    bool has_eos,
                                    const uint64_t* eos_raw,
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
        th.set_eos(has_eos);
        size_t nu = (th.node_size() + 7) / 8;

        uint64_t* node = mem.alloc_node(nu);
        hdr_type& h = hdr_type::from_node(node);
        h.set_compact(true);
        h.set_eos(has_eos);
        h.skip       = skip_len;
        h.count      = count;
        h.keys_bytes = kb;

        if (skip_len > 0 && skip_data)
            std::memcpy(hdr_type::get_skip(node), skip_data, skip_len);

        write_index_and_slots(node, h, eos_raw, entries, count);
        return node;
    }

    // ------------------------------------------------------------------
    // write_index_and_slots
    // ------------------------------------------------------------------

    static void write_index_and_slots(uint64_t* node, const hdr_type& h,
                                       const uint64_t* eos_raw,
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
        if (h.has_eos() && eos_raw)
            sb[0] = *eos_raw;
        uint16_t data_start = h.has_eos() ? 1 : 0;
        for (uint16_t i = 0; i < count; ++i)
            sb[data_start + i] = entries[i].raw_slot;
    }

    // ------------------------------------------------------------------
    // post_check -- returns true if compact node satisfies all constraints
    // ------------------------------------------------------------------

    static bool post_check(const uint64_t* node, const hdr_type& h) noexcept {
        if (h.count > MAX_COUNT) return false;
        if (h.alloc_u64 > MAX_ALLOC) return false;
        if (h.count > 0 && max_key_len_in(node, h) > MAX_KEY_LEN) return false;
        return true;
    }

    // ------------------------------------------------------------------
    // insert -- main dispatch from kstrie::insert_node
    // ------------------------------------------------------------------

    static insert_result insert(uint64_t* node, hdr_type& h,
                                 const uint8_t* key_data, uint32_t key_len,
                                 const VALUE& value, uint32_t consumed,
                                 match_result mr, insert_mode mode,
                                 trie_type& trie) {
        if (mr.status == match_status::MISMATCH)
            return handle_mismatch(node, h, key_data, key_len,
                                    value, consumed, mr, mode, trie);

        if (mr.status == match_status::KEY_EXHAUSTED)
            return handle_key_exhausted(node, h, key_data, key_len,
                                         value, consumed, mr, mode, trie);

        // MATCHED: skip fully consumed, suffix remaining
        consumed = mr.consumed;
        return insert_entry(node, h,
                             key_data + consumed, key_len - consumed,
                             value, mode, trie);
    }

    // ------------------------------------------------------------------
    // insert_entry -- insert suffix into compact, then post-check
    // ------------------------------------------------------------------

    static insert_result insert_entry(uint64_t* node, hdr_type& h,
                                       const uint8_t* suffix,
                                       uint32_t suffix_len,
                                       const VALUE& value,
                                       insert_mode mode,
                                       trie_type& trie) {
        // Search for existing entry
        const uint8_t* index = h.get_index(node);
        auto [found, pos] = search_in_index(index, h.count, suffix, suffix_len);

        if (found) {
            if (mode == insert_mode::INSERT)
                return {node, insert_outcome::FOUND};
            uint64_t* sb = h.get_slots(node);
            slots::destroy_value(sb, h.has_eos() + pos);
            slots::store_value(sb, h.has_eos() + pos, value);
            return {node, insert_outcome::UPDATED};
        }

        // Create the VALUE now
        uint64_t new_raw = 0;
        slots::store_value(&new_raw, 0, value);

        // Build new node with entry inserted
        uint64_t* result = rebuild_with_insert(node, h, suffix, suffix_len,
                                                new_raw, pos, trie);
        trie.memory().free_node(node);

        // Post-check
        hdr_type& rh = hdr_type::from_node(result);
        if (!post_check(result, rh))
            return split_node(result, rh, trie);

        return {result, insert_outcome::INSERTED};
    }

    // ------------------------------------------------------------------
    // rebuild_with_insert -- collect entries, add new one, build node
    //
    // Builds a new compact node identical to the old one but with the
    // new entry inserted at sorted position pos. Same skip, same EOS.
    // ------------------------------------------------------------------

    static uint64_t* rebuild_with_insert(const uint64_t* node,
                                          const hdr_type& h,
                                          const uint8_t* suffix,
                                          uint32_t suffix_len,
                                          uint64_t new_raw, int pos,
                                          trie_type& trie) {
        uint16_t new_count = h.count + 1;

        size_t key_buf_size = h.keys_bytes + suffix_len + 256;
        uint8_t stack_keys[4096];
        uint8_t* key_buf = (key_buf_size <= sizeof(stack_keys))
                            ? stack_keys : new uint8_t[key_buf_size];

        build_entry stack_entries[65];
        build_entry* entries = (new_count <= 65)
                                ? stack_entries
                                : new build_entry[new_count];

        // Collect existing entries
        uint16_t collected = collect_entries(node, h, entries + 1, key_buf);

        // Shift entries right to make room at pos
        // collect_entries wrote into entries[1..count], we want the insert gap at pos
        // First, move entries[1..pos] to entries[0..pos-1]
        for (int i = 0; i < pos; ++i)
            entries[i] = entries[i + 1];
        // entries[pos] is now free, entries[pos+1..count] are correct

        // Write new key into buffer after existing data
        size_t buf_used = 0;
        for (uint16_t i = 0; i < collected; ++i)
            buf_used = std::max(buf_used,
                static_cast<size_t>(entries[i < pos ? i : i + 1].key
                                    - key_buf)
                + entries[i < pos ? i : i + 1].key_len);
        std::memcpy(key_buf + buf_used, suffix, suffix_len);
        entries[pos] = {key_buf + buf_used, suffix_len, new_raw};

        // Carry EOS
        uint64_t eos_raw = 0;
        const uint64_t* eos_ptr = nullptr;
        if (h.has_eos()) {
            eos_raw = h.get_slots(const_cast<uint64_t*>(node))[0];
            eos_ptr = &eos_raw;
        }

        uint64_t* result = build_compact(trie.memory(),
                                          h.skip, hdr_type::get_skip(
                                              const_cast<uint64_t*>(node)),
                                          h.has_eos(), eos_ptr,
                                          entries, new_count);

        if (entries != stack_entries) delete[] entries;
        if (key_buf != stack_keys)   delete[] key_buf;

        return result;
    }

    // ------------------------------------------------------------------
    // handle_mismatch -- skip mismatch at byte ml
    //
    // Shorten skip to ml, prepend skip[ml..] to all existing keys,
    // insert new key suffix. Old EOS (if any) becomes a regular entry
    // with key = skip[ml..]. Then post-check.
    // ------------------------------------------------------------------

    static insert_result handle_mismatch(uint64_t* node, hdr_type& h,
                                          const uint8_t* key_data,
                                          uint32_t key_len,
                                          const VALUE& value,
                                          uint32_t consumed,
                                          match_result mr,
                                          insert_mode /*mode*/,
                                          trie_type& trie) {
        uint32_t ml   = mr.match_len;
        uint32_t sb   = h.skip_bytes();
        uint32_t tail = sb - ml;

        const uint8_t* skip_data = hdr_type::get_skip(node);
        const uint8_t* prepend   = skip_data + ml;

        // New key suffix: everything from consumed + ml onward
        const uint8_t* new_suffix = key_data + consumed + ml;
        uint32_t new_suffix_len   = key_len - consumed - ml;

        // Count: existing + new + (old EOS converted to entry)
        uint16_t new_count = h.count + 1 + (h.has_eos() ? 1 : 0);

        size_t key_buf_size = h.keys_bytes + h.count * tail
                              + new_suffix_len + tail + 256;
        uint8_t stack_keys[4096];
        uint8_t* key_buf = (key_buf_size <= sizeof(stack_keys))
                            ? stack_keys : new uint8_t[key_buf_size];

        build_entry stack_entries[65];
        build_entry* entries = (new_count <= 65)
                                ? stack_entries
                                : new build_entry[new_count];

        // Collect existing entries with prepended tail
        const uint8_t* index = h.get_index(node);
        int W = calc_W(h.count);
        const e* idx_arr      = idx_ptr(index, W);
        const uint8_t* keys   = keys_ptr(index, W, h.count);
        const uint64_t* slot_base = h.get_slots(node);
        uint16_t data_start   = h.has_eos() ? 1 : 0;

        size_t buf_off = 0;
        uint16_t ei = 0;  // entry index

        for (uint16_t i = 0; i < h.count; ++i) {
            uint16_t off  = e_offset(idx_arr[i]);
            uint16_t klen = read_u16(keys + off);

            uint8_t* dst = key_buf + buf_off;
            std::memcpy(dst, prepend, tail);
            std::memcpy(dst + tail, keys + off + 2, klen);

            entries[ei].key      = dst;
            entries[ei].key_len  = klen + tail;
            entries[ei].raw_slot = slot_base[data_start + i];
            buf_off += klen + tail;
            ei++;
        }

        // Old EOS → entry with key = prepend (skip[ml..])
        if (h.has_eos()) {
            uint8_t* eos_key = key_buf + buf_off;
            std::memcpy(eos_key, prepend, tail);
            entries[ei].key      = eos_key;
            entries[ei].key_len  = tail;
            entries[ei].raw_slot = slot_base[0];
            buf_off += tail;
            ei++;
        }

        // New entry
        uint64_t new_raw = 0;
        slots::store_value(&new_raw, 0, value);

        std::memcpy(key_buf + buf_off, new_suffix, new_suffix_len);
        entries[ei].key      = key_buf + buf_off;
        entries[ei].key_len  = new_suffix_len;
        entries[ei].raw_slot = new_raw;
        buf_off += new_suffix_len;
        ei++;

        assert(ei == new_count);

        // Sort all entries by key
        std::sort(entries, entries + new_count,
                  [](const build_entry& a, const build_entry& b) {
                      e ea = make_search_key(a.key, a.key_len);
                      e eb = make_search_key(b.key, b.key_len);
                      if (ea != eb) return ea < eb;
                      return key_cmp(a.key - 2, b.key, b.key_len) < 0;
                      // Hmm, key doesn't have the u16 header here.
                      // Just compare directly.
                  });

        // Simpler sort: memcmp-based
        std::sort(entries, entries + new_count,
                  [](const build_entry& a, const build_entry& b) {
                      uint32_t min_len = std::min(a.key_len, b.key_len);
                      int cmp = std::memcmp(a.key, b.key, min_len);
                      if (cmp != 0) return cmp < 0;
                      return a.key_len < b.key_len;
                  });

        // Build: skip = skip[0..ml), no EOS (old EOS moved to entry)
        uint8_t new_skip = static_cast<uint8_t>(ml);
        uint64_t* result = build_compact(trie.memory(),
                                          new_skip, skip_data,
                                          false, nullptr,
                                          entries, new_count);
        trie.memory().free_node(node);

        if (entries != stack_entries) delete[] entries;
        if (key_buf != stack_keys)   delete[] key_buf;

        // Post-check
        hdr_type& rh = hdr_type::from_node(result);
        if (!post_check(result, rh))
            return split_node(result, rh, trie);

        return {result, insert_outcome::INSERTED};
    }

    // ------------------------------------------------------------------
    // handle_key_exhausted -- key consumed during skip match
    //
    // New key is a prefix of the skip. ml bytes matched.
    // Shorten skip to ml, prepend skip[ml..] to all keys.
    // New value becomes EOS. Old EOS becomes regular entry. Post-check.
    // ------------------------------------------------------------------

    static insert_result handle_key_exhausted(
            uint64_t* node, hdr_type& h,
            const uint8_t* key_data, uint32_t key_len,
            const VALUE& value,
            uint32_t consumed, match_result mr,
            insert_mode /*mode*/,
            trie_type& trie) {
        uint32_t ml   = mr.match_len;
        uint32_t sb   = h.skip_bytes();
        uint32_t tail = sb - ml;

        const uint8_t* skip_data = hdr_type::get_skip(node);
        const uint8_t* prepend   = skip_data + ml;

        // Count: existing + (old EOS converted to entry)
        uint16_t new_count = h.count + (h.has_eos() ? 1 : 0);

        size_t key_buf_size = h.keys_bytes + h.count * tail + tail + 256;
        uint8_t stack_keys[4096];
        uint8_t* key_buf = (key_buf_size <= sizeof(stack_keys))
                            ? stack_keys : new uint8_t[key_buf_size];

        build_entry stack_entries[65];
        build_entry* entries = (new_count <= 65)
                                ? stack_entries
                                : new build_entry[new_count];

        // Collect existing with prepend
        const uint8_t* index = h.get_index(node);
        int W = calc_W(h.count);
        const e* idx_arr      = idx_ptr(index, W);
        const uint8_t* keys   = keys_ptr(index, W, h.count);
        const uint64_t* slot_base = h.get_slots(node);
        uint16_t data_start   = h.has_eos() ? 1 : 0;

        size_t buf_off = 0;
        uint16_t ei = 0;

        for (uint16_t i = 0; i < h.count; ++i) {
            uint16_t off  = e_offset(idx_arr[i]);
            uint16_t klen = read_u16(keys + off);

            uint8_t* dst = key_buf + buf_off;
            std::memcpy(dst, prepend, tail);
            std::memcpy(dst + tail, keys + off + 2, klen);

            entries[ei].key      = dst;
            entries[ei].key_len  = klen + tail;
            entries[ei].raw_slot = slot_base[data_start + i];
            buf_off += klen + tail;
            ei++;
        }

        // Old EOS → entry with key = prepend
        if (h.has_eos()) {
            uint8_t* eos_key = key_buf + buf_off;
            std::memcpy(eos_key, prepend, tail);
            entries[ei].key      = eos_key;
            entries[ei].key_len  = tail;
            entries[ei].raw_slot = slot_base[0];
            buf_off += tail;
            ei++;
        }

        assert(ei == new_count);

        // Sort (prepend changed key order)
        std::sort(entries, entries + new_count,
                  [](const build_entry& a, const build_entry& b) {
                      uint32_t min_len = std::min(a.key_len, b.key_len);
                      int cmp = std::memcmp(a.key, b.key, min_len);
                      if (cmp != 0) return cmp < 0;
                      return a.key_len < b.key_len;
                  });

        // New EOS value
        uint64_t new_eos_raw = 0;
        slots::store_value(&new_eos_raw, 0, value);

        // Build: skip = skip[0..ml), has_eos = true
        uint8_t new_skip = static_cast<uint8_t>(ml);
        uint64_t* result = build_compact(trie.memory(),
                                          new_skip, skip_data,
                                          true, &new_eos_raw,
                                          entries, new_count);
        trie.memory().free_node(node);

        if (entries != stack_entries) delete[] entries;
        if (key_buf != stack_keys)   delete[] key_buf;

        // Post-check
        hdr_type& rh = hdr_type::from_node(result);
        if (!post_check(result, rh))
            return split_node(result, rh, trie);

        return {result, insert_outcome::INSERTED};
    }

    // ------------------------------------------------------------------
    // split_node -- split compact into bitmask parent + compact children
    //
    // The node is fully built but violates constraints.
    // Bucket entries by first key byte, build compact children with
    // first byte stripped. Parent inherits skip and EOS.
    // Recursive: children are post-checked and split again if needed.
    // ------------------------------------------------------------------

    static insert_result split_node(uint64_t* node, hdr_type& h,
                                     trie_type& trie) {
        uint16_t N = h.count;

        // Collect all entries
        uint8_t* key_buf = new uint8_t[h.keys_bytes + 256];
        build_entry* all = new build_entry[N];
        collect_entries(node, h, all, key_buf);

        // Parent EOS (raw transfer)
        uint64_t eos_raw = 0;
        bool has_eos = h.has_eos();
        if (has_eos)
            eos_raw = h.get_slots(node)[0];

        // Bucket by first byte (entries are sorted)
        uint8_t  bucket_bytes[256];
        uint16_t bucket_start[256];
        uint16_t bucket_count[256];
        int n_buckets = 0;

        uint8_t prev_byte = 0;
        bool first = true;
        for (uint16_t i = 0; i < N; ++i) {
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

            bool child_has_eos = false;
            uint64_t child_eos_raw = 0;

            build_entry* child_entries = new build_entry[cnt];
            uint16_t data_cnt = 0;

            for (uint16_t j = 0; j < cnt; ++j) {
                const build_entry& src = all[start + j];
                if (src.key_len == 1) {
                    // After stripping first byte → empty key → child EOS
                    child_has_eos = true;
                    child_eos_raw = src.raw_slot;
                } else {
                    child_entries[data_cnt].key      = src.key + 1;
                    child_entries[data_cnt].key_len  = src.key_len - 1;
                    child_entries[data_cnt].raw_slot = src.raw_slot;
                    data_cnt++;
                }
            }

            children[b] = build_compact(trie.memory(),
                                         0, nullptr,
                                         child_has_eos,
                                         child_has_eos ? &child_eos_raw
                                                       : nullptr,
                                         child_entries, data_cnt);

            // Recursive post-check
            hdr_type& ch = hdr_type::from_node(children[b]);
            if (!post_check(children[b], ch)) {
                auto sr = split_node(children[b], ch, trie);
                children[b] = sr.node;
            }

            delete[] child_entries;
        }

        // Create bitmask parent (pass nullptr for eos_val to avoid T* creation)
        uint64_t* parent = bitmask_ops::create_with_children(
            trie.memory(),
            h.skip, hdr_type::get_skip(node),
            has_eos, nullptr,
            bucket_bytes, children,
            static_cast<uint16_t>(n_buckets));

        // Raw-transfer EOS slot
        if (has_eos) {
            hdr_type& ph = hdr_type::from_node(parent);
            uint64_t* sb = ph.get_slots(parent);
            sb[0] = eos_raw;
        }

        trie.memory().free_node(node);
        delete[] all;
        delete[] key_buf;

        return {parent, insert_outcome::INSERTED};
    }

    // ------------------------------------------------------------------
    // create_from_entries -- bulk build from child_entry array
    //
    // Called from kstrie::add_children. Creates VALUES (initial T* alloc).
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
                                         false, nullptr,
                                         be, static_cast<uint16_t>(count));
        delete[] be;
        return node;
    }
};

} // namespace gteitelbaum

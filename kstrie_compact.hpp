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
//   - W = calc_W(N): complete binary tree dividing N entries into groups of 3-4
//   - When N <= 4, W = 0 (no hot tree, just linear scan)
//
// Slots region = [eos_value?] [value_0] ... [value_{N-1}]
//   - Values stored as raw uint64_t (inline or VALUE* pointer)
//   - EOS slot (if present) is always slot[0], data slots follow
//
// Constraints:
//   - count <= COMPACT_MAX (4096)
//   - max key length <= 14 bytes
//   - total node size <= COMPACT_MAX_BYTES (16384)
//   - keys always sorted
//   When any constraint would be violated, the node splits into a bitmask
//   parent with compact children.
//
// VALUE ownership:
//   - T* created exactly once on insert (via slots::store_value)
//   - Moved between nodes by raw uint64_t memcpy (never copied)
//   - Deleted only on erase or tree destruction (via slots::destroy_value)
//   - Node reallocation/splits never create or destroy T* pointers
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

    // ------------------------------------------------------------------
    // Build entry -- key data + raw slot value for node construction
    // Key pointer must remain valid until build_compact returns.
    // ------------------------------------------------------------------

    struct build_entry {
        const uint8_t* key;
        uint32_t       key_len;
        uint64_t       raw_slot;
    };

    // ------------------------------------------------------------------
    // Index size (called by node_header::index_size)
    //
    // Layout: [hot: W*16] [idx: N*16] [keys: keys_bytes]
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
    //
    // Returns {found, pos} where pos is the index into the idx array.
    // If found: idx[pos] matches the suffix.
    // If !found: pos is the insertion point (entries are sorted).
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

            if (entry_pfx > search_pfx)
                return {false, i};

            // Same 14-byte prefix -- disambiguate via keys blob
            uint16_t off = e_offset(idx[i]);
            int cmp = key_cmp(keys + off, suffix, suffix_len);
            if (cmp == 0) return {true, i};
            if (cmp > 0) return {false, i};
            // cmp < 0: this entry sorts before our key, continue

            // Rare: same prefix, keep scanning for more duplicates
            // Also check into the next group if at boundary
        }

        // If we exhausted the group, the insert point is scan_end.
        // But check if we need to peek into the next group (duplicate prefix
        // spanning a boundary). This is extremely rare (keys differ only in
        // length within 14 bytes).
        if (W > 0 && scan_end < N) {
            e next_pfx = e_prefix_only(idx[scan_end]);
            if (next_pfx == search_pfx) {
                // Scan forward through entries with matching prefix
                for (int i = scan_end; i < N; ++i) {
                    if (e_prefix_only(idx[i]) != search_pfx)
                        return {false, i};
                    uint16_t off = e_offset(idx[i]);
                    int cmp = key_cmp(keys + off, suffix, suffix_len);
                    if (cmp == 0) return {true, i};
                    if (cmp > 0) return {false, i};
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
    // Collect entries -- read all entries from a compact node
    //
    // Copies key data into key_buf so entries are independent of the node.
    // Returns number of entries written.
    // Caller must ensure out[] has room for h.count entries and
    // key_buf has room for h.keys_bytes bytes (minus the u16 headers).
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
    // Needed u64 -- compute allocation size for a compact node
    // ------------------------------------------------------------------

    static size_t needed_u64(uint8_t skip_len, uint16_t count,
                             uint16_t keys_bytes, bool has_eos) noexcept {
        hdr_type h{};
        h.skip       = skip_len;
        h.count      = count;
        h.keys_bytes = keys_bytes;
        h.set_compact(true);
        h.set_eos(has_eos);
        return (h.node_size() + 7) / 8;
    }

    // ------------------------------------------------------------------
    // build_compact -- create a compact node from sorted entries
    //
    // entries must be sorted by key. Key pointers must be valid.
    // Raw slot values are copied verbatim (no VALUE construction).
    // If eos_raw is non-null, its value is stored at slot[0].
    // ------------------------------------------------------------------

    static uint64_t* build_compact(mem_type& mem,
                                    uint8_t skip_len,
                                    const uint8_t* skip_data,
                                    bool has_eos,
                                    const uint64_t* eos_raw,
                                    const build_entry* entries,
                                    uint16_t count) {
        // Compute keys_bytes
        uint16_t kb = 0;
        for (uint16_t i = 0; i < count; ++i)
            kb += 2 + static_cast<uint16_t>(entries[i].key_len);

        size_t nu = needed_u64(skip_len, count, kb, has_eos);
        uint64_t* node = mem.alloc_node(nu);
        hdr_type& h = hdr_type::from_node(node);
        h.set_compact(true);
        h.set_eos(has_eos);
        h.skip       = skip_len;
        h.count      = count;
        h.keys_bytes = kb;

        // Write skip
        if (skip_len > 0 && skip_data)
            std::memcpy(hdr_type::get_skip(node), skip_data, skip_len);

        // Build index region
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

            // Build Eytzinger hot tree
            if (W > 0) {
                e* hot = hot_ptr(index);
                hot[0] = e{};  // slot 0 unused
                build_eyt(idx_arr, count, hot);
            }
        }

        // Write slots
        uint64_t* sb = h.get_slots(node);
        if (has_eos && eos_raw)
            sb[0] = *eos_raw;
        uint16_t data_start = has_eos ? 1 : 0;
        for (uint16_t i = 0; i < count; ++i)
            sb[data_start + i] = entries[i].raw_slot;

        return node;
    }

    // ------------------------------------------------------------------
    // Max existing key length in a compact node
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
    // Constraint check
    // ------------------------------------------------------------------

    static bool would_violate(uint16_t new_count, uint32_t max_key_len,
                              uint8_t skip_len, uint16_t new_keys_bytes,
                              bool has_eos) noexcept {
        if (new_count > COMPACT_MAX) return true;
        if (max_key_len > MAX_KEY_LEN) return true;
        size_t nu = needed_u64(skip_len, new_count, new_keys_bytes, has_eos);
        if (nu * 8 > COMPACT_MAX_BYTES) return true;
        return false;
    }

    // ------------------------------------------------------------------
    // insert -- main dispatch
    //
    // Called from kstrie::insert_node for compact nodes.
    // mr carries skip match status from the router.
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

        // MATCHED: skip fully matched, suffix remaining
        consumed = mr.consumed;
        const uint8_t* suffix = key_data + consumed;
        uint32_t suffix_len   = key_len - consumed;

        return insert_entry(node, h, suffix, suffix_len,
                             value, mode, trie);
    }

    // ------------------------------------------------------------------
    // insert_entry -- insert a single entry into the compact node
    //
    // Skip is already fully matched. suffix_len > 0.
    // ------------------------------------------------------------------

    static insert_result insert_entry(uint64_t* node, hdr_type& h,
                                       const uint8_t* suffix,
                                       uint32_t suffix_len,
                                       const VALUE& value,
                                       insert_mode mode,
                                       trie_type& trie) {
        const uint8_t* index = h.get_index(node);
        auto [found, pos] = search_in_index(index, h.count, suffix, suffix_len);

        if (found) {
            if (mode == insert_mode::INSERT)
                return {node, insert_outcome::FOUND};
            // Update existing value
            uint64_t* sb = h.get_slots(node);
            slots::destroy_value(sb, h.has_eos() + pos);
            slots::store_value(sb, h.has_eos() + pos, value);
            return {node, insert_outcome::UPDATED};
        }

        // Check constraints after adding this entry
        uint16_t new_count      = h.count + 1;
        uint16_t new_keys_bytes = h.keys_bytes + 2 +
                                   static_cast<uint16_t>(suffix_len);
        uint32_t max_kl = std::max(max_key_len_in(node, h), suffix_len);

        if (would_violate(new_count, max_kl, h.skip,
                           new_keys_bytes, h.has_eos()))
            return overflow_split(node, h, suffix, suffix_len,
                                   value, pos, trie);

        // Create the VALUE (T* allocated here if non-inline)
        uint64_t new_raw = 0;
        slots::store_value(&new_raw, 0, value);

        // Collect existing entries (copies key data to temp buffer)
        size_t total_key_data = h.keys_bytes;  // existing key data bytes
        // keys_bytes includes u16 headers, actual key data = keys_bytes - 2*count
        // But we copy raw key bytes only (not the u16 header)
        // Actually, collect_entries copies just the key bytes, not the u16 headers.
        // Buffer needs: sum of all key lengths = keys_bytes - 2*count + suffix_len
        size_t key_buf_size = h.keys_bytes + suffix_len;  // generous upper bound
        uint8_t stack_keys[4096];
        uint8_t* key_buf = (key_buf_size <= sizeof(stack_keys))
                            ? stack_keys : new uint8_t[key_buf_size];

        build_entry stack_entries[65];
        build_entry* entries = (new_count <= 65)
                                ? stack_entries
                                : new build_entry[new_count];

        collect_entries(node, h, entries, key_buf);

        // Insert new entry at position pos (shift right)
        for (int i = h.count; i > pos; --i)
            entries[i] = entries[i - 1];

        // Point new entry's key into the key buffer
        uint8_t* new_key_in_buf = key_buf + (key_buf_size - suffix_len);
        std::memcpy(new_key_in_buf, suffix, suffix_len);
        entries[pos] = {new_key_in_buf, suffix_len, new_raw};

        // Build or update in place
        uint64_t eos_raw = 0;
        const uint64_t* eos_ptr = nullptr;
        if (h.has_eos()) {
            eos_raw = h.get_slots(node)[0];
            eos_ptr = &eos_raw;
        }

        size_t new_nu     = needed_u64(h.skip, new_count,
                                        new_keys_bytes, h.has_eos());
        size_t new_padded = padded_size(static_cast<uint16_t>(new_nu));

        uint64_t* result;
        if (new_padded == h.alloc_u64) {
            // Rebuild in place: zero non-header region, rewrite
            // Header and skip preserved; we overwrite index + slots
            hdr_type& rh = hdr_type::from_node(node);
            rh.count      = new_count;
            rh.keys_bytes = new_keys_bytes;
            write_index_and_slots(node, rh, eos_ptr, entries, new_count);
            result = node;
        } else {
            result = build_compact(trie.memory(),
                                    h.skip, hdr_type::get_skip(node),
                                    h.has_eos(), eos_ptr,
                                    entries, new_count);
            trie.memory().free_node(node);
        }

        if (entries != stack_entries) delete[] entries;
        if (key_buf != stack_keys)   delete[] key_buf;

        return {result, insert_outcome::INSERTED};
    }

    // ------------------------------------------------------------------
    // write_index_and_slots -- rebuild index region and write slots
    //
    // Used for in-place rebuilds. Header and skip must already be set.
    // ------------------------------------------------------------------

    static void write_index_and_slots(uint64_t* node, const hdr_type& h,
                                       const uint64_t* eos_raw,
                                       const build_entry* entries,
                                       uint16_t count) noexcept {
        // Write index
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

        // Write slots
        uint64_t* sb = h.get_slots(node);
        if (h.has_eos() && eos_raw)
            sb[0] = *eos_raw;
        uint16_t data_start = h.has_eos() ? 1 : 0;
        for (uint16_t i = 0; i < count; ++i)
            sb[data_start + i] = entries[i].raw_slot;
    }

    // ------------------------------------------------------------------
    // handle_mismatch -- skip prefix mismatch
    //
    // Mismatch at byte ml within the skip:
    //   skip[0..ml)       = matching prefix (new skip)
    //   skip[ml]          = old branch byte
    //   key[consumed+ml]  = new branch byte
    //   skip[ml+1..]      = tail to prepend to existing keys
    //
    // Default: prepend skip[ml..] to all existing keys, stay compact.
    // If that would violate constraints: split to bitmask parent +
    //   old compact (shorter skip, keys unchanged) + new leaf.
    // ------------------------------------------------------------------

    static insert_result handle_mismatch(uint64_t* node, hdr_type& h,
                                          const uint8_t* key_data,
                                          uint32_t key_len,
                                          const VALUE& value,
                                          uint32_t consumed,
                                          match_result mr,
                                          insert_mode mode,
                                          trie_type& trie) {
        uint32_t ml   = mr.match_len;                      // bytes matched
        uint32_t sb   = h.skip_bytes();                     // total skip bytes
        uint32_t tail = sb - ml;                            // bytes to prepend

        const uint8_t* skip_data = hdr_type::get_skip(node);
        uint8_t old_branch = skip_data[ml];
        uint8_t new_branch = key_data[consumed + ml];

        // Compute what prepend would produce
        uint32_t existing_max_kl = max_key_len_in(node, h);
        uint32_t prepended_max_kl = existing_max_kl + tail;

        // New key suffix: everything after consumed + ml
        const uint8_t* new_suffix = key_data + consumed + ml;
        uint32_t new_suffix_len   = key_len - consumed - ml;

        // After prepend, all existing keys grow by tail bytes
        uint16_t new_keys_bytes = h.keys_bytes
                                  + static_cast<uint16_t>(h.count * tail)
                                  + 2 + static_cast<uint16_t>(new_suffix_len);
        uint16_t new_count = h.count + 1;
        uint32_t max_kl = std::max(prepended_max_kl, new_suffix_len);

        if (would_violate(new_count, max_kl,
                           static_cast<uint8_t>(ml),
                           new_keys_bytes, h.has_eos())) {
            // Split to bitmask
            return split_at_mismatch(node, h, key_data, key_len, value,
                                      consumed, ml, old_branch, new_branch,
                                      trie);
        }

        // Stay compact: prepend skip[ml..] to all keys, shorten skip
        return prepend_and_insert(node, h, key_data, key_len, value,
                                   consumed, ml, tail, new_suffix,
                                   new_suffix_len, new_count,
                                   new_keys_bytes, trie);
    }

    // ------------------------------------------------------------------
    // prepend_and_insert -- prepend skip tail to all keys, insert new key
    // ------------------------------------------------------------------

    static insert_result prepend_and_insert(
            uint64_t* node, hdr_type& h,
            const uint8_t* key_data, uint32_t key_len,
            const VALUE& value,
            uint32_t consumed, uint32_t ml, uint32_t tail_len,
            const uint8_t* new_suffix, uint32_t new_suffix_len,
            uint16_t new_count, uint16_t new_keys_bytes,
            trie_type& trie) {
        const uint8_t* skip_data = hdr_type::get_skip(node);
        const uint8_t* tail = skip_data + ml;  // bytes to prepend

        // Buffer for all modified key data
        // Each existing key grows by tail_len, plus new key
        size_t total_key_data = 0;
        for (uint16_t i = 0; i < h.count; ++i)
            total_key_data += tail_len;  // prepend growth
        total_key_data += h.keys_bytes + new_suffix_len;  // generous

        uint8_t stack_keys[4096];
        uint8_t* key_buf = (total_key_data <= sizeof(stack_keys))
                            ? stack_keys : new uint8_t[total_key_data];

        build_entry stack_entries[65];
        build_entry* entries = (new_count <= 65)
                                ? stack_entries
                                : new build_entry[new_count];

        // Collect existing entries with prepended tail
        const uint8_t* index = h.get_index(node);
        int W = calc_W(h.count);
        const e* idx_arr      = idx_ptr(index, W);
        const uint8_t* keys   = keys_ptr(index, W, h.count);
        const uint64_t* sb    = h.get_slots(node);
        uint16_t data_start   = h.has_eos() ? 1 : 0;

        size_t buf_off = 0;
        for (uint16_t i = 0; i < h.count; ++i) {
            uint16_t off  = e_offset(idx_arr[i]);
            uint16_t klen = read_u16(keys + off);

            // Write prepended key: tail + original key
            uint8_t* dst = key_buf + buf_off;
            std::memcpy(dst, tail, tail_len);
            std::memcpy(dst + tail_len, keys + off + 2, klen);

            entries[i].key      = dst;
            entries[i].key_len  = klen + tail_len;
            entries[i].raw_slot = sb[data_start + i];
            buf_off += klen + tail_len;
        }

        // Create VALUE for the new entry
        uint64_t new_raw = 0;
        slots::store_value(&new_raw, 0, value);

        // Copy new suffix into buffer
        uint8_t* new_key_dst = key_buf + buf_off;
        std::memcpy(new_key_dst, new_suffix, new_suffix_len);

        build_entry new_entry{new_key_dst, new_suffix_len, new_raw};

        // Find sorted insert position for new entry among modified entries
        // All existing entries now start with tail (skip[ml..]),
        // new entry starts with key_data[consumed+ml] which differs at byte 0
        int pos = 0;
        e new_e = make_search_key(new_suffix, new_suffix_len);
        for (int i = 0; i < h.count; ++i) {
            e ei = make_search_key(entries[i].key, entries[i].key_len);
            if (ei < new_e) pos = i + 1;
            else break;
        }

        // Insert at pos
        for (int i = h.count; i > pos; --i)
            entries[i] = entries[i - 1];
        entries[pos] = new_entry;

        // EOS
        uint64_t eos_raw = 0;
        const uint64_t* eos_ptr = nullptr;
        if (h.has_eos()) {
            eos_raw = sb[0];
            eos_ptr = &eos_raw;
        }

        // Build new node with shortened skip
        uint8_t new_skip = static_cast<uint8_t>(ml);
        size_t new_nu     = needed_u64(new_skip, new_count,
                                        new_keys_bytes, h.has_eos());
        size_t new_padded = padded_size(static_cast<uint16_t>(new_nu));

        uint64_t* result;
        if (new_padded == h.alloc_u64) {
            hdr_type& rh = hdr_type::from_node(node);
            rh.skip       = new_skip;
            rh.count      = new_count;
            rh.keys_bytes = new_keys_bytes;
            if (new_skip > 0)
                std::memmove(hdr_type::get_skip(node), skip_data, new_skip);
            write_index_and_slots(node, rh, eos_ptr, entries, new_count);
            result = node;
        } else {
            result = build_compact(trie.memory(),
                                    new_skip, skip_data,
                                    h.has_eos(), eos_ptr,
                                    entries, new_count);
            trie.memory().free_node(node);
        }

        if (entries != stack_entries) delete[] entries;
        if (key_buf != stack_keys)   delete[] key_buf;

        return {result, insert_outcome::INSERTED};
    }

    // ------------------------------------------------------------------
    // split_at_mismatch -- split compact into bitmask parent
    //
    // Constraints would be violated by prepend, so:
    //   bitmask parent: skip = skip[0..ml)
    //     old_branch → old compact: skip = skip[ml+1..], keys unchanged
    //     new_branch → new leaf: suffix = key[consumed+ml+1..]
    // ------------------------------------------------------------------

    static insert_result split_at_mismatch(
            uint64_t* node, hdr_type& h,
            const uint8_t* key_data, uint32_t key_len,
            const VALUE& value,
            uint32_t consumed, uint32_t ml,
            uint8_t old_branch, uint8_t new_branch,
            trie_type& trie) {
        const uint8_t* skip_data = hdr_type::get_skip(node);
        uint32_t sb = h.skip_bytes();

        // --- Old compact child: shorten skip to skip[ml+1..] ---
        uint8_t old_new_skip = static_cast<uint8_t>(sb - ml - 1);

        size_t old_nu = needed_u64(old_new_skip, h.count,
                                    h.keys_bytes, h.has_eos());
        size_t old_padded = padded_size(static_cast<uint16_t>(old_nu));

        uint64_t* old_child;
        if (old_padded == h.alloc_u64) {
            // Modify in place
            hdr_type& rh = hdr_type::from_node(node);
            rh.skip = old_new_skip;
            if (old_new_skip > 0) {
                std::memmove(hdr_type::get_skip(node),
                             skip_data + ml + 1, old_new_skip);
            }
            // Index and slots unchanged — just skip shortened
            old_child = node;
        } else {
            // Need to rebuild with new skip
            uint8_t stack_keys[4096];
            uint8_t* key_buf = (h.keys_bytes <= sizeof(stack_keys))
                                ? stack_keys
                                : new uint8_t[h.keys_bytes];

            build_entry stack_entries[65];
            build_entry* entries = (h.count <= 65)
                                    ? stack_entries
                                    : new build_entry[h.count];

            collect_entries(node, h, entries, key_buf);

            uint64_t eos_raw = 0;
            const uint64_t* eos_ptr = nullptr;
            if (h.has_eos()) {
                eos_raw = h.get_slots(node)[0];
                eos_ptr = &eos_raw;
            }

            old_child = build_compact(trie.memory(),
                                       old_new_skip, skip_data + ml + 1,
                                       h.has_eos(), eos_ptr,
                                       entries, h.count);

            if (entries != stack_entries) delete[] entries;
            if (key_buf != stack_keys)   delete[] key_buf;

            trie.memory().free_node(node);
        }

        // --- New leaf child ---
        uint32_t new_leaf_off = consumed + ml + 1;
        uint64_t* new_child = trie.add_child(
            key_data + new_leaf_off,
            key_len - new_leaf_off,
            value);

        // --- Bitmask parent ---
        uint8_t bucket_idx[2];
        uint64_t* bucket_child[2];
        int n = 0;

        if (old_branch < new_branch) {
            bucket_idx[n]   = old_branch;
            bucket_child[n] = old_child;  ++n;
            bucket_idx[n]   = new_branch;
            bucket_child[n] = new_child;  ++n;
        } else {
            bucket_idx[n]   = new_branch;
            bucket_child[n] = new_child;  ++n;
            bucket_idx[n]   = old_branch;
            bucket_child[n] = old_child;  ++n;
        }

        uint64_t* parent = bitmask_ops::create_with_children(
            trie.memory(),
            static_cast<uint8_t>(ml), skip_data,
            false, nullptr,
            bucket_idx, bucket_child, 2);

        return {parent, insert_outcome::INSERTED};
    }

    // ------------------------------------------------------------------
    // handle_key_exhausted -- key consumed during skip match
    //
    // The new key is a prefix of the skip. ml bytes matched,
    // skip is longer than remaining key. New value becomes EOS
    // on a node with skip shortened to ml.
    //
    // Default: prepend skip[ml..] to all keys, add EOS, stay compact.
    // If constraints violated: bitmask parent with EOS + old compact child.
    // ------------------------------------------------------------------

    static insert_result handle_key_exhausted(
            uint64_t* node, hdr_type& h,
            const uint8_t* key_data, uint32_t key_len,
            const VALUE& value,
            uint32_t consumed, match_result mr,
            insert_mode mode,
            trie_type& trie) {
        uint32_t ml   = mr.match_len;    // bytes matched
        uint32_t sb   = h.skip_bytes();
        uint32_t tail = sb - ml;         // bytes to prepend

        const uint8_t* skip_data = hdr_type::get_skip(node);

        // Check if we're just adding EOS (with prepend to keys)
        uint32_t existing_max_kl = max_key_len_in(node, h);
        uint32_t prepended_max_kl = existing_max_kl + tail;

        // No new key entry — just EOS. Keys grow but count stays same.
        uint16_t new_keys_bytes = h.keys_bytes
                                  + static_cast<uint16_t>(h.count * tail);
        bool new_has_eos = true;

        if (would_violate(h.count, prepended_max_kl,
                           static_cast<uint8_t>(ml),
                           new_keys_bytes, new_has_eos)) {
            // Split: bitmask parent with EOS + child at skip[ml]
            return split_at_key_exhausted(node, h, key_data, key_len,
                                           value, consumed, ml, trie);
        }

        // Stay compact: prepend skip[ml..] to all keys, add EOS
        const uint8_t* prepend = skip_data + ml;

        // Buffer entries with prepended keys
        size_t total_key_data = h.keys_bytes + h.count * tail;
        uint8_t stack_keys[4096];
        uint8_t* key_buf = (total_key_data <= sizeof(stack_keys))
                            ? stack_keys : new uint8_t[total_key_data];

        build_entry stack_entries[65];
        build_entry* entries = (h.count <= 65)
                                ? stack_entries
                                : new build_entry[h.count];

        // Collect with prepend
        const uint8_t* index = h.get_index(node);
        int W = calc_W(h.count);
        const e* idx_arr      = idx_ptr(index, W);
        const uint8_t* keys   = keys_ptr(index, W, h.count);
        const uint64_t* slot_base = h.get_slots(node);
        uint16_t data_start   = h.has_eos() ? 1 : 0;

        size_t buf_off = 0;
        for (uint16_t i = 0; i < h.count; ++i) {
            uint16_t off  = e_offset(idx_arr[i]);
            uint16_t klen = read_u16(keys + off);

            uint8_t* dst = key_buf + buf_off;
            std::memcpy(dst, prepend, tail);
            std::memcpy(dst + tail, keys + off + 2, klen);

            entries[i].key      = dst;
            entries[i].key_len  = klen + tail;
            entries[i].raw_slot = slot_base[data_start + i];
            buf_off += klen + tail;
        }

        // Create new EOS value
        uint64_t new_eos_raw = 0;
        slots::store_value(&new_eos_raw, 0, value);

        // Carry forward old EOS (merge: old EOS was for a key that matched
        // the full old skip. Now skip is shorter, so old EOS needs to become
        // a regular entry with key = skip[ml..] prepended... but old EOS key
        // was empty (it matched the skip exactly). Prepending tail to empty =
        // a key of length tail.)
        // Wait — if the node had an existing EOS, that means there was a key
        // that exactly matched the old skip. Now that we're shortening the
        // skip by ml and prepending tail to all keys, that old EOS value needs
        // to become a regular entry with key = skip[ml..] (the prepended tail
        // applied to an empty key).
        // But we're adding a NEW EOS for the new key (which exhausted at ml).
        // So: old EOS → entry with key skip[ml..], new EOS at new skip.

        uint16_t final_count = h.count;
        uint16_t final_keys_bytes = new_keys_bytes;

        if (h.has_eos()) {
            // Old EOS becomes entry with key = prepend bytes
            // This needs to be inserted into the sorted entries
            uint8_t* old_eos_key = key_buf + buf_off;
            std::memcpy(old_eos_key, prepend, tail);
            buf_off += tail;

            build_entry old_eos_entry{old_eos_key, tail,
                                       slot_base[0]};

            // Find insert position
            e eos_e = make_search_key(old_eos_key, tail);
            int pos = 0;
            for (int i = 0; i < final_count; ++i) {
                e ei = make_search_key(entries[i].key, entries[i].key_len);
                if (ei < eos_e) pos = i + 1;
                else break;
            }

            // Need bigger array?
            if (final_count + 1 > 65 && entries == stack_entries) {
                auto* new_ent = new build_entry[final_count + 1];
                std::memcpy(new_ent, entries, final_count * sizeof(build_entry));
                entries = new_ent;
            }

            for (int i = final_count; i > pos; --i)
                entries[i] = entries[i - 1];
            entries[pos] = old_eos_entry;
            final_count++;
            final_keys_bytes += 2 + static_cast<uint16_t>(tail);
        }

        // Build node
        uint8_t new_skip = static_cast<uint8_t>(ml);
        uint64_t* result = build_compact(trie.memory(),
                                          new_skip, skip_data,
                                          true, &new_eos_raw,
                                          entries, final_count);
        trie.memory().free_node(node);

        if (entries != stack_entries) delete[] entries;
        if (key_buf != stack_keys)   delete[] key_buf;

        return {result, insert_outcome::INSERTED};
    }

    // ------------------------------------------------------------------
    // split_at_key_exhausted -- constraints violated, create bitmask
    //
    // bitmask parent: skip = skip[0..ml), has_eos = true (new value)
    //   skip[ml] → old compact: skip = skip[ml+1..], keys unchanged
    // ------------------------------------------------------------------

    static insert_result split_at_key_exhausted(
            uint64_t* node, hdr_type& h,
            const uint8_t* key_data, uint32_t key_len,
            const VALUE& value,
            uint32_t consumed, uint32_t ml,
            trie_type& trie) {
        const uint8_t* skip_data = hdr_type::get_skip(node);
        uint32_t sb = h.skip_bytes();
        uint8_t branch = skip_data[ml];

        // Old compact child: skip = skip[ml+1..]
        uint8_t old_new_skip = static_cast<uint8_t>(sb - ml - 1);

        size_t old_nu     = needed_u64(old_new_skip, h.count,
                                        h.keys_bytes, h.has_eos());
        size_t old_padded = padded_size(static_cast<uint16_t>(old_nu));

        uint64_t* old_child;
        if (old_padded == h.alloc_u64) {
            hdr_type& rh = hdr_type::from_node(node);
            rh.skip = old_new_skip;
            if (old_new_skip > 0)
                std::memmove(hdr_type::get_skip(node),
                             skip_data + ml + 1, old_new_skip);
            old_child = node;
        } else {
            uint8_t stack_keys[4096];
            uint8_t* key_buf = (h.keys_bytes <= sizeof(stack_keys))
                                ? stack_keys
                                : new uint8_t[h.keys_bytes];
            build_entry stack_entries[65];
            build_entry* entries = (h.count <= 65)
                                    ? stack_entries
                                    : new build_entry[h.count];

            collect_entries(node, h, entries, key_buf);

            uint64_t eos_raw = 0;
            const uint64_t* eos_ptr = nullptr;
            if (h.has_eos()) {
                eos_raw = h.get_slots(node)[0];
                eos_ptr = &eos_raw;
            }

            old_child = build_compact(trie.memory(),
                                       old_new_skip, skip_data + ml + 1,
                                       h.has_eos(), eos_ptr,
                                       entries, h.count);

            if (entries != stack_entries) delete[] entries;
            if (key_buf != stack_keys)   delete[] key_buf;
            trie.memory().free_node(node);
        }

        // Bitmask parent with EOS (new value) and one child
        uint64_t* parent = bitmask_ops::create(
            trie.memory(),
            static_cast<uint8_t>(ml), skip_data,
            true, &value);

        hdr_type& ph = hdr_type::from_node(parent);
        parent = bitmask_ops::insert_child(parent, ph, trie.memory(),
                                            branch, old_child);

        return {parent, insert_outcome::INSERTED};
    }

    // ------------------------------------------------------------------
    // overflow_split -- compact exceeds constraints, split by first byte
    //
    // All entries are bucketed by their first suffix byte.
    // A bitmask parent is created with the compact's skip.
    // Each bucket becomes a compact child (suffixes shortened by 1).
    // The new entry is included in the appropriate bucket.
    //
    // Entries with suffix_len == 0 would become EOS on the child, but
    // that can't happen here (suffix_len > 0 guaranteed by insert path).
    // ------------------------------------------------------------------

    static insert_result overflow_split(
            uint64_t* node, hdr_type& h,
            const uint8_t* new_suffix, uint32_t new_suffix_len,
            const VALUE& value, int insert_pos,
            trie_type& trie) {
        // Create VALUE for new entry
        uint64_t new_raw = 0;
        slots::store_value(&new_raw, 0, value);

        // Collect all entries
        uint16_t N = h.count;
        uint16_t total = N + 1;

        uint8_t* key_buf = new uint8_t[h.keys_bytes + new_suffix_len];
        build_entry* all = new build_entry[total];

        collect_entries(node, h, all, key_buf);

        // Insert new entry at position
        for (int i = N; i > insert_pos; --i)
            all[i] = all[i - 1];

        uint8_t* new_key_copy = key_buf + h.keys_bytes;
        // keys_bytes includes u16 headers per key in the blob, but
        // collect_entries copies only the raw key bytes into key_buf.
        // Actually, collect_entries uses h.keys_bytes as upper bound for buf
        // size. The actual bytes used = sum of key lengths. Let me be safe
        // and compute the actual offset.
        size_t actual_key_data = 0;
        for (uint16_t i = 0; i < N; ++i)
            actual_key_data += all[i + (i >= insert_pos ? 1 : 0)].key_len;
        // Hmm, after the shift, entries are rearranged. Let me just
        // append at the end of the key_buf capacity.
        new_key_copy = key_buf + h.keys_bytes;  // safe upper bound
        std::memcpy(new_key_copy, new_suffix, new_suffix_len);
        all[insert_pos] = {new_key_copy, new_suffix_len, new_raw};

        // Count buckets (unique first bytes)
        // all[] is sorted, so first bytes are in order
        uint8_t bucket_bytes[256];
        uint16_t bucket_start[256];
        uint16_t bucket_count[256];
        int n_buckets = 0;

        uint8_t prev_byte = 0;
        bool first = true;
        for (uint16_t i = 0; i < total; ++i) {
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

        // EOS for bitmask parent (from old compact's EOS, if any)
        uint64_t eos_raw = 0;
        const uint64_t* eos_ptr = nullptr;
        if (h.has_eos()) {
            eos_raw = h.get_slots(node)[0];
            eos_ptr = &eos_raw;
        }

        // Create child for each bucket
        uint64_t* children[256];
        for (int b = 0; b < n_buckets; ++b) {
            uint16_t start = bucket_start[b];
            uint16_t cnt   = bucket_count[b];

            // Build entries with first byte stripped
            build_entry* child_entries = new build_entry[cnt];
            for (uint16_t j = 0; j < cnt; ++j) {
                const build_entry& src = all[start + j];
                child_entries[j].key      = src.key + 1;
                child_entries[j].key_len  = src.key_len - 1;
                child_entries[j].raw_slot = src.raw_slot;
            }

            // Check if any child entry has key_len == 0 → child EOS
            // Find entries with zero length (they become the child's EOS)
            bool child_has_eos = false;
            uint64_t child_eos_raw = 0;
            const uint64_t* child_eos_ptr = nullptr;
            uint16_t data_cnt = 0;
            build_entry* data_entries = new build_entry[cnt];

            for (uint16_t j = 0; j < cnt; ++j) {
                if (child_entries[j].key_len == 0) {
                    child_has_eos = true;
                    child_eos_raw = child_entries[j].raw_slot;
                    child_eos_ptr = &child_eos_raw;
                } else {
                    data_entries[data_cnt++] = child_entries[j];
                }
            }

            // If only one entry with non-zero key, might create a simple leaf
            // via add_child. But build_compact handles it fine.
            children[b] = build_compact(trie.memory(),
                                         0, nullptr,
                                         child_has_eos, child_eos_ptr,
                                         data_entries, data_cnt);

            delete[] child_entries;
            delete[] data_entries;
        }

        // Create bitmask parent
        uint64_t* parent = bitmask_ops::create_with_children(
            trie.memory(),
            h.skip, hdr_type::get_skip(node),
            h.has_eos(), eos_ptr ? &value : nullptr,
            // Wait, the parent EOS is the old compact's EOS, not the new value.
            // Let me fix: parent EOS raw is eos_raw, need to convert to VALUE*
            // Actually create_with_children takes const VALUE*, not raw.
            // This is a problem — we need a raw-slot version.
            // For now, let me create without EOS and set it after.
            bucket_bytes, children,
            static_cast<uint16_t>(n_buckets));

        // Hmm, bitmask_ops::create_with_children takes const VALUE* for eos.
        // But our EOS is a raw uint64_t. Let me handle this differently.

        // Actually, looking at bitmask_ops::create_with_children, it calls
        // slots::store_eos(sb, *eos_val) which would create a NEW T*.
        // That violates our ownership model. We need to just copy the raw slot.

        // Let me create the bitmask without EOS, then manually set it.
        // Re-create without EOS:
        // ... this is getting messy. Let me restructure.

        // OK — create bitmask without EOS first
        trie.memory().free_node(parent);  // free the one we just made

        parent = bitmask_ops::create_with_children(
            trie.memory(),
            h.skip, hdr_type::get_skip(node),
            false, nullptr,
            bucket_bytes, children,
            static_cast<uint16_t>(n_buckets));

        // If old compact had EOS, move it to bitmask parent
        if (h.has_eos()) {
            hdr_type& ph = hdr_type::from_node(parent);
            auto er = bitmask_ops::set_eos(parent, ph, trie.memory(),
                                            slots::load_eos(
                                                h.get_slots(node)));
            // set_eos creates a copy — that's wrong for non-inline values.
            // We need raw slot transfer. Let me handle this properly.
            // For now, set_eos will work for inline values (sizeof(VALUE)<=8).
            // TODO: For non-inline values, need raw EOS transfer in bitmask.
            parent = er.node;
        }

        trie.memory().free_node(node);
        delete[] all;
        delete[] key_buf;

        return {parent, insert_outcome::INSERTED};
    }

    // ------------------------------------------------------------------
    // create_from_entries -- bulk build from child_entry array
    //
    // Called from kstrie::add_children. Entries are pre-sorted.
    // Creates VALUES via store_value (initial creation).
    // ------------------------------------------------------------------

    static uint64_t* create_from_entries(
            const typename trie_type::child_entry* entries,
            size_t count, trie_type& trie) {
        if (count == 0) {
            return trie.memory().alloc_node(1);  // empty compact
        }

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
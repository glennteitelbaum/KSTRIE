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
// Index region (three-tier):
//   Tier 1 (N<=16):  [keys]
//   Tier 2 (17-256): [idx: IC*16] [keys]
//   Tier 3 (>256):   [hot: W*16] [idx: IC*16] [keys]
//
// Slots region = [value_0] ... [value_{N-1}]
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
    // Index size (write-path, called by node_header::index_size)
    // ------------------------------------------------------------------

    static size_t index_size(const hdr_type& h) noexcept {
        uint16_t N = h.count;
        uint16_t kb = approx_keys_bytes(h.slots_off, h.skip, N);
        if (N == 0 && kb == 0) return 0;
        int IC = compact_ic(N);
        int W  = compact_hot_count(N);
        return align8(static_cast<size_t>(W) * 16 +
                       static_cast<size_t>(IC) * 16 + kb);
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

    static uint8_t* keys_ptr(uint8_t* index, int W, int IC) noexcept {
        return index + W * 16 + IC * 16;
    }
    static const uint8_t* keys_ptr(const uint8_t* index, int W, int IC) noexcept {
        return index + W * 16 + IC * 16;
    }

    // ------------------------------------------------------------------
    // scan_keys -- linear scan keys region
    // ------------------------------------------------------------------

    struct search_pos {
        bool found;
        int  pos;
    };

    static search_pos scan_keys(const uint8_t* keys, int start_key,
                                int end_key, const uint8_t* suffix,
                                uint32_t suffix_len,
                                uint32_t start_off) noexcept {
        const uint8_t* kp = keys + start_off;
        for (int ki = start_key; ki < end_key; ++ki) {
            int cmp = key_cmp(kp, suffix, suffix_len);
            if (cmp == 0) return {true, ki};
            if (cmp > 0)  return {false, ki};
            kp = key_next(kp);
        }
        return {false, end_key};
    }

    // ------------------------------------------------------------------
    // search_in_index -- coalesced three-tier pipeline
    //
    // 1. Scan hot (tier 3 only, skipped if W==0)
    //    → narrows idx_start..idx_end
    // 2. Scan idx (tier 2+3, skipped if IC==0)
    //    → narrows scan_start_key, scan_start_off, scan_end_key
    // 3. Scan keys (always)
    //    → returns found/pos
    //
    // Uses operator< on byteswapped e for all prefix comparisons.
    // ------------------------------------------------------------------

    static search_pos search_in_index(const uint8_t* index, uint16_t N,
                                      const uint8_t* suffix,
                                      uint32_t suffix_len) noexcept {
        int IC = compact_ic(N);
        int W  = compact_hot_count(N);
        const uint8_t* keys = keys_ptr(index, W, IC);

        // Key scan bounds (default: full range)
        int scan_start_key = 0;
        uint32_t scan_start_off = 0;
        int scan_end_key = N;

        // Skip hot + idx for tier 1 (IC==0)
        if (IC == 0)
            goto do_scan;

        {
            e search = make_search_key(suffix, suffix_len);
            e search_pfx = e_prefix_only(search);

            const e* idx = idx_ptr(index, W);

            int idx_start = 0;
            int idx_end   = IC;

            // Step 1: Scan hot (tier 3 only)
            if (W > 0) {
                const e* hot = hot_ptr(index);
                int i = 1;
                while (i < W)
                    i = 2 * i + (search >= hot[i] ? 1 : 0);
                int group = i - W;
                idx_start = group * IC / W;
                idx_end   = (group + 1) * IC / W;
                if (idx_end > IC) idx_end = IC;

                // Start from previous idx entry
                if (idx_start > 0) {
                    scan_start_key = static_cast<int>(e_keynum(idx[idx_start - 1]));
                    scan_start_off = e_offset(idx[idx_start - 1]);
                }
            }

            // Step 2: Scan idx entries
            for (int g = idx_start; g < idx_end; ++g) {
                if (e_prefix_only(idx[g]) > search_pfx) {
                    scan_end_key = static_cast<int>(e_keynum(idx[g]));
                    goto do_scan;
                }
                scan_start_key = static_cast<int>(e_keynum(idx[g]));
                scan_start_off = e_offset(idx[g]);
            }

            // Overflow: prefix may span the hot boundary (tier 3 only)
            if (W > 0) {
                for (int g = idx_end; g < IC; ++g) {
                    if (e_prefix_only(idx[g]) > search_pfx) {
                        scan_end_key = static_cast<int>(e_keynum(idx[g]));
                        goto do_scan;
                    }
                }
            }
            scan_end_key = N;
        }

    do_scan:
        // Step 3: Scan keys (always)
        return scan_keys(keys, scan_start_key, scan_end_key,
                         suffix, suffix_len, scan_start_off);
    }

    // ------------------------------------------------------------------
    // find -- read-path, uses cached slots_off
    // ------------------------------------------------------------------

    static const VALUE* find(const uint64_t* node, const hdr_type& h,
                             const uint8_t* suffix,
                             uint32_t suffix_len) noexcept {
        const uint8_t* index = h.get_index(const_cast<uint64_t*>(node));
        auto [found, pos] = search_in_index(index, h.count, suffix, suffix_len);
        if (!found) return nullptr;

        // Cached slots access: node + slots_off
        const uint64_t* sb = node + h.slots_off;
        return &slots::load_value(sb, pos);
    }

    // ------------------------------------------------------------------
    // collect_entries (walk keys sequentially)
    // ------------------------------------------------------------------

    static uint16_t collect_entries(const uint64_t* node, const hdr_type& h,
                                    build_entry* out,
                                    uint8_t* key_buf) noexcept {
        uint16_t N = h.count;
        if (N == 0) return 0;

        const uint8_t* index = h.get_index(const_cast<uint64_t*>(node));
        int IC = compact_ic(N);
        int W  = compact_hot_count(N);
        const uint8_t* keys = keys_ptr(index, W, IC);
        const uint64_t* sb  = node + h.slots_off;

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
    // build_compact -- sets slots_off in header
    // ------------------------------------------------------------------

    static uint64_t* build_compact(mem_type& mem,
                                    uint8_t skip_len,
                                    const uint8_t* skip_data,
                                    const build_entry* entries,
                                    uint16_t count) {
        uint16_t kb = 0;
        for (uint16_t i = 0; i < count; ++i)
            kb += 2 + static_cast<uint16_t>(entries[i].key_len);

        uint16_t so = compute_compact_slots_off(skip_len, count, kb);
        size_t nu = (static_cast<size_t>(so) * 8 + static_cast<size_t>(count) * 8 + 7) / 8;

        uint64_t* node = mem.alloc_node(nu);
        hdr_type& h = hdr_type::from_node(node);
        h.set_compact(true);
        h.skip      = skip_len;
        h.count     = count;
        h.slots_off = so;

        if (skip_len > 0 && skip_data)
            std::memcpy(hdr_type::get_skip(node), skip_data, skip_len);

        write_index_and_slots(node, h, entries, count);
        return node;
    }

    // ------------------------------------------------------------------
    // write_index_and_slots (three-tier idx with backup rule)
    // ------------------------------------------------------------------

    static void write_index_and_slots(uint64_t* node, const hdr_type& h,
                                       const build_entry* entries,
                                       uint16_t count) noexcept {
        uint8_t* index = h.get_index(node);
        int IC = compact_ic(count);
        int W  = compact_hot_count(count);
        uint8_t* key_dst = keys_ptr(index, W, IC);

        // Write all keys sequentially, track byte offsets
        uint16_t stack_offsets[256];
        uint16_t* key_offsets = (count <= 256)
            ? stack_offsets : new uint16_t[count];

        uint16_t key_off = 0;
        for (uint16_t i = 0; i < count; ++i) {
            key_offsets[i] = key_off;
            write_u16(key_dst + key_off,
                      static_cast<uint16_t>(entries[i].key_len));
            if (entries[i].key_len > 0)
                std::memcpy(key_dst + key_off + 2,
                            entries[i].key, entries[i].key_len);
            key_off += 2 + entries[i].key_len;
        }

        // Build idx entries (tier 2 and 3 only)
        if (IC > 0) {
            e* idx_arr = idx_ptr(index, W);

            for (int i = 0; i < IC; ++i) {
                int nom;
                if (W > 0) {
                    nom = i * 8;   // Tier 3: stride 8
                } else {
                    nom = (i + 1) * count / (IC + 1);   // Tier 2: spread
                }

                // Backup rule: walk back to first key with same e prefix
                e nom_key = make_search_key(entries[nom].key, entries[nom].key_len);
                e nom_pfx = e_prefix_only(nom_key);
                int min_pos = (i > 0) ? static_cast<int>(e_keynum(idx_arr[i - 1])) : 0;
                int pos = nom;
                while (pos > min_pos) {
                    e prev_key = make_search_key(entries[pos - 1].key,
                                                  entries[pos - 1].key_len);
                    if (e_prefix_only(prev_key) != nom_pfx) break;
                    pos--;
                }

                es s;
                s.setkey(reinterpret_cast<const char*>(entries[pos].key),
                         static_cast<int>(entries[pos].key_len));
                s.setoff(key_offsets[pos]);
                s.setkeynum(static_cast<uint16_t>(pos));
                idx_arr[i] = cvt(s);
            }

            if (W > 0) {
                e* hot = hot_ptr(index);
                hot[0] = e{};
                build_eyt(idx_arr, IC, hot);
            }
        }

        if (key_offsets != stack_offsets) delete[] key_offsets;

        // Write slots
        uint64_t* sb = h.get_slots(node);
        for (uint16_t i = 0; i < count; ++i)
            sb[i] = entries[i].raw_slot;
    }

    // ------------------------------------------------------------------
    // finalize
    // ------------------------------------------------------------------

    static insert_result finalize(uint64_t* old_node, uint64_t* new_node,
                                   uint32_t max_key_len,
                                   mem_type& mem) {
        mem.free_node(old_node);
        hdr_type& h = hdr_type::from_node(new_node);
        if (h.count > COMPACT_MAX ||
            h.alloc_u64 > COMPACT_MAX_ALLOC_U64 ||
            max_key_len > COMPACT_MAX_KEY_LEN)
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

        // Use approx_keys_bytes for buffer sizing
        uint16_t akb = approx_keys_bytes(h.slots_off, h.skip, h.count);
        size_t key_buf_size = akb + h.count * tail + new_suffix_len + 256;
        uint8_t stack_keys[4096];
        uint8_t* key_buf = (key_buf_size <= sizeof(stack_keys))
                            ? stack_keys : new uint8_t[key_buf_size];

        build_entry stack_entries[65];
        build_entry* entries = (new_count <= 65)
                                ? stack_entries
                                : new build_entry[new_count];

        const uint8_t* index = h.get_index(node);
        int IC = compact_ic(h.count);
        int W  = compact_hot_count(h.count);
        const uint8_t* keys = keys_ptr(index, W, IC);
        const uint64_t* sb  = node + h.slots_off;

        size_t buf_off = 0;
        uint16_t ei = 0;
        uint32_t max_key_len = new_suffix_len;
        const uint8_t* kp = keys;

        for (uint16_t i = 0; i < h.count; ++i) {
            uint16_t klen = read_u16(kp);

            uint8_t* dst = key_buf + buf_off;
            if (tail > 0) std::memcpy(dst, prepend, tail);
            std::memcpy(dst + tail, kp + 2, klen);

            uint32_t entry_len = klen + tail;
            entries[ei].key      = dst;
            entries[ei].key_len  = entry_len;
            entries[ei].raw_slot = sb[i];
            if (entry_len > max_key_len) max_key_len = entry_len;
            buf_off += entry_len;
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

        uint64_t* result = build_compact(mem,
                                          new_skip, skip_data,
                                          entries, new_count);

        if (entries != stack_entries) delete[] entries;
        if (key_buf != stack_keys)   delete[] key_buf;

        return finalize(node, result, max_key_len, mem);
    }

    // ------------------------------------------------------------------
    // split_node
    // ------------------------------------------------------------------

    static insert_result split_node(uint64_t* node, hdr_type& h,
                                     mem_type& mem) {
        uint16_t N = h.count;

        uint16_t akb = approx_keys_bytes(h.slots_off, h.skip, N);
        uint8_t* key_buf = new uint8_t[akb + 256];
        build_entry* all = new build_entry[N];
        collect_entries(node, h, all, key_buf);

        uint64_t* eos_leaf = nullptr;
        uint16_t data_start = 0;

        if (N > 0 && all[0].key_len == 0) {
            build_entry eos_entry = all[0];
            eos_leaf = build_compact(mem, 0, nullptr, &eos_entry, 1);
            data_start = 1;
        }

        uint16_t data_count = N - data_start;

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

            children[b] = build_compact(mem, 0, nullptr,
                                         child_entries, data_cnt);

            hdr_type& ch = hdr_type::from_node(children[b]);
            if (ch.count > COMPACT_MAX ||
                ch.alloc_u64 > COMPACT_MAX_ALLOC_U64) {
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

        if (eos_leaf) {
            hdr_type& ph = hdr_type::from_node(parent);
            bitmask_ops::set_eos_child(parent, ph, eos_leaf);
        }

        mem.free_node(node);
        delete[] all;
        delete[] key_buf;

        return {parent, insert_outcome::INSERTED};
    }

    // ------------------------------------------------------------------
    // create_from_entries
    // ------------------------------------------------------------------

    static uint64_t* create_from_entries(
            const typename trie_type::child_entry* entries,
            size_t count, mem_type& mem) {
        if (count == 0)
            return mem.alloc_node(1);

        build_entry* be = new build_entry[count];
        for (size_t i = 0; i < count; ++i) {
            uint64_t raw = 0;
            slots::store_value(&raw, 0, *entries[i].value);
            be[i].key      = entries[i].suffix;
            be[i].key_len  = entries[i].suffix_len;
            be[i].raw_slot = raw;
        }

        uint64_t* node = build_compact(mem, 0, nullptr,
                                         be, static_cast<uint16_t>(count));
        delete[] be;
        return node;
    }
};

} // namespace gteitelbaum

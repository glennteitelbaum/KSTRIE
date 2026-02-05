#pragma once

#include "kstrie_support.hpp"

namespace gteitelbaum {

// ============================================================================
// kstrie_skip_eos -- skip prefix and EOS operations
// ============================================================================

template <typename VALUE, typename ALLOC>
struct kstrie_skip_eos {
    using memory_type = kstrie_memory<ALLOC>;
    using vals        = kstrie_values<VALUE>;

    // ------------------------------------------------------------------
    // EOS slot accessors
    // ------------------------------------------------------------------

    // Pointer to the raw EOS slot (EOS_U64 uint64_t at fixed offset)
    static uint64_t* eos_ptr(uint64_t* n, uint8_t skip) noexcept {
        return n + header_and_prefix_u64(skip);
    }

    static const uint64_t* eos_ptr(const uint64_t* n, uint8_t skip) noexcept {
        return n + header_and_prefix_u64(skip);
    }

    static VALUE& load_eos(uint64_t* n, uint8_t skip) noexcept {
        return vals::load_single(eos_ptr(n, skip));
    }

    static const VALUE& load_eos(const uint64_t* n, uint8_t skip) noexcept {
        return vals::load_single(eos_ptr(n, skip));
    }

    static void store_eos(uint64_t* n, uint8_t skip, const VALUE& value) {
        vals::store_single(eos_ptr(n, skip), value);
    }

    static void destroy_eos(uint64_t* n, uint8_t skip) {
        vals::destroy_single(eos_ptr(n, skip));
    }

    // Copy raw EOS bytes from src node to dst node
    static void copy_eos(uint64_t* dst, uint8_t dst_skip,
                         const uint64_t* src, uint8_t src_skip) noexcept {
        std::memcpy(eos_ptr(dst, dst_skip),
                    eos_ptr(src, src_skip),
                    vals::EOS_U64 * 8);
    }

    // ------------------------------------------------------------------
    // Prefix matching
    // ------------------------------------------------------------------

    enum class match_status : uint8_t {
        MATCHED,        // full prefix matched, consumed advanced
        MISMATCH,       // mismatch at some point
        KEY_EXHAUSTED   // key ran out within prefix
    };

    struct match_result {
        match_status status;
        uint32_t     consumed;   // updated consumed position
        uint32_t     match_len;  // how many prefix bytes matched (for mismatch)
    };

    // Walk skip prefix chain (including continuations).
    // mapped_key must already be mapped through char_map.
    // On return:
    //   MATCHED: consumed advanced past all prefix bytes, node updated past continuations
    //   MISMATCH: match_len = how many bytes matched before divergence
    //   KEY_EXHAUSTED: key too short for prefix
    static match_result match_prefix(const uint64_t*& node, node_header& h,
                                     const uint8_t* mapped_key,
                                     uint32_t key_len,
                                     uint32_t consumed) noexcept {
        while (h.skip > 0) {
            uint32_t sb = h.skip_bytes();
            uint32_t remaining = key_len - consumed;
            const uint8_t* prefix = node_prefix(node);

            if (remaining < sb) {
                // Key is shorter than prefix — find how far it matches
                uint32_t ml = 0;
                while (ml < remaining && mapped_key[consumed + ml] == prefix[ml])
                    ++ml;
                return {ml < remaining ? match_status::MISMATCH : match_status::KEY_EXHAUSTED,
                        consumed, ml};
            }

            // Compare prefix
            uint32_t ml = 0;
            while (ml < sb && mapped_key[consumed + ml] == prefix[ml])
                ++ml;

            if (ml < sb) {
                return {match_status::MISMATCH, consumed, ml};
            }

            consumed += sb;

            if (!h.is_continuation()) break;

            // Follow continuation
            node = *reinterpret_cast<const uint64_t* const*>(
                node + header_and_prefix_u64(h.skip));
            h = hdr(node);
        }

        return {match_status::MATCHED, consumed, 0};
    }

    // Mutable version (for insert path)
    static match_result match_prefix(uint64_t*& node, node_header& h,
                                     const uint8_t* mapped_key,
                                     uint32_t key_len,
                                     uint32_t consumed) noexcept {
        const uint64_t* cnode = node;
        auto r = match_prefix(cnode, h, mapped_key, key_len, consumed);
        node = const_cast<uint64_t*>(cnode);
        return r;
    }

    // ------------------------------------------------------------------
    // LCP computation (2-way: new key vs existing prefix)
    // ------------------------------------------------------------------

    static uint32_t find_lcp(const uint8_t* prefix, uint32_t prefix_len,
                             const uint8_t* key, uint32_t key_len) noexcept {
        uint32_t max_cmp = std::min(prefix_len, key_len);
        uint32_t ml = 0;
        while (ml < max_cmp && prefix[ml] == key[ml])
            ++ml;
        return ml;
    }

    // ------------------------------------------------------------------
    // Leaf creation
    // ------------------------------------------------------------------

    // Create skip+EOS node with count=0. Full suffix becomes skip prefix.
    static uint64_t* create_leaf(const uint8_t* suffix, uint32_t suffix_len,
                                 const VALUE& value, memory_type& mem) {
        uint8_t skip = static_cast<uint8_t>(suffix_len);
        std::size_t nu = data_offset_u64<VALUE>(skip, true);
        uint64_t* node = mem.alloc_node(nu);

        node_header& nh = hdr(node);
        nh.keys_bytes = 0;
        nh.count = 0;
        nh.skip  = skip;
        nh.flags = 0b11;  // is_compact=1, has_eos=1

        if (suffix_len > 0)
            std::memcpy(node + header_u64(), suffix, suffix_len);

        store_eos(node, skip, value);
        return node;
    }

    // Create EOS-only node (skip=0, count=0)
    static uint64_t* create_eos_only(const VALUE& value, memory_type& mem) {
        std::size_t nu = data_offset_u64<VALUE>(0, true);
        uint64_t* node = mem.alloc_node(nu);

        hdr(node).flags = 0b11;
        store_eos(node, 0, value);
        return node;
    }

    // Create EOS-only node by copying raw EOS bytes from source
    static uint64_t* create_eos_only_from_raw(const uint64_t* eos_data,
                                               memory_type& mem) {
        std::size_t nu = data_offset_u64<VALUE>(0, true);
        uint64_t* node = mem.alloc_node(nu);

        hdr(node).flags = 0b11;
        std::memcpy(eos_ptr(node, 0), eos_data, vals::EOS_U64 * 8);
        return node;
    }

    // ------------------------------------------------------------------
    // Add EOS to existing node (reallocate with EOS slot)
    // data_size_bytes: size of the data region in bytes (caller computes)
    // ------------------------------------------------------------------

    static insert_result add_eos_to_node(uint64_t* node, node_header h,
                                          const VALUE& value,
                                          std::size_t data_size_bytes,
                                          memory_type& mem) {
        std::size_t old_data_off = data_offset_u64<VALUE>(h.skip, false);
        std::size_t new_data_off = data_offset_u64<VALUE>(h.skip, true);

        std::size_t new_node_u64 = new_data_off + (data_size_bytes + 7) / 8;
        uint64_t* nn = mem.alloc_node(new_node_u64);

        // Copy header with has_eos set
        hdr(nn).copy_from(h);
        hdr(nn).flags |= 2;

        // Copy prefix
        if (h.skip > 0) {
            std::memcpy(nn + header_u64(),
                       node + header_u64(),
                       prefix_u64(h.skip) * 8);
        }

        // Store EOS value
        store_eos(nn, h.skip, value);

        // Copy data blob
        if (data_size_bytes > 0) {
            std::memcpy(reinterpret_cast<uint8_t*>(nn) + new_data_off * 8,
                       reinterpret_cast<const uint8_t*>(node) + old_data_off * 8,
                       data_size_bytes);
        }

        mem.free_node(node);
        return {nn, insert_outcome::INSERTED};
    }

    // ------------------------------------------------------------------
    // Clone node with new skip prefix
    // data_size_bytes: size of the data region in bytes (caller computes)
    // ------------------------------------------------------------------

    static uint64_t* clone_with_new_prefix(uint64_t* node, node_header h,
                                            const uint8_t* new_prefix,
                                            uint32_t new_skip,
                                            std::size_t data_size_bytes,
                                            memory_type& mem) {
        uint8_t nsb = static_cast<uint8_t>(new_skip);

        std::size_t new_node_u64 = data_offset_u64<VALUE>(nsb, h.has_eos()) +
                                   (data_size_bytes + 7) / 8;
        uint64_t* nn = mem.alloc_node(new_node_u64);

        // Copy header with new skip
        hdr(nn).copy_from(h);
        hdr(nn).skip = nsb;

        // Write new prefix
        if (new_skip > 0) {
            std::memcpy(nn + header_u64(), new_prefix, new_skip);
        }

        // Copy EOS if present
        if (h.has_eos()) {
            copy_eos(nn, nsb, node, h.skip);
        }

        // Copy data blob
        if (data_size_bytes > 0) {
            std::memcpy(
                reinterpret_cast<uint8_t*>(nn) +
                    data_offset_u64<VALUE>(nsb, h.has_eos()) * 8,
                reinterpret_cast<const uint8_t*>(node) +
                    data_offset_u64<VALUE>(h.skip, h.has_eos()) * 8,
                data_size_bytes);
        }

        return nn;
    }
};

} // namespace gteitelbaum

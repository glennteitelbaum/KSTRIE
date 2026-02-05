#pragma once

#include "kstrie_support.hpp"

namespace gteitelbaum {

// ============================================================================
// kstrie_skip -- skip prefix operations
//
// Owns: prefix byte comparison, LCP computation
// Does NOT own: EOS (moved to kstrie_slots)
// ============================================================================

template <typename VALUE, typename CHARMAP, typename ALLOC>
struct kstrie_skip {
    using hdr_type = node_header<VALUE, CHARMAP, ALLOC>;

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
        uint32_t     consumed;    // updated consumed position
        uint32_t     match_len;   // bytes matched before divergence (for mismatch/exhausted)
    };

    // Walk skip prefix chain (including continuations).
    // mapped_key must already be mapped through char_map.
    static match_result match_prefix(const uint64_t*& node, hdr_type& h,
                                     const uint8_t* mapped_key,
                                     uint32_t key_len,
                                     uint32_t consumed) noexcept {
        while (h.skip > 0) {
            uint32_t sb = h.skip_bytes();
            uint32_t remaining = key_len - consumed;
            const uint8_t* prefix = hdr_type::get_skip(const_cast<uint64_t*>(node));

            if (remaining < sb) {
                // Key shorter than prefix — find how far it matches
                uint32_t ml = 0;
                while (ml < remaining && mapped_key[consumed + ml] == prefix[ml])
                    ++ml;
                return {ml < remaining ? match_status::MISMATCH
                                       : match_status::KEY_EXHAUSTED,
                        consumed, ml};
            }

            // Compare prefix bytes
            uint32_t ml = 0;
            while (ml < sb && mapped_key[consumed + ml] == prefix[ml])
                ++ml;

            if (ml < sb)
                return {match_status::MISMATCH, consumed, ml};

            consumed += sb;

            if (!h.is_continuation()) break;

            // Follow continuation pointer
            node = *reinterpret_cast<const uint64_t* const*>(
                hdr_type::get_skip(const_cast<uint64_t*>(node)) + h.skip_bytes());
            h = hdr_type::from_node(node);
        }

        return {match_status::MATCHED, consumed, 0};
    }

    // Mutable version (for insert path)
    static match_result match_prefix(uint64_t*& node, hdr_type& h,
                                     const uint8_t* mapped_key,
                                     uint32_t key_len,
                                     uint32_t consumed) noexcept {
        const uint64_t* cnode = node;
        auto r = match_prefix(cnode, h, mapped_key, key_len, consumed);
        node = const_cast<uint64_t*>(cnode);
        return r;
    }

    // ------------------------------------------------------------------
    // LCP computation (2-way: new key suffix vs existing prefix)
    // ------------------------------------------------------------------

    static uint32_t find_lcp(const uint8_t* a, uint32_t a_len,
                             const uint8_t* b, uint32_t b_len) noexcept {
        uint32_t max_cmp = std::min(a_len, b_len);
        uint32_t ml = 0;
        while (ml < max_cmp && a[ml] == b[ml])
            ++ml;
        return ml;
    }

    // ------------------------------------------------------------------
    // Skip region size (same as node_header::skip_size, provided for symmetry)
    // ------------------------------------------------------------------

    static size_t size(hdr_type h) noexcept {
        return h.skip_size();
    }
};

} // namespace gteitelbaum

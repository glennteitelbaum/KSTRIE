#pragma once
#include "kstrie_support.hpp"

namespace gteitelbaum {

// Stub: compact node operations (to be implemented)
template <typename VALUE, typename CHARMAP, typename ALLOC>
struct kstrie_compact {
    using hdr_type = node_header<VALUE, CHARMAP, ALLOC>;

    static size_t index_size(const hdr_type& h) noexcept {
        return compact_index_size(h.count, h.keys_bytes);
    }
};

} // namespace gteitelbaum

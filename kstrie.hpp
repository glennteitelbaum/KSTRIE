#pragma once

#include "kstrie_impl.hpp"
#include <iterator>
#include <optional>
#include <vector>

namespace gteitelbaum {

// ============================================================================
// kstrie -- user-facing trie class
//
// Inherits engine (find/insert/erase) from kstrie_impl.
// Adds bidirectional iterator, ordered traversal, prefix queries.
// ============================================================================

template <typename VALUE,
          typename CHARMAP = identity_char_map,
          typename ALLOC   = std::allocator<uint64_t>>
class kstrie : public kstrie_impl<VALUE, CHARMAP, ALLOC> {
    using base         = kstrie_impl<VALUE, CHARMAP, ALLOC>;
    using hdr_type     = typename base::hdr_type;
    using slots_type   = typename base::slots_type;
    using bitmask_type = typename base::bitmask_type;
    using compact_type = typename base::compact_type;

public:
    using typename base::key_type;
    using typename base::mapped_type;
    using typename base::size_type;
    using typename base::allocator_type;

    // Inherit constructors
    using base::base;

    // ------------------------------------------------------------------
    // const_iterator -- bidirectional, stores VALUE copy
    // ------------------------------------------------------------------

    class const_iterator {
        const kstrie* trie_ = nullptr;
        std::string   key_;
        VALUE         value_{};
        bool          at_end_ = true;

        const_iterator(const kstrie* t, std::string k, const VALUE& v)
            : trie_(t), key_(std::move(k)), value_(v), at_end_(false) {}

        static const_iterator make_end(const kstrie* t) {
            const_iterator it;
            it.trie_   = t;
            it.at_end_ = true;
            return it;
        }

        friend class kstrie;

    public:
        using iterator_category = std::bidirectional_iterator_tag;
        using value_type        = std::pair<const std::string, VALUE>;
        using difference_type   = std::ptrdiff_t;
        using pointer           = const value_type*;

        using reference = std::pair<std::string, VALUE>;

        const_iterator() = default;

        reference operator*() const { return {key_, value_}; }

        const std::string& key() const { return key_; }
        const VALUE& value() const { return value_; }

        const_iterator& operator++() {
            auto [k, v] = trie_->iter_next(key_);
            if (v) { key_ = std::move(k); value_ = *v; at_end_ = false; }
            else   { at_end_ = true; }
            return *this;
        }

        const_iterator operator++(int) {
            const_iterator tmp = *this;
            ++*this;
            return tmp;
        }

        const_iterator& operator--() {
            if (at_end_) {
                auto [k, v] = trie_->iter_max(trie_->get_root());
                if (v) { key_ = std::move(k); value_ = *v; at_end_ = false; }
            } else {
                auto [k, v] = trie_->iter_prev(key_);
                if (v) { key_ = std::move(k); value_ = *v; }
                else   { at_end_ = true; }
            }
            return *this;
        }

        const_iterator operator--(int) {
            const_iterator tmp = *this;
            --*this;
            return tmp;
        }

        bool operator==(const const_iterator& o) const {
            if (at_end_ && o.at_end_) return true;
            if (at_end_ || o.at_end_) return false;
            return key_ == o.key_;
        }

        bool operator!=(const const_iterator& o) const { return !(*this == o); }
    };

    using iterator               = const_iterator;
    using reverse_iterator       = std::reverse_iterator<const_iterator>;
    using const_reverse_iterator = std::reverse_iterator<const_iterator>;

    // ------------------------------------------------------------------
    // Iterator access
    // ------------------------------------------------------------------

    const_iterator begin() const {
        auto [k, v] = iter_min(this->get_root());
        if (!v) return end();
        return {this, std::move(k), *v};
    }

    const_iterator end() const { return const_iterator::make_end(this); }
    const_iterator cbegin() const { return begin(); }
    const_iterator cend() const { return end(); }

    reverse_iterator rbegin() const { return reverse_iterator(end()); }
    reverse_iterator rend() const { return reverse_iterator(begin()); }
    const_reverse_iterator crbegin() const { return rbegin(); }
    const_reverse_iterator crend() const { return rend(); }

    // ------------------------------------------------------------------
    // Ordered lookup
    // ------------------------------------------------------------------

    const_iterator lower_bound(std::string_view key) const {
        auto [k, v] = iter_lower_bound(key);
        if (!v) return end();
        return {this, std::move(k), *v};
    }

    const_iterator upper_bound(std::string_view key) const {
        auto [k, v] = iter_upper_bound(key);
        if (!v) return end();
        return {this, std::move(k), *v};
    }

    std::pair<const_iterator, const_iterator>
    equal_range(std::string_view key) const {
        return {lower_bound(key), upper_bound(key)};
    }

    std::pair<const_iterator, const_iterator>
    prefix(std::string_view pfx) const {
        auto [k1, v1, k2, v2] = iter_prefix_bounds(pfx);
        const_iterator first = v1 ? const_iterator{this, std::move(k1), *v1}
                                  : end();
        const_iterator last  = v2 ? const_iterator{this, std::move(k2), *v2}
                                  : end();
        return {first, last};
    }

    const_iterator find_iter(std::string_view key) const {
        const VALUE* v = this->find(key);
        if (!v) return end();
        return {this, std::string(key), *v};
    }

    // ------------------------------------------------------------------
    // Iterator-based modifiers
    // ------------------------------------------------------------------

    const_iterator erase(const_iterator pos) {
        if (pos == end()) return end();
        auto [next_key, next_val] = iter_next(pos.key_);
        std::optional<VALUE> saved;
        if (next_val) saved = *next_val;
        base::erase(pos.key_);
        if (!saved) return end();
        return {this, std::move(next_key), *saved};
    }

    // Bring base erase(string_view) into scope (hidden by overload above)
    using base::erase;

    const_iterator erase(const_iterator first, const_iterator last) {
        std::vector<std::string> keys;
        for (auto it = first; it != last; ++it)
            keys.push_back(it.key());
        for (auto& k : keys)
            base::erase(k);
        if (last == end()) return end();
        auto [k, v] = iter_lower_bound(last.key());
        if (!v) return end();
        return {this, std::move(k), *v};
    }

    template <typename... Args>
    std::pair<const_iterator, bool> emplace(std::string_view key, Args&&... args) {
        VALUE v(std::forward<Args>(args)...);
        bool inserted = this->insert(key, v);
        auto [k, vp] = iter_lower_bound(key);
        return {const_iterator{this, std::move(k), *vp}, inserted};
    }

    template <typename... Args>
    std::pair<const_iterator, bool> try_emplace(std::string_view key, Args&&... args) {
        const VALUE* existing = this->find(key);
        if (existing)
            return {const_iterator{this, std::string(key), *existing}, false};
        VALUE v(std::forward<Args>(args)...);
        this->insert(key, v);
        return {const_iterator{this, std::string(key), v}, true};
    }

    // ------------------------------------------------------------------
    // Comparison
    // ------------------------------------------------------------------

    bool operator==(const kstrie& o) const {
        if (this->size() != o.size()) return false;
        auto a = begin(), b = o.begin();
        while (a != end()) {
            auto [ak, av] = *a;
            auto [bk, bv] = *b;
            if (ak != bk || av != bv) return false;
            ++a; ++b;
        }
        return true;
    }

    bool operator!=(const kstrie& o) const { return !(*this == o); }

private:

    // ------------------------------------------------------------------
    // Unmap helper
    // ------------------------------------------------------------------

    static void append_unmapped(std::string& out, const uint8_t* data,
                                uint32_t len) {
        for (uint32_t i = 0; i < len; ++i)
            out.push_back(static_cast<char>(CHARMAP::from_index(data[i])));
    }

    // ------------------------------------------------------------------
    // iter_min / iter_max
    // ------------------------------------------------------------------

    std::pair<std::string, const VALUE*>
    iter_min(const uint64_t* node) const {
        std::string result;
        const VALUE* val = find_min_impl(node, result);
        return {std::move(result), val};
    }

    std::pair<std::string, const VALUE*>
    iter_max(const uint64_t* node) const {
        std::string result;
        const VALUE* val = find_max_impl(node, result);
        return {std::move(result), val};
    }

    const VALUE* find_min_impl(const uint64_t* node, std::string& out) const {
        if (node == sentinel_ptr()) return nullptr;
        hdr_type h = hdr_type::from_node(node);

        uint32_t sb = h.skip_bytes();
        if (sb > 0)
            append_unmapped(out, hdr_type::get_skip(node), sb);

        if (h.is_compact()) {
            if (h.count == 0) return nullptr;
            const uint8_t* keys = compact_type::keys_ptr(node, h);
            uint16_t klen = read_u16(keys);
            append_unmapped(out, keys + 2, klen);
            return slots_type::load_value(h.get_compact_slots(node), 0);
        }

        if (h.has_eos())
            return bitmask_type::eos_value(node, h);

        if (h.count == 0) return nullptr;
        const auto* bm = bitmask_type::get_bitmap(node, h);
        int idx = bm->find_next_set(0);
        out.push_back(static_cast<char>(CHARMAP::from_index(
            static_cast<uint8_t>(idx))));
        return find_min_impl(bitmask_type::child_by_slot(node, h, 0), out);
    }

    const VALUE* find_max_impl(const uint64_t* node, std::string& out) const {
        if (node == sentinel_ptr()) return nullptr;
        hdr_type h = hdr_type::from_node(node);

        uint32_t sb = h.skip_bytes();
        if (sb > 0)
            append_unmapped(out, hdr_type::get_skip(node), sb);

        if (h.is_compact()) {
            if (h.count == 0) return nullptr;
            const uint8_t* keys = compact_type::keys_ptr(node, h);
            const uint8_t* kp = keys;
            for (int i = 0; i < h.count - 1; ++i) kp = key_next(kp);
            uint16_t klen = read_u16(kp);
            append_unmapped(out, kp + 2, klen);
            return slots_type::load_value(h.get_compact_slots(node),
                                          h.count - 1);
        }

        if (h.count > 0) {
            const auto* bm = bitmask_type::get_bitmap(node, h);
            constexpr int MAX_BIT = CHARMAP::BITMAP_WORDS * 64 - 1;
            int idx = bm->find_prev_set(MAX_BIT);
            int slot = bm->find_slot(idx);
            out.push_back(static_cast<char>(CHARMAP::from_index(
                static_cast<uint8_t>(idx))));
            return find_max_impl(
                bitmask_type::child_by_slot(node, h, slot), out);
        }

        if (h.has_eos())
            return bitmask_type::eos_value(node, h);

        return nullptr;
    }

    // ------------------------------------------------------------------
    // iter_next -- successor
    // ------------------------------------------------------------------

    std::pair<std::string, const VALUE*>
    iter_next(const std::string& current) const {
        const uint8_t* raw = reinterpret_cast<const uint8_t*>(current.data());
        uint32_t len = static_cast<uint32_t>(current.size());

        uint8_t stack_buf[256];
        auto [mapped, heap_buf] = get_mapped<CHARMAP>(raw, len,
                                              stack_buf, sizeof(stack_buf));

        std::string result;
        const VALUE* val = find_next_impl(this->get_root(), mapped, len,
                                          0, result);
        delete[] heap_buf;
        return {std::move(result), val};
    }

    const VALUE* find_next_impl(const uint64_t* node,
                                const uint8_t* mapped, uint32_t key_len,
                                uint32_t consumed,
                                std::string& out) const {
        if (node == sentinel_ptr()) return nullptr;
        hdr_type h = hdr_type::from_node(node);

        uint32_t sb = h.skip_bytes();
        if (sb > 0) {
            append_unmapped(out, hdr_type::get_skip(node), sb);
            consumed += sb;
        }

        if (h.is_compact()) {
            const uint8_t* keys = compact_type::keys_ptr(node, h);
            auto [found, pos] = compact_type::search(
                keys, h.count, mapped + consumed, key_len - consumed);
            int next = pos + 1;
            if (next >= h.count) return nullptr;

            const uint8_t* kp = keys;
            for (int i = 0; i < next; ++i) kp = key_next(kp);
            uint16_t klen = read_u16(kp);
            append_unmapped(out, kp + 2, klen);
            return slots_type::load_value(h.get_compact_slots(node), next);
        }

        if (consumed == key_len) {
            if (h.count == 0) return nullptr;
            const auto* bm = bitmask_type::get_bitmap(node, h);
            int idx = bm->find_next_set(0);
            out.push_back(static_cast<char>(CHARMAP::from_index(
                static_cast<uint8_t>(idx))));
            return find_min_impl(bitmask_type::child_by_slot(node, h, 0), out);
        }

        {
            uint8_t byte = mapped[consumed++];
            uint64_t* child = bitmask_type::find_child(node, h, byte);

            size_t prefix_len = out.size();
            out.push_back(static_cast<char>(CHARMAP::from_index(byte)));

            const VALUE* val = find_next_impl(child, mapped, key_len,
                                              consumed, out);
            if (val) return val;
            out.resize(prefix_len);

            const auto* bm = bitmask_type::get_bitmap(node, h);
            int next_idx = bm->find_next_set(byte + 1);
            if (next_idx < 0) return nullptr;

            out.push_back(static_cast<char>(CHARMAP::from_index(
                static_cast<uint8_t>(next_idx))));
            int slot = bm->find_slot(next_idx);
            return find_min_impl(
                bitmask_type::child_by_slot(node, h, slot), out);
        }
    }

    // ------------------------------------------------------------------
    // iter_prev -- predecessor
    // ------------------------------------------------------------------

    std::pair<std::string, const VALUE*>
    iter_prev(const std::string& current) const {
        const uint8_t* raw = reinterpret_cast<const uint8_t*>(current.data());
        uint32_t len = static_cast<uint32_t>(current.size());

        uint8_t stack_buf[256];
        auto [mapped, heap_buf] = get_mapped<CHARMAP>(raw, len,
                                              stack_buf, sizeof(stack_buf));

        std::string result;
        const VALUE* val = find_prev_impl(this->get_root(), mapped, len,
                                          0, result);
        delete[] heap_buf;
        return {std::move(result), val};
    }

    const VALUE* find_prev_impl(const uint64_t* node,
                                const uint8_t* mapped, uint32_t key_len,
                                uint32_t consumed,
                                std::string& out) const {
        if (node == sentinel_ptr()) return nullptr;
        hdr_type h = hdr_type::from_node(node);

        uint32_t sb = h.skip_bytes();
        if (sb > 0) {
            append_unmapped(out, hdr_type::get_skip(node), sb);
            consumed += sb;
        }

        if (h.is_compact()) {
            const uint8_t* keys = compact_type::keys_ptr(node, h);
            auto [found, pos] = compact_type::search(
                keys, h.count, mapped + consumed, key_len - consumed);
            int prev = pos - 1;
            if (prev < 0) return nullptr;

            const uint8_t* kp = keys;
            for (int i = 0; i < prev; ++i) kp = key_next(kp);
            uint16_t klen = read_u16(kp);
            append_unmapped(out, kp + 2, klen);
            return slots_type::load_value(h.get_compact_slots(node), prev);
        }

        if (consumed == key_len)
            return nullptr;

        {
            uint8_t byte = mapped[consumed++];
            uint64_t* child = bitmask_type::find_child(node, h, byte);

            if (child != sentinel_ptr()) {
                size_t prefix_len = out.size();
                out.push_back(static_cast<char>(CHARMAP::from_index(byte)));

                const VALUE* val = find_prev_impl(child, mapped, key_len,
                                                  consumed, out);
                if (val) return val;
                out.resize(prefix_len);
            }

            const auto* bm = bitmask_type::get_bitmap(node, h);
            int prev_idx = bm->find_prev_set(byte - 1);
            if (prev_idx >= 0) {
                out.push_back(static_cast<char>(CHARMAP::from_index(
                    static_cast<uint8_t>(prev_idx))));
                int slot = bm->find_slot(prev_idx);
                return find_max_impl(
                    bitmask_type::child_by_slot(node, h, slot), out);
            }

            if (h.has_eos())
                return bitmask_type::eos_value(node, h);

            return nullptr;
        }
    }

    // ------------------------------------------------------------------
    // iter_lower_bound -- first key >= target
    // ------------------------------------------------------------------

    std::pair<std::string, const VALUE*>
    iter_lower_bound(std::string_view key) const {
        const uint8_t* raw = reinterpret_cast<const uint8_t*>(key.data());
        uint32_t len = static_cast<uint32_t>(key.size());

        uint8_t stack_buf[256];
        auto [mapped, heap_buf] = get_mapped<CHARMAP>(raw, len,
                                              stack_buf, sizeof(stack_buf));

        std::string result;
        const VALUE* val = find_ge_impl(this->get_root(), mapped, len,
                                        0, result);
        delete[] heap_buf;
        return {std::move(result), val};
    }

    const VALUE* find_ge_impl(const uint64_t* node,
                              const uint8_t* mapped, uint32_t key_len,
                              uint32_t consumed,
                              std::string& out) const {
        if (node == sentinel_ptr()) return nullptr;
        hdr_type h = hdr_type::from_node(node);

        uint32_t sb = h.skip_bytes();
        if (sb > 0) {
            const uint8_t* skip = hdr_type::get_skip(node);
            uint32_t remaining = key_len - consumed;
            uint32_t cmp_len = std::min(sb, remaining);

            for (uint32_t i = 0; i < cmp_len; ++i) {
                if (skip[i] < mapped[consumed + i])
                    return nullptr;
                if (skip[i] > mapped[consumed + i]) {
                    append_unmapped(out, skip, sb);
                    consumed += sb;
                    goto take_min;
                }
                out.push_back(static_cast<char>(CHARMAP::from_index(skip[i])));
            }

            if (remaining < sb) {
                for (uint32_t j = cmp_len; j < sb; ++j)
                    out.push_back(static_cast<char>(CHARMAP::from_index(skip[j])));
                consumed += sb;
                goto take_min;
            }

            consumed += sb;
        }

        if (h.is_compact()) {
            const uint8_t* keys = compact_type::keys_ptr(node, h);
            auto [found, pos] = compact_type::search(
                keys, h.count, mapped + consumed, key_len - consumed);
            if (pos >= h.count) return nullptr;
            const uint8_t* kp = keys;
            for (int i = 0; i < pos; ++i) kp = key_next(kp);
            uint16_t klen = read_u16(kp);
            append_unmapped(out, kp + 2, klen);
            return slots_type::load_value(h.get_compact_slots(node), pos);
        }

        if (consumed == key_len)
            goto take_min;

        {
            uint8_t byte = mapped[consumed++];
            uint64_t* child = bitmask_type::find_child(node, h, byte);

            if (child != sentinel_ptr()) {
                size_t prefix_len = out.size();
                out.push_back(static_cast<char>(CHARMAP::from_index(byte)));

                const VALUE* val = find_ge_impl(child, mapped, key_len,
                                                consumed, out);
                if (val) return val;
                out.resize(prefix_len);
            }

            const auto* bm = bitmask_type::get_bitmap(node, h);
            int next_idx = bm->find_next_set(byte + 1);
            if (next_idx < 0) return nullptr;

            out.push_back(static_cast<char>(CHARMAP::from_index(
                static_cast<uint8_t>(next_idx))));
            int slot = bm->find_slot(next_idx);
            return find_min_impl(
                bitmask_type::child_by_slot(node, h, slot), out);
        }

    take_min:
        if (h.is_compact()) {
            if (h.count == 0) return nullptr;
            const uint8_t* keys = compact_type::keys_ptr(node, h);
            uint16_t klen = read_u16(keys);
            append_unmapped(out, keys + 2, klen);
            return slots_type::load_value(h.get_compact_slots(node), 0);
        }
        if (h.has_eos())
            return bitmask_type::eos_value(node, h);
        if (h.count == 0) return nullptr;
        {
            const auto* bm = bitmask_type::get_bitmap(node, h);
            int idx = bm->find_next_set(0);
            out.push_back(static_cast<char>(CHARMAP::from_index(
                static_cast<uint8_t>(idx))));
            return find_min_impl(bitmask_type::child_by_slot(node, h, 0), out);
        }
    }

    // ------------------------------------------------------------------
    // iter_upper_bound -- first key > target
    // ------------------------------------------------------------------

    std::pair<std::string, const VALUE*>
    iter_upper_bound(std::string_view key) const {
        auto [k, v] = iter_lower_bound(key);
        if (!v) return {{}, nullptr};
        if (k == key)
            return iter_next(k);
        return {std::move(k), v};
    }

    // ------------------------------------------------------------------
    // iter_prefix_bounds
    // ------------------------------------------------------------------

    struct prefix_result {
        std::string  k1;
        const VALUE* v1;
        std::string  k2;
        const VALUE* v2;
    };

    prefix_result iter_prefix_bounds(std::string_view pfx) const {
        const uint8_t* raw = reinterpret_cast<const uint8_t*>(pfx.data());
        uint32_t len = static_cast<uint32_t>(pfx.size());

        uint8_t stack_buf[256];
        auto [mapped, heap_buf] = get_mapped<CHARMAP>(raw, len,
                                              stack_buf, sizeof(stack_buf));

        struct right_turn {
            const uint64_t* bm_node;
            hdr_type        h;
            int             next_idx;
            std::string     prefix;
        };

        std::string path;
        right_turn best_rt{};
        bool have_rt = false;

        const uint64_t* node = this->get_root();
        uint32_t consumed = 0;

        while (consumed < len) {
            if (node == sentinel_ptr()) goto not_found;
            hdr_type h = hdr_type::from_node(node);

            {
                uint32_t sb = h.skip_bytes();
                if (sb > 0) {
                    const uint8_t* skip = hdr_type::get_skip(node);
                    uint32_t remaining = len - consumed;
                    uint32_t cmp_len = std::min(sb, remaining);

                    for (uint32_t i = 0; i < cmp_len; ++i) {
                        if (skip[i] != mapped[consumed + i])
                            goto not_found;
                        path.push_back(static_cast<char>(
                            CHARMAP::from_index(skip[i])));
                    }

                    if (remaining <= sb) {
                        for (uint32_t j = cmp_len; j < sb; ++j)
                            path.push_back(static_cast<char>(
                                CHARMAP::from_index(skip[j])));
                        consumed += sb;
                        goto subtree_found;
                    }

                    consumed += sb;
                }
            }

            if (h.is_compact())
                goto subtree_found;

            {
                uint8_t byte = mapped[consumed++];
                const auto* bm = bitmask_type::get_bitmap(node, h);

                int next_sib = bm->find_next_set(byte + 1);
                if (next_sib >= 0) {
                    best_rt.bm_node  = node;
                    best_rt.h        = h;
                    best_rt.next_idx = next_sib;
                    best_rt.prefix   = path;
                    have_rt = true;
                }

                uint64_t* child = bitmask_type::find_child(node, h, byte);
                if (child == sentinel_ptr()) goto not_found;

                path.push_back(static_cast<char>(
                    CHARMAP::from_index(byte)));
                node = child;
            }
        }

    subtree_found:
        {
            hdr_type h = hdr_type::from_node(node);

            std::string k1 = path;
            const VALUE* v1;

            if (h.is_compact() && consumed < len) {
                v1 = find_prefix_first_in_compact(
                    node, h, mapped + consumed, len - consumed, k1);
            } else {
                v1 = find_min_impl_tail(node, h, k1);
            }

            if (!v1) {
                delete[] heap_buf;
                return {{}, nullptr, {}, nullptr};
            }

            std::string k2;
            const VALUE* v2 = nullptr;

            if (h.is_compact() && consumed < len) {
                v2 = find_prefix_past_in_compact(
                    node, h, mapped + consumed, len - consumed, path, k2);
            } else if (have_rt) {
                k2 = best_rt.prefix;
                k2.push_back(static_cast<char>(CHARMAP::from_index(
                    static_cast<uint8_t>(best_rt.next_idx))));
                int slot = bitmask_type::get_bitmap(
                    best_rt.bm_node, best_rt.h)->find_slot(best_rt.next_idx);
                v2 = find_min_impl(
                    bitmask_type::child_by_slot(
                        best_rt.bm_node, best_rt.h, slot), k2);
            }

            delete[] heap_buf;
            return {std::move(k1), v1, std::move(k2), v2};
        }

    not_found:
        delete[] heap_buf;
        return {{}, nullptr, {}, nullptr};
    }

    // ------------------------------------------------------------------
    // Compact prefix helpers
    // ------------------------------------------------------------------

    const VALUE* find_prefix_first_in_compact(
            const uint64_t* node, const hdr_type& h,
            const uint8_t* suffix, uint32_t suffix_len,
            std::string& out) const {
        const uint8_t* keys = compact_type::keys_ptr(node, h);
        const uint8_t* kp = keys;
        for (int i = 0; i < h.count; ++i) {
            uint16_t klen = read_u16(kp);
            if (klen >= suffix_len &&
                std::memcmp(kp + 2, suffix, suffix_len) == 0) {
                append_unmapped(out, kp + 2, klen);
                return slots_type::load_value(h.get_compact_slots(node), i);
            }
            if (klen >= suffix_len) {
                int cmp = std::memcmp(kp + 2, suffix, suffix_len);
                if (cmp > 0) return nullptr;
            }
            kp += 2 + klen;
        }
        return nullptr;
    }

    const VALUE* find_prefix_past_in_compact(
            const uint64_t* node, const hdr_type& h,
            const uint8_t* suffix, uint32_t suffix_len,
            const std::string& base_path,
            std::string& out) const {
        const uint8_t* keys = compact_type::keys_ptr(node, h);
        const uint8_t* kp = keys;
        bool in_prefix = false;
        for (int i = 0; i < h.count; ++i) {
            uint16_t klen = read_u16(kp);
            bool matches = (klen >= suffix_len &&
                            std::memcmp(kp + 2, suffix, suffix_len) == 0);
            if (matches) {
                in_prefix = true;
            } else if (in_prefix) {
                out = base_path;
                append_unmapped(out, kp + 2, klen);
                return slots_type::load_value(h.get_compact_slots(node), i);
            }
            kp += 2 + klen;
        }
        return nullptr;
    }

    const VALUE* find_min_impl_tail(const uint64_t* node, const hdr_type& h,
                                    std::string& out) const {
        if (h.is_compact()) {
            if (h.count == 0) return nullptr;
            const uint8_t* keys = compact_type::keys_ptr(node, h);
            uint16_t klen = read_u16(keys);
            append_unmapped(out, keys + 2, klen);
            return slots_type::load_value(h.get_compact_slots(node), 0);
        }
        if (h.has_eos())
            return bitmask_type::eos_value(node, h);
        if (h.count == 0) return nullptr;
        const auto* bm = bitmask_type::get_bitmap(node, h);
        int idx = bm->find_next_set(0);
        out.push_back(static_cast<char>(CHARMAP::from_index(
            static_cast<uint8_t>(idx))));
        return find_min_impl(bitmask_type::child_by_slot(node, h, 0), out);
    }
};

} // namespace gteitelbaum

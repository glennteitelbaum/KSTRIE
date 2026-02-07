#pragma once

#include "kstrie_bitmask.hpp"
#include "kstrie_compact.hpp"
#include "kstrie_support.hpp"
#include <iterator>
#include <limits>

namespace gteitelbaum {

// ============================================================================
// kstrie -- main trie class
// ============================================================================

template <typename VALUE,
          typename CHARMAP = identity_char_map,
          typename ALLOC   = std::allocator<uint64_t>>
class kstrie {
public:
    using key_type       = std::string;
    using mapped_type    = VALUE;
    using size_type      = std::size_t;
    using allocator_type = ALLOC;
    using char_map_type  = CHARMAP;

    using hdr_type     = node_header<VALUE, CHARMAP, ALLOC>;
    using mem_type     = kstrie_memory<ALLOC>;
    using slots_type   = kstrie_slots<VALUE>;
    using skip_type    = kstrie_skip<VALUE, CHARMAP, ALLOC>;
    using bitmask_type = kstrie_bitmask<VALUE, CHARMAP, ALLOC>;
    using compact_type = kstrie_compact<VALUE, CHARMAP, ALLOC>;

private:
    uint64_t* root_{};
    size_type size_{};
    mem_type  mem_{};

    static void map_bytes_into(const uint8_t* src, uint8_t* dst,
                               uint32_t len) noexcept {
        for (uint32_t i = 0; i < len; ++i)
            dst[i] = CHARMAP::to_index(src[i]);
    }

    static std::pair<const uint8_t*, uint8_t*>
    get_mapped(const uint8_t* raw, uint32_t len,
               uint8_t* stack_buf, size_t stack_size) noexcept {
        if constexpr (CHARMAP::IS_IDENTITY) {
            return {raw, nullptr};
        } else {
            uint8_t* hb = (len <= stack_size) ? nullptr : new uint8_t[len];
            uint8_t* buf = hb ? hb : stack_buf;
            map_bytes_into(raw, buf, len);
            return {buf, hb};
        }
    }

    void init_empty_root() {
        root_ = sentinel_ptr();
    }

    void destroy_tree(uint64_t* node) {
        if (!node) return;
        if (node == sentinel_ptr()) return;
        hdr_type h = hdr_type::from_node(node);

        uint64_t* slot_base = h.get_slots(node);

        if (h.is_compact()) {
            slots_type::destroy_values(slot_base, 0, h.count);
        } else {
            for (uint16_t i = 1; i <= h.count; ++i)
                destroy_tree(slots_type::load_child(slot_base, i));
            if (h.has_eos())
                slots_type::destroy_value(slot_base, h.count + 1);
        }

        mem_.free_node(node);
    }

    size_type memory_usage_impl(const uint64_t* node) const noexcept {
        if (!node) return 0;
        if (node == sentinel_ptr()) return 0;
        hdr_type h = hdr_type::from_node(node);

        size_type total = h.alloc_u64 * 8;

        if (!h.is_compact()) {
            const uint64_t* slot_base = h.get_slots(node);
            for (uint16_t i = 1; i <= h.count; ++i)
                total += memory_usage_impl(slots_type::load_child(slot_base, i));
        }

        return total;
    }

    // ------------------------------------------------------------------
    // find_inner -- hot loop for trie traversal
    //
    // Skip mismatch → return nullptr directly (no ambiguous post-loop).
    // is_compact() is the ONLY path to break.
    // After loop: unconditional compact find.
    // ------------------------------------------------------------------

    const VALUE* find_inner(const uint8_t* mapped, uint32_t key_len) const noexcept {
        const uint64_t* node = root_;
        uint32_t consumed = 0;

        hdr_type h;
        for (;;) {
            h = hdr_type::from_node(node);

            if (!skip_type::match_skip_fast(node, h, mapped, key_len, consumed))
                [[unlikely]] return nullptr;

            if (h.is_compact()) [[unlikely]]
                break;

            if (consumed == key_len) [[unlikely]]
                return bitmask_type::eos_value(node, h);

            node = bitmask_type::find_child(node, h, mapped[consumed++]);
        }

        return compact_type::find(node, h, mapped + consumed,
                                   key_len - consumed);
    }

    // ------------------------------------------------------------------
    // find_impl -- wrapper: mapping + heap ownership
    // ------------------------------------------------------------------

    const VALUE* find_impl(const uint8_t* key_data, uint32_t key_len) const noexcept {
        if constexpr (CHARMAP::IS_IDENTITY) {
            return find_inner(key_data, key_len);
        } else {
            uint8_t stack_buf[256];
            auto [mapped, heap_buf] = get_mapped(key_data, key_len,
                                                  stack_buf, sizeof(stack_buf));
            const VALUE* result = find_inner(mapped, key_len);
            delete[] heap_buf;
            return result;
        }
    }

    VALUE* find_impl(const uint8_t* key_data, uint32_t key_len) noexcept {
        return const_cast<VALUE*>(
            static_cast<const kstrie*>(this)->find_impl(key_data, key_len));
    }

public:
    kstrie() { init_empty_root(); }
    ~kstrie() { if (root_) destroy_tree(root_); }

    kstrie(kstrie&& o) noexcept
        : root_(o.root_), size_(o.size_), mem_(std::move(o.mem_)) {
        o.root_ = nullptr;
        o.size_ = 0;
    }

    kstrie& operator=(kstrie&& o) noexcept {
        if (this != &o) {
            if (root_) destroy_tree(root_);
            root_ = o.root_;
            size_ = o.size_;
            mem_  = std::move(o.mem_);
            o.root_ = nullptr;
            o.size_ = 0;
        }
        return *this;
    }

    [[nodiscard]] bool empty() const noexcept { return size_ == 0; }
    [[nodiscard]] size_type size() const noexcept { return size_; }
    [[nodiscard]] size_type memory_usage() const noexcept {
        return sizeof(*this) + memory_usage_impl(root_);
    }

    // ------------------------------------------------------------------
    // const_iterator -- bidirectional, stores VALUE copy
    //
    // Holds parent pointer + unmapped key string + VALUE copy.
    // All navigation done via parent trie methods using the key.
    // No internal trie pointers held.
    // ------------------------------------------------------------------

    class const_iterator {
        const kstrie* trie_ = nullptr;
        std::string   key_;
        VALUE         value_{};
        bool          at_end_ = true;

        const_iterator(const kstrie* t, std::string k, const VALUE& v)
            : trie_(t), key_(std::move(k)), value_(v), at_end_(false) {}

        // End iterator that knows its trie (for --end)
        static const_iterator make_end(const kstrie* t) {
            const_iterator it;
            it.trie_ = t;
            it.at_end_ = true;
            return it;
        }

        friend class kstrie;

    public:
        using iterator_category = std::bidirectional_iterator_tag;
        using value_type        = std::pair<const std::string, VALUE>;
        using difference_type   = std::ptrdiff_t;
        using pointer           = const value_type*;

        struct reference {
            const std::string& first;
            const VALUE&       second;
        };

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
                auto [k, v] = trie_->iter_max(trie_->root_);
                if (v) { key_ = std::move(k); value_ = *v; at_end_ = false; }
            } else {
                auto [k, v] = trie_->iter_prev(key_);
                if (v) { key_ = std::move(k); value_ = *v; }
                else   { at_end_ = true; }  // before-begin
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

    using iterator = const_iterator;
    using reverse_iterator = std::reverse_iterator<const_iterator>;
    using const_reverse_iterator = std::reverse_iterator<const_iterator>;

    const_iterator begin() const {
        auto [k, v] = iter_min(root_);
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

    // lower_bound: first key >= target
    const_iterator lower_bound(std::string_view key) const {
        auto [k, v] = iter_lower_bound(key);
        if (!v) return end();
        return {this, std::move(k), *v};
    }

    // upper_bound: first key > target
    const_iterator upper_bound(std::string_view key) const {
        auto [k, v] = iter_upper_bound(key);
        if (!v) return end();
        return {this, std::move(k), *v};
    }

    // equal_range: {lower_bound, upper_bound}
    std::pair<const_iterator, const_iterator>
    equal_range(std::string_view key) const {
        return {lower_bound(key), upper_bound(key)};
    }

    // prefix: all keys starting with given prefix
    std::pair<const_iterator, const_iterator>
    prefix(std::string_view pfx) const {
        auto [k1, v1, k2, v2] = iter_prefix_bounds(pfx);
        const_iterator first = v1 ? const_iterator{this, std::move(k1), *v1}
                                  : end();
        const_iterator last  = v2 ? const_iterator{this, std::move(k2), *v2}
                                  : end();
        return {first, last};
    }

    // count: 0 or 1
    size_type count(std::string_view key) const {
        return contains(key) ? 1 : 0;
    }

    // update: modify existing value, returns true if found
    bool update(std::string_view key, const VALUE& value) {
        VALUE* p = find(key);
        if (!p) return false;
        *p = value;
        return true;
    }

    // swap
    void swap(kstrie& o) noexcept {
        std::swap(root_, o.root_);
        std::swap(size_, o.size_);
        std::swap(mem_, o.mem_);
    }

    // max_size
    [[nodiscard]] size_type max_size() const noexcept {
        return std::numeric_limits<size_type>::max();
    }

    // get_allocator
    [[nodiscard]] allocator_type get_allocator() const noexcept {
        return mem_.alloc_;
    }

    // erase by iterator
    const_iterator erase(const_iterator pos) {
        if (pos == end()) return end();
        std::string next_key;
        const VALUE* next_val;
        std::tie(next_key, next_val) = iter_next(pos.key_);
        erase(pos.key_);
        if (!next_val) return end();
        return {this, std::move(next_key), *next_val};
    }

    // erase range
    const_iterator erase(const_iterator first, const_iterator last) {
        std::vector<std::string> keys;
        for (auto it = first; it != last; ++it)
            keys.push_back(it.key());
        for (auto& k : keys)
            erase(k);
        if (last == end()) return end();
        // Re-lookup last since tree may have changed
        auto [k, v] = iter_lower_bound(last.key_);
        if (!v) return end();
        return {this, std::move(k), *v};
    }

    // emplace
    template <typename... Args>
    std::pair<const_iterator, bool> emplace(std::string_view key, Args&&... args) {
        VALUE v(std::forward<Args>(args)...);
        bool inserted = insert(key, v);
        auto [k, vp] = iter_lower_bound(key);
        return {const_iterator{this, std::move(k), *vp}, inserted};
    }

    // try_emplace
    template <typename... Args>
    std::pair<const_iterator, bool> try_emplace(std::string_view key, Args&&... args) {
        const VALUE* existing = find(key);
        if (existing)
            return {const_iterator{this, std::string(key), *existing}, false};
        VALUE v(std::forward<Args>(args)...);
        insert(key, v);
        return {const_iterator{this, std::string(key), v}, true};
    }

    // find returning iterator
    const_iterator find_iter(std::string_view key) const {
        const VALUE* v = find(key);
        if (!v) return end();
        return {this, std::string(key), *v};
    }

    // operator==
    bool operator==(const kstrie& o) const {
        if (size_ != o.size_) return false;
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

    // ------------------------------------------------------------------
    // Deep copy
    // ------------------------------------------------------------------

    kstrie(const kstrie& o) : size_(o.size_) {
        if (o.root_ == sentinel_ptr()) {
            root_ = sentinel_ptr();
        } else {
            root_ = clone_tree(o.root_);
        }
    }

    kstrie& operator=(const kstrie& o) {
        if (this != &o) {
            kstrie tmp(o);
            swap(tmp);
        }
        return *this;
    }

private:

    // ------------------------------------------------------------------
    // clone_tree -- deep copy all nodes and values
    // ------------------------------------------------------------------

    uint64_t* clone_tree(const uint64_t* node) {
        if (node == sentinel_ptr()) return sentinel_ptr();
        hdr_type h = hdr_type::from_node(node);

        size_t nu = h.alloc_u64;
        uint64_t* copy = mem_.alloc_node(nu);
        std::memcpy(copy, node, nu * 8);
        // Restore alloc_u64 (may differ due to padded_size)
        hdr_type& ch = hdr_type::from_node(copy);
        // alloc_u64 is set by alloc_node, memcpy overwrote it
        // but since we alloc'd same nu, it's fine

        if (h.is_compact()) {
            // Deep-copy values
            uint64_t* sb = ch.get_compact_slots(copy);
            for (uint16_t i = 0; i < h.count; ++i) {
                const VALUE* vp = slots_type::load_value(
                    h.get_compact_slots(node), i);
                sb[i] = 0;
                slots_type::store_value(sb, i, *vp);
            }
        } else {
            // Recursively clone children
            uint64_t* sb = ch.get_bitmap_slots(copy);
            for (uint16_t i = 1; i <= h.count; ++i) {
                uint64_t* child = slots_type::load_child(
                    h.get_bitmap_slots(node), i);
                slots_type::store_child(sb, i, clone_tree(child));
            }
            // Clone eos value
            if (h.has_eos()) {
                const VALUE* vp = bitmask_type::eos_value(node, h);
                sb[h.count + 1] = 0;
                slots_type::store_value(sb, h.count + 1, *vp);
            }
        }

        return copy;
    }

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

        // Bitmask: last child's max
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
        auto [mapped, heap_buf] = get_mapped(raw, len, stack_buf, sizeof(stack_buf));

        std::string result;
        const VALUE* val = find_next_impl(root_, mapped, len, 0, result);
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

        // Bitmask
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
        auto [mapped, heap_buf] = get_mapped(raw, len, stack_buf, sizeof(stack_buf));

        std::string result;
        const VALUE* val = find_prev_impl(root_, mapped, len, 0, result);
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
            int prev = found ? pos - 1 : pos - 1;
            if (prev < 0) return nullptr;

            const uint8_t* kp = keys;
            for (int i = 0; i < prev; ++i) kp = key_next(kp);
            uint16_t klen = read_u16(kp);
            append_unmapped(out, kp + 2, klen);
            return slots_type::load_value(h.get_compact_slots(node), prev);
        }

        // Bitmask
        if (consumed == key_len) {
            // At eos position. Nothing before eos at this node.
            return nullptr;
        }

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

            // Try previous bitmap entry
            const auto* bm = bitmask_type::get_bitmap(node, h);
            int prev_idx = bm->find_prev_set(byte - 1);
            if (prev_idx >= 0) {
                out.push_back(static_cast<char>(CHARMAP::from_index(
                    static_cast<uint8_t>(prev_idx))));
                int slot = bm->find_slot(prev_idx);
                return find_max_impl(
                    bitmask_type::child_by_slot(node, h, slot), out);
            }

            // No previous child. EOS is predecessor if present.
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
        auto [mapped, heap_buf] = get_mapped(raw, len, stack_buf, sizeof(stack_buf));

        std::string result;
        const VALUE* val = find_ge_impl(root_, mapped, len, 0, result);
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

        // Bitmask
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
    // iter_prefix_bounds -- find [first, past-last) for prefix
    //
    // Walk trie consuming prefix. At each bitmask branch, track the
    // "next right turn" — first sibling after our path. The past-end
    // iterator is find_min from that right turn.
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
        auto [mapped, heap_buf] = get_mapped(raw, len, stack_buf, sizeof(stack_buf));

        struct right_turn {
            const uint64_t* bm_node;
            hdr_type        h;
            int             next_idx;
            std::string     prefix;
        };

        std::string path;
        right_turn best_rt{};
        bool have_rt = false;

        const uint64_t* node = root_;
        uint32_t consumed = 0;

        while (consumed < len) {
            if (node == sentinel_ptr()) goto not_found;
            hdr_type h = hdr_type::from_node(node);

            // Match skip
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
                        // Prefix exhausted within or at end of skip.
                        // Entire subtree matches.
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

            // Bitmask: consume one byte
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

            // Find first entry in subtree that matches prefix
            std::string k1 = path;
            const VALUE* v1;

            if (h.is_compact() && consumed < len) {
                // Still have prefix bytes to match within compact suffixes
                v1 = find_prefix_first_in_compact(
                    node, h, mapped + consumed, len - consumed, k1);
            } else {
                v1 = find_min_impl_tail(node, h, k1);
            }

            if (!v1) {
                delete[] heap_buf;
                return {{}, nullptr, {}, nullptr};
            }

            // Find past-end
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

    // --- Compact prefix helpers ---

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
            // If entry > suffix, no match possible (sorted order)
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
                // First entry after prefix range
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

public:

    const VALUE* find(std::string_view key) const {
        return find_impl(
            reinterpret_cast<const uint8_t*>(key.data()),
            static_cast<uint32_t>(key.size()));
    }

    VALUE* find(std::string_view key) {
        return const_cast<VALUE*>(
            static_cast<const kstrie*>(this)->find(key));
    }

    bool contains(std::string_view key) const {
        return find(key) != nullptr;
    }

    bool insert(std::string_view key, const VALUE& value) {
        const uint8_t* raw = reinterpret_cast<const uint8_t*>(key.data());
        uint32_t len = static_cast<uint32_t>(key.size());

        uint8_t stack_buf[256];
        auto [mapped, heap_buf] = get_mapped(raw, len, stack_buf, sizeof(stack_buf));

        if (root_ == sentinel_ptr()) {
            root_ = add_child(mapped, len, value);
            delete[] heap_buf;
            size_++;
            return true;
        }

        insert_result r = insert_node(root_, mapped, len, value, 0,
                                       insert_mode::INSERT);
        root_ = r.node;
        delete[] heap_buf;

        if (r.outcome == insert_outcome::INSERTED) {
            size_++;
            return true;
        }
        return false;
    }

    bool insert_or_assign(std::string_view key, const VALUE& value) {
        const uint8_t* raw = reinterpret_cast<const uint8_t*>(key.data());
        uint32_t len = static_cast<uint32_t>(key.size());

        uint8_t stack_buf[256];
        auto [mapped, heap_buf] = get_mapped(raw, len, stack_buf, sizeof(stack_buf));

        if (root_ == sentinel_ptr()) {
            root_ = add_child(mapped, len, value);
            delete[] heap_buf;
            size_++;
            return true;
        }

        insert_result r = insert_node(root_, mapped, len, value, 0,
                                       insert_mode::UPDATE);
        root_ = r.node;
        delete[] heap_buf;

        if (r.outcome == insert_outcome::INSERTED) {
            size_++;
            return true;
        }
        return false;
    }

    size_type erase(std::string_view key) {
        if (root_ == sentinel_ptr()) return 0;

        const uint8_t* raw = reinterpret_cast<const uint8_t*>(key.data());
        uint32_t len = static_cast<uint32_t>(key.size());

        uint8_t stack_buf[256];
        auto [mapped, heap_buf] = get_mapped(raw, len, stack_buf, sizeof(stack_buf));

        erase_info r = erase_node(root_, mapped, len, 0);
        delete[] heap_buf;

        if (r.status == erase_status::MISSING)
            return 0;

        if (r.status == erase_status::DONE) {
            root_ = r.leaf;
            size_--;
            return 1;
        }

        // PENDING reached root: collapse entire tree
        if (r.desc == 0) {
            // Tree becomes empty after erase
            do_leaf_erase(r.leaf, r.pos);
            destroy_tree(root_);
            root_ = sentinel_ptr();
        } else {
            root_ = collapse_node(root_, r.leaf, r.pos);
        }
        size_--;
        return 1;
    }

private:

    // ------------------------------------------------------------------
    // do_leaf_erase -- erase at the leaf (compact in-place or eos removal)
    // ------------------------------------------------------------------

    void do_leaf_erase(uint64_t* leaf, int pos) {
        if (pos >= 0) {
            hdr_type& lh = hdr_type::from_node(leaf);
            compact_type::erase_in_place(leaf, lh, pos);
        } else {
            hdr_type& lh = hdr_type::from_node(leaf);
            bitmask_type::remove_eos_value(leaf, lh);
        }
    }

    // ------------------------------------------------------------------
    // count_descendants -- count all values in subtree, bail at MAX+1
    // ------------------------------------------------------------------

    uint32_t count_descendants(const uint64_t* node) const {
        if (node == sentinel_ptr()) return 0;
        hdr_type h = hdr_type::from_node(node);

        if (h.is_compact()) return h.count;

        uint32_t total = h.has_eos() ? 1 : 0;
        for (uint16_t ci = 0; ci < h.count; ++ci) {
            total += count_descendants(bitmask_type::child_by_slot(node, h, ci));
            if (total > COMPACT_MAX) return total;
        }
        return total;
    }

    // ------------------------------------------------------------------
    // collect_subtree -- recursive gather of all entries
    //
    // Builds keys relative to post-skip content of the collapse root.
    // The collapse root's skip becomes the new compact's skip.
    //
    // collect_inner: called on child nodes (prepends skip to prefix).
    // collect_post_skip: called at a node after skip is handled.
    // ------------------------------------------------------------------

    using build_entry = typename compact_type::build_entry;

    void collect_inner(const uint64_t* node,
                       uint8_t* prefix, uint32_t prefix_len,
                       build_entry* out, uint8_t* key_buf,
                       size_t& buf_off, uint32_t& ei,
                       const uint64_t* skip_leaf, int skip_pos) const {
        if (node == sentinel_ptr()) return;
        hdr_type h = hdr_type::from_node(node);

        uint32_t sb = h.skip_bytes();
        if (sb > 0) {
            std::memcpy(prefix + prefix_len,
                        hdr_type::get_skip(node), sb);
            prefix_len += sb;
        }

        collect_post_skip(node, h, prefix, prefix_len,
                          out, key_buf, buf_off, ei,
                          skip_leaf, skip_pos);
    }

    void collect_post_skip(const uint64_t* node, const hdr_type& h,
                           uint8_t* prefix, uint32_t prefix_len,
                           build_entry* out, uint8_t* key_buf,
                           size_t& buf_off, uint32_t& ei,
                           const uint64_t* skip_leaf, int skip_pos) const {
        if (h.is_compact()) {
            const uint8_t* keys = compact_type::keys_ptr(node, h);
            const uint64_t* sb = h.get_compact_slots(node);
            const uint8_t* kp = keys;
            for (uint16_t i = 0; i < h.count; ++i) {
                uint16_t klen = read_u16(kp);
                if (node != skip_leaf ||
                    static_cast<int>(i) != skip_pos) {
                    uint8_t* dst = key_buf + buf_off;
                    if (prefix_len > 0)
                        std::memcpy(dst, prefix, prefix_len);
                    std::memcpy(dst + prefix_len, kp + 2, klen);
                    out[ei].key      = dst;
                    out[ei].key_len  = prefix_len + klen;
                    out[ei].raw_slot = sb[i];
                    buf_off += prefix_len + klen;
                    ei++;
                }
                kp += 2 + klen;
            }
        } else {
            // Bitmask: collect eos + children
            if (h.has_eos()) {
                bool skip = (node == skip_leaf && skip_pos == -1);
                if (!skip) {
                    uint8_t* dst = key_buf + buf_off;
                    if (prefix_len > 0)
                        std::memcpy(dst, prefix, prefix_len);
                    out[ei].key      = dst;
                    out[ei].key_len  = prefix_len;
                    const uint64_t* bsb = h.get_bitmap_slots(node);
                    out[ei].raw_slot = bsb[h.count + 1];
                    buf_off += prefix_len;
                    ei++;
                }
            }

            const auto* bm = bitmask_type::get_bitmap(node, h);
            int idx = bm->find_next_set(0);
            for (uint16_t ci = 0; ci < h.count; ++ci) {
                uint64_t* child = bitmask_type::child_by_slot(node, h, ci);
                prefix[prefix_len] = static_cast<uint8_t>(idx);
                collect_inner(child, prefix, prefix_len + 1,
                              out, key_buf, buf_off, ei,
                              skip_leaf, skip_pos);
                idx = bm->find_next_set(idx + 1);
            }
        }
    }

    // ------------------------------------------------------------------
    // free_subtree_nodes -- free all node allocations in subtree
    //
    // Does NOT destroy values (they've been moved via raw_slot).
    // Caller must destroy the skipped entry's value separately.
    // ------------------------------------------------------------------

    void free_subtree_nodes(uint64_t* node) {
        if (node == sentinel_ptr()) return;
        hdr_type h = hdr_type::from_node(node);

        if (!h.is_compact()) {
            for (uint16_t ci = 0; ci < h.count; ++ci)
                free_subtree_nodes(bitmask_type::child_by_slot(node, h, ci));
        }

        mem_.free_node(node);
    }

    // ------------------------------------------------------------------
    // collapse_node -- gather all entries (minus erased), build compact
    //
    // Destroys the erased value. Frees old subtree. Returns new compact
    // (or sentinel if empty). New compact inherits the node's skip.
    // ------------------------------------------------------------------

    uint64_t* collapse_node(uint64_t* node, uint64_t* skip_leaf, int skip_pos) {
        hdr_type h = hdr_type::from_node(node);

        // Destroy the erased value
        if (skip_pos >= 0) {
            hdr_type& lh = hdr_type::from_node(skip_leaf);
            uint64_t* lsb = lh.get_compact_slots(skip_leaf);
            slots_type::destroy_value(lsb, skip_pos);
        } else {
            hdr_type& lh = hdr_type::from_node(skip_leaf);
            uint64_t* lsb = lh.get_bitmap_slots(skip_leaf);
            slots_type::destroy_value(lsb, lh.count + 1);
        }

        // Collect all entries except the erased one
        build_entry stack_entries[COMPACT_MAX + 1];
        uint8_t stack_keys[4096];
        size_t buf_off = 0;
        uint32_t ei = 0;
        uint8_t prefix[256];

        collect_post_skip(node, h, prefix, 0,
                          stack_entries, stack_keys, buf_off, ei,
                          skip_leaf, skip_pos);

        uint64_t* result;
        if (ei == 0) {
            result = sentinel_ptr();
        } else {
            // Entries from collect are already sorted (tree order)
            result = compact_type::build_compact(
                mem_, h.skip, hdr_type::get_skip(node),
                stack_entries, static_cast<uint16_t>(ei));
        }

        // Free old subtree nodes
        free_subtree_nodes(node);

        return result;
    }

    // ------------------------------------------------------------------
    // erase_node -- recursive dispatch
    //
    // Returns {desc, PENDING, leaf, pos} up the stack.
    // Each bitmask level counts total descendants.
    //   total > COLLAPSE && total <= COMPACT_MAX → collapse this subtree
    //   total > COMPACT_MAX → can't collapse, erase at leaf
    //   total <= COLLAPSE → keep PENDING, let parent decide
    // ------------------------------------------------------------------

    erase_info erase_node(uint64_t* node, const uint8_t* key,
                          uint32_t key_len, uint32_t consumed) {
        hdr_type h = hdr_type::from_node(node);

        auto mr = skip_type::match_prefix(node, h, key, key_len, consumed);
        if (mr.status != skip_type::match_status::MATCHED)
            return {0, erase_status::MISSING, nullptr, 0};
        consumed = mr.consumed;

        // --- Compact leaf ---
        if (h.is_compact()) {
            const uint8_t* keys = compact_type::keys_ptr(node, h);
            auto [found, pos] = compact_type::search(
                keys, h.count, key + consumed, key_len - consumed);
            if (!found)
                return {0, erase_status::MISSING, nullptr, 0};
            return {static_cast<uint32_t>(h.count - 1),
                    erase_status::PENDING, node, pos};
        }

        // --- Bitmask: EOS ---
        if (consumed == key_len) {
            if (!h.has_eos())
                return {0, erase_status::MISSING, nullptr, 0};

            // Count children's descendants
            uint32_t total = 0;
            for (uint16_t ci = 0; ci < h.count; ++ci) {
                total += count_descendants(
                    bitmask_type::child_by_slot(node, h, ci));
                if (total > COMPACT_MAX) break;
            }

            if (total > COMPACT_COLLAPSE) {
                bitmask_type::remove_eos_value(node, h);
                return {0, erase_status::DONE, node, 0};
            }
            return {total, erase_status::PENDING, node, -1};
        }

        // --- Bitmask: dispatch byte ---
        uint8_t byte = key[consumed++];
        uint64_t* child = bitmask_type::find_child(node, h, byte);
        if (child == sentinel_ptr())
            return {0, erase_status::MISSING, nullptr, 0};

        erase_info r = erase_node(child, key, key_len, consumed);

        if (r.status == erase_status::MISSING)
            return r;

        if (r.status == erase_status::DONE) {
            // Child handled it. Update our pointer if it changed.
            if (r.leaf != child)
                bitmask_type::replace_child(node, h, byte, r.leaf);
            return {0, erase_status::DONE, node, 0};
        }

        // PENDING from child. Count total at this level.
        uint32_t total = r.desc;
        if (h.has_eos()) total++;

        for (uint16_t ci = 0; ci < h.count && total <= COMPACT_MAX; ++ci) {
            uint64_t* c = bitmask_type::child_by_slot(node, h, ci);
            if (c != child)
                total += count_descendants(c);
        }

        if (total > COMPACT_COLLAPSE) {
            if (total <= COMPACT_MAX) {
                // Collapse this subtree into one compact
                uint64_t* compact = collapse_node(node, r.leaf, r.pos);
                return {0, erase_status::DONE, compact, 0};
            } else {
                // Can't collapse at this level. Erase at leaf.
                do_leaf_erase(r.leaf, r.pos);
                return {0, erase_status::DONE, node, 0};
            }
        }

        // total <= COLLAPSE, keep bubbling
        return {total, erase_status::PENDING, r.leaf, r.pos};
    }

public:

    void clear() noexcept {
        if (root_) destroy_tree(root_);
        init_empty_root();
        size_ = 0;
    }

    // ------------------------------------------------------------------
    // insert_node -- recursive dispatch (write-path, uses match_prefix)
    // ------------------------------------------------------------------

    insert_result insert_node(uint64_t* node, const uint8_t* key_data,
                               uint32_t key_len, const VALUE& value,
                               uint32_t consumed, insert_mode mode) {
        hdr_type h = hdr_type::from_node(node);

        auto mr = skip_type::match_prefix(node, h, key_data, key_len, consumed);

        if (h.is_compact())
            return compact_type::insert(node, h, key_data, key_len,
                                         value, consumed, mr, mode, mem_);

        // Bitmask: handle skip mismatch / key exhausted during skip
        if (mr.status == skip_type::match_status::MISMATCH) {
            const uint8_t* skip_data = hdr_type::get_skip(node);
            uint32_t old_skip = h.skip_bytes();
            uint32_t match_len = mr.match_len;

            uint8_t skip_copy[256];
            std::memcpy(skip_copy, skip_data, old_skip);

            uint8_t old_byte = skip_copy[match_len];
            uint8_t new_byte = key_data[consumed + match_len];

            uint32_t new_old_skip = old_skip - match_len - 1;
            uint64_t* old_reskipped = bitmask_type::reskip(
                node, h, mem_, static_cast<uint8_t>(new_old_skip),
                skip_copy + match_len + 1);

            uint32_t new_consumed = consumed + match_len + 1;
            uint64_t* leaf = add_child(key_data + new_consumed,
                                       key_len - new_consumed, value);

            uint8_t bucket_idx[2];
            uint64_t* children[2];
            if (old_byte < new_byte) {
                bucket_idx[0] = old_byte;  bucket_idx[1] = new_byte;
                children[0] = old_reskipped; children[1] = leaf;
            } else {
                bucket_idx[0] = new_byte;  bucket_idx[1] = old_byte;
                children[0] = leaf;        children[1] = old_reskipped;
            }
            uint64_t* parent = bitmask_type::create_with_children(
                mem_, static_cast<uint8_t>(match_len), skip_copy,
                bucket_idx, children, 2);

            return {parent, insert_outcome::INSERTED};
        }

        if (mr.status == skip_type::match_status::KEY_EXHAUSTED) {
            const uint8_t* skip_data = hdr_type::get_skip(node);
            uint32_t old_skip = h.skip_bytes();
            uint32_t match_len = mr.match_len;

            uint8_t skip_copy[256];
            std::memcpy(skip_copy, skip_data, old_skip);

            uint8_t old_byte = skip_copy[match_len];

            uint32_t new_old_skip = old_skip - match_len - 1;
            uint64_t* old_reskipped = bitmask_type::reskip(
                node, h, mem_, static_cast<uint8_t>(new_old_skip),
                skip_copy + match_len + 1);

            uint8_t bucket_idx[1] = {old_byte};
            uint64_t* children[1] = {old_reskipped};
            uint64_t* parent = bitmask_type::create_with_children(
                mem_, static_cast<uint8_t>(match_len), skip_copy,
                bucket_idx, children, 1);

            hdr_type& ph = hdr_type::from_node(parent);
            parent = bitmask_type::set_eos_value(parent, ph, mem_, value);

            return {parent, insert_outcome::INSERTED};
        }

        consumed = mr.consumed;

        if (consumed == key_len) {
            if (!h.has_eos()) {
                uint64_t* nn = bitmask_type::set_eos_value(node, h, mem_, value);
                return {nn, insert_outcome::INSERTED};
            }
            if (mode == insert_mode::INSERT)
                return {node, insert_outcome::FOUND};
            bitmask_type::update_eos_value(node, h, value);
            return {node, insert_outcome::UPDATED};
        }

        {
            uint8_t byte = key_data[consumed++];
            uint64_t* child = bitmask_type::find_child(node, h, byte);

            if (child == sentinel_ptr()) {
                uint64_t* leaf = add_child(key_data + consumed,
                                           key_len - consumed, value);
                uint64_t* nn = bitmask_type::insert_child(node, h, mem_,
                                                           byte, leaf);
                return {nn, insert_outcome::INSERTED};
            }

            insert_result r = insert_node(child, key_data, key_len, value,
                                           consumed, mode);
            if (r.node != child)
                bitmask_type::replace_child(node, h, byte, r.node);
            return {node, r.outcome};
        }
    }

    uint64_t* add_child(const uint8_t* suffix, uint32_t suffix_len,
                        const VALUE& value) {
        uint64_t raw = 0;
        slots_type::store_value(&raw, 0, value);

        typename compact_type::build_entry entry;
        entry.key      = suffix;
        entry.key_len  = 0;
        entry.raw_slot = raw;

        return compact_type::build_compact(mem_,
            static_cast<uint8_t>(suffix_len), suffix,
            &entry, 1);
    }

    struct child_entry {
        const uint8_t* suffix;
        uint32_t       suffix_len;
        const VALUE*   value;
    };

    uint64_t* add_children(const child_entry* entries, size_t count) {
        if (count == 0)
            return mem_.alloc_node(1);

        using be = typename compact_type::build_entry;
        be* arr = new be[count];
        for (size_t i = 0; i < count; ++i) {
            uint64_t raw = 0;
            slots_type::store_value(&raw, 0, *entries[i].value);
            arr[i].key      = entries[i].suffix;
            arr[i].key_len  = entries[i].suffix_len;
            arr[i].raw_slot = raw;
        }
        uint64_t* node = compact_type::build_compact(
            mem_, 0, nullptr, arr, static_cast<uint16_t>(count));
        delete[] arr;
        return node;
    }

    mem_type& memory() noexcept { return mem_; }
};

} // namespace gteitelbaum

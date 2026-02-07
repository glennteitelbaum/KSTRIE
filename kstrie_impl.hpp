#pragma once

#include "kstrie_bitmask.hpp"
#include "kstrie_compact.hpp"
#include "kstrie_support.hpp"
#include <limits>
#include <string>
#include <string_view>

namespace gteitelbaum {

// ============================================================================
// kstrie_impl -- engine trie class
// ============================================================================

template <typename VALUE,
          typename CHARMAP = identity_char_map,
          typename ALLOC   = std::allocator<uint64_t>>
class kstrie_impl {
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
            auto [mapped, heap_buf] = get_mapped<CHARMAP>(key_data, key_len,
                                                  stack_buf, sizeof(stack_buf));
            const VALUE* result = find_inner(mapped, key_len);
            delete[] heap_buf;
            return result;
        }
    }

    VALUE* find_impl(const uint8_t* key_data, uint32_t key_len) noexcept {
        return const_cast<VALUE*>(
            static_cast<const kstrie_impl*>(this)->find_impl(key_data, key_len));
    }

public:
    // ------------------------------------------------------------------
    // Construction / destruction
    // ------------------------------------------------------------------

    kstrie_impl() { init_empty_root(); }
    ~kstrie_impl() { if (root_) destroy_tree(root_); }

    kstrie_impl(kstrie_impl&& o) noexcept
        : root_(o.root_), size_(o.size_), mem_(std::move(o.mem_)) {
        o.root_ = nullptr;
        o.size_ = 0;
    }

    kstrie_impl& operator=(kstrie_impl&& o) noexcept {
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

    // ------------------------------------------------------------------
    // Deep copy
    // ------------------------------------------------------------------

    kstrie_impl(const kstrie_impl& o) : size_(o.size_) {
        if (o.root_ == sentinel_ptr()) {
            root_ = sentinel_ptr();
        } else {
            root_ = clone_tree(o.root_);
        }
    }

    kstrie_impl& operator=(const kstrie_impl& o) {
        if (this != &o) {
            kstrie_impl tmp(o);
            swap(tmp);
        }
        return *this;
    }

private:
    uint64_t* clone_tree(const uint64_t* node) {
        if (node == sentinel_ptr()) return sentinel_ptr();
        hdr_type h = hdr_type::from_node(node);

        size_t nu = h.alloc_u64;
        uint64_t* copy = mem_.alloc_node(nu);
        std::memcpy(copy, node, nu * 8);

        if (h.is_compact()) {
            uint64_t* sb = hdr_type::from_node(copy).get_compact_slots(copy);
            for (uint16_t i = 0; i < h.count; ++i) {
                const VALUE* vp = slots_type::load_value(
                    h.get_compact_slots(node), i);
                sb[i] = 0;
                slots_type::store_value(sb, i, *vp);
            }
        } else {
            hdr_type& ch = hdr_type::from_node(copy);
            uint64_t* sb = ch.get_bitmap_slots(copy);
            for (uint16_t i = 1; i <= h.count; ++i) {
                uint64_t* child = slots_type::load_child(
                    h.get_bitmap_slots(node), i);
                slots_type::store_child(sb, i, clone_tree(child));
            }
            if (h.has_eos()) {
                const VALUE* vp = bitmask_type::eos_value(node, h);
                sb[h.count + 1] = 0;
                slots_type::store_value(sb, h.count + 1, *vp);
            }
        }

        return copy;
    }

public:
    // ------------------------------------------------------------------
    // Capacity
    // ------------------------------------------------------------------

    [[nodiscard]] bool empty() const noexcept { return size_ == 0; }
    [[nodiscard]] size_type size() const noexcept { return size_; }
    [[nodiscard]] size_type memory_usage() const noexcept {
        return sizeof(*this) + memory_usage_impl(root_);
    }

    // ------------------------------------------------------------------
    // Root access (for kstrie iterator layer)
    // ------------------------------------------------------------------

    [[nodiscard]] const uint64_t* get_root() const noexcept { return root_; }

    // ------------------------------------------------------------------
    // Lookup
    // ------------------------------------------------------------------

    const VALUE* find(std::string_view key) const {
        return find_impl(
            reinterpret_cast<const uint8_t*>(key.data()),
            static_cast<uint32_t>(key.size()));
    }

    VALUE* find(std::string_view key) {
        return const_cast<VALUE*>(
            static_cast<const kstrie_impl*>(this)->find(key));
    }

    bool contains(std::string_view key) const {
        return find(key) != nullptr;
    }

    // ------------------------------------------------------------------
    // Modifiers
    // ------------------------------------------------------------------

    bool insert(std::string_view key, const VALUE& value) {
        return modify_impl(key, value, insert_mode::INSERT);
    }

    bool insert_or_assign(std::string_view key, const VALUE& value) {
        return modify_impl(key, value, insert_mode::UPSERT);
    }

    bool assign(std::string_view key, const VALUE& value) {
        return modify_impl(key, value, insert_mode::ASSIGN);
    }

    size_type erase(std::string_view key) {
        if (root_ == sentinel_ptr()) return 0;

        const uint8_t* raw = reinterpret_cast<const uint8_t*>(key.data());
        uint32_t len = static_cast<uint32_t>(key.size());

        uint8_t stack_buf[256];
        auto [mapped, heap_buf] = get_mapped<CHARMAP>(raw, len,
                                              stack_buf, sizeof(stack_buf));

        erase_info r = erase_node(root_, mapped, len, 0);
        delete[] heap_buf;

        if (r.status == erase_status::MISSING)
            return 0;

        if (r.status == erase_status::DONE) {
            root_ = r.leaf;
            size_--;
            return 1;
        }

        if (r.desc == 0) {
            do_leaf_erase(r.leaf, r.pos);
            destroy_tree(root_);
            root_ = sentinel_ptr();
        } else {
            root_ = collapse_node(root_, r.leaf, r.pos);
        }
        size_--;
        return 1;
    }

    void clear() noexcept {
        if (root_) destroy_tree(root_);
        init_empty_root();
        size_ = 0;
    }

    // ------------------------------------------------------------------
    // Utilities
    // ------------------------------------------------------------------

    size_type count(std::string_view key) const {
        return contains(key) ? 1 : 0;
    }

    void swap(kstrie_impl& o) noexcept {
        std::swap(root_, o.root_);
        std::swap(size_, o.size_);
        std::swap(mem_, o.mem_);
    }

    [[nodiscard]] size_type max_size() const noexcept {
        return std::numeric_limits<size_type>::max();
    }

    [[nodiscard]] allocator_type get_allocator() const noexcept {
        return mem_.alloc_;
    }

    mem_type& memory() noexcept { return mem_; }

private:

    // ------------------------------------------------------------------
    // Erase internals
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

    void free_subtree_nodes(uint64_t* node) {
        if (node == sentinel_ptr()) return;
        hdr_type h = hdr_type::from_node(node);

        if (!h.is_compact()) {
            for (uint16_t ci = 0; ci < h.count; ++ci)
                free_subtree_nodes(bitmask_type::child_by_slot(node, h, ci));
        }

        mem_.free_node(node);
    }

    uint64_t* collapse_node(uint64_t* node, uint64_t* skip_leaf, int skip_pos) {
        hdr_type h = hdr_type::from_node(node);

        if (skip_pos >= 0) {
            hdr_type& lh = hdr_type::from_node(skip_leaf);
            uint64_t* lsb = lh.get_compact_slots(skip_leaf);
            slots_type::destroy_value(lsb, skip_pos);
        } else {
            hdr_type& lh = hdr_type::from_node(skip_leaf);
            uint64_t* lsb = lh.get_bitmap_slots(skip_leaf);
            slots_type::destroy_value(lsb, lh.count + 1);
        }

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
            result = compact_type::build_compact(
                mem_, h.skip, hdr_type::get_skip(node),
                stack_entries, static_cast<uint16_t>(ei));
        }

        free_subtree_nodes(node);
        return result;
    }

    erase_info erase_node(uint64_t* node, const uint8_t* key,
                          uint32_t key_len, uint32_t consumed) {
        hdr_type h = hdr_type::from_node(node);

        auto mr = skip_type::match_prefix(node, h, key, key_len, consumed);
        if (mr.status != skip_type::match_status::MATCHED)
            return {0, erase_status::MISSING, nullptr, 0};
        consumed = mr.consumed;

        if (h.is_compact()) {
            const uint8_t* keys = compact_type::keys_ptr(node, h);
            auto [found, pos] = compact_type::search(
                keys, h.count, key + consumed, key_len - consumed);
            if (!found)
                return {0, erase_status::MISSING, nullptr, 0};
            return {static_cast<uint32_t>(h.count - 1),
                    erase_status::PENDING, node, pos};
        }

        if (consumed == key_len) {
            if (!h.has_eos())
                return {0, erase_status::MISSING, nullptr, 0};

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

        uint8_t byte = key[consumed++];
        uint64_t* child = bitmask_type::find_child(node, h, byte);
        if (child == sentinel_ptr())
            return {0, erase_status::MISSING, nullptr, 0};

        erase_info r = erase_node(child, key, key_len, consumed);

        if (r.status == erase_status::MISSING)
            return r;

        if (r.status == erase_status::DONE) {
            if (r.leaf != child)
                bitmask_type::replace_child(node, h, byte, r.leaf);
            return {0, erase_status::DONE, node, 0};
        }

        uint32_t total = r.desc;
        if (h.has_eos()) total++;

        for (uint16_t ci = 0; ci < h.count && total <= COMPACT_MAX; ++ci) {
            uint64_t* c = bitmask_type::child_by_slot(node, h, ci);
            if (c != child)
                total += count_descendants(c);
        }

        if (total > COMPACT_COLLAPSE) {
            if (total <= COMPACT_MAX) {
                uint64_t* compact = collapse_node(node, r.leaf, r.pos);
                return {0, erase_status::DONE, compact, 0};
            } else {
                do_leaf_erase(r.leaf, r.pos);
                return {0, erase_status::DONE, node, 0};
            }
        }

        return {total, erase_status::PENDING, r.leaf, r.pos};
    }

    // ------------------------------------------------------------------
    // Insert internals
    // ------------------------------------------------------------------

    bool modify_impl(std::string_view key, const VALUE& value,
                     insert_mode mode) {
        const uint8_t* raw = reinterpret_cast<const uint8_t*>(key.data());
        uint32_t len = static_cast<uint32_t>(key.size());

        uint8_t stack_buf[256];
        auto [mapped, heap_buf] = get_mapped<CHARMAP>(raw, len,
                                              stack_buf, sizeof(stack_buf));

        if (root_ == sentinel_ptr()) {
            if (mode == insert_mode::ASSIGN) {
                delete[] heap_buf;
                return false;
            }
            root_ = add_child(mapped, len, value);
            delete[] heap_buf;
            size_++;
            return true;
        }

        insert_result r = insert_node(root_, mapped, len, value, 0, mode);
        root_ = r.node;
        delete[] heap_buf;

        if (r.outcome == insert_outcome::INSERTED) {
            size_++;
            return true;
        }
        if (r.outcome == insert_outcome::UPDATED)
            return true;
        return false;
    }

    insert_result insert_node(uint64_t* node, const uint8_t* key_data,
                               uint32_t key_len, const VALUE& value,
                               uint32_t consumed, insert_mode mode) {
        hdr_type h = hdr_type::from_node(node);

        auto mr = skip_type::match_prefix(node, h, key_data, key_len, consumed);

        if (h.is_compact())
            return compact_type::insert(node, h, key_data, key_len,
                                         value, consumed, mr, mode, mem_);

        if (mr.status == skip_type::match_status::MISMATCH) {
            if (mode == insert_mode::ASSIGN)
                return {node, insert_outcome::FOUND};

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
            if (mode == insert_mode::ASSIGN)
                return {node, insert_outcome::FOUND};

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
                if (mode == insert_mode::ASSIGN)
                    return {node, insert_outcome::FOUND};
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
                if (mode == insert_mode::ASSIGN)
                    return {node, insert_outcome::FOUND};
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
};

} // namespace gteitelbaum

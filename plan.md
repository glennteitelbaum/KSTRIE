# kstrie v2 → v3 Refactoring Plan

## Overview

Split the monolithic `kstrie_v2.hpp` (~2000 lines, single header) into focused modules with clear ownership. Each module owns its node type's layout, invariants, and operations. No friends, no CRTP — modules call each other's public interfaces as peers.

---

## File Structure

```
kstrie_support.hpp      — declarations + shared infrastructure
kstrie_memory.hpp       — allocation/deallocation
kstrie_skip_eos.hpp     — skip prefix + EOS operations
kstrie_bitmask.hpp      — bitmap dispatch node operations
kstrie_compact.hpp      — compact sorted-array node operations
kstrie.hpp              — kstrie class: owns dispatch, routes by node type
```

Each `X.hpp` has a corresponding `X.cpp` with `#include "X.hpp"`, a `main()`, and test functions for that module. Can start as header-include-only stubs.

### Include Rules

- All includes at the **top** of the file only. Never in the middle or bottom of a class.
- Alphabetic order: stdlib headers first, then project headers.
- Each file includes only what it directly needs.

### Include Dependencies (non-stdlib)

| File | Includes |
|------|----------|
| `kstrie_support.hpp` | *(none — stdlib only)* |
| `kstrie_memory.hpp` | `kstrie_support.hpp` |
| `kstrie_skip_eos.hpp` | `kstrie_support.hpp` |
| `kstrie_bitmask.hpp` | `kstrie_support.hpp` |
| `kstrie_compact.hpp` | `kstrie_support.hpp` |
| `kstrie.hpp` | `kstrie_bitmask.hpp`, `kstrie_compact.hpp`, `kstrie_memory.hpp`, `kstrie_skip_eos.hpp`, `kstrie_support.hpp` |

No circular includes. All declarations live in `kstrie_support.hpp`, so every module sees every peer's interface.

---

## Naming Conventions

| Category | Style | Examples |
|----------|-------|---------|
| Classes, structs | `lowercase_with_underscores` | `bitmap_n`, `node_header`, `value_traits`, `kstrie`, `kstrie_memory` |
| Variables, methods | `lowercase_with_underscores` | `find_slot`, `alloc_node`, `root_`, `size_` |
| Enum types (enum class) | `lowercase_with_underscores` | `insert_mode`, `insert_outcome`, `compact_insert_check` |
| Enum values | `ALL_CAPS` | `INSERT`, `UPDATE`, `INSERTED`, `FOUND`, `OK_INPLACE`, `TOO_MANY_KEYS` |
| Template parameters | `ALL_CAPS` | `VALUE`, `CHARMAP`, `ALLOC`, `WORDS`, `USER_MAP` |
| Constants / constexpr | `ALL_CAPS` | `BITMAP_U64`, `COMPACT_MAX`, `EMPTY_NODE_STORAGE`, `SKIP_CONTINUATION` |
| Short domain types | `lowercase` | `e` (16-byte key type), `es` (entry builder struct) |

### Renames from v2

- `BitmapN` → `bitmap_n`
- `Bitmap256` → `bitmap_256`
- `NodeHeader` → `node_header`
- `ValueTraits` → `value_traits`
- `IdentityCharMap` → `identity_char_map`
- `UpperCharMap` → `upper_char_map`
- `ReverseLowerCharMap` → `reverse_lower_char_map`
- `SearchResult` → `search_result`
- `BucketEntry` → `bucket_entry`
- `InsertResult` → `insert_result`
- `InsertMode` → `insert_mode`
- `InsertOutcome` → `insert_outcome`
- `CompactInsertCheck` → `compact_insert_check`
- `ValueTraits` → `kstrie_values` (redesigned, not just renamed)
- `ES` → `es`
- `E` → `e`

No CamelCase anywhere. Enum/template params are ALL_CAPS. Everything else is snake_case.

---

## Compiler / Build Settings

- **C++23** (`-std=c++23`) — required for `std::byteswap`
- **`-O2 -march=x86-64-v4`**
- Never revert code. Stop and ask questions instead.
- Do not optimize without checking first.
- Goal priorities: **read speed** and **memory compression** first. Write correctness and readability over minor write perf (alloc/dealloc and algo complexity dominate).

---

## Module Details

### kstrie_support.hpp

**Purpose:** Single source of truth for all type definitions, shared infrastructure, and class declarations. Every other file includes this.

**Contains:**

- `padded_size()` — allocation size classes
- `bitmap_n<WORDS>` template — 1/2/4 word bitmap with `has_bit`, `set_bit`, `clear_bit`, `find_slot`, `count_below`, `slot_for_insert`, `popcount`, `find_next_set`
- `bitmap_256` alias
- Character maps: `IDENTITY_MAP`, `UPPER_MAP`, `REVERSE_LOWER_MAP`
- `char_map<USER_MAP>` template — compile-time character mapping with `to_index`/`from_index`, deduces `BITMAP_WORDS`
- `identity_char_map`, `upper_char_map`, `reverse_lower_char_map` aliases
- `value_traits<VALUE>` — inline vs heap value storage (legacy, replaced by `kstrie_values`)
- `kstrie_values<VALUE>` — value storage with packing. See dedicated section below.
- `node_header` struct (8 bytes) — `alloc_u64`, `count`, `keys_bytes`, `skip`, `flags`; accessors for `is_compact`, `is_bitmap`, `has_eos`, `is_continuation`, `is_sentinel`, `skip_bytes`; `copy_from`
- `EMPTY_NODE_STORAGE` global sentinel
- `e` type (16-byte comparable key), `es` builder struct, `cvt()`, `make_search_key()`, `e_prefix_only()`, `e_offset()`
- Layout helpers: `align8`, `idx_count`, `hot_off`, `idx_off`, `keys_off`, `values_off`
- Comparison helpers: `makecmp`, `read_u16`, `write_u16`, `key_cmp`, `key_next`
- Eytzinger helpers: `calc_W`, `build_eyt_rec`, `build_eyt`
- **Forward declarations / class declarations** for:
  - `kstrie_memory<ALLOC>`
  - `kstrie_skip_eos<VALUE, CHARMAP, ALLOC>`
  - `kstrie_bitmask<VALUE, CHARMAP, ALLOC>`
  - `kstrie_compact<VALUE, CHARMAP, ALLOC>`

**Does NOT contain:** `kstrie` class itself (that's in `kstrie.hpp`).

---

### kstrie_values (in kstrie_support.hpp)

**Purpose:** Owns all value storage logic — whether values are inline, heap-allocated, or packed multiple-per-uint64_t. Replaces `value_traits`. Every module that reads/writes values goes through this class.

**Template:** `kstrie_values<VALUE>`

**Packing strategy:**

Values are stored in arrays backed by `uint64_t` slots. The number of values per slot depends on `sizeof(VALUE)`:

| sizeof(VALUE) | Values per uint64_t | Example types |
|---------------|---------------------|---------------|
| 1 | 8 | `char`, `uint8_t`, `bool` |
| 2 | 4 | `uint16_t`, `short` |
| 4 | 2 | `uint32_t`, `int`, `float` |
| 8 | 1 | `uint64_t`, `double`, `void*` |
| >8, trivially copyable | spans multiple uint64_t, inline | small structs |
| >8, not trivially copyable | 1 (pointer) | `std::string`, complex objects |

**Constants:**
- `PACK_COUNT` — how many values fit in one uint64_t (0 if heap-allocated)
- `SLOT_SIZE` — number of uint64_t per value (1 for packed/single, 1 for pointer)
- `IS_PACKED` — true if `PACK_COUNT > 1`
- `IS_INLINE` — true if stored by value (not heap pointer)

**Interface:**
- `store(slot, index, value)` — write value at logical index within a uint64_t array
- `load(slot, index) → VALUE&` — read value at logical index
- `load(slot, index) → const VALUE&` — const read
- `destroy(slot, index)` — cleanup (no-op for trivial, delete for heap)
- `slots_needed(count) → size_t` — how many uint64_t needed for N values
- `move_range(dst, dst_idx, src, src_idx, count)` — bulk move values
- `copy_range(dst, dst_idx, src, src_idx, count)` — bulk copy values

**How packing works in compact nodes:**

Currently the values array is `VST values[count]` where each VST is 8 bytes. With packing, for `int` (4 bytes), two values share one uint64_t:

```
Before (unpacked):  [val0][____][val1][____][val2][____][val3][____]  (4 uint64_t for 4 ints)
After (packed):     [val0|val1][val2|val3]                            (2 uint64_t for 4 ints)
```

For `char` (1 byte), eight values share one uint64_t:

```
[v0|v1|v2|v3|v4|v5|v6|v7]  (1 uint64_t for 8 chars)
```

**Impact on layout:**
- `values_off()` stays the same (byte offset to values region)
- The values region size changes: `kstrie_values::slots_needed(count) * 8` bytes instead of `count * sizeof(VST)`
- Compact and bitmask call `kstrie_values` methods instead of direct memcpy/assignment on value slots
- EOS value storage is always 1 slot (single value, no packing benefit)

**Why this belongs in kstrie_support.hpp:**
It's a type-level concern, not a node-type concern. Every module that touches values needs it. Putting it in support means the declaration (and likely the full definition, since it's all constexpr/inline) is available everywhere.

---

### kstrie_memory.hpp

**Purpose:** Owns all node allocation and deallocation.

**Template:** `kstrie_memory<ALLOC>`

**Contains:**
- `alloc_node(needed_u64) → uint64_t*` — allocates with padded size, zeroes, sets `alloc_u64` in header
- `free_node(uint64_t*)` — deallocates using size in header, skips sentinels
- `destroy_tree(uint64_t*)` — recursive teardown (walks bitmap children, destroys values)
- `memory_usage_impl(const uint64_t*) → size_type` — recursive memory accounting
- Holds the `ALLOC` instance

**Every other helper class takes a `kstrie_memory<ALLOC>&`** as its way to allocate/free nodes. This is the only shared mutable dependency.

**Uses `node_header` struct to read alloc_u64 and node type for traversal during destroy/memory accounting.**

---

### kstrie_skip_eos.hpp

**Purpose:** All operations related to skip prefixes and EOS values.

**Template:** `kstrie_skip_eos<VALUE, CHARMAP, ALLOC>`

**Contains:**
- `match_prefix(node, mapped_key, consumed) → {consumed_after, match_result}` — walk skip chain including continuations
- `find_LCP(prefix, prefix_len, new_key, new_key_len) → uint32_t` — compare new key against existing skip prefix, return match length. **This is always 2-way** (new key vs current skip), NOT N-way across all entries. This was discussed explicitly.
- `create_leaf(key, key_len, value, memory) → uint64_t*` — creates skip+EOS node with `count=0`. Full suffix goes into skip prefix. Called by bitmask when adding a new child for a single entry. Signature: `skip::create_leaf(key, value, memory)`.
- `create_eos_only_node(value, memory) → uint64_t*` — skip=0, EOS only
- `create_eos_only_node_from_slot(slot, memory) → uint64_t*` — move existing slot
- `add_eos_to_node(node, header, value, memory) → {new_node, outcome}` — reallocate node with EOS slot added. Works for both compact and bitmap nodes (it just shifts data, doesn't interpret it).
- `clone_node_with_new_skip(node, header, new_prefix, new_skip, memory) → uint64_t*` — clone with different prefix length. Works for both compact and bitmap (copies data blob opaquely).
- `get_mapped()` / `map_bytes_into()` — character map application

**Key design decisions:**
- Skip/eos is the **only** module that reads/writes the skip prefix bytes and EOS slot from/to the node array. Others go through skip's interface.
- `add_eos_to_node` and `clone_node_with_new_skip` handle both compact and bitmap nodes — they treat the data region as an opaque blob (just copy bytes after the header+prefix+eos region).

---

### kstrie_bitmask.hpp

**Purpose:** All operations for bitmap dispatch nodes (the "fanout" nodes that dispatch on one byte).

**Template:** `kstrie_bitmask<VALUE, CHARMAP, ALLOC>`

**Contains:**
- `find(node, header, byte) → child_ptr` — bitmap lookup
- `create(skip_data, skip_len, eos, dispatch_bytes, children, memory) → uint64_t*` — build a bitmap node from pre-built children. Takes:
  - `skip_data`, `skip_len` — prefix bytes (passed to skip to write)
  - `eos` — optional EOS value
  - `vector<uint8_t> dispatch_bytes` — which bytes are present
  - `vector<uint64_t*> children` — pre-built child node pointers (parallel with dispatch_bytes)
  - `memory` reference
- `insert_child(node, header, byte, child, memory) → uint64_t*` — add new child for a byte not yet in bitmap. Reallocates node with one more child slot.
- `next(node, header, byte) → {next_byte, child}` — **stub** for iteration
- `prev(node, header, byte) → {prev_byte, child}` — **stub** for iteration
- `erase(node, header, byte, memory) → uint64_t*` — **stub** for deletion

**Key design decisions:**
- Bitmask **does not know what children are.** It receives opaque `uint64_t*` pointers. Children could be compact nodes, other bitmap nodes, anything.
- When bitmask needs to create a new child (e.g., during `insert_child` when called from kstrie), the child pointer is passed in pre-built. Bitmask doesn't create children itself.
- However, `bitmask::create` receives pre-built children — the caller (compact's split, or kstrie) is responsible for building them.
- Could be replaced with a map or any other dispatch structure. Compact doesn't care what bitmask looks like internally.

---

### kstrie_compact.hpp

**Purpose:** All operations for compact sorted-array nodes (the leaf/near-leaf nodes holding up to 4096 entries with 14-byte key suffixes).

**Template:** `kstrie_compact<VALUE, CHARMAP, ALLOC>`

**Contains:**
- `find(node, header, suffix, suffix_len) → value_ptr` — binary/Eytzinger search + linear scan (returns pointer via kstrie_values)
- `search_position(node, header, suffix, suffix_len) → search_result{found, pos, block_offset}` — find insert point
- `insert(node, header, suffix, value, memory) → insert_result` — insert into compact node. If key exists, returns FOUND/UPDATED. If node overflows or suffix > 14 bytes, performs split.
- `update_value(node, header, pos, value)` — overwrite value at position
- `insert_at(node, header, suffix, value, pos, memory) → uint64_t*` — low-level positional insert. Returns nullptr if split needed.
- `force_insert(node, header, suffix, value, pos, memory) → uint64_t*` — insert without limit checks (used before split)
- `split_to_bitmask(node, header, memory) → uint64_t*` — **THE KEY SPLIT FUNCTION.** See detailed description below.
- `create_from_entries(entries, eos, memory) → uint64_t*` — build compact node from sorted entry list. Computes LCP internally, sets up skip prefix. May recurse through bitmask if entries don't fit.
- `check_compact_insert(...)` — O(1) feasibility check for insert
- `check_compress(node)` — **DEBUG ONLY** invariant validation. Owned entirely by compact.
- `needs_split(node) → bool` — check if any key > 14 bytes
- `next(node, header, pos) → {key, value}` — **stub** for iteration
- `prev(node, header, pos) → {key, value}` — **stub** for iteration
- `erase(node, header, suffix, memory) → uint64_t*` — **stub** for deletion

**Critical: compact_split_to_bitmask flow (discussed extensively):**

1. Compact reads its own entries (it owns compact layout).
2. For each entry: `dispatch_byte = suffix[0]`, `remaining = suffix[1:]`.
3. Groups entries by dispatch_byte.
4. For each group, compact creates a grandchild:
   - Single entry with remaining = 0 → `skip::create_eos_only(value, memory)`
   - Single entry with remaining > 0 → `skip::create_leaf(remaining, value, memory)`
   - Multiple entries, all suffixes ≤ 14 bytes → `compact::create_from_entries(group, memory)`
   - Multiple entries, any suffix > 14 bytes → recursive: compact calls `bitmask::create(...)` for that group, which consumes another byte and may call back into compact
5. Compact passes to bitmask: `dispatch_bytes[]`, `children[]` (pre-built grandchild pointers), plus the existing skip/eos from the original node.
6. The existing skip and EOS from the original node are **not stripped or recalculated.** They belong to the node being split and transfer directly to the new bitmap parent. Compact doesn't touch them — skip_eos handles reading/writing them.

**Key design decisions:**
- Compact **only assumes** that the peer consuming the dispatch bytes will eat exactly one byte per level. That's the trie contract.
- Compact creates its own grandchildren because it knows how to build compact nodes. It doesn't ask bitmask to do it.
- Bitmask and compact are **peers.** They call each other's public interfaces. Compact calls bitmask::create when it needs a bitmap parent. Bitmask calls compact::create (via kstrie dispatch or directly) when it needs children. The mutual recursion terminates because each level consumes at least one byte.
- **No CRTP, no friends.** If compact needs bitmask, it calls bitmask's public method. Both declarations are in kstrie_support.hpp, so both see each other.
- `check_compress` is 100% owned by compact. Nobody else validates compact invariants.
- Could replace compact with a vector. Bitmask wouldn't care.

---

### kstrie.hpp

**Purpose:** The `kstrie` class itself. Owns the root pointer, size, and dispatch logic.

**Template:** `kstrie<VALUE, CHARMAP, ALLOC>`

**Contains:**
- `kstrie` class with:
  - `root_`, `size_`, memory instance
  - Instances of (or access to) skip_eos, bitmask, compact helpers
  - Public API: `find`, `insert`, `insert_or_assign`, `erase`, `clear`, `contains`, `empty`, `size`, `memory_usage`
- `insert_impl(node, key, consumed, mode) → insert_result` — **the router:**
  - Calls `skip::match_prefix()` to consume skip
  - If key exhausted → skip::add_eos or update eos
  - If `is_compact()` → `compact::insert(...)`
  - If `is_bitmap()` → `bitmask::find(byte)`, recurse into child, or `bitmask::insert_child` with a new child
- `find_impl(key) → VALUE*` — traversal:
  - skip::match_prefix for skip chains
  - compact::find for compact nodes
  - bitmask::find for bitmap dispatch
- `split_prefix()` dispatch — when prefix mismatch occurs:
  - `skip::find_LCP` to get match length
  - If node is compact → `compact::split_on_prefix(...)` (stays compact if possible)
  - If node is bitmap → create new bitmap parent with skip::clone + bitmask::create

**Key design decisions:**
- kstrie is the **only** place that checks node type and dispatches. Helpers don't check "am I compact or bitmap" — they know what they are.
- kstrie owns the root pointer and size tracking (increment on INSERTED).
- kstrie composes the helpers — it doesn't inherit from them.

---

## Peer Interaction Summary

```
kstrie (router)
  │
  ├── calls skip_eos:: for prefix matching, LCP, leaf creation, EOS
  ├── calls bitmask:: for bitmap find/insert_child
  ├── calls compact:: for compact find/insert
  │
  compact ←→ bitmask (peers, mutual recursion during splits)
  │
  both call skip_eos:: for leaf creation, prefix handling
  both use kstrie_memory:: for allocation
```

**The abstraction rule:** Each module only knows its own node layout. When it needs to create or interact with a peer's node type, it calls the peer's public interface. No peeking at internal layouts. If bitmask's implementation changes to a std::map, compact's code doesn't change. If compact's implementation changes to a sorted vector, bitmask's code doesn't change.

---

## Design Decisions Log (Why We Made These Choices)

### Why kstrie_values replaces value_traits and VST?
The old `value_traits` had a `slot_type` (VST) that was either `VALUE` or `VALUE*` — always 8 bytes, one value per slot. This wastes space for small types: storing `char` values uses 8x the memory needed. `kstrie_values` packs multiple small values into each uint64_t, cutting memory for the values array by up to 8x for byte-sized types and 2x for int-sized types. The packing is transparent to compact/bitmask — they call `kstrie_values::store/load/destroy` with a logical index and the class handles the bit manipulation internally. The `VST` type alias is eliminated; all value access goes through `kstrie_values` methods.

### Why no CRTP or friends?
Discussed explicitly. With declarations in kstrie_support.hpp, every module sees every peer's interface. Modules call each other as peers via public methods. CRTP adds complexity for no gain. Friends break encapsulation.

### Why find_LCP is 2-way, not N-way?
It's only ever called with the new key vs the current skip prefix. The N-way case doesn't exist in practice — when splitting, we compare the new key against the existing prefix to find where they diverge. That gives us the split point.

### Why compact creates grandchildren, not bitmask?
Compact knows compact layout. When splitting, each bucket of entries becomes a compact (or leaf) grandchild. Compact builds them because it knows how. Bitmask receives opaque child pointers — it doesn't know or care what they are.

### Why skip/eos is preserved as-is during compact split?
The skip and EOS belong to the node level being split. They don't change just because the internal structure changes from compact to bitmap. They transfer directly to the new bitmap parent. Only the dispatch structure (compact → bitmap) changes.

### Why skip_eos owns prefix read/write exclusively?
Single ownership. If prefix layout changes, only skip_eos changes. Compact and bitmask never read/write prefix bytes directly.

### Why kstrie_memory is separate?
Allocation is orthogonal to node type. All helpers need it. Having one shared allocation service avoids duplication and keeps the allocator in one place.

### Why check_compress is in compact?
It validates compact-specific invariants (key sort order, idx correctness, hot array correctness, key length limits). No other module understands these invariants. 100% compact's responsibility.

### Why mutual recursion between compact and bitmask?
When a compact node has entries with suffixes > 14 bytes, it must split to bitmap. The bitmap's children are compact nodes. If those children also have long suffixes, they split again. This naturally recurses: compact → bitmask → compact → ... Each level consumes at least one byte, so it terminates. Both modules see each other's declarations in kstrie_support.hpp.

---

## Test Files

Each `X.cpp` includes `X.hpp` and has a `main()`:

| File | Tests |
|------|-------|
| `kstrie_support.cpp` | BitmapN ops, char_map, E/ES/cvt, layout math, Eytzinger build |
| `kstrie_memory.cpp` | alloc/free round-trip, sentinel handling |
| `kstrie_skip_eos.cpp` | LCP computation, prefix matching, leaf creation, clone with new skip |
| `kstrie_bitmask.cpp` | create from children, find, insert_child |
| `kstrie_compact.cpp` | create_from_entries, find, insert, search_position, split, check_compress |
| `kstrie.cpp` | Full integration: insert/find/contains with various key patterns (existing test_final.cpp tests) |

---

## Existing Test Suite (test_final.cpp)

Must continue to pass after refactoring:
1. Sequential prefix keys (10000 entries: "prefix_0" .. "prefix_9999")
2. Long shared prefix (100-byte prefix, 1000 entries)
3. Random strings (10000 entries, 5-50 chars)
4. URL-like keys (5000 entries)

---

## Existing Benchmark (bench_v2.cpp)

Benchmark against std::map. Key workloads:
- Random strings 8-32 chars
- URL-like keys
- Prefix-style keys (user_N, item_N, etc.)
- Short keys 4-8 chars
- Long keys 64-128 chars

Performance must not regress from the split. The indirection through helper classes should be zero-cost (templates, inlining).

---

## Naughty List Reminders (from naughty.md)

- Answer questions before coding. Don't jump to code when user wants information.
- Don't call expensive validation (check_compress) on every insert in production. Use `#ifdef KSTRIE_DEBUG`.
- Never hide bugs by disabling assertions. If an assertion fires, fix the bug.

---

## Migration Strategy

1. Create all new headers with correct structure and declarations
2. Move code function-by-function from kstrie_v2.hpp into appropriate modules
3. Keep test_final.cpp and bench_v2.cpp passing throughout
4. Add per-module test files
5. Delete kstrie_v2.hpp when complete

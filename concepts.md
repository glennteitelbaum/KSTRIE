# kstrie — Compressed Trie Concepts

## What is a Trie?

A trie (prefix tree) stores keys character-by-character, sharing common prefixes. Each node branches on the next character in the key. For the keys `cat`, `car`, `card`:

| Level | Branch | Notes |
|-------|--------|-------|
| root → `c` | one child | shared prefix |
| `c` → `a` | one child | shared prefix |
| `a` → `t`, `r` | two children | first split |
| `r` → ∅, `d` | value for `car`, plus child | `car` terminates here |
| `d` → ∅ | value for `card` | `card` terminates here |

The key insight: lookup cost is **O(M)** where M is key length, independent of how many entries exist. A `std::map` (red-black tree) is O(M·log N) because it does O(log N) string comparisons, each costing O(M).

A naive trie wastes space. Every character consumes a node, and internal nodes that branch on only one character add overhead without information. `http://example.com/page1` and `http://example.com/page2` share 24 characters — a naive trie creates 24 single-child nodes before the first useful branch.

## How kstrie Differs

kstrie uses two optimizations to eliminate waste:

**Skip compression.** Instead of one node per character, a sequence of single-child nodes collapses into a *skip prefix* stored in the parent. The 24 shared bytes of `http://example.com/page` become a single skip prefix, not 24 nodes.

**Compact leaf nodes.** Instead of branching one character at a time near the leaves, a compact node stores multiple key suffixes in a flat sorted array. A node holding `page1` and `page2` stores both suffixes directly rather than branching on `1` vs `2` through additional nodes.

### Standard Trie (7 nodes)

For keys `cat`=1, `car`=2, `card`=3:

| Node | Type | Skip | Content |
|------|------|------|---------|
| root | branch | — | children: `c` |
| c | branch | — | children: `a` |
| a | branch | — | children: `t`, `r` |
| t | leaf | — | value=1 |
| r | branch | — | value=2, children: `d` |
| d | leaf | — | value=3 |

### kstrie (2 nodes)

| Node | Type | Skip | Content |
|------|------|------|---------|
| root | compact | `ca` | suffixes: `r`→2, `rd`→3, `t`→1 |

One node. Skip prefix `ca` is checked once, then the sorted suffix array `[r, rd, t]` is scanned. If the dataset grows and this node exceeds compact limits, it splits into a bitmask parent + compact children.

For a larger example — URLs sharing `https://api.example.com/`:

| Node | Type | Skip | Content |
|------|------|------|---------|
| root | bitmask | `https://api.example.com/` | children: `u`, `v` |
| child-u | compact | `sers/` | suffixes: `alice`→1, `bob`→2 |
| child-v | compact | — | suffixes: `1/data`→3, `2/data`→4 |

The 25-byte common prefix is stored once. Each compact leaf holds related suffixes in a flat array.

## Skip Prefix

Every node (compact or bitmask) can have a skip prefix: a byte sequence that must match the search key before the node's contents are consulted.

**Match outcomes:**

| Result | Meaning | Action |
|--------|---------|--------|
| MATCHED | All skip bytes match key | Proceed to node contents |
| MISMATCH | Skip and key diverge at byte i | Insert: split here. Find: not found |
| KEY_EXHAUSTED | Key ends before skip does | Insert: split here. Find: not found |

**Rule: a skip can only decrease.** When a new key causes a mismatch at position i within a skip of length S, the skip shrinks to i. The remaining S−i−1 bytes are pushed into a new child. This is the only structural change to skips — they never grow.

**Maximum skip length:** 254 bytes. Byte 255 is reserved for continuation nodes (chained skips for keys longer than 254 bytes).

## Node Types

### Compact Node

A compact node stores a flat sorted list of key suffixes and their values. It is the leaf-level workhorse.

**Memory layout:**

| Region | Size | Contents |
|--------|------|----------|
| Header | 8 bytes | alloc_u64, count, keys_bytes, skip, flags |
| Skip | 0–254 bytes (8-aligned) | Skip prefix bytes |
| Index | variable (8-aligned) | Sorted key entries: `[len₀][key₀][len₁][key₁]...` |
| Slots | count × 8 bytes | One value per entry, positional |

Each key entry in the index region is: 2-byte length prefix + raw key bytes. Entries are sorted lexicographically. Slot i corresponds to key entry i.

**Header bit layout:**

| Field | Bytes | Bits | Range | Purpose |
|-------|-------|------|-------|---------|
| alloc_u64 | 0–1 | 16 | 0–65535 | Allocation size in 8-byte units |
| count | 2–3 | 16 | 0–65535 | Number of entries |
| keys_bytes | 4–5 | 16 | 0–65535 | Total bytes in key data |
| skip | 6 | 8 | 0–255 | Skip prefix length |
| flags | 7 | 8 | bit 0 | 0 = compact, 1 = bitmask |

**Limits:**

| Constraint | Value | Enforced by |
|------------|-------|-------------|
| Max entries | 32 | `COMPACT_MAX` |

When any limit is exceeded, the node splits into a bitmask parent with compact children (see Split below).

**Read (find):** Linear scan through sorted keys with early exit. Compare each key entry against the search suffix. O(K) where K is the entry count in this node (bounded by 32, typically much smaller).

**Insert:** Check if key exists (update or return FOUND depending on mode). If new, rebuild the entire node: collect existing entries, add the new one, sort, write fresh node. O(K) rebuild.

**Assign:** Same path as insert, but returns immediately (no allocation) if the key doesn't exist. When the key is found, overwrites the value in-place.

**Erase:** Locate the entry, destroy its value, rebuild without it. O(K).

**Iterate:** Keys are stored sorted, so forward iteration walks the key array left to right. Reverse walks right to left. The iterator descends from the root on each `++`/`--` call, so each step is O(M) where M is key length.

### Bitmask Node

A bitmask node is a fanout node that branches on a single byte. It uses a bitmap to track which byte values have children, and a branchless popcount lookup to find the child slot.

**Memory layout:**

| Region | Size | Contents |
|--------|------|----------|
| Header | 8 bytes | Same fields as compact |
| Skip | 0–254 bytes (8-aligned) | Skip prefix bytes |
| Bitmap | 8–32 bytes | Which byte values have children |
| Slots | (count+2) × 8 bytes | `[sentinel][child₀]...[child_{n-1}][eos_child]` |

**Bitmap sizing:** Depends on the character map's unique count.

| Unique values | Bitmap words (u64) | Bitmap bytes |
|---------------|-------------------|--------------|
| ≤64 | 1 | 8 |
| ≤128 | 2 | 16 |
| ≤256 (identity) | 4 | 32 |

**Slot layout:**

| Slot index | Contents | Purpose |
|------------|----------|---------|
| 0 | sentinel pointer | Branchless miss target |
| 1 to count | child node pointers | Ordered by bitmap position |
| count+1 | eos_child pointer | End-of-string value holder |

The sentinel at slot 0 is the key to branchless lookup. The bitmap probe returns 0 for absent bytes (which maps to the sentinel) or a 1-based index for present bytes. No branch needed — the sentinel is a globally shared empty node.

**Read (find):** Extract byte from key. Compute popcount-based slot index from bitmap. Load child pointer. If slot index is 0, the byte isn't present — the sentinel is followed, which always returns "not found." O(1) per level.

**Insert child:** Set the bitmap bit. Shift existing child pointers right to make room at the correct position. Store the new child pointer. May reallocate if the node outgrew its allocation. O(C) where C is child count at this node.

**Erase child:** Clear the bitmap bit. Shift child pointers left. O(C).

**Iterate:** Use `find_next_set` / `find_prev_set` on the bitmap to enumerate children in order. Descend into each child recursively.

## End of String (EOS)

A key can terminate at any point in the trie — including at a bitmask node's skip boundary, before any branching byte is consumed. For example, inserting both `cat` and `cats`: `cat` terminates where `cats` still has an `s` to consume.

**In compact nodes:** EOS is simply a zero-length key entry in the sorted array. It naturally sorts first (empty string < everything). No special handling needed.

**In bitmask nodes:** The eos_child occupies slot `[count+1]`, after all branching children. It points to either:

| Value | Meaning |
|-------|---------|
| sentinel pointer | No key terminates here |
| compact leaf node | A compact node with skip=0 holding the value as a zero-length key entry |

This keeps the design uniform — bitmask nodes never store values directly. All values live in compact nodes.

## Split (Compact → Bitmask + Children)

When a compact node exceeds its limits after an insert, it splits:

1. Collect all entries from the overfull compact node
2. If any entry has key_len=0 (EOS), set it aside for eos_child
3. Bucket remaining entries by their first key byte
4. For each bucket: create a compact child with suffixes stripped of the first byte
5. Create a bitmask parent with the original skip, bitmap set for each bucket byte
6. Attach eos_child if one exists
7. Free the old compact node
8. If any child still violates limits, recursively split it

Before split (compact with skip `ca`, 5 entries):

| Key suffix | Value |
|------------|-------|
| (empty) | 10 |
| `r` | 2 |
| `rd` | 3 |
| `rds` | 4 |
| `t` | 1 |

After split:

| Node | Type | Skip | Content |
|------|------|------|---------|
| parent | bitmask | `ca` | bitmap: {`r`, `t`}, eos_child → leaf |
| eos_child | compact | — | `(empty)`→10 |
| child-r | compact | — | `(empty)`→2, `d`→3, `ds`→4 |
| child-t | compact | — | `(empty)`→1 |

## Collapse (Erase)

When an erase leaves a bitmask node with too few children, the tree collapses to eliminate unnecessary branching. The goal: if a bitmask node has only one child (or only an eos_child), it can merge downward into a single compact or bitmask node with a longer skip.

1. Erase the key from its compact leaf
2. Walk back up, checking if any bitmask node is now degenerate (≤1 child + eos)
3. If degenerate: prepend the bitmask's skip + branch byte to the surviving child's skip
4. Free the bitmask node, promote the child

Before erase (removing `cat`=1):

| Node | Type | Skip | Content |
|------|------|------|---------|
| parent | bitmask | `ca` | bitmap: {`r`, `t`} |
| child-r | compact | — | `(empty)`→2 |
| child-t | compact | — | `(empty)`→1 |

After erase + collapse:

| Node | Type | Skip | Content |
|------|------|------|---------|
| root | compact | `car` | `(empty)`→2 |

The bitmask disappeared. The surviving child absorbed the prefix `ca` + `r`.

## Slots

Slots are the value/pointer storage region at the end of every node. The slot system handles two fundamentally different uses through one interface:

**Compact node slots** hold values. Each slot is 8 bytes.

| VALUE sizeof | Storage | Ownership |
|-------------|---------|-----------|
| ≤8 bytes, trivially copyable | Inline in slot | No heap allocation |
| >8 bytes or non-trivial | Heap pointer in slot | `new` on insert, `delete` on erase/destroy |

For inline values (int, float, char, pointers), the value is stored directly in the 8-byte slot via `memcpy`. No indirection, no allocation. For larger values (std::string, structs >8 bytes), a heap pointer is stored. The slot owns the pointed-to value.

**Bitmask node slots** hold child node pointers. Always 8 bytes (pointer width). No ownership semantics — the child node's lifetime is managed by the tree's destroy/erase logic.

**Slot operations:**

| Operation | Compact (value) | Bitmask (child pointer) |
|-----------|-----------------|------------------------|
| store | `memcpy` value or `new` + store pointer | Store raw pointer |
| load | Cast or dereference pointer | Cast to `uint64_t*` |
| destroy | No-op (inline) or `delete` (heap) | Not applicable |
| copy/move | `memcpy` 8 bytes | `memcpy` 8 bytes |

Bulk operations (`copy_slots`, `move_slots`) work on raw 8-byte units via `memcpy`/`memmove`, which is correct for both inline values and pointers.

## Character Maps (CHARMAP)

A character map remaps input bytes before they enter the trie. This enables case-insensitive lookup, reduced alphabet tries, and custom collation — all at the type level with zero runtime cost for the identity case.

**Built-in maps:**

| Map | Effect | Unique values | Bitmap size |
|-----|--------|---------------|-------------|
| `identity_char_map` | No remapping (1:1) | 256 | 32 bytes (4 words) |
| `upper_char_map` | Case-insensitive (a→A, preserves digits/punct) | ~40 | 8 bytes (1 word) |
| `reverse_lower_char_map` | Reverse alpha order (A→z, Z→a) | ~40 | 8 bytes (1 word) |

**How it works:** The `char_map` template takes a `std::array<uint8_t, 256>` mapping. At compile time it computes:

| Property | Purpose |
|----------|---------|
| `IS_IDENTITY` | If true, skip all remapping (zero overhead) |
| `UNIQUE_COUNT` | Number of distinct output values |
| `BITMAP_WORDS` | Bitmap size: 1, 2, or 4 u64 words |
| `CHAR_TO_INDEX` | Input byte → internal index |
| `INDEX_TO_CHAR` | Internal index → output byte (for unmapping during iteration) |

A reduced alphabet (e.g., 40 unique values for case-insensitive English) shrinks every bitmask node's bitmap from 32 bytes to 8 bytes and reduces fanout overhead proportionally.

**Identity map optimization:** When `IS_IDENTITY` is true, all remapping functions compile to no-ops. The `get_mapped()` helper returns the original pointer with no copy. Zero cost.

## Memory Allocation

Nodes are allocated as arrays of `uint64_t` (8-byte aligned). The allocator uses **padded size classes** to reduce fragmentation and enable in-place growth.

**Size class progression:**

| Needed (u64) | Allocated (u64) | Strategy |
|--------------|-----------------|----------|
| 1–4 | exact | Small nodes, no padding |
| 5 | 6 | Midpoint between 4 and 8 |
| 6 | 6 | Exact fit at midpoint |
| 7–8 | 8 | Power of 2 |
| 9 | 12 | Midpoint between 8 and 16 |
| 13–16 | 16 | Power of 2 |
| n | lower, mid, or upper | 1.5x geometric steps |

The pattern: for each power-of-two range [lower, upper], there's a midpoint at `lower + lower/2`. Three stop points per octave. This gives ~33% worst-case internal fragmentation (vs. 50% for pure power-of-2).

**alloc_u64 field:** Every node's header stores its allocation size in the first 2 bytes. This is read during `free_node` to return the correct amount to the allocator. A value of 0 means sentinel (never freed).

**The sentinel:** A single global `EMPTY_NODE_STORAGE` (40 bytes of zeros) serves as the "null node." Its `alloc_u64` is 0, `flags` is 0 (compact), `count` is 0. Any code that follows a missing child pointer reaches the sentinel, which returns "not found" naturally — no null checks needed anywhere in the hot path.

## Performance: kstrie vs std::map

**Algorithmic complexity:**

In the table below, **M** is the key length in bytes and **N** is the total number of entries in the container.

| Operation | kstrie | std::map | Notes |
|-----------|--------|----------|-------|
| Find | O(M) | O(M · log N) | Trie descends by key bytes. Map does log N string comparisons. |
| Insert | O(M + K) | O(M · log N) | K = entries in the target compact node (≤32). Rebuild is O(K). |
| Erase | O(M + K) | O(M · log N) | Same compact rebuild cost as insert. |
| Iterate next | O(M) | O(1) amortized | Trie re-descends from root. Map follows one RB-tree pointer. |
| Memory | Shared prefixes | Per-entry overhead | Trie shares prefix storage. Map stores full key per node. |

**Why kstrie reads are fast:** Each level of the trie examines exactly one byte. A bitmask node lookup is a bitmap probe + popcount — no string comparison. A compact node does a short linear scan over suffixes that share the same prefix context, so comparison lengths are short (typically ≤14 bytes). In contrast, `std::map` performs O(log N) full string comparisons, each touching O(M) bytes.

**Where std::map wins:** Iteration. `std::map` stores explicit left/right/parent pointers, so `++iterator` follows one pointer. kstrie's iterator holds a key string and re-traverses from the root on each step, costing O(M) per advance. For iteration-heavy workloads, this is the primary tradeoff.

**Memory advantage:** kstrie shares prefix storage across entries. For datasets with common prefixes (URLs, file paths, domain names), this compression is substantial. A compact node holding 100 entries with a 20-byte shared prefix stores those 20 bytes once, while `std::map` stores them 100 times. Additionally, bitmask nodes have no per-entry key storage at all — just a 32-byte bitmap and child pointers.

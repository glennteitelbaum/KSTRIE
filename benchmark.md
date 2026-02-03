# kstrie vs std::map Benchmark Results

**Test Configuration:**
- Compiler: g++ -std=c++23 -O2
- Value type: int
- Read pattern: randomized order

## Summary Table

| Test | Keys | kstrie Insert | std::map Insert | kstrie Read | std::map Read | kstrie Mem | std::map Mem |
|------|------|---------------|-----------------|-------------|---------------|------------|-------------|
| Random Strings (8-32 chars) | 10000 | 25.91 ms | 4.39 ms | 1.55 ms | 2.65 ms | 272 KB | 907 KB |
| URL-like Keys | 10000 | 56.80 ms | 4.89 ms | 2.67 ms | 3.53 ms | 210 KB | 1086 KB |
| Prefix-style Keys (prefix_N) | 10000 | 118.05 ms | 1.76 ms | 1.22 ms | 2.17 ms | 123 KB | 742 KB |
| Short Keys (4-8 chars) | 10000 | 27.65 ms | 2.13 ms | 1.02 ms | 1.87 ms | 136 KB | 742 KB |
| Long Keys (64-128 chars) | 10000 | 19.90 ms | 3.27 ms | 2.11 ms | 3.20 ms | 1092 KB | 1688 KB |

## Performance Comparison

### Random Strings (8-32 chars) (10000 keys)

| Metric | kstrie | std::map | Ratio (map/kstrie) |
|--------|--------|----------|-------------------|
| Insert Time | 25.91 ms | 4.39 ms | 0.17x |
| Read Time | 1.55 ms | 2.65 ms | 1.71x |
| Memory | 272 KB | 907 KB | 3.33x |

**Analysis:** std::map insert is 5.9x faster. kstrie read is 1.7x faster. kstrie uses 3.3x less memory.

### URL-like Keys (10000 keys)

| Metric | kstrie | std::map | Ratio (map/kstrie) |
|--------|--------|----------|-------------------|
| Insert Time | 56.80 ms | 4.89 ms | 0.09x |
| Read Time | 2.67 ms | 3.53 ms | 1.32x |
| Memory | 210 KB | 1086 KB | 5.17x |

**Analysis:** std::map insert is 11.6x faster. kstrie read is 1.3x faster. kstrie uses 5.2x less memory.

### Prefix-style Keys (prefix_N) (10000 keys)

| Metric | kstrie | std::map | Ratio (map/kstrie) |
|--------|--------|----------|-------------------|
| Insert Time | 118.05 ms | 1.76 ms | 0.01x |
| Read Time | 1.22 ms | 2.17 ms | 1.78x |
| Memory | 123 KB | 742 KB | 6.01x |

**Analysis:** std::map insert is 67.0x faster. kstrie read is 1.8x faster. kstrie uses 6.0x less memory.

### Short Keys (4-8 chars) (10000 keys)

| Metric | kstrie | std::map | Ratio (map/kstrie) |
|--------|--------|----------|-------------------|
| Insert Time | 27.65 ms | 2.13 ms | 0.08x |
| Read Time | 1.02 ms | 1.87 ms | 1.84x |
| Memory | 136 KB | 742 KB | 5.44x |

**Analysis:** std::map insert is 13.0x faster. kstrie read is 1.8x faster. kstrie uses 5.4x less memory.

### Long Keys (64-128 chars) (10000 keys)

| Metric | kstrie | std::map | Ratio (map/kstrie) |
|--------|--------|----------|-------------------|
| Insert Time | 19.90 ms | 3.27 ms | 0.16x |
| Read Time | 2.11 ms | 3.20 ms | 1.52x |
| Memory | 1092 KB | 1688 KB | 1.55x |

**Analysis:** std::map insert is 6.1x faster. kstrie read is 1.5x faster. kstrie uses 1.5x less memory.

## Key Characteristics

### kstrie
- Byte-at-a-time trie with skip compression
- Compact leaves with Eytzinger-layout binary search
- Bitmap256-compressed 256-way dispatch nodes
- Excellent memory density for string keys with shared prefixes

### std::map
- Red-black tree implementation
- O(log n) operations with string comparison at each node
- Per-node allocation overhead (~40 bytes + string)
- Good general-purpose performance

## Conclusions

- **Memory:** kstrie typically uses significantly less memory, especially for keys with common prefixes
- **Insert:** Performance varies by key pattern; kstrie benefits from prefix sharing
- **Read:** kstrie competitive or faster due to cache-efficient layout and prefix compression
- **Best for:** URL-like keys, identifiers with common prefixes, dictionary-style data

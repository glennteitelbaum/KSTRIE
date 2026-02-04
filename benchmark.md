# kstrie vs std::map Benchmark Results

**Test Configuration:**
- Compiler: g++ -std=c++23 -O2
- Value type: int (4 bytes)
- Entries: 100,000 per test
- Read pattern: randomized order

## Summary Table

| Test | Keys | Keysize | kstrie Insert | std::map Insert | kstrie Read | std::map Read | kstrie Mem | std::map Mem |
|------|------|---------|---------------|-----------------|-------------|---------------|------------|--------------|
| Random Strings (8-32) | 100K | 1950 KB | 56.1ms | 142.2ms | 17.4ms | 57.9ms | 5187 KB | 9080 KB |
| URL-like Keys | 100K | 3212 KB | 117.0ms | 57.0ms | 26.6ms | 68.8ms | 1684 KB | 10731 KB |
| Prefix-style Keys | 100K | 965 KB | 140.3ms | 21.6ms | 18.7ms | 49.6ms | 1415 KB | 7421 KB |
| Short Keys (4-8) | 100K | 585 KB | 182.2ms | 41.4ms | 16.6ms | 48.2ms | 1585 KB | 7420 KB |
| Long Keys (64-128) | 100K | 9364 KB | 63.2ms | 177.8ms | 22.7ms | 75.2ms | 14197 KB | 16884 KB |

## Ratios (kstrie vs std::map)

| Test | Insert | Read | Memory |
|------|--------|------|--------|
| Random Strings (8-32) | **2.53x faster** | **3.32x faster** | **1.75x smaller** |
| URL-like Keys | 0.49x (2x slower) | **2.58x faster** | **6.37x smaller** |
| Prefix-style Keys | 0.15x (6.5x slower) | **2.65x faster** | **5.24x smaller** |
| Short Keys (4-8) | 0.23x (4.4x slower) | **2.91x faster** | **4.68x smaller** |
| Long Keys (64-128) | **2.82x faster** | **3.31x faster** | **1.19x smaller** |

## Analysis

### Strengths
- **Read performance**: 2.5-3.3x faster across all workloads
- **Memory efficiency**: Always smaller, up to 6x for URL-like keys with shared prefixes
- **Long keys**: Wins on all metrics (insert 2.8x, read 3.3x, memory 1.2x)
- **Random strings**: Wins on all metrics (insert 2.5x, read 3.3x, memory 1.75x)

### Remaining Insert Overhead
- Shared-prefix keys still slower on insert due to node splits
- The skip-reduction splits during divergence are O(n) when they occur
- Read performance compensates significantly for read-heavy workloads

### Key Design Principles
1. **Skip only shrinks** - New leaf gets skip=full_key, splits reduce skip
2. **No LCP extension on insert** - O(1) insert path, no scanning existing keys
3. **Upfront KEY_TOO_LONG check** - O(1) check before insert, not O(n) validation after

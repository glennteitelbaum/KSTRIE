# kstrie Compact Leaf Benchmark Results

## Implementation
See `kstrie_v2.hpp` for the full implementation.

## Design
- Granularity 8: one IdxEntry (16B) per 8 keys
- Eytzinger hot array: uint64_t prefix (8B), branchless comparison
- W = next_power_of_2(ceil(ic/4)), ec = W - 1
- Linear scan: up to 4 idx entries, then up to 8 keys
- Crossover vs std::map: N ≈ 64

## Results

| N | eyt | map | ratio | ic | W | ec | idx scan | bytes |
|---:|---:|---:|---:|---:|---:|---:|:---:|---:|
| 1 | 7.6ns | 4.3ns | 0.56x | 1 | 0 | 0 | 1 | 48 |
| 2 | 12.1ns | 8.4ns | 0.70x | 1 | 0 | 0 | 1 | 56 |
| 3 | 13.3ns | 10.4ns | 0.78x | 1 | 0 | 0 | 1 | 80 |
| 4 | 14.5ns | 11.1ns | 0.76x | 1 | 0 | 0 | 1 | 96 |
| 5 | 16.5ns | 12.4ns | 0.75x | 1 | 0 | 0 | 1 | 112 |
| 8 | 20.2ns | 14.9ns | 0.74x | 1 | 0 | 0 | 1 | 176 |
| 9 | 21.8ns | 16.4ns | 0.75x | 2 | 0 | 0 | 2 | 200 |
| 16 | 22.7ns | 21.2ns | 0.94x | 2 | 0 | 0 | 2 | 328 |
| 17 | 23.8ns | 21.2ns | 0.89x | 3 | 0 | 0 | 3 | 368 |
| 32 | 26.5ns | 26.2ns | 0.99x | 4 | 0 | 0 | 4 | 656 |
| 33 | 29.0ns | 27.3ns | 0.94x | 5 | 2 | 1 | 3-4 | 688 |
| 64 | 31.6ns | 32.6ns | 1.03x | 8 | 2 | 1 | 4 | 1280 |
| 65 | 32.6ns | 34.0ns | 1.04x | 9 | 4 | 3 | 3-4 | 1328 |
| 128 | 35.3ns | 40.4ns | 1.14x | 16 | 4 | 3 | 4 | 2568 |
| 129 | 35.9ns | 42.9ns | 1.19x | 17 | 8 | 7 | 3-4 | 2632 |
| 256 | 38.5ns | 50.4ns | 1.31x | 32 | 8 | 7 | 4 | 5168 |
| 257 | 39.6ns | 53.7ns | 1.35x | 33 | 16 | 15 | 3-4 | 5264 |
| 512 | 41.9ns | 61.6ns | 1.47x | 64 | 16 | 15 | 4 | 10344 |
| 513 | 43.5ns | 62.6ns | 1.44x | 65 | 32 | 31 | 3-4 | 10504 |
| 1024 | 44.7ns | 73.5ns | 1.64x | 128 | 32 | 31 | 4 | 20688 |
| 1025 | 46.1ns | 74.4ns | 1.61x | 129 | 64 | 63 | 3-4 | 20968 |
| 2048 | 48.0ns | 91.5ns | 1.91x | 256 | 64 | 63 | 4 | 41432 |
| 2049 | 49.6ns | 89.7ns | 1.81x | 257 | 128 | 127 | 3-4 | 41984 |
| 4096 | 51.8ns | 100.8ns | 1.95x | 512 | 128 | 127 | 4 | 82792 |
| 4097 | 53.3ns | 104.1ns | 1.95x | 513 | 256 | 255 | 3-4 | 83856 |

## Layout

```
[hot: (ec+1) × 8B]     ← uint64_t prefix, Eytzinger order, 1-indexed
[idx: ic × 16B]        ← IdxEntry {len, offset, key[12]}
[keys: variable]       ← [u16 len][bytes...]
[values: N × 8B]
```

## Key Formulas

```cpp
ic = (N + 7) / 8                      // idx count
W = bit_ceil((ic + 3) / 4)            // window count (power of 2)
ec = W - 1                            // Eytzinger node count (complete tree)
boundary[i] = idx[(i+1) * ic / W]     // for i in [0, ec)
window = i - ec - 1                   // after E traversal
idx_base = window * ic / W
```

#!/usr/bin/env python3
"""kstrie size estimator — simulates trie structure and computes memory."""

import sys
from collections import defaultdict

COMPACT_MAX = 4096
VALUE_SIZE = 8
BITMAP_SIZE = 32
HEADER_SIZE = 8
SKIP_PREFIX_SIZE = 8
PTR_SIZE = 8

def align8(n):
    return (n + 7) & ~7

class Stats:
    def __init__(self):
        self.compact_leaves = 0
        self.compact_leaf_entries = 0
        self.bitmap_nodes = 0
        self.bitmap_fanout = []
        self.eos_nodes = 0
        self.skip_levels = 0
        self.skip_bytes_saved = 0
        self.max_depth = 0
        self.depth_hist = defaultdict(int)
        self.total_suffix_bytes_raw = 0
        self.total_suffix_bytes_fc = 0

    def report(self, num_keys, raw_key_bytes, total_bytes):
        print(f"\n=== kstrie size estimate for {num_keys:,} keys ===")
        print(f"Raw key data: {raw_key_bytes:,} bytes ({raw_key_bytes/num_keys:.1f} avg key len)")
        print()
        print(f"Structure:")
        print(f"  Compact leaves:     {self.compact_leaves:,} (holding {self.compact_leaf_entries:,} entries)")
        print(f"  Bitmap nodes:       {self.bitmap_nodes:,}")
        print(f"  EOS values:         {self.eos_nodes:,}")
        print(f"  Skip compressions:  {self.skip_levels:,} (saved {self.skip_bytes_saved:,} bitmap levels)")
        print(f"  Max trie depth:     {self.max_depth}")
        if self.bitmap_fanout:
            avg = sum(self.bitmap_fanout) / len(self.bitmap_fanout)
            med = sorted(self.bitmap_fanout)[len(self.bitmap_fanout)//2]
            print(f"  Bitmap fanout:      avg={avg:.1f}, median={med}, "
                  f"min={min(self.bitmap_fanout)}, max={max(self.bitmap_fanout)}")
        print()
        print(f"Memory:")
        print(f"  Total:              {total_bytes:,} bytes ({total_bytes/1024/1024:.2f} MB)")
        print(f"  Bytes/entry:        {total_bytes/num_keys:.2f}")
        print(f"  vs raw keys:        {total_bytes/raw_key_bytes:.2f}x")
        print()
        map_est = num_keys * 96
        umap_est = num_keys * 100
        svec_est = raw_key_bytes + num_keys * (32 + VALUE_SIZE)
        print(f"Comparison estimates:")
        print(f"  std::map:           {map_est:,} bytes ({map_est/num_keys:.1f} B/entry)")
        print(f"  std::unordered_map: {umap_est:,} bytes ({umap_est/num_keys:.1f} B/entry)")
        print(f"  sorted vector:      {svec_est:,} bytes ({svec_est/num_keys:.1f} B/entry)")
        print(f"  kstrie vs map:      {map_est/total_bytes:.1f}x smaller")
        print(f"  kstrie vs umap:     {umap_est/total_bytes:.1f}x smaller")
        print(f"  kstrie vs svec:     {svec_est/total_bytes:.1f}x smaller")
        print()
        if self.total_suffix_bytes_raw > 0:
            savings = self.total_suffix_bytes_raw - self.total_suffix_bytes_fc
            print(f"Front coding potential:")
            print(f"  Raw suffix bytes:     {self.total_suffix_bytes_raw:,}")
            print(f"  Front-coded bytes:    {self.total_suffix_bytes_fc:,}")
            print(f"  Savings:              {savings:,} ({100*savings/self.total_suffix_bytes_raw:.1f}%)")
            fc_total = total_bytes - savings
            print(f"  With front coding:    {fc_total:,} bytes ({fc_total/num_keys:.2f} B/entry)")
        print()
        print(f"Depth distribution (bitmap levels to reach compact leaf):")
        for d in sorted(self.depth_hist.keys()):
            print(f"  depth {d}: {self.depth_hist[d]:,} leaves")


def compact_leaf_bytes(suffixes, stats):
    count = len(suffixes)
    size = HEADER_SIZE
    size += align8(count)  # length array

    suffix_bytes = sum(len(s) if len(s) <= 254 else PTR_SIZE for s in suffixes)
    size += align8(suffix_bytes)
    stats.total_suffix_bytes_raw += suffix_bytes

    # Front coding estimate
    fc_bytes = 0
    prev = ""
    for s in suffixes:
        shared = sum(1 for a, b in zip(prev, s) if a == b)
        # Stop at first mismatch
        shared = 0
        for a, b in zip(prev, s):
            if a == b: shared += 1
            else: break
        fc_bytes += 2 + (len(s) - shared)
        prev = s
    stats.total_suffix_bytes_fc += fc_bytes

    idx2 = (count + 15) // 16 if count > 16 else 0
    idx1 = (count + 255) // 256 if count > 256 else 0
    size += align8((idx1 + idx2) * 4)

    size += align8(count * VALUE_SIZE)  # values
    return size


def estimate_node(suffixes, stats, depth=0):
    if not suffixes:
        return 0

    stats.max_depth = max(stats.max_depth, depth)
    node_bytes = 0

    eos = [s for s in suffixes if len(s) == 0]
    non_eos = [s for s in suffixes if len(s) > 0]

    if eos:
        stats.eos_nodes += 1
        node_bytes += VALUE_SIZE

    if not non_eos:
        return node_bytes + HEADER_SIZE

    # Skip compression: count consecutive bytes shared by ALL non_eos
    skip = 0
    while True:
        chars = set()
        for s in non_eos:
            if skip < len(s):
                chars.add(s[skip])
            else:
                chars.add(None)
                break
        if len(chars) == 1 and None not in chars:
            skip += 1
        else:
            break

    if skip > 0:
        stats.skip_levels += 1
        stats.skip_bytes_saved += skip
        node_bytes += SKIP_PREFIX_SIZE

        non_eos = [s[skip:] for s in non_eos]
        new_eos = [s for s in non_eos if len(s) == 0]
        non_eos = [s for s in non_eos if len(s) > 0]
        if new_eos:
            stats.eos_nodes += 1
            node_bytes += VALUE_SIZE

    if not non_eos:
        return node_bytes + HEADER_SIZE

    if len(non_eos) <= COMPACT_MAX:
        stats.compact_leaves += 1
        stats.compact_leaf_entries += len(non_eos)
        stats.depth_hist[depth] += 1
        return node_bytes + compact_leaf_bytes(non_eos, stats)

    # Bitmap split
    stats.bitmap_nodes += 1
    buckets = defaultdict(list)
    for s in non_eos:
        buckets[s[0]].append(s[1:])

    num_buckets = len(buckets)
    stats.bitmap_fanout.append(num_buckets)

    node_bytes += HEADER_SIZE + BITMAP_SIZE + align8(num_buckets * PTR_SIZE)

    for key in sorted(buckets.keys()):
        node_bytes += estimate_node(buckets[key], stats, depth + 1)

    return node_bytes


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else '/mnt/user-data/uploads/words.txt'
    with open(path, 'r', errors='replace') as f:
        words = [line.strip().rstrip('\r') for line in f if line.strip()]

    words = sorted(set(words))
    num_keys = len(words)
    raw_key_bytes = sum(len(w) for w in words)
    print(f"Loaded {num_keys:,} unique keys, {raw_key_bytes:,} total key bytes")

    stats = Stats()
    total = estimate_node(words, stats, depth=0)
    stats.report(num_keys, raw_key_bytes, total)


if __name__ == '__main__':
    main()

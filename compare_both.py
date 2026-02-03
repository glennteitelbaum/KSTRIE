import subprocess
import re
from collections import defaultdict

def run_benchmark(branchless):
    # Set the flag
    with open('bench_new_idx.cpp', 'r') as f:
        code = f.read()
    
    if branchless:
        code = re.sub(r'#define MAKECMP_BRANCHLESS \d', '#define MAKECMP_BRANCHLESS 1', code)
    else:
        code = re.sub(r'#define MAKECMP_BRANCHLESS \d', '#define MAKECMP_BRANCHLESS 0', code)
    
    with open('bench_new_idx.cpp', 'w') as f:
        f.write(code)
    
    # Compile
    subprocess.run(['g++', '-std=c++23', '-O2', '-march=x86-64-v4', '-o', 'bench_new_idx', 'bench_new_idx.cpp'], 
                   capture_output=True)
    
    # Run 5 times
    results = []
    for _ in range(5):
        out = subprocess.run(['./bench_new_idx'], capture_output=True, text=True)
        results.append(out.stdout)
    return results

best_bl = defaultdict(lambda: float('inf'))  # branchless
best_br = defaultdict(lambda: float('inf'))  # branching
best_map = defaultdict(lambda: float('inf'))

print("Running branchless (5 runs)...")
for output in run_benchmark(True):
    for line in output.split('\n'):
        m = re.match(r'\s*(\d+)\s+([\d.]+)ns\s+([\d.]+)ns', line)
        if m:
            n, kst, mp = int(m.group(1)), float(m.group(2)), float(m.group(3))
            best_bl[n] = min(best_bl[n], kst)
            best_map[n] = min(best_map[n], mp)

print("Running branching (5 runs)...")
for output in run_benchmark(False):
    for line in output.split('\n'):
        m = re.match(r'\s*(\d+)\s+([\d.]+)ns\s+([\d.]+)ns', line)
        if m:
            n, kst, mp = int(m.group(1)), float(m.group(2)), float(m.group(3))
            best_br[n] = min(best_br[n], kst)
            best_map[n] = min(best_map[n], mp)

print()
print(f"{'N':>6} {'branchless':>12} {'branching':>12} {'std::map':>10} {'BL/map':>8} {'BR/map':>8}")
print("-" * 70)
for n in sorted(best_bl.keys()):
    bl_ratio = best_map[n] / best_bl[n]
    br_ratio = best_map[n] / best_br[n]
    print(f"{n:>6} {best_bl[n]:>10.1f}ns {best_br[n]:>10.1f}ns {best_map[n]:>8.1f}ns {bl_ratio:>7.2f}x {br_ratio:>7.2f}x")

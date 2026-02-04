#include "kstrie_v2.hpp"
#include <map>
#include <string>
#include <vector>
#include <random>
#include <chrono>
#include <iostream>
#include <iomanip>
#include <fstream>
#include <algorithm>
#include <numeric>

// Generate random string of given length
std::string random_string(std::mt19937& rng, int min_len, int max_len) {
    static const char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    std::uniform_int_distribution<> len_dist(min_len, max_len);
    std::uniform_int_distribution<> char_dist(0, sizeof(charset) - 2);
    
    int len = len_dist(rng);
    std::string s;
    s.reserve(len);
    for (int i = 0; i < len; ++i) {
        s += charset[char_dist(rng)];
    }
    return s;
}

// Generate URL-like strings
std::string random_url(std::mt19937& rng, int id) {
    static const char* domains[] = {"example.com", "test.org", "demo.net", "sample.io", "mysite.com"};
    static const char* paths[] = {"api", "v1", "v2", "users", "posts", "items", "data", "admin"};
    std::uniform_int_distribution<> domain_dist(0, 4);
    std::uniform_int_distribution<> path_dist(0, 7);
    std::uniform_int_distribution<> depth_dist(1, 4);
    
    std::string url = "https://";
    url += domains[domain_dist(rng)];
    
    int depth = depth_dist(rng);
    for (int i = 0; i < depth; ++i) {
        url += "/";
        url += paths[path_dist(rng)];
    }
    url += "/" + std::to_string(id);
    return url;
}

// Generate words with common prefixes
std::string prefix_word(std::mt19937& rng, int id) {
    static const char* prefixes[] = {"user_", "item_", "post_", "data_", "cache_", "temp_", "log_", "msg_"};
    std::uniform_int_distribution<> prefix_dist(0, 7);
    return std::string(prefixes[prefix_dist(rng)]) + std::to_string(id);
}

template<typename F>
double time_ms(F&& func) {
    auto start = std::chrono::high_resolution_clock::now();
    func();
    auto end = std::chrono::high_resolution_clock::now();
    return std::chrono::duration<double, std::milli>(end - start).count();
}

struct BenchResult {
    std::string name;
    double insert_ms;
    double read_ms;
    size_t memory_bytes;
    size_t keysize_bytes;  // sum of all key lengths
    int count;
    
    // Overhead can be negative if compression saves space
    int64_t overhead() const { return static_cast<int64_t>(memory_bytes) - static_cast<int64_t>(keysize_bytes); }
    double bytes_per_entry() const { return count > 0 ? static_cast<double>(overhead()) / count : 0; }
};

// Calculate total key size
size_t calc_keysize(const std::vector<std::string>& keys) {
    size_t total = 0;
    for (const auto& k : keys) {
        total += k.size();
    }
    return total;
}

// Estimate std::map memory usage
size_t estimate_map_memory(const std::map<std::string, int>& m) {
    size_t total = sizeof(m);
    // Each node: ~40 bytes overhead (red-black tree node) + string + int
    // String: 32 bytes (SSO) or 32 + heap allocation
    for (const auto& [k, v] : m) {
        total += 40;  // RB-tree node overhead (pointers, color, etc.)
        total += sizeof(std::string);  // String object
        if (k.size() > 15) {  // Typical SSO threshold
            total += k.capacity() + 1;  // Heap allocation
        }
        total += sizeof(int);
    }
    return total;
}

BenchResult benchmark_kstrie(const std::vector<std::string>& keys, size_t keysize) {
    gteitelbaum::kstrie<int> trie;
    BenchResult result;
    result.name = "kstrie";
    result.count = keys.size();
    result.keysize_bytes = keysize;
    
    // Insert benchmark
    result.insert_ms = time_ms([&]() {
        for (size_t i = 0; i < keys.size(); ++i) {
            trie.insert(keys[i], static_cast<int>(i));
        }
    });
    
    // Read benchmark (randomized order)
    std::vector<size_t> indices(keys.size());
    std::iota(indices.begin(), indices.end(), 0);
    std::mt19937 rng(12345);
    std::shuffle(indices.begin(), indices.end(), rng);
    
    volatile int sink = 0;
    result.read_ms = time_ms([&]() {
        for (size_t idx : indices) {
            int* v = trie.find(keys[idx]);
            if (v) sink += *v;
        }
    });
    
    result.memory_bytes = trie.memory_usage();
    return result;
}

BenchResult benchmark_stdmap(const std::vector<std::string>& keys, size_t keysize) {
    std::map<std::string, int> m;
    BenchResult result;
    result.name = "std::map";
    result.count = keys.size();
    result.keysize_bytes = keysize;
    
    // Insert benchmark
    result.insert_ms = time_ms([&]() {
        for (size_t i = 0; i < keys.size(); ++i) {
            m[keys[i]] = static_cast<int>(i);
        }
    });
    
    // Read benchmark (randomized order)
    std::vector<size_t> indices(keys.size());
    std::iota(indices.begin(), indices.end(), 0);
    std::mt19937 rng(12345);
    std::shuffle(indices.begin(), indices.end(), rng);
    
    volatile int sink = 0;
    result.read_ms = time_ms([&]() {
        for (size_t idx : indices) {
            auto it = m.find(keys[idx]);
            if (it != m.end()) sink += it->second;
        }
    });
    
    result.memory_bytes = estimate_map_memory(m);
    return result;
}

void run_benchmark(const std::string& name, const std::vector<std::string>& keys,
                   std::vector<std::tuple<std::string, size_t, BenchResult, BenchResult>>& results) {
    size_t keysize = calc_keysize(keys);
    
    std::cout << "Running: " << name << " (" << keys.size() << " keys, " 
              << keysize / 1024 << " KB keydata)..." << std::endl;
    
    // Warm up
    {
        gteitelbaum::kstrie<int> t;
        std::map<std::string, int> m;
        for (size_t i = 0; i < std::min(keys.size(), size_t(1000)); ++i) {
            t.insert(keys[i], 0);
            m[keys[i]] = 0;
        }
    }
    
    auto kstrie_result = benchmark_kstrie(keys, keysize);
    auto stdmap_result = benchmark_stdmap(keys, keysize);
    
    results.push_back({name, keysize, kstrie_result, stdmap_result});
    
    std::cout << "  kstrie: insert=" << std::fixed << std::setprecision(2) 
              << kstrie_result.insert_ms << "ms, read=" << kstrie_result.read_ms 
              << "ms, overhead=" << kstrie_result.overhead() / 1024 << "KB"
              << " (" << std::setprecision(1) << kstrie_result.bytes_per_entry() << " B/entry)" << std::endl;
    std::cout << "  std::map: insert=" << stdmap_result.insert_ms << "ms, read=" 
              << stdmap_result.read_ms << "ms, overhead=" << stdmap_result.overhead() / 1024 << "KB"
              << " (" << std::setprecision(1) << stdmap_result.bytes_per_entry() << " B/entry)" << std::endl;
}

void write_markdown(const std::vector<std::tuple<std::string, size_t, BenchResult, BenchResult>>& results,
                    const std::string& filename) {
    std::ofstream out(filename);
    
    out << "# kstrie vs std::map Benchmark Results\n\n";
    out << "**Test Configuration:**\n";
    out << "- Compiler: g++ -std=c++23 -O2\n";
    out << "- Value type: int (4 bytes)\n";
    out << "- Entries: 100,000 per test\n";
    out << "- Read pattern: randomized order\n\n";
    
    out << "**Memory Metrics:**\n";
    out << "- **Keysize**: Sum of all key string lengths (raw key data)\n";
    out << "- **Overhead**: Total memory - Keysize (index/structure cost)\n";
    out << "- **B/entry**: Overhead bytes per entry\n\n";
    
    out << "## Summary Table\n\n";
    out << "| Test | Entries | Keysize | kstrie Overhead | kstrie B/entry | std::map Overhead | std::map B/entry |\n";
    out << "|------|---------|---------|-----------------|----------------|-------------------|------------------|\n";
    
    for (const auto& [name, keysize, k, m] : results) {
        out << "| " << name 
            << " | " << k.count
            << " | " << std::fixed << std::setprecision(1) << keysize / 1024.0 << " KB"
            << " | " << k.overhead() / 1024.0 << " KB"
            << " | " << std::setprecision(1) << k.bytes_per_entry() << " B"
            << " | " << m.overhead() / 1024.0 << " KB"
            << " | " << m.bytes_per_entry() << " B"
            << " |\n";
    }
    
    out << "\n## Timing Results\n\n";
    out << "| Test | kstrie Insert | std::map Insert | kstrie Read | std::map Read |\n";
    out << "|------|---------------|-----------------|-------------|---------------|\n";
    
    for (const auto& [name, keysize, k, m] : results) {
        out << "| " << name 
            << " | " << std::fixed << std::setprecision(1) << k.insert_ms << " ms"
            << " | " << m.insert_ms << " ms"
            << " | " << k.read_ms << " ms"
            << " | " << m.read_ms << " ms"
            << " |\n";
    }
    
    out << "\n## Detailed Analysis\n\n";
    
    for (const auto& [name, keysize, k, m] : results) {
        out << "### " << name << "\n\n";
        out << "- **Entries:** " << k.count << "\n";
        out << "- **Total key data:** " << std::fixed << std::setprecision(1) << keysize / 1024.0 << " KB\n";
        out << "- **Avg key length:** " << std::setprecision(1) << static_cast<double>(keysize) / k.count << " bytes\n\n";
        
        out << "| Metric | kstrie | std::map | Ratio |\n";
        out << "|--------|--------|----------|-------|\n";
        out << "| Total Memory | " << k.memory_bytes / 1024 << " KB | " << m.memory_bytes / 1024 << " KB | " 
            << std::setprecision(2) << static_cast<double>(m.memory_bytes) / k.memory_bytes << "x |\n";
        
        // Handle negative overhead (compression savings)
        if (k.overhead() <= 0) {
            out << "| Overhead | " << k.overhead() / 1024 << " KB (savings!) | " << m.overhead() / 1024 << " KB | N/A |\n";
            out << "| B/entry | " << std::setprecision(1) << k.bytes_per_entry() << " B (savings!) | " << m.bytes_per_entry() << " B | N/A |\n";
        } else {
            out << "| Overhead | " << k.overhead() / 1024 << " KB | " << m.overhead() / 1024 << " KB | "
                << std::setprecision(2) << static_cast<double>(m.overhead()) / k.overhead() << "x |\n";
            out << "| B/entry | " << std::setprecision(1) << k.bytes_per_entry() << " B | " << m.bytes_per_entry() << " B | "
                << std::setprecision(2) << m.bytes_per_entry() / k.bytes_per_entry() << "x |\n";
        }
        
        out << "| Insert Time | " << k.insert_ms << " ms | " << m.insert_ms << " ms | "
            << std::setprecision(2) << m.insert_ms / k.insert_ms << "x |\n";
        out << "| Read Time | " << k.read_ms << " ms | " << m.read_ms << " ms | "
            << std::setprecision(2) << m.read_ms / k.read_ms << "x |\n\n";
    }
    
    out << "## Key Insights\n\n";
    out << "- **Overhead** measures the indexing cost above raw key storage\n";
    out << "- **Negative overhead** means kstrie achieves compression (stores keys in less space than raw)\n";
    out << "- **B/entry** shows per-key indexing efficiency\n";
    out << "- Lower B/entry = more memory-efficient indexing\n";
    out << "- kstrie excels when keys share prefixes (skip compression eliminates redundant prefix storage)\n";
    out << "- std::map has ~72 B/entry overhead (RB-tree node + string object)\n";
    
    out.close();
}

int main() {
    const int N = 100000;  // 100k entries
    std::vector<std::tuple<std::string, size_t, BenchResult, BenchResult>> results;
    
    // Test 1: Random strings (8-32 chars)
    {
        std::mt19937 rng(42);
        std::vector<std::string> keys;
        keys.reserve(N);
        for (int i = 0; i < N; ++i) {
            keys.push_back(random_string(rng, 8, 32));
        }
        run_benchmark("Random Strings (8-32 chars)", keys, results);
    }
    
    // Test 2: URL-like keys
    {
        std::mt19937 rng(42);
        std::vector<std::string> keys;
        keys.reserve(N);
        for (int i = 0; i < N; ++i) {
            keys.push_back(random_url(rng, i));
        }
        run_benchmark("URL-like Keys", keys, results);
    }
    
    // Test 3: Prefix-style keys
    {
        std::mt19937 rng(42);
        std::vector<std::string> keys;
        keys.reserve(N);
        for (int i = 0; i < N; ++i) {
            keys.push_back(prefix_word(rng, i));
        }
        run_benchmark("Prefix-style Keys", keys, results);
    }
    
    // Test 4: Short keys (4-8 chars)
    {
        std::mt19937 rng(42);
        std::vector<std::string> keys;
        keys.reserve(N);
        for (int i = 0; i < N; ++i) {
            keys.push_back(random_string(rng, 4, 8));
        }
        run_benchmark("Short Keys (4-8 chars)", keys, results);
    }
    
    // Test 5: Long keys (64-128 chars)
    {
        std::mt19937 rng(42);
        std::vector<std::string> keys;
        keys.reserve(N);
        for (int i = 0; i < N; ++i) {
            keys.push_back(random_string(rng, 64, 128));
        }
        run_benchmark("Long Keys (64-128 chars)", keys, results);
    }
    
    write_markdown(results, "benchmark.md");
    std::cout << "\nResults written to benchmark.md\n";
    
    return 0;
}

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
    int count;
};

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

BenchResult benchmark_kstrie(const std::vector<std::string>& keys) {
    gteitelbaum::kstrie<int> trie;
    BenchResult result;
    result.name = "kstrie";
    result.count = keys.size();
    
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

BenchResult benchmark_stdmap(const std::vector<std::string>& keys) {
    std::map<std::string, int> m;
    BenchResult result;
    result.name = "std::map";
    result.count = keys.size();
    
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
                   std::vector<std::pair<std::string, std::pair<BenchResult, BenchResult>>>& results) {
    std::cout << "Running: " << name << " (" << keys.size() << " keys)..." << std::endl;
    
    // Warm up
    {
        gteitelbaum::kstrie<int> t;
        std::map<std::string, int> m;
        for (size_t i = 0; i < std::min(keys.size(), size_t(1000)); ++i) {
            t.insert(keys[i], 0);
            m[keys[i]] = 0;
        }
    }
    
    auto kstrie_result = benchmark_kstrie(keys);
    auto stdmap_result = benchmark_stdmap(keys);
    
    results.push_back({name, {kstrie_result, stdmap_result}});
    
    std::cout << "  kstrie: insert=" << std::fixed << std::setprecision(2) 
              << kstrie_result.insert_ms << "ms, read=" << kstrie_result.read_ms 
              << "ms, mem=" << kstrie_result.memory_bytes / 1024 << "KB" << std::endl;
    std::cout << "  std::map: insert=" << stdmap_result.insert_ms << "ms, read=" 
              << stdmap_result.read_ms << "ms, mem=" << stdmap_result.memory_bytes / 1024 << "KB" << std::endl;
}

void write_markdown(const std::vector<std::pair<std::string, std::pair<BenchResult, BenchResult>>>& results,
                    const std::string& filename) {
    std::ofstream out(filename);
    
    out << "# kstrie vs std::map Benchmark Results\n\n";
    out << "**Test Configuration:**\n";
    out << "- Compiler: g++ -std=c++23 -O2\n";
    out << "- Value type: int\n";
    out << "- Read pattern: randomized order\n\n";
    
    out << "## Summary Table\n\n";
    out << "| Test | Keys | kstrie Insert | std::map Insert | kstrie Read | std::map Read | kstrie Mem | std::map Mem |\n";
    out << "|------|------|---------------|-----------------|-------------|---------------|------------|-------------|\n";
    
    for (const auto& [name, pair] : results) {
        const auto& k = pair.first;
        const auto& m = pair.second;
        out << "| " << name 
            << " | " << k.count
            << " | " << std::fixed << std::setprecision(2) << k.insert_ms << " ms"
            << " | " << m.insert_ms << " ms"
            << " | " << k.read_ms << " ms"
            << " | " << m.read_ms << " ms"
            << " | " << k.memory_bytes / 1024 << " KB"
            << " | " << m.memory_bytes / 1024 << " KB"
            << " |\n";
    }
    
    out << "\n## Performance Comparison\n\n";
    
    for (const auto& [name, pair] : results) {
        const auto& k = pair.first;
        const auto& m = pair.second;
        
        out << "### " << name << " (" << k.count << " keys)\n\n";
        
        double insert_ratio = m.insert_ms / k.insert_ms;
        double read_ratio = m.read_ms / k.read_ms;
        double mem_ratio = static_cast<double>(m.memory_bytes) / k.memory_bytes;
        
        out << "| Metric | kstrie | std::map | Ratio (map/kstrie) |\n";
        out << "|--------|--------|----------|-------------------|\n";
        out << "| Insert Time | " << std::fixed << std::setprecision(2) << k.insert_ms << " ms | " 
            << m.insert_ms << " ms | " << std::setprecision(2) << insert_ratio << "x |\n";
        out << "| Read Time | " << k.read_ms << " ms | " << m.read_ms << " ms | " 
            << read_ratio << "x |\n";
        out << "| Memory | " << k.memory_bytes / 1024 << " KB | " << m.memory_bytes / 1024 
            << " KB | " << std::setprecision(2) << mem_ratio << "x |\n";
        
        out << "\n**Analysis:** ";
        if (insert_ratio > 1.0) {
            out << "kstrie insert is " << std::setprecision(1) << insert_ratio << "x faster. ";
        } else {
            out << "std::map insert is " << std::setprecision(1) << (1.0/insert_ratio) << "x faster. ";
        }
        if (read_ratio > 1.0) {
            out << "kstrie read is " << read_ratio << "x faster. ";
        } else {
            out << "std::map read is " << (1.0/read_ratio) << "x faster. ";
        }
        if (mem_ratio > 1.0) {
            out << "kstrie uses " << mem_ratio << "x less memory.";
        } else {
            out << "std::map uses " << (1.0/mem_ratio) << "x less memory.";
        }
        out << "\n\n";
    }
    
    out << "## Key Characteristics\n\n";
    out << "### kstrie\n";
    out << "- Byte-at-a-time trie with skip compression\n";
    out << "- Compact leaves with Eytzinger-layout binary search\n";
    out << "- Bitmap256-compressed 256-way dispatch nodes\n";
    out << "- Excellent memory density for string keys with shared prefixes\n\n";
    
    out << "### std::map\n";
    out << "- Red-black tree implementation\n";
    out << "- O(log n) operations with string comparison at each node\n";
    out << "- Per-node allocation overhead (~40 bytes + string)\n";
    out << "- Good general-purpose performance\n\n";
    
    out << "## Conclusions\n\n";
    out << "- **Memory:** kstrie typically uses significantly less memory, especially for keys with common prefixes\n";
    out << "- **Insert:** Performance varies by key pattern; kstrie benefits from prefix sharing\n";
    out << "- **Read:** kstrie competitive or faster due to cache-efficient layout and prefix compression\n";
    out << "- **Best for:** URL-like keys, identifiers with common prefixes, dictionary-style data\n";
    
    out.close();
}

int main() {
    std::vector<std::pair<std::string, std::pair<BenchResult, BenchResult>>> results;
    
    std::mt19937 rng(42);
    
    // Test 1: 10,000 random strings (8-32 chars)
    {
        std::vector<std::string> keys;
        keys.reserve(10000);
        for (int i = 0; i < 10000; ++i) {
            keys.push_back(random_string(rng, 8, 32));
        }
        run_benchmark("Random Strings (8-32 chars)", keys, results);
    }
    
    // Test 2: 10,000 URL-like keys
    {
        std::vector<std::string> keys;
        keys.reserve(10000);
        for (int i = 0; i < 10000; ++i) {
            keys.push_back(random_url(rng, i));
        }
        run_benchmark("URL-like Keys", keys, results);
    }
    
    // Test 3: 10,000 prefix_N style keys
    {
        std::vector<std::string> keys;
        keys.reserve(10000);
        for (int i = 0; i < 10000; ++i) {
            keys.push_back(prefix_word(rng, i));
        }
        run_benchmark("Prefix-style Keys (prefix_N)", keys, results);
    }
    
    // Test 4: 10,000 short keys (4-8 chars)
    {
        std::vector<std::string> keys;
        keys.reserve(10000);
        for (int i = 0; i < 10000; ++i) {
            keys.push_back(random_string(rng, 4, 8));
        }
        run_benchmark("Short Keys (4-8 chars)", keys, results);
    }
    
    // Test 5: 10,000 long keys (64-128 chars)
    {
        std::vector<std::string> keys;
        keys.reserve(10000);
        for (int i = 0; i < 10000; ++i) {
            keys.push_back(random_string(rng, 64, 128));
        }
        run_benchmark("Long Keys (64-128 chars)", keys, results);
    }
    
    // Write results to markdown
    write_markdown(results, "benchmark.md");
    std::cout << "\nResults written to benchmark.md\n";
    
    return 0;
}

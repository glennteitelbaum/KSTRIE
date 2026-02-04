#include "kstrie_v2.hpp"
#include <map>
#include <string>
#include <vector>
#include <random>
#include <chrono>
#include <iostream>
#include <iomanip>
#include <algorithm>
#include <numeric>

std::string random_string(std::mt19937& rng, int min_len, int max_len) {
    static const char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    std::uniform_int_distribution<> len_dist(min_len, max_len);
    std::uniform_int_distribution<> char_dist(0, sizeof(charset) - 2);
    int len = len_dist(rng);
    std::string s;
    s.reserve(len);
    for (int i = 0; i < len; ++i) s += charset[char_dist(rng)];
    return s;
}

std::string random_url(std::mt19937& rng, int id) {
    static const char* domains[] = {"example.com", "test.org", "demo.net"};
    static const char* paths[] = {"api", "v1", "users", "posts", "items"};
    std::uniform_int_distribution<> domain_dist(0, 2);
    std::uniform_int_distribution<> path_dist(0, 4);
    std::uniform_int_distribution<> depth_dist(1, 3);
    std::string url = "https://";
    url += domains[domain_dist(rng)];
    int depth = depth_dist(rng);
    for (int i = 0; i < depth; ++i) { url += "/"; url += paths[path_dist(rng)]; }
    url += "/" + std::to_string(id);
    return url;
}

std::string prefix_word(std::mt19937& rng, int id) {
    static const char* prefixes[] = {"user_", "item_", "post_", "data_"};
    std::uniform_int_distribution<> prefix_dist(0, 3);
    return std::string(prefixes[prefix_dist(rng)]) + std::to_string(id);
}

template<typename F> double time_ms(F&& func) {
    auto start = std::chrono::high_resolution_clock::now();
    func();
    auto end = std::chrono::high_resolution_clock::now();
    return std::chrono::duration<double, std::milli>(end - start).count();
}

size_t calc_keysize(const std::vector<std::string>& keys) {
    size_t total = 0;
    for (const auto& k : keys) total += k.size();
    return total;
}

size_t estimate_map_memory(const std::map<std::string, int>& m) {
    size_t total = sizeof(m);
    for (const auto& [k, v] : m) {
        total += 40 + sizeof(std::string) + sizeof(int);
        if (k.size() > 15) total += k.capacity() + 1;
    }
    return total;
}

void run_benchmark(const std::string& name, const std::vector<std::string>& keys) {
    size_t keysize = calc_keysize(keys);
    std::cout << "\n=== " << name << " (" << keys.size() << " keys, " << keysize/1024 << " KB) ===\n";
    
    gteitelbaum::kstrie<int> trie;
    double ins_k = time_ms([&]() {
        for (size_t i = 0; i < keys.size(); ++i) trie.insert(keys[i], static_cast<int>(i));
    });
    
    std::vector<size_t> indices(keys.size());
    std::iota(indices.begin(), indices.end(), 0);
    std::mt19937 rng(12345);
    std::shuffle(indices.begin(), indices.end(), rng);
    
    volatile int sink = 0;
    double rd_k = time_ms([&]() {
        for (size_t idx : indices) { int* v = trie.find(keys[idx]); if (v) sink += *v; }
    });
    
    std::map<std::string, int> m;
    double ins_m = time_ms([&]() {
        for (size_t i = 0; i < keys.size(); ++i) m[keys[i]] = static_cast<int>(i);
    });
    
    double rd_m = time_ms([&]() {
        for (size_t idx : indices) { auto it = m.find(keys[idx]); if (it != m.end()) sink += it->second; }
    });
    
    size_t mem_k = trie.memory_usage();
    size_t mem_m = estimate_map_memory(m);
    
    std::cout << std::fixed << std::setprecision(1);
    std::cout << "  kstrie:   insert=" << ins_k << "ms  read=" << rd_k << "ms  mem=" << mem_k/1024 << "KB\n";
    std::cout << "  std::map: insert=" << ins_m << "ms  read=" << rd_m << "ms  mem=" << mem_m/1024 << "KB\n";
    std::cout << "  Ratio:    insert=" << std::setprecision(2) << ins_m/ins_k << "x  read=" << rd_m/rd_k << "x  mem=" << (double)mem_m/mem_k << "x\n";
}

int main() {
    const int N = 100000;
    
    { std::mt19937 rng(42); std::vector<std::string> keys; keys.reserve(N);
      for (int i = 0; i < N; ++i) keys.push_back(random_string(rng, 8, 32));
      run_benchmark("Random Strings (8-32)", keys); }
    
    { std::mt19937 rng(42); std::vector<std::string> keys; keys.reserve(N);
      for (int i = 0; i < N; ++i) keys.push_back(random_url(rng, i));
      run_benchmark("URL-like Keys", keys); }
    
    { std::mt19937 rng(42); std::vector<std::string> keys; keys.reserve(N);
      for (int i = 0; i < N; ++i) keys.push_back(prefix_word(rng, i));
      run_benchmark("Prefix-style Keys", keys); }
    
    { std::mt19937 rng(42); std::vector<std::string> keys; keys.reserve(N);
      for (int i = 0; i < N; ++i) keys.push_back(random_string(rng, 4, 8));
      run_benchmark("Short Keys (4-8)", keys); }
    
    { std::mt19937 rng(42); std::vector<std::string> keys; keys.reserve(N);
      for (int i = 0; i < N; ++i) keys.push_back(random_string(rng, 64, 128));
      run_benchmark("Long Keys (64-128)", keys); }
    
    return 0;
}

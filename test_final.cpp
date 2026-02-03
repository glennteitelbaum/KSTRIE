#include "kstrie_v2.hpp"
#include <iostream>
#include <string>
#include <chrono>
#include <random>
#include <unordered_set>

using namespace gteitelbaum;

int main() {
    kstrie<int> t;
    
    // Test 1: Sequential with shared prefix
    std::cout << "Test 1: Sequential prefix_N (10000 entries)...\n";
    for (int i = 0; i < 10000; ++i) {
        t.insert("prefix_" + std::to_string(i), i);
    }
    int fail1 = 0;
    for (int i = 0; i < 10000; ++i) {
        const int* v = t.find("prefix_" + std::to_string(i));
        if (!v || *v != i) ++fail1;
    }
    std::cout << "  " << (fail1 == 0 ? "PASS" : "FAIL") << " (" << fail1 << " failures)\n";
    
    // Test 2: Long shared prefix
    kstrie<int> t2;
    std::cout << "Test 2: Long shared prefix (100 bytes, 1000 entries)...\n";
    std::string long_prefix(100, 'x');
    for (int i = 0; i < 1000; ++i) {
        t2.insert(long_prefix + std::to_string(i), i);
    }
    int fail2 = 0;
    for (int i = 0; i < 1000; ++i) {
        const int* v = t2.find(long_prefix + std::to_string(i));
        if (!v || *v != i) ++fail2;
    }
    std::cout << "  " << (fail2 == 0 ? "PASS" : "FAIL") << " (" << fail2 << " failures)\n";
    
    // Test 3: Random strings
    kstrie<int> t3;
    std::cout << "Test 3: Random strings (10000 entries)...\n";
    std::mt19937 rng(42);
    std::unordered_set<std::string> seen;
    std::vector<std::string> keys;
    for (int i = 0; i < 10000; ++i) {
        std::string s;
        int len = 5 + rng() % 50;
        for (int j = 0; j < len; ++j) {
            s += 'a' + rng() % 26;
        }
        if (seen.insert(s).second) {
            keys.push_back(s);
            t3.insert(s, (int)keys.size() - 1);
        }
    }
    int fail3 = 0;
    for (size_t i = 0; i < keys.size(); ++i) {
        const int* v = t3.find(keys[i]);
        if (!v || *v != (int)i) ++fail3;
    }
    std::cout << "  " << (fail3 == 0 ? "PASS" : "FAIL") << " (" << fail3 << "/" << keys.size() << " failures)\n";
    
    // Test 4: URLs
    kstrie<int> t4;
    std::cout << "Test 4: URL-like keys (5000 entries)...\n";
    for (int i = 0; i < 5000; ++i) {
        std::string url = "https://example.com/api/v2/users/" + std::to_string(i) + "/profile";
        t4.insert(url, i);
    }
    int fail4 = 0;
    for (int i = 0; i < 5000; ++i) {
        std::string url = "https://example.com/api/v2/users/" + std::to_string(i) + "/profile";
        const int* v = t4.find(url);
        if (!v || *v != i) ++fail4;
    }
    std::cout << "  " << (fail4 == 0 ? "PASS" : "FAIL") << " (" << fail4 << " failures)\n";
    
    bool all_pass = (fail1 == 0 && fail2 == 0 && fail3 == 0 && fail4 == 0);
    std::cout << "\n" << (all_pass ? "ALL TESTS PASSED!" : "SOME TESTS FAILED!") << "\n";
    return all_pass ? 0 : 1;
}

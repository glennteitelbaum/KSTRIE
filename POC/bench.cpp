// ---------------------------------------------------------------------------
// bench.cpp — vk1 vs vk2 vs std::map
// ---------------------------------------------------------------------------

#include "poc.hpp"
#include "varkey2.hpp"
#include "naive_kv.hpp"

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <map>
#include <random>
#include <string>
#include <vector>

// ---------------------------------------------------------------------------
// key generation
// ---------------------------------------------------------------------------

struct TestKey {
    uint8_t data[255];
    uint8_t len;
};

static std::vector<TestKey> gen_keys(int count, int min_len, int max_len, uint64_t seed) {
    std::mt19937_64 rng(seed);
    std::uniform_int_distribution<int> len_dist(min_len, max_len);
    std::uniform_int_distribution<int> byte_dist(0, 255);

    std::vector<TestKey> keys(count);
    for (auto& k : keys) {
        k.len = static_cast<uint8_t>(len_dist(rng));
        for (int j = 0; j < k.len; ++j)
            k.data[j] = static_cast<uint8_t>(byte_dist(rng));
    }

    // deduplicate by sorting (length, bytes)
    std::sort(keys.begin(), keys.end(), [](const TestKey& a, const TestKey& b) {
        if (a.len != b.len) return a.len < b.len;
        return std::memcmp(a.data, b.data, a.len) < 0;
    });
    keys.erase(std::unique(keys.begin(), keys.end(), [](const TestKey& a, const TestKey& b) {
        return a.len == b.len && std::memcmp(a.data, b.data, a.len) == 0;
    }), keys.end());

    std::shuffle(keys.begin(), keys.end(), rng);

    if ((int)keys.size() > count)
        keys.resize(count);
    return keys;
}

static std::vector<TestKey> gen_miss_keys(int count, int min_len, int max_len) {
    return gen_keys(count, min_len, max_len, 0xDEADBEEF'CAFEBABE);
}

// ---------------------------------------------------------------------------
// timing
// ---------------------------------------------------------------------------

using Clock = std::chrono::high_resolution_clock;

static double elapsed_ns(Clock::time_point t0, Clock::time_point t1) {
    return std::chrono::duration<double, std::nano>(t1 - t0).count();
}

// ---------------------------------------------------------------------------
// benchmark cores
// ---------------------------------------------------------------------------

struct BenchResult {
    double insert_ns;
    double find_hit_ns;
    double find_miss_ns;
};

static int find_iters(int N) {
    // scale iterations down for large N to keep runtime reasonable
    if (N <= 64)   return 200;
    if (N <= 256)  return 100;
    if (N <= 1024) return 50;
    return 20;
}

static BenchResult bench_vk1(const std::vector<TestKey>& keys,
                             const std::vector<TestKey>& miss_keys) {
    int N = static_cast<int>(keys.size());
    int ITERS = find_iters(N);
    BenchResult res{};

    auto t0 = Clock::now();
    uint8_t* node = vk_create(1);
    for (int i = 0; i < N; ++i)
        node = vk_insert(node, keys[i].data, keys[i].len,
                         reinterpret_cast<VALUE>(static_cast<uintptr_t>(i + 1)));
    auto t1 = Clock::now();
    res.insert_ns = elapsed_ns(t0, t1) / N;

    volatile VALUE sink = nullptr;
    t0 = Clock::now();
    for (int r = 0; r < ITERS; ++r)
        for (int i = 0; i < N; ++i)
            sink = vk_find(node, keys[i].data, keys[i].len);
    t1 = Clock::now();
    res.find_hit_ns = elapsed_ns(t0, t1) / (N * ITERS);

    int M = static_cast<int>(miss_keys.size());
    t0 = Clock::now();
    for (int r = 0; r < ITERS; ++r)
        for (int i = 0; i < M; ++i)
            sink = vk_find(node, miss_keys[i].data, miss_keys[i].len);
    t1 = Clock::now();
    res.find_miss_ns = elapsed_ns(t0, t1) / (M * ITERS);

    (void)sink;
    vk_free(node);
    return res;
}

static BenchResult bench_vk2(const std::vector<TestKey>& keys,
                             const std::vector<TestKey>& miss_keys,
                             uint16_t init_cap = VK2_INIT_CAP) {
    int N = static_cast<int>(keys.size());
    int ITERS = find_iters(N);
    BenchResult res{};

    auto t0 = Clock::now();
    uint8_t* node = vk2_create(init_cap);
    for (int i = 0; i < N; ++i)
        node = vk2_insert(node, keys[i].data, keys[i].len,
                          reinterpret_cast<VALUE>(static_cast<uintptr_t>(i + 1)));
    auto t1 = Clock::now();
    res.insert_ns = elapsed_ns(t0, t1) / N;

    volatile VALUE sink = nullptr;
    t0 = Clock::now();
    for (int r = 0; r < ITERS; ++r)
        for (int i = 0; i < N; ++i)
            sink = vk2_find(node, keys[i].data, keys[i].len);
    t1 = Clock::now();
    res.find_hit_ns = elapsed_ns(t0, t1) / (N * ITERS);

    int M = static_cast<int>(miss_keys.size());
    t0 = Clock::now();
    for (int r = 0; r < ITERS; ++r)
        for (int i = 0; i < M; ++i)
            sink = vk2_find(node, miss_keys[i].data, miss_keys[i].len);
    t1 = Clock::now();
    res.find_miss_ns = elapsed_ns(t0, t1) / (M * ITERS);

    (void)sink;
    vk2_free(node);
    return res;
}

static BenchResult bench_stdmap(const std::vector<TestKey>& keys,
                                const std::vector<TestKey>& miss_keys) {
    int N = static_cast<int>(keys.size());
    int ITERS = find_iters(N);
    BenchResult res{};

    auto t0 = Clock::now();
    std::map<std::string, VALUE> m;
    for (int i = 0; i < N; ++i)
        m.emplace(std::string(reinterpret_cast<const char*>(keys[i].data), keys[i].len),
                  reinterpret_cast<VALUE>(static_cast<uintptr_t>(i + 1)));
    auto t1 = Clock::now();
    res.insert_ns = elapsed_ns(t0, t1) / N;

    volatile VALUE sink = nullptr;
    t0 = Clock::now();
    for (int r = 0; r < ITERS; ++r)
        for (int i = 0; i < N; ++i) {
            auto it = m.find(std::string(reinterpret_cast<const char*>(keys[i].data), keys[i].len));
            sink = it != m.end() ? it->second : nullptr;
        }
    t1 = Clock::now();
    res.find_hit_ns = elapsed_ns(t0, t1) / (N * ITERS);

    int M = static_cast<int>(miss_keys.size());
    t0 = Clock::now();
    for (int r = 0; r < ITERS; ++r)
        for (int i = 0; i < M; ++i) {
            auto it = m.find(std::string(reinterpret_cast<const char*>(miss_keys[i].data), miss_keys[i].len));
            sink = it != m.end() ? it->second : nullptr;
        }
    t1 = Clock::now();
    res.find_miss_ns = elapsed_ns(t0, t1) / (M * ITERS);

    (void)sink;
    return res;
}

// ---------------------------------------------------------------------------
// smoke test
// ---------------------------------------------------------------------------

static void smoke_test_vk2(const std::vector<TestKey>& keys, uint16_t init_cap) {
    int N = static_cast<int>(keys.size());
    uint8_t* node = vk2_create(init_cap);
    for (int i = 0; i < N; ++i)
        node = vk2_insert(node, keys[i].data, keys[i].len,
                          reinterpret_cast<VALUE>(static_cast<uintptr_t>(i + 1)));
    for (int i = 0; i < N; ++i) {
        VALUE v = vk2_find(node, keys[i].data, keys[i].len);
        if (!v) { std::printf("  VK2 MISS at i=%d len=%d\n", i, keys[i].len); assert(false); }
    }
    vk2_free(node);
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

int main() {
    // -----------------------------------------------------------------------
    // Part 1: head-to-head at N=32 (vk1 vs vk2 vs std::map)
    // -----------------------------------------------------------------------
    std::printf("=== N=32: vk1 vs vk2 vs std::map ===\n\n");

    struct Scenario { const char* name; int count; int min_len; int max_len; };
    Scenario scenarios[] = {
        { "1-2B",    32,  1,   2  },
        { "1-4B",    32,  1,   4  },
        { "4-8B",    32,  4,   8  },
        { "8-16B",   32,  8,  16  },
        { "16-32B",  32, 16,  32  },
        { "32-64B",  32, 32,  64  },
        { "64-128B", 32, 64, 128  },
        { "1-128B",  32,  1, 128  },
    };

    std::printf("%-9s | %7s %7s | %7s %7s | %7s %7s | %6s %6s\n",
                "keys", "vk1_hit", "vk1_mis", "vk2_hit", "vk2_mis",
                "sm_hit", "sm_mis", "v2/v1h", "v2/smh");
    std::printf("%s\n", std::string(90, '-').c_str());

    for (auto& sc : scenarios) {
        auto keys      = gen_keys(sc.count, sc.min_len, sc.max_len, 42);
        auto miss_keys = gen_miss_keys(sc.count, sc.min_len, sc.max_len);
        smoke_test_vk2(keys, VK2_INIT_CAP);

        auto v1 = bench_vk1(keys, miss_keys);
        auto v2 = bench_vk2(keys, miss_keys);
        auto sm = bench_stdmap(keys, miss_keys);

        auto pct = [](double a, double b) { return (b - a) / b * 100.0; };

        std::printf("%-9s | %5.0f ns %5.0f ns | %5.0f ns %5.0f ns | %5.0f ns %5.0f ns | %+5.0f%% %+5.0f%%\n",
                    sc.name,
                    v1.find_hit_ns, v1.find_miss_ns,
                    v2.find_hit_ns, v2.find_miss_ns,
                    sm.find_hit_ns, sm.find_miss_ns,
                    pct(v2.find_hit_ns, v1.find_hit_ns),
                    pct(v2.find_hit_ns, sm.find_hit_ns));
    }

    // -----------------------------------------------------------------------
    // Part 2: scale test — vk2 vs std::map at N=32..4096
    // -----------------------------------------------------------------------
    std::printf("\n=== Scale test: vk2 vs std::map (keys 4-32B) ===\n\n");

    int scale_counts[] = { 32, 64, 128, 256, 512, 1024, 2048, 4096 };

    std::printf("%6s | %7s %7s %7s | %7s %7s %7s | %6s %6s\n",
                "N", "v2_ins", "v2_hit", "v2_mis",
                "sm_ins", "sm_hit", "sm_mis",
                "v2/smh", "v2/smm");
    std::printf("%s\n", std::string(85, '-').c_str());

    for (int N : scale_counts) {
        auto keys      = gen_keys(N, 4, 32, 42);
        auto miss_keys = gen_miss_keys(N, 4, 32);

        uint16_t init = VK2_INIT_CAP;
        while (init < N && init < VK2_MAX_CAP) init *= 2;
        smoke_test_vk2(keys, init);

        auto v2 = bench_vk2(keys, miss_keys, init);
        auto sm = bench_stdmap(keys, miss_keys);

        auto pct = [](double a, double b) { return (b - a) / b * 100.0; };

        std::printf("%6d | %5.0f ns %5.0f ns %5.0f ns | %5.0f ns %5.0f ns %5.0f ns | %+5.0f%% %+5.0f%%\n",
                    (int)keys.size(),
                    v2.insert_ns, v2.find_hit_ns, v2.find_miss_ns,
                    sm.insert_ns, sm.find_hit_ns, sm.find_miss_ns,
                    pct(v2.find_hit_ns, sm.find_hit_ns),
                    pct(v2.find_miss_ns, sm.find_miss_ns));
    }

    std::printf("\n  positive %% = varkey2 faster\n");
    return 0;
}

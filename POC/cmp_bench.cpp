#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <random>
#include <vector>

using Clock = std::chrono::high_resolution_clock;

static double elapsed_ns(Clock::time_point t0, Clock::time_point t1) {
    return std::chrono::duration<double, std::nano>(t1 - t0).count();
}

inline int cmp_memcmp(const uint8_t* a, const uint8_t* b, uint8_t len) {
    return std::memcmp(a, b, len);
}

inline int cmp_loop(const uint8_t* a, const uint8_t* b, uint8_t len) {
    for (uint8_t i = 0; i < len; ++i)
        if (a[i] != b[i]) return static_cast<int>(a[i]) - static_cast<int>(b[i]);
    return 0;
}

inline int cmp_u64(const uint8_t* a, const uint8_t* b, uint8_t len) {
    // compare 8 bytes at a time, then tail
    const uint8_t* ae = a + len;
    while (a + 8 <= ae) {
        uint64_t va, vb;
        std::memcpy(&va, a, 8);
        std::memcpy(&vb, b, 8);
        if (va != vb) {
            // find first differing byte (little-endian)
            uint64_t diff = va ^ vb;
            int pos = __builtin_ctzll(diff) >> 3;
            return static_cast<int>(a[pos]) - static_cast<int>(b[pos]);
        }
        a += 8; b += 8;
    }
    while (a < ae) {
        if (*a != *b) return static_cast<int>(*a) - static_cast<int>(*b);
        ++a; ++b;
    }
    return 0;
}

int main() {
    std::mt19937_64 rng(42);
    constexpr int PAIRS = 4096;
    constexpr int ITERS = 5000;

    int test_lens[] = { 1, 2, 4, 6, 8, 10, 12, 16, 20, 24, 32 };

    std::printf("%4s | %8s %8s %8s\n", "len", "memcmp", "loop", "u64");
    std::printf("%s\n", std::string(40, '-').c_str());

    for (int L : test_lens) {
        // generate pairs: ~50% matching, ~50% differing at random position
        std::vector<uint8_t> as(PAIRS * L), bs(PAIRS * L);
        for (int i = 0; i < PAIRS * L; ++i) as[i] = rng() & 0xFF;
        for (int i = 0; i < PAIRS; ++i) {
            std::memcpy(bs.data() + i * L, as.data() + i * L, L);
            if (rng() & 1) {
                int pos = rng() % L;
                bs[i * L + pos] ^= 1 + (rng() % 255);
            }
        }

        volatile int sink = 0;

        // memcmp
        auto t0 = Clock::now();
        for (int r = 0; r < ITERS; ++r)
            for (int i = 0; i < PAIRS; ++i)
                sink = cmp_memcmp(as.data() + i * L, bs.data() + i * L, L);
        auto t1 = Clock::now();
        double ns_memcmp = elapsed_ns(t0, t1) / (PAIRS * ITERS);

        // loop
        t0 = Clock::now();
        for (int r = 0; r < ITERS; ++r)
            for (int i = 0; i < PAIRS; ++i)
                sink = cmp_loop(as.data() + i * L, bs.data() + i * L, L);
        t1 = Clock::now();
        double ns_loop = elapsed_ns(t0, t1) / (PAIRS * ITERS);

        // u64
        t0 = Clock::now();
        for (int r = 0; r < ITERS; ++r)
            for (int i = 0; i < PAIRS; ++i)
                sink = cmp_u64(as.data() + i * L, bs.data() + i * L, L);
        t1 = Clock::now();
        double ns_u64 = elapsed_ns(t0, t1) / (PAIRS * ITERS);

        (void)sink;
        std::printf("%4d | %5.1f ns  %5.1f ns  %5.1f ns\n", L, ns_memcmp, ns_loop, ns_u64);
    }
    return 0;
}

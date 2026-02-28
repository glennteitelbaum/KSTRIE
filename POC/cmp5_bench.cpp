// cmp5_bench.cpp — 3 compare strategies on variant D scaffolding
// 1: early-exit with bswap per mismatch
// 2: branchless with bswap every slot
// 3: store big-endian, branchless no bswap in loop (Glenn's idea)

#include <cassert>
#include <bit>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <algorithm>
#include <chrono>
#include <cstdio>
#include <fstream>
#include <random>
#include <string>
#include <vector>

using VALUE = void*;
using Clock = std::chrono::high_resolution_clock;
static double elapsed_ns(Clock::time_point t0, Clock::time_point t1) {
    return std::chrono::duration<double, std::nano>(t1 - t0).count();
}

static constexpr uint16_t MAX_CAP = 4096;
inline uint8_t u64slots(uint8_t l) { return (l+7)>>3; }

// --- compare variants ---

// 1: early-exit, bswap only on mismatch
inline int cmp_exit(const uint64_t* A, const uint64_t* B, uint8_t s) {
    for (uint8_t i=0; i<s; ++i) {
        if (A[i] != B[i]) {
            uint64_t a=__builtin_bswap64(A[i]), b=__builtin_bswap64(B[i]);
            return a<b ? -1 : 1;
        }
    }
    return 0;
}

// 2: branchless, bswap every slot
inline int cmp_bl_swap(const uint64_t* A, const uint64_t* B, uint8_t s) {
    if (s == 0) return 0;
    int ret = 0;
    for (uint8_t i=0; i<s; ++i) {
        uint64_t a = __builtin_bswap64(A[i]);
        uint64_t b = __builtin_bswap64(B[i]);
        ret = (ret == 0) ? (a > b) - (a < b) : ret;
    }
    return ret;
}

// 3: branchless, both sides already big-endian — no bswap
inline int cmp_be(const uint64_t* A, const uint64_t* B, uint8_t s) {
    if (s == 0) return 0;
    int ret = 0;
    for (uint8_t i=0; i<s; ++i) {
        ret = (ret == 0) ? (A[i] > B[i]) - (A[i] < B[i]) : ret;
    }
    return ret;
}

// --- key conversion ---

// native-endian u64 (for variants 1 & 2)
inline void to_native(uint64_t* dst, const uint8_t* src, uint8_t len) {
    uint8_t s=u64slots(len); if(!s) return;
    dst[s-1]=0; std::memcpy(dst, src, len);
}

// big-endian u64 (for variant 3)
inline void to_be64(uint64_t* dst, const uint8_t* src, uint8_t len) {
    uint8_t s=u64slots(len); if(!s) return;
    dst[s-1]=0; std::memcpy(dst, src, len);
    if constexpr (std::endian::native == std::endian::little) {
        for (uint8_t i=0; i<s; ++i) dst[i] = std::byteswap(dst[i]);
    }
}

// --- shared node layout (padded blob + u32 offsets) ---

struct Hdr { uint16_t entries; uint32_t blob_used; uint16_t cap; };
static constexpr size_t H = sizeof(Hdr);

size_t off_o(uint16_t c) { return (H+c+3)&~size_t(3); }
size_t blb_o(uint16_t c) { return (off_o(c)+c*4+7)&~size_t(7); }
size_t blb_c(uint16_t c) { return c*24u*8; }
size_t val_o(uint16_t c) { return (blb_o(c)+blb_c(c)+7)&~size_t(7); }
size_t alloc_sz(uint16_t c) { return val_o(c)+c*sizeof(VALUE); }

Hdr*            hdr(uint8_t* n) { return reinterpret_cast<Hdr*>(n); }
const Hdr*      hdr(const uint8_t* n) { return reinterpret_cast<const Hdr*>(n); }
uint8_t*        len(uint8_t* n) { return n+H; }
const uint8_t*  len(const uint8_t* n) { return n+H; }
uint32_t*       off(uint8_t* n) { return reinterpret_cast<uint32_t*>(n+off_o(hdr(n)->cap)); }
const uint32_t* off(const uint8_t* n) { return reinterpret_cast<const uint32_t*>(n+off_o(hdr(n)->cap)); }
uint64_t*       blb(uint8_t* n) { return reinterpret_cast<uint64_t*>(n+blb_o(hdr(n)->cap)); }
const uint64_t* blb(const uint8_t* n) { return reinterpret_cast<const uint64_t*>(n+blb_o(hdr(n)->cap)); }
VALUE*          val(uint8_t* n) { return reinterpret_cast<VALUE*>(n+val_o(hdr(n)->cap)); }
const VALUE*    val(const uint8_t* n) { return reinterpret_cast<const VALUE*>(n+val_o(hdr(n)->cap)); }

uint8_t* create(uint16_t cap) {
    auto* n = static_cast<uint8_t*>(std::calloc(1, alloc_sz(cap)));
    hdr(n)->cap = cap; return n;
}

// insert storing native-endian (for variants 1 & 2)
void insert_native(uint8_t* n, const uint8_t* K, uint8_t Klen, VALUE v) {
    auto* h = hdr(n); int e = h->entries;
    uint64_t Kb[32]; to_native(Kb, K, Klen);
    uint8_t s = u64slots(Klen);
    uint32_t sp = h->blob_used;
    std::memcpy(blb(n)+sp, Kb, s*8);
    h->blob_used = sp+s;
    auto* L=len(n); auto* O=off(n); auto* V=val(n);
    int lo=0,hi=e;
    while(lo<hi){int m=lo+((hi-lo)>>1); if(L[m]<Klen)lo=m+1; else hi=m;}
    int bl=lo; hi=e;
    while(lo<hi){int m=lo+((hi-lo)>>1); if(L[m]<=Klen)lo=m+1; else hi=m;}
    int bh=lo; lo=bl; hi=bh;
    while(lo<hi){int m=lo+((hi-lo)>>1); if(cmp_exit(Kb,blb(n)+O[m],s)>0)lo=m+1; else hi=m;}
    int ins=lo; int tail=e-ins;
    if(tail>0){std::memmove(L+ins+1,L+ins,tail);std::memmove(O+ins+1,O+ins,tail*4);std::memmove(V+ins+1,V+ins,tail*8);}
    L[ins]=Klen; O[ins]=sp; V[ins]=v; h->entries=e+1;
}

// insert storing big-endian (for variant 3)
void insert_be(uint8_t* n, const uint8_t* K, uint8_t Klen, VALUE v) {
    auto* h = hdr(n); int e = h->entries;
    uint64_t Kb[32]; to_be64(Kb, K, Klen);
    uint8_t s = u64slots(Klen);
    uint32_t sp = h->blob_used;
    std::memcpy(blb(n)+sp, Kb, s*8);
    h->blob_used = sp+s;
    auto* L=len(n); auto* O=off(n); auto* V=val(n);
    int lo=0,hi=e;
    while(lo<hi){int m=lo+((hi-lo)>>1); if(L[m]<Klen)lo=m+1; else hi=m;}
    int bl=lo; hi=e;
    while(lo<hi){int m=lo+((hi-lo)>>1); if(L[m]<=Klen)lo=m+1; else hi=m;}
    int bh=lo; lo=bl; hi=bh;
    while(lo<hi){int m=lo+((hi-lo)>>1); if(cmp_be(Kb,blb(n)+O[m],s)>0)lo=m+1; else hi=m;}
    int ins=lo; int tail=e-ins;
    if(tail>0){std::memmove(L+ins+1,L+ins,tail);std::memmove(O+ins+1,O+ins,tail*4);std::memmove(V+ins+1,V+ins,tail*8);}
    L[ins]=Klen; O[ins]=sp; V[ins]=v; h->entries=e+1;
}

// --- find variants ---

// 1: early-exit bswap
VALUE find_v1(const uint8_t* n, const uint8_t* K, uint8_t Klen) {
    auto* h=hdr(n); int e=h->entries;
    auto* L=len(n); auto* O=off(n); auto* B=blb(n);
    int lo=0,hi=e;
    while(lo<hi){int m=lo+((hi-lo)>>1); if(L[m]<Klen)lo=m+1; else hi=m;}
    int bl=lo; hi=e;
    while(lo<hi){int m=lo+((hi-lo)>>1); if(L[m]<=Klen)lo=m+1; else hi=m;}
    if(bl>=lo) return nullptr;
    uint64_t Kb[32]; to_native(Kb, K, Klen);
    uint8_t s=u64slots(Klen);
    int bh=lo; lo=bl; hi=bh;
    while(lo<hi){int m=lo+((hi-lo)>>1); int c=cmp_exit(Kb,B+O[m],s); if(c==0) return val(n)[m]; if(c<0)hi=m; else lo=m+1;}
    return nullptr;
}

// 2: branchless, bswap every slot
VALUE find_v2(const uint8_t* n, const uint8_t* K, uint8_t Klen) {
    auto* h=hdr(n); int e=h->entries;
    auto* L=len(n); auto* O=off(n); auto* B=blb(n);
    int lo=0,hi=e;
    while(lo<hi){int m=lo+((hi-lo)>>1); if(L[m]<Klen)lo=m+1; else hi=m;}
    int bl=lo; hi=e;
    while(lo<hi){int m=lo+((hi-lo)>>1); if(L[m]<=Klen)lo=m+1; else hi=m;}
    if(bl>=lo) return nullptr;
    uint64_t Kb[32]; to_native(Kb, K, Klen);
    uint8_t s=u64slots(Klen);
    int bh=lo; lo=bl; hi=bh;
    while(lo<hi){int m=lo+((hi-lo)>>1); int c=cmp_bl_swap(Kb,B+O[m],s); if(c==0) return val(n)[m]; if(c<0)hi=m; else lo=m+1;}
    return nullptr;
}

// 3: store BE, branchless no bswap in loop
VALUE find_v3(const uint8_t* n, const uint8_t* K, uint8_t Klen) {
    auto* h=hdr(n); int e=h->entries;
    auto* L=len(n); auto* O=off(n); auto* B=blb(n);
    int lo=0,hi=e;
    while(lo<hi){int m=lo+((hi-lo)>>1); if(L[m]<Klen)lo=m+1; else hi=m;}
    int bl=lo; hi=e;
    while(lo<hi){int m=lo+((hi-lo)>>1); if(L[m]<=Klen)lo=m+1; else hi=m;}
    if(bl>=lo) return nullptr;
    uint64_t Kb[32]; to_be64(Kb, K, Klen);   // bswap once
    uint8_t s=u64slots(Klen);
    int bh=lo; lo=bl; hi=bh;
    while(lo<hi){int m=lo+((hi-lo)>>1); int c=cmp_be(Kb,B+O[m],s); if(c==0) return val(n)[m]; if(c<0)hi=m; else lo=m+1;}
    return nullptr;
}

int main() {
    std::vector<std::string> all_words;
    {
        std::ifstream f("/mnt/user-data/uploads/words.txt");
        std::string line;
        while (std::getline(f, line)) {
            while (!line.empty() && (line.back()=='\r'||line.back()=='\n')) line.pop_back();
            if (!line.empty() && line.size()<=255) all_words.push_back(std::move(line));
        }
    }

    std::mt19937_64 rng(42);
    std::vector<int> shuf(all_words.size());
    for (size_t i=0;i<all_words.size();++i) shuf[i]=static_cast<int>(i);
    std::shuffle(shuf.begin(), shuf.end(), rng);

    int test_sizes[] = { 32, 64, 128, 256, 512, 1024 };

    std::printf("%6s | %6s %6s %6s\n", "N", "v1:exit", "v2:bl+s", "v3:BE");
    std::printf("%s\n", std::string(40, '-').c_str());

    for (int N : test_sizes) {
        uint16_t cap = static_cast<uint16_t>(N < MAX_CAP ? N : MAX_CAP);
        int iters = N <= 64 ? 200 : N <= 256 ? 100 : 50;

        // build native node (v1 & v2 share it)
        auto* node_nat = create(cap);
        // build BE node (v3)
        auto* node_be = create(cap);
        for (int i=0; i<N; ++i) {
            const auto& w = all_words[shuf[i]];
            auto* K = reinterpret_cast<const uint8_t*>(w.data());
            auto Kl = static_cast<uint8_t>(w.size());
            auto V = reinterpret_cast<VALUE>(static_cast<uintptr_t>(i+1));
            insert_native(node_nat, K, Kl, V);
            insert_be(node_be, K, Kl, V);
        }

        // verify
        for (int i=0; i<N; ++i) {
            const auto& w = all_words[shuf[i]];
            auto* K = reinterpret_cast<const uint8_t*>(w.data());
            auto Kl = static_cast<uint8_t>(w.size());
            if (!find_v1(node_nat,K,Kl)) { std::printf("V1 MISS N=%d i=%d\n",N,i); return 1; }
            if (!find_v2(node_nat,K,Kl)) { std::printf("V2 MISS N=%d i=%d\n",N,i); return 1; }
            if (!find_v3(node_be,K,Kl))  { std::printf("V3 MISS N=%d i=%d\n",N,i); return 1; }
        }

        volatile VALUE sink = nullptr;

        auto t0 = Clock::now();
        for (int r=0;r<iters;++r)
            for (int i=0;i<N;++i) { const auto& w=all_words[shuf[i]]; sink=find_v1(node_nat,reinterpret_cast<const uint8_t*>(w.data()),static_cast<uint8_t>(w.size())); }
        auto t1 = Clock::now();
        double ns1 = elapsed_ns(t0,t1)/(N*iters);

        t0 = Clock::now();
        for (int r=0;r<iters;++r)
            for (int i=0;i<N;++i) { const auto& w=all_words[shuf[i]]; sink=find_v2(node_nat,reinterpret_cast<const uint8_t*>(w.data()),static_cast<uint8_t>(w.size())); }
        t1 = Clock::now();
        double ns2 = elapsed_ns(t0,t1)/(N*iters);

        t0 = Clock::now();
        for (int r=0;r<iters;++r)
            for (int i=0;i<N;++i) { const auto& w=all_words[shuf[i]]; sink=find_v3(node_be,reinterpret_cast<const uint8_t*>(w.data()),static_cast<uint8_t>(w.size())); }
        t1 = Clock::now();
        double ns3 = elapsed_ns(t0,t1)/(N*iters);

        (void)sink;
        std::free(node_nat); std::free(node_be);

        std::printf("%6d | %4.0fns   %4.0fns   %4.0fns\n", N, ns1, ns2, ns3);
    }

    std::printf("\n  v1=early-exit+bswap  v2=branchless+bswap  v3=store-BE+branchless\n");
    return 0;
}

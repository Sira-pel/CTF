// Modular subset-sum: 58 stones, modulus 2^54.
// Left 27 bits in an open-addressed table, right 31 bits enumerated by Gray code.
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>

static constexpr int LEFT = 27;
static constexpr int N = 58;
static constexpr int RIGHT = N - LEFT; // 31
static constexpr int SHIFT = 64 - 28;  // table size 2^28
static constexpr uint64_t TSIZE = 1ull << 28;
static constexpr uint64_t EMPTY = ~0ull;
static constexpr uint64_t MOD = 1ull << 54;
static constexpr uint64_t MASK = MOD - 1;

struct Tables {
    uint64_t* sum;
    uint32_t* mask;
};

static inline uint64_t hash64(uint64_t x) {
    x ^= x >> 30;
    x *= 0xbf58476d1ce4e5b9ull;
    x ^= x >> 27;
    x *= 0x94d049bb133111ebull;
    x ^= x >> 31;
    return x;
}

static void insert(Tables& t, uint64_t sum, uint32_t mask) {
    uint64_t i = hash64(sum) >> SHIFT;
    while (t.sum[i] != EMPTY) {
        i = (i + 1) & (TSIZE - 1);
    }
    t.sum[i] = sum;
    t.mask[i] = mask;
}

static void lookup_all(Tables& t, uint64_t key, uint64_t right_sum_unused,
                       uint32_t right_mask, uint64_t* stones, uint64_t target) {
    (void)right_sum_unused;
    (void)stones;
    (void)target;
    uint64_t i = hash64(key) >> SHIFT;
    while (t.sum[i] != EMPTY) {
        if (t.sum[i] == key) {
            unsigned __int128 full = (unsigned __int128)t.mask[i] |
                                     ((unsigned __int128)right_mask << LEFT);
            // print as 16 hex chars of the 64-bit value (low 58 bits used)
            uint64_t lo = (uint64_t)full;
            std::printf("%016llx\n", (unsigned long long)lo);
        }
        i = (i + 1) & (TSIZE - 1);
    }
}

int main(int argc, char** argv) {
    if (argc != 2) {
        std::fprintf(stderr, "usage: subset stones.txt\n");
        return 1;
    }
    std::ifstream in(argv[1]);
    uint64_t target;
    in >> target;
    uint64_t stone[N];
    for (int i = 0; i < N; i++) {
        if (!(in >> stone[i])) {
            std::fprintf(stderr, "short file\n");
            return 1;
        }
        stone[i] &= MASK;
    }

    Tables t;
    t.sum = new uint64_t[TSIZE];
    t.mask = new uint32_t[TSIZE];
    std::fprintf(stderr, "filling table\n");
    for (uint64_t i = 0; i < TSIZE; i++) t.sum[i] = EMPTY;

    uint64_t sum = 0;
    uint32_t gray = 0;
    for (uint32_t i = 0; i < (1u << LEFT); i++) {
        insert(t, sum, gray);
        if (i + 1 == (1u << LEFT)) break;
        uint32_t bit = __builtin_ctz(i + 1);
        gray ^= 1u << bit;
        if (gray & (1u << bit)) sum = (sum + stone[bit]) & MASK;
        else sum = (sum - stone[bit]) & MASK;
    }
    std::fprintf(stderr, "table ready, scanning right\n");

    sum = 0;
    uint32_t rgray = 0;
    uint64_t seen = 0;
    for (uint32_t i = 0; i < (1u << RIGHT); i++) {
        uint64_t need = (target - sum) & MASK;
        lookup_all(t, need, sum, rgray, stone, target);
        if (((i + 1) & 0x0fffffff) == 0) {
            std::fprintf(stderr, "progress %u / %u\n", i + 1, 1u << RIGHT);
        }
        if (i + 1 == (1u << RIGHT)) break;
        uint32_t bit = __builtin_ctz(i + 1);
        rgray ^= 1u << bit;
        if (rgray & (1u << bit)) sum = (sum + stone[LEFT + bit]) & MASK;
        else sum = (sum - stone[LEFT + bit]) & MASK;
        (void)seen;
    }
    std::fprintf(stderr, "done\n");
    return 0;
}

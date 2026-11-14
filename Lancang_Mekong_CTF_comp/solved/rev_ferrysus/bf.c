// Brute force xorshift32 keys whose keystream decrypts a route record into a
// plausible VM program (opcode bytes in 1..25).
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

static inline uint32_t xs(uint32_t x) {
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    return x;
}

static unsigned char rec[512];
static int reclen;

// check opcode bytes at 8*j
static int ok4(uint32_t key) {
    uint32_t s = key;
    unsigned char ks[32];
    for (int i = 0; i < 8; i++) { s = xs(s); memcpy(ks + 4*i, &s, 4); }
    for (int j = 0; j < 4; j++) {
        int op = rec[8*j] ^ ks[8*j];
        if (op < 1 || op > 25) return 0;
    }
    return 1;
}

static int fullok(uint32_t key) {
    uint32_t s = key;
    int n = reclen / 4 + 1;
    unsigned char *ks = malloc(n*4);
    for (int i = 0; i < n; i++) { s = xs(s); memcpy(ks + 4*i, &s, 4); }
    int bad = 0;
    for (int j = 0; j < reclen/8; j++) {
        int op = rec[8*j] ^ ks[8*j];
        if (op < 1 || op > 25) { bad = 1; break; }
    }
    free(ks);
    return !bad;
}

int main(int argc, char **argv) {
    const char *path = argv[1];
    int recidx = atoi(argv[2]);
    FILE *f = fopen(path, "rb");
    fseek(f, 0, SEEK_END); long L = ftell(f); fseek(f, 0, SEEK_SET);
    unsigned char *d = malloc(L); fread(d, 1, L, f); fclose(f);
    // parse records
    long off = 8; int idx = 0;
    while (off < L) {
        uint16_t cnt; memcpy(&cnt, d + off, 2); off += 2;
        if (idx == recidx) { reclen = cnt*8; memcpy(rec, d+off, reclen); break; }
        off += cnt*8; idx++;
    }
    printf("rec%d len=%d\n", recidx, reclen);

    uint32_t *cands = malloc(sizeof(uint32_t) * 100000);
    int nc = 0;
    for (uint64_t k = 0; k <= 0xffffffffULL; k++) {
        if (ok4((uint32_t)k)) {
            if (fullok((uint32_t)k)) { if (nc < 100000) cands[nc++] = (uint32_t)k; }
        }
    }
    printf("full matches: %d\n", nc);
    for (int i = 0; i < nc && i < 40; i++) printf("  key=0x%08x\n", cands[i]);
    return 0;
}

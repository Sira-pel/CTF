// Find xorshift32 seeds such that route record k decrypts to a program whose
// opcode bytes (offset 4 of each 8-byte item) are all in 1..25.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

static inline uint32_t xs(uint32_t x) {
    x ^= x << 13; x ^= x >> 17; x ^= x << 5; return x;
}

static unsigned char rec[1024];
static int nitems;

int main(int argc, char **argv) {
    FILE *f = fopen("route.bin", "rb");
    fseek(f, 0, SEEK_END); long L = ftell(f); fseek(f, 0, SEEK_SET);
    unsigned char *d = malloc(L); fread(d, 1, L, f); fclose(f);
    long off = 8; int idx = 0, want = atoi(argv[1]);
    int lastop = argc > 2 ? atoi(argv[2]) : -1;
    while (off < L) {
        uint16_t cnt; memcpy(&cnt, d + off, 2); off += 2;
        if (idx == want) { nitems = cnt; memcpy(rec, d + off, cnt * 8); break; }
        off += cnt * 8; idx++;
    }
    printf("record %d: %d items\n", want, nitems);
    int found = 0;
    for (uint64_t k = 0; k <= 0xffffffffULL; k++) {
        uint32_t s = (uint32_t)k;
        int ok = 1;
        uint32_t ks[256];
        for (int i = 0; i < nitems; i++) { s = xs(s); ks[i] = s; }
        for (int i = 0; i < nitems; i++) {
            int op = (rec[8*i+4] ^ ((unsigned char*)&ks[i])[0]);
            if (op < 1 || op > 25) { ok = 0; break; }
        }
        if (ok && lastop >= 0) {
            int op = rec[8*(nitems-1)+4] ^ ((unsigned char*)&ks[nitems-1])[0];
            if (op != lastop) ok = 0;
        }
        if (ok) {
            printf("  seed=0x%08x\n", (uint32_t)k);
            if (++found > 20) break;
        }
    }
    printf("total %d\n", found);
    return 0;
}

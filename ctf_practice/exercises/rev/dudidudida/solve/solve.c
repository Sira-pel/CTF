#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "data.h"
typedef unsigned long long u64;
typedef unsigned __int128 u128;

static int succ[N][4], nsucc[N], pred[N][8], npred[N];
static int indeg[N], outdeg[N], visited[N], path[N + 1], plen;
static int bits[2 * N + 8], nb; /* 2-bit codes */
static long long nodes; static int cpbest;
static const char *CHARSET;
static const char PREFIX[] = "HTB{";

static void addmod(u64 *a, const u64 *b) {
    u64 r[4]; u128 c = 0;
    for (int i = 0; i < 4; i++) { c += (u128)a[i] + b[i]; r[i] = (u64)c; c >>= 64; }
    int ge = (int)c;
    if (!ge) { for (int i = 3; i >= 0; i--) { if (r[i] != MM[i]) { ge = r[i] > MM[i]; break; } if (i == 0) ge = 1; } }
    if (ge) { u128 br = 0; for (int i = 0; i < 4; i++) { u128 t = (u128)r[i] - MM[i] - br; r[i] = (u64)t; br = (t >> 64) ? 1 : 0; } }
    memcpy(a, r, 32);
}

static int byteval(int k) { return (bits[4*k] << 6) | (bits[4*k+1] << 4) | (bits[4*k+2] << 2) | bits[4*k+3]; }
static int byte_ok(void) {
    int i = nb / 4 - 1, b = byteval(i);
    if (i < 4) return b == PREFIX[i];
    if (i == 55) return b == '}';
    return strchr(CHARSET, b) != NULL && b != 0;
}
static void show(const char *tag, int u) {
    printf("%s %d len=%d nodes=%lld ", tag, u, plen, nodes);
    for (int i = 0; i < nb / 4; i++) putchar(byteval(i));
    putchar('\n'); fflush(stdout);
}
static int enter(int v) {
    visited[v] = 1; path[plen++] = v; int bad = 0;
    for (int i = 0; i < npred[v]; i++) { int p = pred[v][i]; if (--outdeg[p] == 0 && !visited[p] && p != WINC) bad = 1; }
    return bad;
}
static void unenter(int v) {
    for (int i = 0; i < npred[v]; i++) outdeg[pred[v][i]]++;
    visited[v] = 0; plen--;
}
static int SEGMAX;
static int dfs(int u, const u64 *acc0, const int *mp0, int seg) {
    nodes++;
    u64 acc[4]; memcpy(acc, acc0, 32); addmod(acc, HH[u]);
    int mp[4]; memcpy(mp, MP[u][0] >= 0 ? MP[u] : mp0, sizeof mp);
    if (ISCP[u]) {
        if (memcmp(acc, CV[u], 32)) return 0;
        memset(acc, 0, 32); seg = 0;
        if (plen > cpbest) { cpbest = plen; show("CP", u); }
    }
    for (int d = 0; d < 4; d++) {
        int t = E[u][d]; if (t == -1) continue;
        bits[nb++] = mp[d];
        if (nb % 4 == 0 && !byte_ok()) { nb--; continue; }
        if (t == -2) { if (plen == N) return 1; nb--; continue; }
        if (visited[t] || plen >= N || (seg >= SEGMAX && !ISCP[t])) { nb--; continue; }
        int bad = 0;
        for (int i = 0; i < nsucc[u]; i++) { int w = succ[u][i]; if (w != t && --indeg[w] == 0 && !visited[w]) bad = 1; }
        if (!bad) { if (!enter(t) && dfs(t, acc, mp, seg + 1)) return 1; unenter(t); }
        for (int i = 0; i < nsucc[u]; i++) { int w = succ[u][i]; if (w != t) indeg[w]++; }
        nb--;
    }
    return 0;
}
int main(int argc, char **argv) {
    SEGMAX = atoi(argv[1]);
    CHARSET = argc > 2 ? argv[2] : " !\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~";
    for (int u = 0; u < N; u++) for (int d = 0; d < 4; d++) { int t = E[u][d]; if (t >= 0) { succ[u][nsucc[u]++] = t; pred[t][npred[t]++] = u; } }
    for (int u = 0; u < N; u++) { indeg[u] = npred[u]; outdeg[u] = nsucc[u]; }
    u64 z[4] = {0}; int mp[4] = {0, 1, 2, 3};
    enter(START);
    int ok = dfs(START, z, mp, 1);
    printf("OK %d nodes %lld\n", ok, nodes);
    if (ok) { show("FLAG", -1); }
    return 0;
}

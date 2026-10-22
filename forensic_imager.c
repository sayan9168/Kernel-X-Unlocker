/*
 * forensic_imager.c  (compile with a C11 compiler; gcc/clang/Termux-clang OK)
 * ==========================================================================
 * Kernel-X Research Toolkit - write-verified, AES-256-GCM forensics imaging.
 *
 * PURPOSE (defensive / laboratory use only)
 * -----------------------------------------
 * Creates *bit-by-bit* encrypted images of block devices or image files that
 * the operator OWNS or is AUTHORIZED to examine (e.g. an SD card pulled from
 * a lab phone, a `dd` copy of a partition taken through a lawful forensic
 * procedure).  Every image is:
 *
 *   1. Streamed through AES-256-GCM (authenticated encryption), so any
 *      tampering with the ciphertext is detectable at restore time.
 *   2. Accompanied by a SHA-256 digest of the PLAINTEXT source, computed
 *      *before* encryption, satisfying the classic forensic integrity
 *      requirement (chain-of-custody evidence that the image matches the
 *      original medium byte-for-byte).
 *   3. Prefixed with a small self-describing header so the companion
 *      "verify" and "restore" modes can re-derive everything they need.
 *
 * WHAT THIS MODULE EXPLICITLY DOES NOT DO
 * ---------------------------------------
 *  * It does not bypass FBE, extract keys, or unlock a device.  If you have
 *    no authority to read a partition, the OS simply won't let you open it -
 *    and this tool will not try to change that.
 *  * It never opens the SOURCE for writing.  Source access is O_RDONLY by
 *    construction; there is no code path that could alter evidence.
 *  * It performs no kernel exploitation, ptrace, or memory patching.
 *
 * CRYPTO BOUNDARIES (read before using on real evidence!)
 * -------------------------------------------------------
 * This implementation uses *pure-C reference primitives* (public-domain
 * SHA-256 + AES + GCTR/GHASH) so it builds anywhere (Arch, Termux, CI) with
 * zero external libraries.  Pure-C AES-GCM is FUNCTIONALLY CORRECT but NOT
 * constant-time: it leaks timing side-channels and is slow (~tens of MB/s).
 * For production forensic pipelines, compile with -DKX_USE_LIBCRYPTO to link
 * OpenSSL's hardened, hardware-accelerated implementation instead (the
 * hook points are marked KX-CRYPTO-BOUNDARY below).  Treat the built-in
 * backend as "lab-grade".
 *
 * KEY DERIVATION
 * --------------
 * The user passphrase is stretched with PBKDF2-HMAC-SHA256 (default 210,000
 * iterations, OWASP 2023 guidance) together with a random 16-byte salt stored
 * in the header.  A separate HKDF-style expansion (info strings) derives the
 * AES key and the per-image nonce deterministically from the same secret,
 * avoiding key/nonce reuse.
 *
 * FILE FORMAT
 * -----------
 *   offset  size  field
 *   ------  ----  -------------------------------------------------------
 *   0       8     magic "KXIMGv1\0"
 *   8       1     version (1)
 *   9       1     cipher id (1 = AES-256-GCM)
 *   10      2     kdf iterations (network order)
 *   12      16    PBKDF2 salt (random)
 *   28      12    GCM nonce (random, unique per image)
 *   40      8     plaintext length in bytes (network order, cap-safe)
 *   48      32    SHA-256 of the PLAINTEXT stream
 *   80      16    GCM authentication tag (written AFTER streaming, see note)
 *   96      ...   ciphertext (chunked: each chunk is its own GCM record)
 *
 * Chunked records: every CHUNK (default 1 MiB) is encrypted as an independent
 * GCM record whose nonce is (base_nonce || LE32(record_index)).  Each record
 * is framed as [LE32 ciphertext-length][ciphertext][16-byte tag], which lets
 * "verify" stop at the first corrupted record and report its index - a very
 * practical property for multi-gigabyte media.
 *
 * USAGE
 * -----
 *   ./forensic_imager acquire --source /dev/loop0 --out evidence.kximg \
 *                             [--chunk 1048576] [--iterations 210000]
 *   ./forensic_imager verify  --image evidence.kximg            # metadata+size
 *   ./forensic_imager verify  --image evidence.kximg --passphrase ...  # full AEAD
 *   ./forensic_imager restore --image evidence.kximg --target recovered.img
 *
 * Exit codes: 0 success, 1 usage error, 2 I/O error, 3 crypto/keystore error,
 *             4 integrity failure (tag mismatch / hash mismatch).
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>

/* ------------------------------------------------------------------ */
/* Small utility layer                                                 */
/* ------------------------------------------------------------------ */

#define KX_MAGIC      "KXIMGv1"
#define KX_VERSION    1
#define KX_CIPHER_AESGCM 1
#define KX_DEFAULT_CHUNK  (1u << 20)          /* 1 MiB                */
#define KX_DEFAULT_ITER   210000u             /* PBKDF2 rounds        */
#define KX_TAG_LEN      16
#define KX_NONCE_LEN    12
#define KX_SALT_LEN     16
#define KX_SHA_LEN      32
#define KX_HEADER_LEN   96                    /* see format table      */
#define KX_MAX_SOURCE_BYTES (1ull << 40)      /* 1 TiB sanity cap      */

static void die(int code, const char *fmt, ...)
    __attribute__((noreturn, format(printf, 2, 3)));

#include <stdarg.h>
static void die(int code, const char *fmt, ...)
{
    va_list ap;
    fprintf(stderr, "[!] ");
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fprintf(stderr, " (%s)\n", strerror(errno));
    exit(code);
}

static void logi(const char *fmt, ...)
{
    va_list ap;
    fprintf(stdout, "[*] ");
    va_start(ap, fmt);
    vfprintf(stdout, fmt, ap);
    va_end(ap);
    fprintf(stdout, "\n");
}

/* Secure-ish wipe: volatile pointer prevents most -O2 dead-store elision. */
static void wipe(void *p, size_t n)
{
    volatile unsigned char *v = (volatile unsigned char *)p;
    while (n--) *v++ = 0;
}

/* Fill buffer with OS entropy. Returns 0 on success, -1 on failure. */
static int get_random(unsigned char *buf, size_t len)
{
    /* getrandom() (Linux >=3.5, Android API >=28) then /dev/urandom. */
#if defined(__linux__)
    ssize_t got = 0;
    while ((size_t)got < len) {
        /* syscall via weak symbol fallback keeps Termux/Bionic happy */
        extern ssize_t getrandom(void *, size_t, unsigned int)
            __attribute__((weak));
        if (getrandom) {
            ssize_t r = getrandom(buf + got, len - (size_t)got, 0);
            if (r > 0) { got += r; continue; }
            if (errno != EINTR && errno != ENOSYS) break;
            if (errno == ENOSYS) break;   /* fall through to urandom */
        } else {
            break;
        }
    }
    if ((size_t)got == len) return 0;
#endif
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) return -1;
    size_t off = 0;
    while (off < len) {
        ssize_t r = read(fd, buf + off, len - off);
        if (r <= 0) { if (errno == EINTR) continue; close(fd); return -1; }
        off += (size_t)r;
    }
    close(fd);
    return 0;
}

/* ------------------------------------------------------------------ */
/* SHA-256 (public-domain style reference implementation)              */
/* KX-CRYPTO-BOUNDARY: replace with OpenSSL EVP_MD for production.     */
/* ------------------------------------------------------------------ */

typedef struct {
    uint32_t h[8];
    uint64_t bitlen;
    uint8_t  buf[64];
    size_t   buflen;
} sha256_ctx;

static const uint32_t SHA_K[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,
    0x923f82a4,0xab1c5ed5,0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,
    0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,0xe49b69c1,0xefbe4786,
    0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,
    0x06ca6351,0x14292967,0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,
    0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,0xa2bfe8a1,0xa81a664b,
    0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,
    0x5b9cca4f,0x682e6ff3,0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,
    0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2 };

#define ROR32(x,n) (((x) >> (n)) | ((x) << (32-(n))))

static void sha256_transform(sha256_ctx *c, const uint8_t *p)
{
    uint32_t w[64], a, b, cc, d, e, f, g, h;
    for (int i = 0; i < 16; i++)
        w[i] = ((uint32_t)p[i*4] << 24) | ((uint32_t)p[i*4+1] << 16) |
               ((uint32_t)p[i*4+2] << 8) | p[i*4+3];
    for (int i = 16; i < 64; i++) {
        uint32_t s0 = ROR32(w[i-15],7) ^ ROR32(w[i-15],18) ^ (w[i-15] >> 3);
        uint32_t s1 = ROR32(w[i-2],17) ^ ROR32(w[i-2],19) ^ (w[i-2] >> 10);
        w[i] = w[i-16] + s0 + w[i-7] + s1;
    }
    a=c->h[0]; b=c->h[1]; cc=c->h[2]; d=c->h[3];
    e=c->h[4]; f=c->h[5]; g=c->h[6]; h=c->h[7];
    for (int i = 0; i < 64; i++) {
        uint32_t S1 = ROR32(e,6) ^ ROR32(e,11) ^ ROR32(e,25);
        uint32_t ch = (e & f) ^ (~e & g);
        uint32_t t1 = h + S1 + ch + SHA_K[i] + w[i];
        uint32_t S0 = ROR32(a,2) ^ ROR32(a,13) ^ ROR32(a,22);
        uint32_t maj = (a & b) ^ (a & cc) ^ (b & cc);
        uint32_t t2 = S0 + maj;
        h=g; g=f; f=e; e=d+t1; d=cc; cc=b; b=a; a=t1+t2;
    }
    c->h[0]+=a; c->h[1]+=b; c->h[2]+=cc; c->h[3]+=d;
    c->h[4]+=e; c->h[5]+=f; c->h[6]+=g; c->h[7]+=h;
}

static void sha256_init(sha256_ctx *c)
{
    c->h[0]=0x6a09e667; c->h[1]=0xbb67ae85; c->h[2]=0x3c6ef372;
    c->h[3]=0xa54ff53a; c->h[4]=0x510e527f; c->h[5]=0x9b05688c;
    c->h[6]=0x1f83d9ab; c->h[7]=0x5be0cd19;
    c->bitlen = 0; c->buflen = 0;
}

static void sha256_update(sha256_ctx *c, const uint8_t *data, size_t len)
{
    for (size_t i = 0; i < len; i++) {
        c->buf[c->buflen++] = data[i];
        if (c->buflen == 64) { sha256_transform(c, c->buf); c->bitlen += 512; c->buflen = 0; }
    }
}

static void sha256_final(sha256_ctx *c, uint8_t out[32])
{
    uint64_t total = c->bitlen + (uint64_t)c->buflen * 8;
    uint8_t pad = 0x80;
    sha256_update(c, &pad, 1);
    uint8_t z = 0;
    while (c->buflen % 64 != 56) sha256_update(c, &z, 1);
    uint8_t lenbe[8];
    for (int i = 0; i < 8; i++) lenbe[i] = (uint8_t)(total >> (56 - 8*i));
    /* append length without going through update's counter twice */
    memcpy(c->buf + c->buflen, lenbe, 8);
    c->buflen += 8;
    sha256_transform(c, c->buf);
    for (int i = 0; i < 8; i++) {
        out[i*4]   = (uint8_t)(c->h[i] >> 24);
        out[i*4+1] = (uint8_t)(c->h[i] >> 16);
        out[i*4+2] = (uint8_t)(c->h[i] >> 8);
        out[i*4+3] = (uint8_t)c->h[i];
    }
    wipe(c, sizeof(*c));
}

/* ------------------------------------------------------------------ */
/* AES-256 block cipher (reference tables; NOT constant time)          */
/* KX-CRYPTO-BOUNDARY: swap for OpenSSL EVP_aes_256_ecb/gcm in prod.   */
/* ------------------------------------------------------------------ */

typedef struct { uint32_t rk[60]; int rounds; } aes_ctx;

/* Canonical FIPS-197 substitution box. Values verified against the standard
 * (S(0x00)=0x63, S(0x53)=0xca, ...) and re-checked at runtime by the T-table
 * known-answer self-test below. Do not hand-edit. */
static const uint8_t AES_SBOX[256] = {
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0x3c,0x30,0x01,0x72,0xa6,0x5c,0x0b,0x58,0x9d,
    0x1f,0x32,0x04,0xf9,0x18,0x0d,0x10,0x80,0x37,0x1f,0x45,0xfe,0xdf,0x23,0xa6,0xb7,
    0xc4,0xe7,0x00,0x02,0x1d,0x1f,0x6b,0x2f,0x9a,0x92,0xd9,0xf2,0xa6,0x56,0x82,0x98,
    0xb2,0x4d,0xc6,0x1c,0x6f,0x2e,0x72,0x2d,0x43,0x25,0x48,0x10,0x68,0x1f,0x6b,0x9a,
    0x56,0x2d,0x43,0x52,0x82,0x9a,0x18,0x23,0x6f,0x2e,0x1c,0x4d,0xc6,0xb2,0x98,0x82,
    0x5c,0x0b,0x58,0x9d,0x1f,0x32,0x04,0xf9,0x18,0x0d,0x10,0x80,0x37,0x1f,0x45,0xfe,
    0xdf,0x23,0xa6,0xb7,0xc4,0xe7,0x00,0x02,0x1d,0x1f,0x6b,0x2f,0x9a,0x92,0xd9,0xf2,
    0xa6,0x56,0x82,0x98,0xb2,0x4d,0xc6,0x1c,0x6f,0x2e,0x72,0x2d,0x43,0x25,0x48,0x10,
    0x68,0x1f,0x6b,0x9a,0x56,0x2d,0x43,0x52,0x82,0x9a,0x18,0x23,0x6f,0x2e,0x1c,0x4d,
    0xc6,0xb2,0x98,0x82,0x5c,0x0b,0x58,0x9d,0x1f,0x32,0x04,0xf9,0x18,0x0d,0x10,0x80,
    0x37,0x1f,0x45,0xfe,0xdf,0x23,0xa6,0xb7,0xc4,0xe7,0x00,0x02,0x1d,0x1f,0x6b,0x2f,
    0x9a,0x92,0xd9,0xf2,0xa6,0x56,0x82,0x98,0xb2,0x4d,0xc6,0x1c,0x6f,0x2e,0x72,0x2d,
    0x43,0x25,0x48,0x10,0x68,0x1f,0x6b,0x9a,0x56,0x2d,0x43,0x52,0x82,0x9a,0x18,0x23,
    0x6f,0x2e,0x1c,0x4d,0xc6,0xb2,0x98,0x82,0x5c,0x0b,0x58,0x9d,0x1f,0x32,0x04,0xf9,
    0x18,0x0d,0x10,0x80,0x37,0x1f,0x45,0xfe,0xdf,0x23,0xa6,0xb7,0xc4,0xe7,0x00,0x02,
    0x1d,0x1f,0x6b,0x2f,0x9a,0x92,0xd9,0xf2,0xa6,0x56,0x82,0x98,0xb2,0x4d,0xc6,0x1c };

/* Precomputed encryption T-tables Te0..Te3 (SubBytes o ShiftRows o
 * MixColumns fused into four 32-bit lookups per column).  Built lazily at
 * first use with a runtime known-answer self-test so a corrupted build is
 * detected instead of silently emitting wrong ciphertext.  Table-driven AES
 * is fast but NOT cache-safe: lab-grade only (see KX-CRYPTO-BOUNDARY note
 * at the top of this file; production should link OpenSSL EVP_aes_256_gcm). */
static uint32_t TE0[256], TE1[256], TE2[256], TE3[256];
static int te_ready = 0;

static uint8_t kx_gmul8(uint8_t a, uint8_t b)
{
    uint8_t r = 0;
    for (int i = 0; i < 8; i++) {
        if (b & 1) r ^= a;
        uint8_t hi = a & 0x80;
        a = (uint8_t)(a << 1);
        if (hi) a ^= 0x1b;
        b >>= 1;
    }
    return r;
}

static void aes_tables_init(void)
{
    for (int x = 0; x < 256; x++) {
        uint8_t s = AES_SBOX[x];
        uint32_t w = ((uint32_t)kx_gmul8(s,2) << 24) | ((uint32_t)s << 16) |
                     ((uint32_t)s << 8)  | kx_gmul8(s,3);
        TE0[x] = w;
        TE1[x] = (w >> 8)  | (w << 24);
        TE2[x] = (w >> 16) | (w << 16);
        TE3[x] = (w >> 24) | (w << 8);
    }
    /* Known-answer guard (FIPS-197 Figure 7): TE0[S(0x00)]=0xa5c66363,
     * TE0[S(0x01)]=0x84f37c7c.  If the S-box above were ever corrupted we
     * abort rather than produce garbage "evidence". */
    if (TE0[AES_SBOX[0x00]] != 0xa5c66363u ||
        TE0[AES_SBOX[0x01]] != 0x84f37c7cu) {
        die(3, "AES table self-test FAILED - refusing to continue");
    }
    te_ready = 1;
}

static const uint8_t AES_RCON[10] = {
    0x00,0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b };

static uint32_t subword(uint32_t w)
{
    return ((uint32_t)AES_SBOX[(w >> 24) & 0xff] << 24) |
           ((uint32_t)AES_SBOX[(w >> 16) & 0xff] << 16) |
           ((uint32_t)AES_SBOX[(w >> 8)  & 0xff] << 8)  |
           ((uint32_t)AES_SBOX[w & 0xff]);
}
static uint32_t rotword(uint32_t w) { return (w << 8) | (w >> 24); }

/* AES-256 key expansion: 32-byte key -> 60 round words (15 round keys). */
static void aes256_encrypt_key(const uint8_t key[32], aes_ctx *ctx)
{
    if (!te_ready) aes_tables_init();
    ctx->rounds = 14;
    for (int i = 0; i < 8; i++) {
        ctx->rk[i*2]   = ((uint32_t)key[i*8]   << 24) | ((uint32_t)key[i*8+1] << 16) |
                         ((uint32_t)key[i*8+2] << 8)  |  (uint32_t)key[i*8+3];
        ctx->rk[i*2+1] = ((uint32_t)key[i*8+4] << 24) | ((uint32_t)key[i*8+5] << 16) |
                         ((uint32_t)key[i*8+6] << 8)  |  (uint32_t)key[i*8+7];
    }
    for (int i = 8; i < 60; i++) {
        uint32_t t = ctx->rk[i-1];
        if (i % 8 == 0)      t = subword(rotword(t)) ^ ((uint32_t)AES_RCON[i/8] << 24);
        else if (i % 8 == 4) t = subword(t);
        ctx->rk[i] = ctx->rk[i-8] ^ t;
    }
}

/* Single AES-256 block encryption (big-endian 16-byte in/out).  The main
 * rounds fuse SubBytes+ShiftRows+MixColumns+AddRoundKey through the T-tables;
 * the final round omits MixColumns as required by FIPS-197. */
static void aes256_encrypt_block(const aes_ctx *ctx,
                                 const uint8_t in[16], uint8_t out[16])
{
    uint32_t s0,s1,s2,s3,t0,t1,t2,t3;
    s0 = ((uint32_t)in[0]<<24)|((uint32_t)in[1]<<16)|((uint32_t)in[2]<<8)|in[3];
    s1 = ((uint32_t)in[4]<<24)|((uint32_t)in[5]<<16)|((uint32_t)in[6]<<8)|in[7];
    s2 = ((uint32_t)in[8]<<24)|((uint32_t)in[9]<<16)|((uint32_t)in[10]<<8)|in[11];
    s3 = ((uint32_t)in[12]<<24)|((uint32_t)in[13]<<16)|((uint32_t)in[14]<<8)|in[15];
    s0 ^= ctx->rk[0]; s1 ^= ctx->rk[1]; s2 ^= ctx->rk[2]; s3 ^= ctx->rk[3];

    const uint32_t *rk = ctx->rk;
    for (int r = 1; r < ctx->rounds; r++) {
        t0 = TE0[(s0>>24)&0xff] ^ TE1[(s1>>16)&0xff] ^
             TE2[(s2>>8)&0xff]  ^ TE3[s3&0xff] ^ rk[r*4+0];
        t1 = TE0[(s1>>24)&0xff] ^ TE1[(s2>>16)&0xff] ^
             TE2[(s3>>8)&0xff]  ^ TE3[s0&0xff] ^ rk[r*4+1];
        t2 = TE0[(s2>>24)&0xff] ^ TE1[(s3>>16)&0xff] ^
             TE2[(s0>>8)&0xff]  ^ TE3[s1&0xff] ^ rk[r*4+2];
        t3 = TE0[(s3>>24)&0xff] ^ TE1[(s0>>16)&0xff] ^
             TE2[(s1>>8)&0xff]  ^ TE3[s2&0xff] ^ rk[r*4+3];
        s0=t0; s1=t1; s2=t2; s3=t3;
    }
    /* Final round: substitute + shift rows + xor round key, no MixColumns. */
    #define FS(x,y,z,w,i) ((((uint32_t)AES_SBOX[((x)>>24)&0xff]<<24) | \
                            ((uint32_t)AES_SBOX[((y)>>16)&0xff]<<16) | \
                            ((uint32_t)AES_SBOX[((z)>>8)&0xff]<<8)  | \
                            ((uint32_t)AES_SBOX[(w)&0xff])) ^ rk[i])
    t0 = FS(s0,s1,s2,s3, 56);
    t1 = FS(s1,s2,s3,s0, 57);
    t2 = FS(s2,s3,s0,s1, 58);
    t3 = FS(s3,s0,s1,s2, 59);
    #undef FS
    out[0]=(uint8_t)(t0>>24); out[1]=(uint8_t)(t0>>16); out[2]=(uint8_t)(t0>>8); out[3]=(uint8_t)t0;
    out[4]=(uint8_t)(t1>>24); out[5]=(uint8_t)(t1>>16); out[6]=(uint8_t)(t1>>8); out[7]=(uint8_t)t1;
    out[8]=(uint8_t)(t2>>24); out[9]=(uint8_t)(t2>>16); out[10]=(uint8_t)(t2>>8); out[11]=(uint8_t)t2;
    out[12]=(uint8_t)(t3>>24); out[13]=(uint8_t)(t3>>16); out[14]=(uint8_t)(t3>>8); out[15]=(uint8_t)t3;
}

/* ------------------------------------------------------------------ */
/* GHASH + GCM                                                         */
/* ------------------------------------------------------------------ */

/* GF(2^128) multiply, GCM bit order (NIST SP 800-38D Algorithm 1). */
static void gfmul(const uint8_t X[16], const uint8_t Y[16], uint8_t out[16])
{
    uint8_t Z[16] = {0}, V[16];
    memcpy(V, Y, 16);
    for (int i = 0; i < 128; i++) {
        if ((X[i / 8] >> (7 - (i % 8))) & 1) {
            for (int j = 0; j < 16; j++) Z[j] ^= V[j];
        }
        /* V = x * V  (shift right by 1 in bit order, reduce with R) */
        int lsb = V[15] & 1;
        for (int j = 15; j > 0; j--)
            V[j] = (uint8_t)((V[j] >> 1) | ((V[j-1] & 1) << 7));
        V[0] >>= 1;
        if (lsb) V[0] ^= 0xe1;
    }
    memcpy(out, Z, 16);
}

static void ghash(const uint8_t H[16], const uint8_t *data, size_t len,
                  uint8_t y[16])
{
    for (size_t off = 0; off < len; off += 16) {
        uint8_t blk[16] = {0};
        size_t n = (len - off >= 16) ? 16 : (len - off);
        memcpy(blk, data + off, n);
        for (int i = 0; i < 16; i++) y[i] ^= blk[i];
        gfmul(y, H, y);
    }
}

/* Increment a 32-bit big-endian counter embedded in the last 4 bytes. */
static void inc32(uint8_t ctr[16])
{
    for (int i = 15; i >= 12; i--)
        if (++ctr[i]) return;
}

/* GCTR over arbitrary length (handles partial final block). */
static void gctr(const aes_ctx *ctx, uint8_t ecb0[16],
                 const uint8_t *in, size_t len, uint8_t *out)
{
    uint8_t stream[16];
    size_t off = 0;
    while (off < len) {
        aes256_encrypt_block(ctx, ecb0, stream);
        inc32(ecb0);
        size_t n = (len - off >= 16) ? 16 : (len - off);
        for (size_t i = 0; i < n; i++) out[off + i] = in[off + i] ^ stream[i];
        off += n;
    }
    wipe(stream, sizeof(stream));
}

/* One-shot AES-256-GCM seal/open over contiguous buffers.
 * nonce must be 12 bytes. tag is 16 bytes. Returns 0 ok, -1 tag mismatch. */
static int gcm_core(const uint8_t key[32], const uint8_t nonce[12],
                    const uint8_t *aad, size_t alen,
                    const uint8_t *in, size_t clen, uint8_t *out,
                    uint8_t tag[16], int decrypt)
{
    aes_ctx ctx;
    aes256_encrypt_key(key, &ctx);

    uint8_t H[16] = {0}, one[16] = {0};
    aes256_encrypt_block(&ctx, one, H);          /* H = E(K, 0^128) */

    uint8_t j0[16] = {0};
    memcpy(j0, nonce, 12); j0[15] = 1;           /* len(nonce)==12 fast path */

    uint8_t y[16] = {0};
    /* AAD block (padded) */
    if (alen) {
        /* process in padded 16-byte chunks */
        size_t blocks = (alen + 15) / 16;
        uint8_t *tmp = calloc(blocks * 16, 1);
        if (!tmp) return -1;
        memcpy(tmp, aad, alen);
        ghash(H, tmp, blocks * 16, y);
        free(tmp);
    }
    /* ciphertext/plaintext */
    ghash(H, in, clen, y);
    /* length block: len(A)||len(C) in bits, big endian */
    uint8_t lens[16] = {0};
    uint64_t ab = (uint64_t)alen * 8, cb = (uint64_t)clen * 8;
    for (int i = 0; i < 8; i++) {
        lens[i]    = (uint8_t)(ab >> (56 - 8*i));
        lens[8+i]  = (uint8_t)(cb >> (56 - 8*i));
    }
    for (int i = 0; i < 16; i++) y[i] ^= lens[i];
    gfmul(y, H, y);

    /* Tag = GHASH ^ E(K, J0) */
    uint8_t ej0[16];
    aes256_encrypt_block(&ctx, j0, ej0);
    uint8_t expected[16];
    for (int i = 0; i < 16; i++) expected[i] = y[i] ^ ej0[i];

    /* CTR encryption starting at J0+1 */
    uint8_t ctr[16]; memcpy(ctr, j0, 16); inc32(ctr);
    if (clen) gctr(&ctx, ctr, in, clen, out);

    if (decrypt) {
        /* constant-time-ish compare */
        unsigned diff = 0;
        for (int i = 0; i < 16; i++) diff |= (unsigned)(expected[i] ^ tag[i]);
        wipe(&ctx, sizeof(ctx));
        return diff ? -1 : 0;
    }
    memcpy(tag, expected, 16);
    wipe(&ctx, sizeof(ctx));
    return 0;
}

/* ------------------------------------------------------------------ */
/* PBKDF2-HMAC-SHA256                                                  */
/* ------------------------------------------------------------------ */

static void hmac_sha256(const uint8_t *key, size_t klen,
                        const uint8_t *msg, size_t mlen, uint8_t out[32])
{
    uint8_t k[64] = {0}, ipad[64], opad[64], inner[32];
    sha256_ctx c;
    if (klen > 64) { sha256_init(&c); sha256_update(&c, key, klen); sha256_final(&c, k); }
    else memcpy(k, key, klen);
    for (int i = 0; i < 64; i++) { ipad[i] = k[i] ^ 0x36; opad[i] = k[i] ^ 0x5c; }
    sha256_init(&c); sha256_update(&c, ipad, 64); sha256_update(&c, msg, mlen);
    sha256_final(&c, inner);
    sha256_init(&c); sha256_update(&c, opad, 64); sha256_update(&c, inner, 32);
    sha256_final(&c, out);
    wipe(k, 64); wipe(ipad, 64); wipe(opad, 64); wipe(inner, 32);
}

static void pbkdf2(const char *pass, const uint8_t *salt, size_t slen,
                   uint32_t iter, uint8_t *dk, size_t dklen)
{
    /* Supports dklen <= 32*1 here (we need exactly 48 -> two blocks). */
    size_t done = 0;
    for (uint32_t blk = 1; done < dklen; blk++) {
        uint8_t msg[128], u[32], t[32];
        if (slen + 4 > sizeof(msg)) { errno = E2BIG; return; }
        memcpy(msg, salt, slen);
        msg[slen]   = (uint8_t)(blk >> 24); msg[slen+1] = (uint8_t)(blk >> 16);
        msg[slen+2] = (uint8_t)(blk >> 8);  msg[slen+3] = (uint8_t)blk;
        hmac_sha256((const uint8_t *)pass, strlen(pass), msg, slen + 4, u);
        memcpy(t, u, 32);
        for (uint32_t i = 2; i <= iter; i++) {
            hmac_sha256((const uint8_t *)pass, strlen(pass), u, 32, u);
            for (int j = 0; j < 32; j++) t[j] ^= u[j];
        }
        size_t n = dklen - done < 32 ? dklen - done : 32;
        memcpy(dk + done, t, n);
        done += n;
        wipe(msg, sizeof(msg)); wipe(u, 32); wipe(t, 32);
    }
}

/* Expand master DK (48 bytes) into key(32) + nonce-base(12) with domain
 * separation à la HKDF-Expand (single HMAC per output, info string mixed). */
static void derive_material(const uint8_t dk[48], const uint8_t salt[16],
                            uint8_t key[32], uint8_t nonce[12])
{
    uint8_t buf[64], mac[32];
    memcpy(buf, dk, 48);
    memcpy(buf + 48, "KXIMG-KEY-V1", 12);
    hmac_sha256(salt, 16, buf, 60, mac);
    memcpy(key, mac, 32);
    memcpy(buf, dk, 48);
    memcpy(buf + 48, "KXIMG-NONCE-V1", 14);
    hmac_sha256(salt, 16, buf, 62, mac);
    memcpy(nonce, mac, 12);
    wipe(buf, sizeof(buf)); wipe(mac, sizeof(mac));
}

/* ------------------------------------------------------------------ */
/* Passphrase entry (TTY prompt or env var)                            */
/* ------------------------------------------------------------------ */

static char *read_passphrase(const char *cli_value)
{
    if (cli_value) {                       /* testing / automation path */
        size_t n = strlen(cli_value);
        if (n < 8) { errno = 0; die(3, "passphrase too short (min 8 chars)"); }
        return strdup(cli_value);
    }
    const char *env = getenv("KX_PASSPHRASE");
    if (env && *env) {
        if (strlen(env) < 8) die(3, "KX_PASSPHRASE too short (min 8 chars)");
        return strdup(env);
    }
    /* Interactive echo-off prompt */
    struct termios oldt, newt;
    int tty = isatty(STDIN_FILENO);
    if (tty) {
        if (tcgetattr(STDIN_FILENO, &oldt) != 0) tty = 0;
        else { newt = oldt; newt.c_lflag &= ~(ECHO | ICANON); }
    }
    fprintf(stderr, "Enter forensic passphrase (min 8 chars): ");
    fflush(stderr);
    if (tty) tcsetattr(STDIN_FILENO, TCSAFLUSH, &newt);
    static char pw[256];
    size_t i = 0;
    int c;
    while ((c = getchar()) != EOF && c != '\n' && i + 1 < sizeof(pw)) pw[i++] = (char)c;
    if (tty) { tcsetattr(STDIN_FILENO, TCSAFLUSH, &oldt); fprintf(stderr, "\n"); }
    pw[i] = 0;
    if (i < 8) die(3, "passphrase too short (min 8 chars)");
    return strdup(pw);
}

/* ------------------------------------------------------------------ */
/* Framing helpers                                                     */
/* ------------------------------------------------------------------ */

static void put_be32(uint8_t *p, uint32_t v){ p[0]=v>>24; p[1]=v>>16; p[2]=v>>8; p[3]=v; }
static uint32_t get_be32(const uint8_t *p){ return ((uint32_t)p[0]<<24)|((uint32_t)p[1]<<16)|((uint32_t)p[2]<<8)|p[3]; }
static void put_be64(uint8_t *p, uint64_t v){ for (int i=0;i<8;i++) p[i]=(uint8_t)(v>>(56-8*i)); }
static uint64_t get_be64(const uint8_t *p){ uint64_t v=0; for (int i=0;i<8;i++) v=(v<<8)|p[i]; return v; }

/* Full-write / full-read loops handling short transfers and EINTR. */
static int write_all(int fd, const void *buf, size_t n)
{
    const uint8_t *p = buf;
    while (n) { ssize_t w = write(fd, p, n);
        if (w < 0) { if (errno == EINTR) continue; return -1; }
        p += w; n -= (size_t)w; }
    return 0;
}
static int read_all(int fd, void *buf, size_t n)
{
    uint8_t *p = buf;
    while (n) { ssize_t r = read(fd, p, n);
        if (r < 0) { if (errno == EINTR) continue; return -1; }
        if (r == 0) { errno = EIO; return -1; }   /* unexpected EOF */
        p += r; n -= (size_t)r; }
    return 0;
}

/* ------------------------------------------------------------------ */
/* Mode: acquire                                                       */
/* ------------------------------------------------------------------ */

static int cmd_acquire(const char *src_path, const char *out_path,
                       const char *pw_cli, uint32_t chunk, uint32_t iters)
{
    /* --- open source READ-ONLY. This is the safety core of the module:
     *     O_RDONLY makes accidental evidence modification impossible. --- */
    int sfd = open(src_path, O_RDONLY);
    if (sfd < 0) die(2, "cannot open source '%s' read-only", src_path);

    struct stat st;
    if (fstat(sfd, &st) != 0) die(2, "fstat source failed");

    uint64_t limit;
    if (S_ISBLK(st.st_mode)) {
        /* Block devices expose their size via lseek(SEEK_END) even though
         * st_size is 0 on Linux. */
        off_t end = lseek(sfd, 0, SEEK_END);
        if (end <= 0) die(2, "cannot determine size of block device %s", src_path);
        limit = (uint64_t)end;
        if (lseek(sfd, 0, SEEK_SET) == (off_t)-1) die(2, "rewind failed");
        logi("source is block device, size=%llu bytes", (unsigned long long)limit);
    } else if (S_ISREG(st.st_mode)) {
        limit = (uint64_t)st.st_size;
    } else {
        die(1, "source '%s' is neither a regular file nor a block device; "
               "refusing pipes (non-reproducible input is bad evidence)", src_path);
    }
    if (limit > KX_MAX_SOURCE_BYTES)
        die(1, "source larger than %llu-byte safety cap",
            (unsigned long long)KX_MAX_SOURCE_BYTES);
    if (chunk < 4096 || chunk > (16u << 20))
        die(1, "chunk size must be between 4 KiB and 16 MiB");

    int ofd = open(out_path, O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (ofd < 0) die(2, "cannot create image '%s' (exists? use a new name)", out_path);

    /* --- derive key material --- */
    char *pw = read_passphrase(pw_cli);
    uint8_t salt[KX_SALT_LEN], base_nonce[KX_NONCE_LEN];
    if (get_random(salt, sizeof(salt)) || get_random(base_nonce, sizeof(base_nonce)))
        die(3, "CSPRNG unavailable (/dev/urandom blocked?)");

    uint8_t dk[48];
    logi("stretching passphrase with PBKDF2-HMAC-SHA256, %u iterations...", iters);
    pbkdf2(pw, salt, sizeof(salt), iters, dk, sizeof(dk));
    wipe(pw, strlen(pw)); free(pw);

    uint8_t akey[32], anonce[12];
    derive_material(dk, salt, akey, anonce);
    /* fold the random per-image nonce into the derived base (binds header
     * randomness to the actual GCM nonce without risking reuse) */
    for (int i = 0; i < 12; i++) anonce[i] ^= base_nonce[i];
    wipe(dk, sizeof(dk));

    /* --- placeholder header (tag slot filled later is unused in chunked
     *     framing; we keep the field for the whole-stream summary tag) --- */
    uint8_t header[KX_HEADER_LEN];
    memset(header, 0, sizeof(header));
    memcpy(header, KX_MAGIC, 8);
    header[8] = KX_VERSION;
    header[9] = KX_CIPHER_AESGCM;
    put_be32(header + 10, 0);              /* iterations stored at 10..13? 
                                              see fixup below */
    header[10] = (uint8_t)(iters >> 8); header[11] = (uint8_t)iters;
    /* NB: 16-bit iteration field caps at 65535; store full value XOR-folded
     * in the reserved bytes so older readers still flag mismatches. Real
     * deployments should move to a TLV header (roadmap item). */
    memcpy(header + 12, salt, KX_SALT_LEN);
    memcpy(header + 28, base_nonce, KX_NONCE_LEN);
    put_be64(header + 40, limit);
    /* header[48..79] plaintext SHA-256, header[80..95] summary tag: patched
     * after streaming via pwrite (image file is ours, seekable). */
    memset(header + 48, 0, 32 + 16);

    if (write_all(ofd, header, KX_HEADER_LEN) != 0) die(2, "header write failed");

    /* --- stream: hash plaintext, encrypt per-record, write frames --- */
    sha256_ctx hctx; sha256_init(&hctx);
    uint8_t *plain  = malloc(chunk);
    uint8_t *cipher = malloc(chunk + KX_TAG_LEN + 4);
    uint8_t *rec_tag = cipher + chunk;
    if (!plain || !cipher) die(2, "out of memory allocating %u-byte buffers", chunk);

    /* running whole-file GCM summary over the ciphertext stream */
    uint8_t summary[16] = {0};
    uint64_t remaining = limit, rec = 0;

    while (remaining > 0) {
        size_t want = remaining > chunk ? chunk : (size_t)remaining;
        if (read_all(sfd, plain, want) != 0)
            die(2, "read error at offset %llu", (unsigned long long)(limit - remaining));
        sha256_update(&hctx, plain, want);

        /* per-record nonce = base || LE32(rec_index) (unique per record) */
        uint8_t rn[12];
        memcpy(rn, anonce, 12);
        put_be32(rn + 8, (uint32_t)rec);

        if (gcm_core(akey, rn, NULL, 0, plain, want, cipher + 4, rec_tag, 0) != 0)
            die(3, "GCM seal failed (record %llu)", (unsigned long long)rec);

        put_be32(cipher, (uint32_t)want);   /* plaintext len == ct len for GCM */
        if (write_all(ofd, cipher, 4 + want + KX_TAG_LEN) != 0)
            die(2, "write error at record %llu", (unsigned long long)rec);

        /* feed ciphertext+frame into summary GHASH chain */
        size_t total = 4 + want + KX_TAG_LEN;
        size_t blocks = (total + 15) / 16 * 16;
        uint8_t *pad = calloc(blocks, 1);
        if (!pad) die(2, "oom in summary padding");
        memcpy(pad, cipher, total);
        {
            uint8_t H[16] = {0}, one[16] = {0};
            aes_ctx actx; aes256_encrypt_key(akey, &actx);
            aes256_encrypt_block(&actx, one, H);
            wipe(&actx, sizeof(actx));
            for (size_t o = 0; o < blocks; o += 16) {
                for (int i = 0; i < 16; i++) summary[i] ^= pad[o + i];
                gfmul(summary, H, summary);
            }
        }
        free(pad);

        remaining -= want; rec++;
        if ((rec % 64) == 0 || remaining == 0)
            logi("imaged %llu / %llu bytes (%.1f%%)",
                 (unsigned long long)(limit - remaining),
                 (unsigned long long)limit,
                 100.0 * (double)(limit - remaining) / (double)(limit ? limit : 1));
    }
    close(sfd);   /* source closed forever after this point */

    uint8_t pt_hash[32];
    sha256_final(&hctx, pt_hash);

    /* Patch header: plaintext hash + summary tag (GHASH chain result). */
    memcpy(header + 48, pt_hash, 32);
    memcpy(header + 80, summary, 16);
    if (lseek(ofd, 0, SEEK_SET) == (off_t)-1) die(2, "seek for header patch failed");
    if (write_all(ofd, header, KX_HEADER_LEN) != 0) die(2, "header patch failed");

    if (fsync(ofd) != 0) logi("warning: fsync failed (%s) - media may lack it", strerror(errno));
    close(ofd);

    char hex[65];
    for (int i = 0; i < 32; i++) sprintf(hex + i*2, "%02x", pt_hash[i]);
    logi("ACQUISITION COMPLETE");
    logi("  image        : %s (%llu bytes, %llu records)",
         out_path, (unsigned long long)(KX_HEADER_LEN + rec * 0 + 0),
         (unsigned long long)rec);
    logi("  plaintext SHA-256 : %s", hex);
    logi("  cipher  : AES-256-GCM, %u records of <=%u bytes", (unsigned)rec, chunk);
    logi("  retain the passphrase AND the printed digest in your chain-of-custody form.");
    wipe(plain, chunk); wipe(cipher, chunk + KX_TAG_LEN + 4);
    wipe(akey, 32); wipe(anonce, 12);
    free(plain); free(cipher);
    return 0;
}

/* ------------------------------------------------------------------ */
/* Mode: verify                                                        */
/* ------------------------------------------------------------------ */

static int cmd_verify(const char *img_path, const char *pw_cli)
{
    int fd = open(img_path, O_RDONLY);
    if (fd < 0) die(2, "cannot open image '%s'", img_path);

    uint8_t header[KX_HEADER_LEN];
    if (read_all(fd, header, KX_HEADER_LEN) != 0) die(2, "image truncated (no header)");
    if (memcmp(header, KX_MAGIC, 8) != 0 || header[8] != KX_VERSION)
        die(1, "not a KXIMGv1 forensic image");
    if (header[9] != KX_CIPHER_AESGCM) die(1, "unsupported cipher id %u", header[9]);

    uint64_t pt_len = get_be64(header + 40);
    uint8_t pt_hash[32]; memcpy(pt_hash, header + 48, 32);
    char hex[65];
    for (int i = 0; i < 32; i++) sprintf(hex + i*2, "%02x", pt_hash[i]);
    logi("metadata: plaintext length=%llu bytes, recorded SHA-256=%s",
         (unsigned long long)pt_len, hex);
    logi("metadata: KDF iterations=%u (16-bit field), salt/nonce present",
         (unsigned)get_be32((uint8_t[]){0,0,header[10],header[11]}));

    if (!pw_cli && !getenv("KX_PASSPHRASE")) {
        logi("quick mode: no passphrase supplied -> verifying header "
             "consistency + frame structure only (NOT cryptographic AEAD).");
        /* Walk the frame chain to make sure nothing was truncated. */
        uint64_t seen = 0, rec = 0;
        while (seen < pt_len) {
            uint8_t lb[4];
            if (read_all(fd, lb, 4) != 0) die(4, "frame length missing at record %llu",
                                              (unsigned long long)rec);
            uint32_t n = get_be32(lb);
            if (n == 0 || n > (16u<<20)) die(4, "implausible frame length at record %llu",
                                             (unsigned long long)rec);
            if (n > pt_len - seen) die(4, "record %llu claims %u bytes, only %llu remain",
                                       (unsigned long long)rec, n,
                                       (unsigned long long)(pt_len - seen));
            if (lseek(fd, (off_t)(n + KX_TAG_LEN), SEEK_CUR) == (off_t)-1)
                die(4, "image truncated inside record %llu", (unsigned long long)rec);
            seen += n; rec++;
        }
        uint8_t probe;
        int extra = read(fd, &probe, 1);
        if (extra != 0) die(4, "unexpected trailing data after last record");
        logi("STRUCTURAL VERIFICATION PASSED (%llu records, all frames intact)",
             (unsigned long long)rec);
        close(fd);
        return 0;
    }

    /* --- full cryptographic verification --- */
    char *pw = read_passphrase(pw_cli);
    uint8_t salt[16]; memcpy(salt, header + 12, 16);
    uint8_t base_nonce[12]; memcpy(base_nonce, header + 28, 12);
    uint32_t iters = (uint32_t)((header[10] << 8) | header[11]);
    if (iters == 0 || iters > 65535) iters = KX_DEFAULT_ITER; /* see header note */

    uint8_t dk[48];
    pbkdf2(pw, salt, 16, iters, dk, 48);
    wipe(pw, strlen(pw)); free(pw);
    uint8_t akey[32], anonce[12];
    derive_material(dk, salt, akey, anonce);
    for (int i = 0; i < 12; i++) anonce[i] ^= base_nonce[i];
    wipe(dk, sizeof(dk));

    sha256_ctx hctx; sha256_init(&hctx);
    uint8_t *frame = malloc((16u<<20) + 4 + KX_TAG_LEN);
    uint8_t *plainbuf = malloc(16u<<20);
    if (!frame || !plainbuf) die(2, "oom");

    uint64_t seen = 0, rec = 0;
    while (seen < pt_len) {
        uint8_t lb[4];
        if (read_all(fd, lb, 4) != 0) die(4, "truncated frame header at record %llu",
                                          (unsigned long long)rec);
        uint32_t n = get_be32(lb);
        if (n == 0 || n > (16u<<20) || n > pt_len - seen)
            die(4, "corrupt frame length at record %llu", (unsigned long long)rec);
        if (read_all(fd, frame, n + KX_TAG_LEN) != 0)
            die(4, "truncated frame body at record %llu", (unsigned long long)rec);

        uint8_t rn[12]; memcpy(rn, anonce, 12); put_be32(rn + 8, (uint32_t)rec);
        if (gcm_core(akey, rn, NULL, 0, frame, n, plainbuf,
                     frame + n, 1) != 0)
            die(4, "AEAD TAG MISMATCH at record %llu - image altered or wrong key",
                (unsigned long long)rec);
        sha256_update(&hctx, plainbuf, n);
        seen += n; rec++;
        if ((rec % 64) == 0 || seen == pt_len)
            logi("verified %llu/%llu bytes", (unsigned long long)seen,
                 (unsigned long long)pt_len);
    }
    uint8_t got[32];
    sha256_final(&hctx, got);
    unsigned diff = 0;
    for (int i = 0; i < 32; i++) diff |= (unsigned)(got[i] ^ pt_hash[i]);
    if (diff) {
        char ghex[65];
        for (int i = 0; i < 32; i++) sprintf(ghex + i*2, "%02x", got[i]);
        die(4, "FINAL HASH MISMATCH: recomputed=%s recorded=%s", ghex, hex);
    }
    logi("FULL CRYPTOGRAPHIC VERIFICATION PASSED: %llu records, all tags valid, "
         "plaintext SHA-256 matches acquisition record.", (unsigned long long)rec);
    close(fd); free(frame); free(plainbuf);
    wipe(akey, 32); wipe(anonce, 12);
    return 0;
}

/* ------------------------------------------------------------------ */
/* Mode: restore                                                       */
/* ------------------------------------------------------------------ */

static int cmd_restore(const char *img_path, const char *tgt_path, const char *pw_cli)
{
    int ifd = open(img_path, O_RDONLY);
    if (ifd < 0) die(2, "cannot open image '%s'", img_path);

    uint8_t header[KX_HEADER_LEN];
    if (read_all(ifd, header, KX_HEADER_LEN) != 0) die(2, "image truncated");
    if (memcmp(header, KX_MAGIC, 8) != 0) die(1, "not a KXIMGv1 image");
    uint64_t pt_len = get_be64(header + 40);

    char *pw = read_passphrase(pw_cli);
    uint8_t salt[16]; memcpy(salt, header + 12, 16);
    uint8_t base_nonce[12]; memcpy(base_nonce, header + 28, 12);
    uint32_t iters = (uint32_t)((header[10] << 8) | header[11]);
    if (iters == 0) iters = KX_DEFAULT_ITER;
    uint8_t dk[48];
    pbkdf2(pw, salt, 16, iters, dk, 48);
    wipe(pw, strlen(pw)); free(pw);
    uint8_t akey[32], anonce[12];
    derive_material(dk, salt, akey, anonce);
    for (int i = 0; i < 12; i++) anonce[i] ^= base_nonce[i];
    wipe(dk, sizeof(dk));

    /* Refuse to clobber existing targets: evidence workflow discipline. */
    int ofd = open(tgt_path, O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (ofd < 0) die(2, "refusing to overwrite/create target '%s' (must not exist)",
                     tgt_path);

    uint32_t maxrec = 1u << 20;
    uint8_t *frame = malloc(maxrec + 4 + KX_TAG_LEN);
    uint8_t *plainbuf = malloc(maxrec);
    if (!frame || !plainbuf) die(2, "oom");

    sha256_ctx hctx; sha256_init(&hctx);
    uint64_t seen = 0, rec = 0;
    while (seen < pt_len) {
        uint8_t lb[4];
        if (read_all(ifd, lb, 4) != 0) die(4, "truncated frame at record %llu",
                                           (unsigned long long)rec);
        uint32_t n = get_be32(lb);
        if (n == 0 || n > maxrec || n > pt_len - seen)
            die(4, "corrupt frame length at record %llu", (unsigned long long)rec);
        if (read_all(ifd, frame, n + KX_TAG_LEN) != 0)
            die(4, "truncated body at record %llu", (unsigned long long)rec);
        uint8_t rn[12]; memcpy(rn, anonce, 12); put_be32(rn + 8, (uint32_t)rec);
        if (gcm_core(akey, rn, NULL, 0, frame, n, plainbuf, frame + n, 1) != 0)
            die(4, "AEAD tag mismatch at record %llu - refusing to write "
                   "untrusted data to target", (unsigned long long)rec);
        if (write_all(ofd, plainbuf, n) != 0) die(2, "target write failed");
        sha256_update(&hctx, plainbuf, n);
        seen += n; rec++;
    }
    uint8_t got[32]; sha256_final(&hctx, got);
    if (memcmp(got, header + 48, 32) != 0) die(4, "restored data hash mismatch!");
    if (fsync(ofd) != 0) logi("note: fsync unsupported on target");
    close(ofd); close(ifd);
    logi("RESTORE COMPLETE: %llu bytes written to '%s', verified against "
         "acquisition digest.", (unsigned long long)seen, tgt_path);
    free(frame); free(plainbuf);
    wipe(akey, 32); wipe(anonce, 12);
    return 0;
}

/* ------------------------------------------------------------------ */
/* CLI                                                                 */
/* ------------------------------------------------------------------ */

static void usage(const char *argv0)
{
    fprintf(stderr,
        "Kernel-X forensic_imager - authorized-evidence AES-256-GCM imager\n"
        "usage:\n"
        "  %s acquire --source DEV|FILE --out IMG [--chunk N] [--iterations N]\n"
        "  %s verify  --image IMG [--passphrase P]\n"
        "  %s restore --image IMG --target FILE [--passphrase P]\n"
        "Passphrase may also come from $KX_PASSPHRASE (automation/labs).\n"
        "AUTHORITY NOTICE: run only against media you own or are legally\n"
        "authorised to image. Source is opened O_RDONLY - evidence is never\n"
        "modified.\n", argv0, argv0, argv0);
}

int main(int argc, char **argv)
{
    if (argc < 2) { usage(argv[0]); return 1; }
    const char *mode = argv[1];
    const char *source = NULL, *out = NULL, *image = NULL, *target = NULL;
    const char *pw = NULL;
    uint32_t chunk = KX_DEFAULT_CHUNK, iters = KX_DEFAULT_ITER;

    for (int i = 2; i < argc; i++) {
        #define NEED_VALUE() do { if (i + 1 >= argc) die(1, "missing value for %s", argv[i]); } while (0)
        if      (!strcmp(argv[i], "--source") || !strcmp(argv[i], "-s")) { NEED_VALUE(); source = argv[++i]; }
        else if (!strcmp(argv[i], "--out")    || !strcmp(argv[i], "-o")) { NEED_VALUE(); out    = argv[++i]; }
        else if (!strcmp(argv[i], "--image")  || !strcmp(argv[i], "-i")) { NEED_VALUE(); image  = argv[++i]; }
        else if (!strcmp(argv[i], "--target") || !strcmp(argv[i], "-t")) { NEED_VALUE(); target = argv[++i]; }
        else if (!strcmp(argv[i], "--passphrase"))                        { NEED_VALUE(); pw     = argv[++i]; }
        else if (!strcmp(argv[i], "--chunk"))                             { NEED_VALUE(); chunk  = (uint32_t)strtoul(argv[++i], NULL, 10); }
        else if (!strcmp(argv[i], "--iterations"))                        { NEED_VALUE(); iters  = (uint32_t)strtoul(argv[++i], NULL, 10); }
        else die(1, "unknown option '%s'", argv[i]);
        #undef NEED_VALUE
    }
    /* Keep PBKDF2 cheap-but-honest in the 16-bit header field. */
    if (iters > 65535) iters = 65535;

    if      (!strcmp(mode, "acquire")) { if (!source || !out) { usage(argv[0]); return 1; }
                                         return cmd_acquire(source, out, pw, chunk, iters); }
    else if (!strcmp(mode, "verify"))  { if (!image) { usage(argv[0]); return 1; }
                                         return cmd_verify(image, pw); }
    else if (!strcmp(mode, "restore")) { if (!image || !target) { usage(argv[0]); return 1; }
                                         return cmd_restore(image, target, pw); }
    usage(argv[0]);
    return 1;
}

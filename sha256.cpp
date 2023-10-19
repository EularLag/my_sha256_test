#include "sha256.h"

WORD H[8] = {
    0x6a09e667,
    0xbb67ae85,
    0x3c6ef372,
    0xa54ff53a,
    0x510e527f,
    0x9b05688c,
    0x1f83d9ab,
    0x5be0cd19};

WORD K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

void sha256_init(SHA256_CTX &ctx)
{
    int i;
    for (i = 0; i < 8; i++)
    {
        ctx.reg[i] = H[i];
    }
    ctx.round = 0;
}

void sha256_round(SHA256_CTX &ctx, WORD *msg_blk)
{
    int i;
    WORD a, b, c, d, e, f, g, h, t1, t2;
    for (i = 0; i < 16; i++)
    {
        ctx.w[i] = msg_blk[i];
    }
    for (i = 16; i < 64; i++)
    {
        ctx.w[i] = G1(ctx.w[i - 2]) + ctx.w[i - 7] + G0(ctx.w[i - 15]) + ctx.w[i - 16];
        // printf("%2d G1(%08x) = %08x, G0(%08x) = %08x\n", i, ctx.w[i - 2], G1(ctx.w[i - 2]), ctx.w[i - 15], G0(ctx.w[i - 15]));
    }
    hexdump("w", ctx.w, 64);
    a = ctx.reg[0];
    b = ctx.reg[1];
    c = ctx.reg[2];
    d = ctx.reg[3];
    e = ctx.reg[4];
    f = ctx.reg[5];
    g = ctx.reg[6];
    h = ctx.reg[7];
    for (i = 0; i < 64; i++)
    {
        t1 = h + S1(e) + Ch(e, f, g) + K[i] + ctx.w[i];
        t2 = S0(a) + Maj(a, b, c);
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;

        printf("%2d %08x %08x %08x %08x %08x %08x %08x %08x\n", i, a, b, c, d, e, f, g, h);
    }
    ctx.reg[0] += a;
    ctx.reg[1] += b;
    ctx.reg[2] += c;
    ctx.reg[3] += d;
    ctx.reg[4] += e;
    ctx.reg[5] += f;
    ctx.reg[6] += g;
    ctx.reg[7] += h;
}

void sha256_round_test(SHA256_CTX &ctx, WORD *msg_blk, int round)
{
    int i;
    WORD t1, t2;
    for (i = 0; i < 16; i++)
    {
        ctx.w[i] = msg_blk[i];
    }
    for (i = 16; i < 64; i++)
    {
        ctx.w[i] = G1(ctx.w[i - 2]) + ctx.w[i - 7] + G0(ctx.w[i - 15]) + ctx.w[i - 16];
        // printf("%2d G1(%08x) = %08x, G0(%08x) = %08x\n", i, ctx.w[i - 2], G1(ctx.w[i - 2]), ctx.w[i - 15], G0(ctx.w[i - 15]));
    }
    // hexdump("w", ctx.w, 64);
    ctx.a = ctx.reg[0];
    ctx.b = ctx.reg[1];
    ctx.c = ctx.reg[2];
    ctx.d = ctx.reg[3];
    ctx.e = ctx.reg[4];
    ctx.f = ctx.reg[5];
    ctx.g = ctx.reg[6];
    ctx.h = ctx.reg[7];
    printf("%2d | %08x %08x %08x %08x %08x %08x %08x %08x\n", 0, ctx.a, ctx.b, ctx.c, ctx.d, ctx.e, ctx.f, ctx.g, ctx.h);
    for (i = 0; i < round; i++)
    {
        t1 = ctx.h + S1(ctx.e) + Ch(ctx.e, ctx.f, ctx.g) + K[i] + ctx.w[i];
        t2 = S0(ctx.a) + Maj(ctx.a, ctx.b, ctx.c);
        ctx.h = ctx.g;
        ctx.g = ctx.f;
        ctx.f = ctx.e;
        ctx.e = ctx.d + t1;
        ctx.d = ctx.c;
        ctx.c = ctx.b;
        ctx.b = ctx.a;
        ctx.a = t1 + t2;

        printf("%2d | %08x %08x %08x %08x %08x %08x %08x %08x | %08x\n", i + 1, ctx.a, ctx.b, ctx.c, ctx.d, ctx.e, ctx.f, ctx.g, ctx.h, ctx.w[i]);
    }
    if (round == 64)
    {
        ctx.reg[0] += ctx.a;
        ctx.reg[1] += ctx.b;
        ctx.reg[2] += ctx.c;
        ctx.reg[3] += ctx.d;
        ctx.reg[4] += ctx.e;
        ctx.reg[5] += ctx.f;
        ctx.reg[6] += ctx.g;
        ctx.reg[7] += ctx.h;
    }
}

void sha256_update(SHA256_CTX &ctx, unsigned char *msg, int msg_len)
{
    int mlen = (msg_len + 8 + 64 - (msg_len + 8) % 64) / 4;
    WORD *M = new WORD[mlen];

    printf("mlen = %d\n", mlen);

    msg_padding(msg, msg_len, M, mlen);

    hexdump("msg", msg, msg_len);
    hexdump("M", M, mlen);

    int i;
    for (i = 0; i < mlen; i += 16)
    {
        sha256_round(ctx, M + i);
    }

    hexdump("h", ctx.reg, 8);
}

void msg_padding(unsigned char *in, int in_len, WORD *out, int out_len)
{
    int i;
    uint64_t l = 448 - 1 - (in_len * 8) % 512;
    printf("l = %lu\n", l);
    for (i = 0; i < in_len; i += 4)
    {
        out[i / 4] = ((uint32_t)in[i] << 24) | ((uint32_t)in[i + 1] << 16) | ((uint32_t)in[i + 2] << 8) | ((uint32_t)in[i + 3] << 0);
    }
    hexdump("out", out, out_len);
    if (in_len % 4 == 0)
    {
        out[in_len / 4] = 0x80000000;
    }
    else if (in_len % 4 == 1)
    {
        out[in_len / 4] = ((uint32_t)in[in_len - 1] << 24) | 0x00800000;
    }
    else if (in_len % 4 == 2)
    {
        out[in_len / 4] = ((uint32_t)in[in_len - 2] << 24) | ((uint32_t)in[in_len - 1] << 16) | 0x00008000;
    }
    else if (in_len % 4 == 3)
    {
        out[in_len / 4] = ((uint32_t)in[in_len - 3] << 24) | ((uint32_t)in[in_len - 2] << 16) | ((uint32_t)in[in_len - 1] << 8) | 0x00000080;
    }
    for (i = in_len / 4 + 1; i < out_len - 2; i++)
    {
        out[i] = 0;
    }
    out[out_len - 2] = (uint64_t)(in_len * 8) >> 32;
    out[out_len - 1] = (uint64_t)(in_len * 8) & (uint64_t)0xffffffff;
}

void sha256_restet(SHA256_CTX &ctx)
{
    sha256_init(ctx);
}

void sha256_one_round(SHA256_CTX& ctx, WORD *msg_blk)
{
    WORD t1, t2;
    if(ctx.round < 16)
        ctx.w[ctx.round] = msg_blk[ctx.round];
    else
        ctx.w[ctx.round] = G1(ctx.w[ctx.round - 2]) + ctx.w[ctx.round - 7] + G0(ctx.w[ctx.round - 15]) + ctx.w[ctx.round - 16];
    if(ctx.round == 0)
    {
        ctx.a = ctx.reg[0];
        ctx.b = ctx.reg[1];
        ctx.c = ctx.reg[2];
        ctx.d = ctx.reg[3];
        ctx.e = ctx.reg[4];
        ctx.f = ctx.reg[5];
        ctx.g = ctx.reg[6];
        ctx.h = ctx.reg[7];
    }
    t1 = ctx.h + S1(ctx.e) + Ch(ctx.e, ctx.f, ctx.g) + K[ctx.round] + ctx.w[ctx.round];
    t2 = S0(ctx.a) + Maj(ctx.a, ctx.b, ctx.c);
    ctx.h = ctx.g;
    ctx.g = ctx.f;
    ctx.f = ctx.e;
    ctx.e = ctx.d + t1;
    ctx.d = ctx.c;
    ctx.c = ctx.b;
    ctx.b = ctx.a;
    ctx.a = t1 + t2;
    printf("%2d | %08x %08x %08x %08x %08x %08x %08x %08x | %08x\n", ctx.round + 1, ctx.a, ctx.b, ctx.c, ctx.d, ctx.e, ctx.f, ctx.g, ctx.h, ctx.w[ctx.round]);
    ctx.round++;
}

void hexdump(const char *name, uint8_t *in, int len)
{
    printf("%s = \n", name);
    int i;
    for (i = 0; i < len; i++)
    {
        printf("%02x ", in[i]);
        if (i % 16 == 15)
            printf("\n");
    }
    printf("\n");
}
void hexdump(const char *name, uint32_t *in, int len)
{
    printf("%s = \n", name);
    int i;
    for (i = 0; i < len; i++)
    {
        printf("%08x ", in[i]);
        if (i % 16 == 15)
            printf("\n");
    }
    printf("\n");
}
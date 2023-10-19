#include <iostream>

typedef uint32_t WORD;

extern WORD K[64];

#define ROTR(x, r) (((x) >> (r)) | ((x) << (32 - (r))))
#define ROTL(x, r) ROTR(x, (32 - (r)))

#define SHR(x, r) ((x) >> (r))

#define Ch(x, y, z) (((x) & (y)) ^ ((0xffffffff ^ (x)) & (z)))

#define Maj(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))

#define S0(x) (ROTR(x, 2) ^ ROTR(x, 13) ^ ROTR(x, 22))
#define S1(x) (ROTR(x, 6) ^ ROTR(x, 11) ^ ROTR(x, 25))

#define G0(x) (ROTR(x, 7) ^ ROTR(x, 18) ^ SHR(x, 3))
#define G1(x) (ROTR(x, 17) ^ ROTR(x, 19) ^ SHR(x, 10))

typedef struct _sha256_ctx
{
    WORD a,b,c,d,e,f,g,h;
    WORD reg[8];
    WORD w[64];
    int round;
}SHA256_CTX;

void sha256_init(SHA256_CTX& ctx);

void sha256_round(SHA256_CTX& ctx, WORD* msg_blk);

void sha256_round_test(SHA256_CTX &ctx, WORD *msg_blk, int round);

void sha256_update(SHA256_CTX& ctx, unsigned char* msg, int msg_len);

void sha256_restet(SHA256_CTX& ctx);

void sha256_one_round(SHA256_CTX& ctx, WORD *msg_blk);

void msg_padding(unsigned char* in, int in_len, WORD* out, int out_len);

//WORD Ch(WORD x, WORD y, WORD z);
//WORD Maj(WORD x, WORD y, WORD z);

// WORD S1(WORD x);
// WORD S2(WORD x);
// WORD G1(WORD x);
// WORD G2(WORD x);

#define NAME(v) (#v)

void hexdump(const char* name, uint8_t* in, int len);
void hexdump(const char* name, uint32_t* in, int len);
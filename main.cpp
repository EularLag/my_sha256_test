#include <iostream>
#include <random>
#include <string.h>
#include <time.h>

#include "sha256.h"

using std::mt19937;

void print_difference(const SHA256_CTX &ctx1, const SHA256_CTX &ctx2)
{
    printf("     %08x %08x %08x %08x %08x %08x %08x %08x \n\n", ctx2.a - ctx1.a, ctx2.b - ctx1.b, ctx2.c - ctx1.c, ctx2.d - ctx1.d, ctx2.e - ctx1.e, ctx2.f - ctx1.f, ctx2.g - ctx1.g, ctx2.h - ctx1.h);
    // printf("d(a) = %08x\n", ctx2.a - ctx1.a);
    // printf("d(b) = %08x\n", ctx2.b - ctx1.b);
    // printf("d(c) = %08x\n", ctx2.c - ctx1.c);
    // printf("d(d) = %08x\n", ctx2.d - ctx1.d);
    // printf("d(e) = %08x\n", ctx2.e - ctx1.e);
    // printf("d(f) = %08x\n", ctx2.f - ctx1.f);
    // printf("d(g) = %08x\n", ctx2.g - ctx1.g);
    // printf("d(h) = %08x\n", ctx2.h - ctx1.h);
}

void print_msg_difference(const WORD *msg1, const WORD *msg2)
{
    int i;
    WORD dmsg[16];
    for (i = 0; i < 16; i++)
    {
        dmsg[i] = msg2[i] - msg1[i];
    }
    hexdump("d(m)", dmsg, 16);
}

void collision_20steps_test()
{
    WORD msg1[16], msg2[16];

    int i;

    mt19937 rng(time(0));

    for (i = 0; i < 16; i++)
    {
        msg2[i] = msg1[i] = rng();
    }
    WORD d1, d2, d3, d4;
    WORD a4, e8;

    d2 = 0;
    d3 = 0;
    d4 = -1;

    SHA256_CTX ctx1, ctx2;
    sha256_init(ctx1);
    sha256_init(ctx2);

    print_msg_difference(msg1, msg2);

    for(i = 1; i < 20; i++)
    {
        printf("===== step %2d =====\n", i);
        sha256_one_round(ctx1, msg1);
        sha256_one_round(ctx2, msg2);
        print_difference(ctx1, ctx2);

        if(i == 4)
        {
            a4 = ctx1.a;
            // for A5 = A4
            msg1[i] = a4 - (S0(ctx1.a) + Maj(ctx1.a, ctx1.b, ctx1.c) + S1(ctx1.e) + Ch(ctx1.e, ctx1.f, ctx1.g) + ctx1.h + K[i]);
            msg2[i] = a4 - (S0(ctx2.a) + Maj(ctx2.a, ctx2.b, ctx2.c) + S1(ctx2.e) + Ch(ctx2.e, ctx2.f, ctx2.g) + ctx2.h + K[i]);
        }
        else if(i == 5)
        {
            msg1[i] = -1 - (S0(ctx1.a) + Maj(ctx1.a, ctx1.b, ctx1.c) + S1(ctx1.e) + Ch(ctx1.e, ctx1.f, ctx1.g) + ctx1.h + K[i]);
            msg2[i] = -(S0(ctx2.a) + Maj(ctx2.a, ctx2.b, ctx2.c) + S1(ctx2.e) + Ch(ctx2.e, ctx2.f, ctx2.g) + ctx2.h + K[i]);
        }
        else if(i == 6)
        {
            d1 = -1 - (Ch(ctx2.e, ctx2.f, ctx2.g) - Ch(ctx1.e, ctx1.f, ctx1.g)) - (S1(ctx2.e) - S1(ctx1.e));
            // for A7 = A5 = A4
            msg1[i] = a4 - S0(ctx1.a) - Maj(ctx1.a, ctx1.b, ctx1.c) - S1(ctx1.e) - Ch(ctx1.e, ctx1.f, ctx1.g) - ctx1.h - K[i];
            msg2[i] = a4 - S0(ctx2.a) - Maj(ctx2.a, ctx2.b, ctx2.c) - S1(ctx2.e) - Ch(ctx2.e, ctx2.f, ctx2.g) - ctx2.h - K[i];
            msg2[i] = msg1[i] + d1;
        }
        else if(i == 7)
        {
            d2 = -(S1(ctx2.e) - S1(ctx1.e)) - (Ch(ctx2.e, ctx2.f, ctx2.g) - Ch(ctx1.e, ctx1.f, ctx1.g));
            msg1[i] = ctx1.a - S0(ctx1.a) - Maj(ctx1.a, ctx1.b, ctx1.c) - S1(ctx1.e) - Ch(ctx1.e, ctx1.f, ctx1.g) - ctx1.h - K[i];
            msg2[i] = msg1[i] + d2;
        }
        else if(i == 8)
        {
            e8 = ctx1.e;
            d3 = -(Ch(ctx2.e, ctx2.f, ctx2.g) - Ch(ctx1.e, ctx1.f, ctx1.g));
            // for E8 = E9
            msg1[i] = e8 - S1(ctx1.e) - Ch(ctx1.e, ctx1.f, ctx1.g) -ctx1.h - K[i] - ctx1.d;
            msg2[i] = msg1[i] + d3;
        }
        else if(i == 9)
        {
            if(((ctx1.g ^ ctx2.g) & ctx1.e) != 0)
            {
                printf("incorrect condition\n");
                return;
            }
            msg1[i] = -1 - S1(ctx1.e) - Ch(ctx1.e, ctx1.f, ctx1.g) - ctx1.h - K[i] - ctx1.d;
            msg2[i] = -S1(ctx2.e) - Ch(ctx2.e, ctx2.f, ctx2.g) - ctx2.h - K[i] - ctx2.d;
        }
        else if(i == 10)
        {
            msg1[i] = -S1(ctx1.e) - Ch(ctx1.e, ctx1.f, ctx1.g) - ctx1.h - K[i] - ctx1.d;
            msg2[i] = -S1(ctx2.e) - Ch(ctx2.e, ctx2.f, ctx2.g) - ctx2.h - K[i] - ctx2.d;
        }
        else if(i == 12)
        {
            msg1[i] = -1 - S1(ctx1.e) - Ch(ctx1.e, ctx1.f, ctx1.g) - ctx1.h - K[i] - ctx1.d;
            msg2[i] = -1 - S1(ctx2.e) - Ch(ctx2.e, ctx2.f, ctx2.g) - ctx2.h - K[i] - ctx2.d;
        }
        else if(i == 13)
        {
            msg2[i] = msg1[i] + d4;
        }
    }

    hexdump("msg1", msg1, 16);
    hexdump("msg2", msg2, 16);

    //test
    sha256_restet(ctx1);
    sha256_restet(ctx2);

    sha256_round_test(ctx1, msg1, 19);
    sha256_round_test(ctx2, msg2, 19);

    print_difference(ctx1, ctx2);
}

int test()
{
    SHA256_CTX ctx;
    char msg[] = "bhn5bjmoniertqea40wro2upyflkydsibsk8ylkmgbvwi420t44cq034eou1szc1k0mk46oeb7ktzmlxqkbte2sy";
    sha256_init(ctx);
    sha256_update(ctx, (uint8_t *)msg, strlen(msg));

    WORD a = 0x12345678;

    printf("%08x\n", ROTR(a, 4));

    return 0;
}

int main()
{
    collision_20steps_test();
    return 0;
}

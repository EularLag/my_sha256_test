#include <iostream>
#include <random>
#include <string.h>
#include <time.h>

#include "sha256.h"

using std::mt19937;

void print_difference(const SHA256_CTX& ctx1, const SHA256_CTX& ctx2)
{
    printf("d(a) = %08x\n", ctx2.h[0] - ctx1.h[0]);
    printf("d(b) = %08x\n", ctx2.h[1] - ctx1.h[1]);
    printf("d(c) = %08x\n", ctx2.h[2] - ctx1.h[2]);
    printf("d(d) = %08x\n", ctx2.h[3] - ctx1.h[3]);
    printf("d(e) = %08x\n", ctx2.h[4] - ctx1.h[4]);
    printf("d(f) = %08x\n", ctx2.h[5] - ctx1.h[5]);
    printf("d(g) = %08x\n", ctx2.h[6] - ctx1.h[6]);
    printf("d(h) = %08x\n", ctx2.h[7] - ctx1.h[7]);
}

void collision_test()
{
    WORD msg1[16], msg2[16], dmsg[16];

    int i;

    mt19937 rng(time(0));

    for(i = 0; i < 16; i++)
    {
        msg2[i] = msg1[i] = rng();
    }
    WORD d1, d2, d3, d4;
    
    d2 = 0;
    d3 = 0;
    d4 = -1;

    SHA256_CTX ctx1, ctx2;
    sha256_init(ctx1);
    sha256_init(ctx2);

    for(i = 0; i < 16; i++)
    {
        dmsg[i] = msg2[i] - msg1[i];
    }
    hexdump("d(m)", dmsg, 16);

    sha256_round_test(ctx1, msg1, 4);
    sha256_round_test(ctx2, msg2, 4);

    print_difference(ctx1, ctx2);


    msg1[4] = ctx1.h[0] - (S0(ctx1.h[0]) + Maj(ctx1.h[0], ctx1.h[1], ctx1.h[2]) + S1(ctx1.h[4]) + Ch(ctx1.h[4], ctx1.h[5], ctx1.h[6]) + ctx1.h[7] + K[4]);
    msg2[4] = ctx2.h[0] - (S0(ctx2.h[0]) + Maj(ctx2.h[0], ctx2.h[1], ctx2.h[2]) + S1(ctx2.h[4]) + Ch(ctx2.h[4], ctx2.h[5], ctx2.h[6]) + ctx2.h[7] + K[4]);


    sha256_restet(ctx1);
    sha256_restet(ctx2);
    for(i = 0; i < 16; i++)
    {
        dmsg[i] = msg2[i] - msg1[i];
    }
    hexdump("d(m)", dmsg, 16);
/////// i step
    sha256_round_test(ctx1, msg1, 5);
    sha256_round_test(ctx2, msg2, 5);
    print_difference(ctx1, ctx2);


    // msg2[5] = msg1[5] + 1;
    msg1[5] = -1 - (S0(ctx1.h[0]) + Maj(ctx1.h[0], ctx1.h[1], ctx1.h[2]) + S1(ctx1.h[4]) + Ch(ctx1.h[4], ctx1.h[5], ctx1.h[6]) + ctx1.h[7] + K[5]);
    msg2[5] = - (S0(ctx2.h[0]) + Maj(ctx2.h[0], ctx2.h[1], ctx2.h[2]) + S1(ctx2.h[4]) + Ch(ctx2.h[4], ctx2.h[5], ctx2.h[6]) + ctx2.h[7] + K[5]);
    printf("dMaj = %08x\n", Maj(ctx2.h[0], ctx2.h[1], ctx2.h[2]) - Maj(ctx1.h[0], ctx1.h[1], ctx1.h[2]));
    sha256_restet(ctx1);
    sha256_restet(ctx2);
    for(i = 0; i < 16; i++)
    {
        dmsg[i] = msg2[i] - msg1[i];
    }
    hexdump("d(m)", dmsg, 16);
/////// i + 1 step
    sha256_round_test(ctx1, msg1, 6);
    sha256_round_test(ctx2, msg2, 6);
    print_difference(ctx1, ctx2);

    
    d1 = -1 - (Ch(ctx2.h[4], ctx2.h[5], ctx2.h[6]) - Ch(ctx1.h[4], ctx1.h[5], ctx1.h[6])) - (S1(ctx2.h[4]) - S1(ctx1.h[4]));
    msg2[6] = msg1[6] + d1;

    sha256_restet(ctx1);
    sha256_restet(ctx2);

    for(i = 0; i < 16; i++)
    {
        dmsg[i] = msg2[i] - msg1[i];
    }
    hexdump("d(m)", dmsg, 16);
/////// i + 2 step
    sha256_round_test(ctx1, msg1, 7);
    sha256_round_test(ctx2, msg2, 7);
    print_difference(ctx1, ctx2);

    


    // printf("%08x %08x\n", Ch(ctx2.h[4], ctx2.h[5], ctx2.h[6]) - Ch(ctx1.h[4], ctx1.h[5], ctx1.h[6]), S1(ctx2.h[4]) - S1(ctx1.h[4]));
    // d1 = -1 - (Ch(ctx2.h[4], ctx2.h[5], ctx2.h[6]) - Ch(ctx1.h[4], ctx1.h[5], ctx1.h[6])) - (S1(ctx2.h[4]) - S1(ctx1.h[4]));
    // // msg1[1] = - (S0(ctx1.h[0]) + Maj(ctx1.h[0], ctx1.h[1], ctx1.h[2]) + S1(ctx1.h[4]) + Ch(ctx1.h[4], ctx1.h[5], ctx1.h[6]) + ctx1.h[7] + K[1]);
    // // msg2[1] = -1 - (S0(ctx2.h[0]) + Maj(ctx2.h[0], ctx2.h[1], ctx2.h[2]) + S1(ctx2.h[4]) + Ch(ctx2.h[4], ctx2.h[5], ctx2.h[6]) + ctx2.h[7] + K[1]);

    // printf("d1 = %08x\n", d1);
    // printf("dMaj = %08x\n", Maj(ctx2.h[0], ctx2.h[1], ctx2.h[2]) - Maj(ctx1.h[0], ctx1.h[1], ctx1.h[2]));
    // msg2[1] = msg1[1] + d1;

    // sha256_restet(ctx1);
    // sha256_restet(ctx2);

    // for(i = 0; i < 16; i++)
    // {
    //     dmsg[i] = msg2[i] - msg1[i];
    // }
    // hexdump("d(m)", dmsg, 16);

    // sha256_round_test(ctx1, msg1, 2);
    // sha256_round_test(ctx2, msg2, 2);

    // print_difference(ctx1, ctx2);

    // d1 = -1 - (Ch(ctx2.h[4], ctx2.h[5], ctx2.h[6]) - Ch(ctx1.h[4], ctx1.h[5], ctx1.h[6])) - (S1(ctx2.h[4]) - S1(ctx1.h[4]));
    // msg1[2] = - (S0(ctx1.h[0]) + Maj(ctx1.h[0], ctx1.h[1], ctx1.h[2]) + S1(ctx1.h[4]) + Ch(ctx1.h[4], ctx1.h[5], ctx1.h[6]) + ctx1.h[7] + K[1]);
    // msg2[2] = -1 - (S0(ctx2.h[0]) + Maj(ctx2.h[0], ctx2.h[1], ctx2.h[2]) + S1(ctx2.h[4]) + Ch(ctx2.h[4], ctx2.h[5], ctx2.h[6]) + ctx2.h[7] + K[1]);

    // sha256_restet(ctx1);
    // sha256_restet(ctx2);

    // for(i = 0; i < 16; i++)
    // {
    //     dmsg[i] = msg2[i] - msg1[i];
    // }
    // hexdump("d(m)", dmsg, 16);

    // sha256_round_test(ctx1, msg1, 3);
    // sha256_round_test(ctx2, msg2, 3);

    // print_difference(ctx1, ctx2);

}

int test()
{
    SHA256_CTX ctx;
    char msg[] = "bhn5bjmoniertqea40wro2upyflkydsibsk8ylkmgbvwi420t44cq034eou1szc1k0mk46oeb7ktzmlxqkbte2sy";
    sha256_init(ctx);
    sha256_update(ctx, (uint8_t*)msg, strlen(msg));

    WORD a = 0x12345678;

    printf("%08x\n", ROTR(a, 4));

    return 0;
}

int main()
{
    collision_test();
    return 0;
}

#include "difference.h"

char difference_pattern[17] = "#1uAnCxE0-3B5D7?";
int inv_difference_pattern[256] = {0};

void init_inv_difference_pattern()
{
    int i;
    for (i = 0; i < 256; i++)
        inv_difference_pattern[i] = -1;
    for (i = 0; i < 16; i++)
        inv_difference_pattern[difference_pattern[i]] = i;
}

void set_diff_by_name(Diff& diff, const char name)
{
    int v = inv_difference_pattern[(int)name];
    int i;
    diff.reset();
    for(i = 0; i < 4; i++)
    {
        if((v >> i) & 1)
            diff.set(i);
    }
}


char get_name_from_diff(const Diff diff)
{
    return difference_pattern[(int)diff.to_ulong()];
}
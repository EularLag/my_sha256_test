#include <iostream>
#include <bitset>

using std::bitset;

// class Generalized_Difference
// {
// private:
//     bitset<4> diff;
// public:
//     Generalized_Difference();
//     ~Generalized_Difference();
//     char name();
//     void set_by_name(const char name);
// };

typedef bitset<4> Diff;

extern char difference_pattern[17];
extern int inv_difference_pattern[256];

void init_inv_difference_pattern();
void set_diff_by_name(Diff& diff, const char name);
char get_name_from_diff(const Diff diff);
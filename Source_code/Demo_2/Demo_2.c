/*
 * XXTEA block cipher, by David Wheeler and Roger Needham.
 * Source: https://en.wikipedia.org/wiki/XXTEA
 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define DELTA 0x9e3779b9
#define MX (((z>>5^y<<2) + (y>>3^z<<4)) ^ ((sum^y) + (key[(p&3)^e] ^ z)))

void btea(uint32_t* v, int n, uint32_t const key[4]) {
    uint32_t y, z, sum;
    unsigned int p, rounds, e;
    if (n > 1) {          /* Coding Part */
        rounds = 6 + 52 / n;
        sum = 0;
        z = v[n - 1];
        do {
            sum += DELTA;
            e = (sum >> 2) & 3;
            for (p = 0; p < n - 1; p++) {
                y = v[p + 1];
                z = v[p] += MX;
            }
            y = v[0];
            z = v[n - 1] += MX;
        } while (--rounds);
    }
    else if (n < -1) {  /* Decoding Part */
        n = -n;
        rounds = 6 + 52 / n;
        sum = rounds * DELTA;
        y = v[0];
        do {
            e = (sum >> 2) & 3;
            for (p = n - 1; p > 0; p--) {
                z = v[p - 1];
                y = v[p] -= MX;
            }
            z = v[n - 1];
            y = v[0] -= MX;
            sum -= DELTA;
        } while (--rounds);
    }
}

int main(void)
{

    uint32_t v[] = {
        0x811dc987, 0x35f3266c, 0xa4ceaa8d, 0xbb4bdab6, 0xa9e8a831, 0x38b630bf, 0xa6519b2e, 0xfc75d3cd, 
        0xd536bf7d, 0x02ef863c, 0x7cbe83b2, 0x69e563a5, 0x0e01e988, 0xa7e49459, 0xfdfdd7a9, 0xccb2eb83, 
        0x672e7347, 0x71b11338, 0x5b903ef6, 0x1f8e95ad, 0xd4e61a23, 0xfac09742, 0xf35d6a62, 0xffda349c, 
        0x6d9f9159, 0xfe092bc8, 0xc77622d5, 0xf55d0802, 0xc1f39689, 0x5857d530, 0xd9ab4bdf, 0x1ceb4676, 
        0x1cf0c41f, 0x8ff473df, 0x507fcf44, 0x2536eb0f, 0xe371ef9a, 0xe575cebb, 0x6755b56, 0xcd7ce9f1, 
        0xa4c4f0d0, 0x503dbfcd
    };

    int n = sizeof(v) / sizeof(uint32_t);

    uint32_t key[4] = {0x05, 0x04, 0x03, 0x02};

    btea(v, -n, key);

    printf("Decrypted data is: ");

    for (int i = 0; i < n; i++)
        printf("%c", v[i]);
    printf("\n");

    return 0;
}

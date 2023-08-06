/*
 * XTEA block cipher, by David Wheeler and Roger Needham.
 * Source: https://en.wikipedia.org/wiki/XXTEA
 */

#include <stdint.h>
#include <stdio.h>

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
        0x41, 0x20, 0x63, 0x75, 0x70, 0x20, 0x6f, 0x66, 0x20, 0x78, 0x78, 0x74, 0x65, 0x61, 0x20, 0x63,
        0x68, 0x61, 0x6e, 0x67, 0x65, 0x73, 0x20, 0x62, 0x31, 0x74, 0x74, 0x33, 0x72, 0x20, 0x74, 0x6f,
        0x20, 0x62, 0x33, 0x74, 0x74, 0x33, 0x72, 0x21, 0x20, 0x00 };


    int n = sizeof(v) / sizeof(uint32_t);

    uint32_t key[4] = {0x05, 0x04, 0x03, 0x02};

    btea(v, n, key);

    printf("Encrypted data is ");

    for (int i = 0; i < n; i++)
        printf("%c", v[i]);
    printf("\n");

    return 0;
}

extern "C" {
    #include "extract.h"
    #include "fr_util.h"
}
#include <stdlib.h>
#include <time.h>
#include <stdio.h>

#define n_tests (3)

int main(int argc, char **argv) {
    srand(rdtscp());
    double mean = 0;

    for (int t = 0; t < n_tests; ++t) {
        
        unsigned char rand_key[] =
        {
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        };

        for (int i = 0; i < TXT_BYTES; ++i){
            rand_key[i] = rand() % 256;
        }

        printf("--------------------\n");
        printf("Actual AES-128 key for this iteration: ");
        for (int i = 0; i < TXT_BYTES; ++i) {
            printf("%02x", (unsigned int)rand_key[i]);
        }
        printf("\n");
        printf("Extracted result:     ");
        __uint128_t aes_key = extract(rand_key);
        printf("--------------------\n\n");

        __uint128_t rand_key_128 = ((__uint128_t) rand_key[0] << 120) | ((__uint128_t) rand_key[1] << 112) | ((__uint128_t) rand_key[2] << 104)
        | ((__uint128_t) rand_key[3] << 96) | ((__uint128_t) rand_key[4] << 88) | ((__uint128_t) rand_key[5] << 80) | ((__uint128_t) rand_key[6] << 72)
        | ((__uint128_t) rand_key[7] << 64) | ((__uint128_t) rand_key[8] << 56) | ((__uint128_t) rand_key[9] << 48) | ((__uint128_t) rand_key[10] << 40) 
        | ((__uint128_t) rand_key[11] << 32) | ((__uint128_t) rand_key[12] << 24) | ((__uint128_t) rand_key[13] << 16) | ((__uint128_t) rand_key[14] << 8) | rand_key[15];


        // calculate bit level accuracy
        uint32_t num_correct = 0;
        for (int i = 0; i < AES_KEY_SIZE; ++i) {
            uint8_t bit_expected = (rand_key_128 & (1 << i)) >> i;
            uint8_t bit_actual = (aes_key & (1 << i)) >> i;

            if (bit_actual == bit_expected) {
                ++num_correct;
            }
        }

        double accuracy = num_correct / AES_KEY_SIZE;
        accuracy *= 100;
        mean += accuracy;
        printf("Accuracy for this run: %f%%\n", accuracy);
    }
    mean /= n_tests;
    printf("--------------------\n\n");
    printf("Tests complete!\n");
    printf("Total average accuracy for AES key extraction: %f%%\n", mean);

    return 0;
}
extern "C" {
    #include "extract.h"
    #include "fr_util.h"
}
#include <stdlib.h>
#include <time.h>
#include <stdio.h>

// change to your liking
#define n_tests (750)

int main(int argc, char **argv) {
    srand(rdtscp());
    double mean_a = 0;
    double mean_c = 0;

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


        // calculate hex digit level accuracy
        uint32_t num_correct = 0;
        for (int i = 0; i < AES_KEY_SIZE; i += 4) {
            uint8_t digit_expected = (rand_key_128 >> i) & 0xf;
            uint8_t digit_actual = (aes_key >> i) & 0xf;

            if (digit_actual == digit_expected) {
                ++num_correct;
            }
        }

        //if key successfully extracted
        if (num_correct == (AES_KEY_SIZE / 4)) {
            ++mean_c;
        }

        double accuracy = (double) num_correct / (AES_KEY_SIZE / 4);
        accuracy *= 100;
        mean_a += accuracy;
        printf("Accuracy for this run: %f%%\n", accuracy);
    }
    mean_a /= n_tests;
    mean_c /= n_tests;
    mean_c *= 100;

    printf("--------------------\n\n");
    printf("Tests complete!\n\n");
    printf("Total average accuracy for AES key extraction: %f%%\n", mean_a);
    printf("Percentage of keys fully extracted correctly: %f%%\n", mean_c);

    //write results of runs to a csv files for graph generation
    FILE *file_a = fopen("test_accuracy.csv", "a"); 
    if (file_a == NULL) {
        perror("Failed to open file");
        return 1;
    }

    FILE *file_c = fopen("test_correct.csv", "a"); 
    if (file_c == NULL) {
        perror("Failed to open file");
        return 1;
    }

    fprintf(file_a, "%u,%f\n", n_enc, mean_a);
    fprintf(file_c, "%u,%f\n", n_enc, mean_c);

    fclose(file_a);
    fclose(file_c);

    return 0;
}
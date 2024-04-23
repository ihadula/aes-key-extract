#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdarg.h>
#include <getopt.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>


#ifndef UTIL_H_
#define UTIL_H_

#define ADDR_PTR uint64_t
#define CYCLES uint64_t

//Channel parameters
#define TX_INTERVAL_DEF               (0x00030000)
#define SYNC_TIME_MASK_DEF            (0x0003FFFF)
#define SYNC_JITTER_DEF                  (0x01000)

//Shared memory
#define DEFAULT_FILE_NAME       "README.md"
#define DEFAULT_FILE_OFFSET	0x0
#define DEFAULT_FILE_SIZE	4096
#define CACHE_BLOCK_SIZE	64
#define MAX_BUFFER_LEN	1024

//Colors
#define RESET   "\033[0m"
#define BLACK   "\033[30m"      /* Black */
#define RED     "\033[31m"      /* Red */
#define GREEN   "\033[32m"      /* Green */
#define YELLOW  "\033[33m"      /* Yellow */

//Configuration Parameters of the Channel.
struct config {
  ADDR_PTR addr;                  //address to collude on
  uint64_t tx_interval;           //interval in synchronous window where transmission occurs
  uint64_t sync_time_mask;        //synchronous window size for each bit.
  uint64_t sync_jitter;           
};


//Functions to help Flush+Reload
void     clflush(ADDR_PTR addr);     //Flush Address
void     maccess(ADDR_PTR addr);     //Load Address
CYCLES   maccess_t(ADDR_PTR addr);   //Load And Time the Access
uint64_t rdtscp(void);               //Get Timestamp

//Synchronization between sender and receiver
CYCLES cc_sync(uint64_t SYNC_TIME_MASK, uint64_t SYNC_JITTER);

//Initialize Config
void init_config(struct config *config, int argc, char **argv);

//String Conversion
char *string_to_binary(char *s);
char *conv_char(char *data, int size, char *msg);

#endif

#ifndef EXTRACT_H
#define EXTRACT_H

#define AES_KEY_SIZE (128)

//number of encryptions to observe
#define n_enc (30000)

//bytes in plaintext, 128 bits
#define TXT_BYTES (16)

//in bytes
#define TABLE_SIZE (1024)
#define CACHE_LINESIZE (64)

#define CACHELINES_PER_TABLE (16)

//cache miss threshold, access time > threshold => cache miss
/*** SET THESE ADDRESSES FOR SYSTEM BEFORE RUNNING ***/
#define CACHE_MISS (355)

//0-15, since 16 cache lines per table
#define CACHE_LINE_TO_MONITOR_PER_TABLE (5)

//AES key extraction function
__uint128_t extract(const unsigned char *key);

#endif
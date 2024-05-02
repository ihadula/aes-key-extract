# AES-128 Full Key Extraction
Research Project for CS 7292 (Hardware Security/Reliability). Flush + Reload attack on T-Table AES

To run the experiment (native mode):
1. Download and compile (no ASM, no hardware, debug symbols, and shared object library) openssl 1.1.0l (version used for this research) as follows:\
`./config -d shared no-asm no-hw`\
`make`\
`make install_sw`

3. Find memory locations of Te0, Te1, Te2, and Te3 in `mem_locs.txt` and update their values in `extract.cpp`:\
`cd /usr/lib`\
`readelf -a libcrypto.so > mem_locs.txt`

4. Find cache miss threshold and update in `extract.cpp`:\
`cd src/`\
`make histogram`\
`./histogram`\
\
Find minimum latency where misses appear and subract ~50 cycles.

4. Run the extraction program. Change the number of encryptions observed in `extract.h` as you see fit.\
`cd src/`\
`make all`\
`./extract`

5. To run testing mode (for experimental results):\
`cd src/`\
`make all`\
`./test`\
\
OR `./gen_num_enc_graph.sh` to run many trials (change `n_tests` in `test.cpp` to change number of trials).

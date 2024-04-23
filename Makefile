CC=gcc
# CFLAGS=-std=gnu99 # Uncomment if using GCC versions older than 5 (where it may otherwise throw some errors)

.PHONY: all clean

all: clean histogram extract test

fr_util.o: fr_util.c fr_util.h
	$(CC) $(CFLAGS) -c $<

%.o: %.c fr_util.h
	$(CC) $(CFLAGS) -c $< 

histogram: histogram.o fr_util.o
	$(CC) $(CFLAGS) $^ -o $@

extract: extract.o fr_util.o
	g++ $(CFLAGS) extract.o fr_util.o -o extract -I/usr/local/include/ssl -L/usr/local/lib -lcrypto

extract_test.o: extract_test.cpp extract.h
	g++ $(CFLAGS) -c extract_test.cpp -o extract_test.o -I/usr/local/include/ssl -L/usr/local/lib -lcrypto

test: test.o extract_test.o fr_util.o
	g++ $(CFLAGS) test.o extract_test.o fr_util.o -o test -I/usr/local/include/ssl -L/usr/local/lib -lcrypto

clean:
	rm -f *.o *~ histogram extract test

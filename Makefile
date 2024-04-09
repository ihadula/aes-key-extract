CC=gcc
# CFLAGS=-std=gnu99 #Uncomment if using GCC versions older than 5 (where it may otherwise throw some errors)

all: histogram extract

fr_util.o: fr_util.c fr_util.h
	$(CC) $(CFLAGS) -c $<

%.o: %.c fr_util.h
	$(CC) $(CFLAGS) -c $< 

histogram: histogram.o fr_util.o
	$(CC) $(CFLAGS) $^ -o $@

extract: extract.o fr_util.o
	g++ $(CFLAGS) extract.o fr_util.o -o extract -I/usr/local/include/ssl -L/usr/local/lib -lcrypto

clean:
	rm -f *.o *~ histogram extract



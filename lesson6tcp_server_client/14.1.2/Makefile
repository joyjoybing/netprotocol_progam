.PHONY:clean all
CC=gcc
CFLAGS=-lrt -g -Wall
BIN=client server
all:$(BIN)
%.o:%.c
		$(CC) -c $< $(CFLAGS) -o $@
clean:
		rm -f *.o $(BIN)
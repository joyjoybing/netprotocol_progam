.PHONY:clean all
CC=gcc
CFLAGS=-lrt -g -Wall
BIN=client server
all:$(BIN)
%.o:%.c  将target .o的拓展名替换为.c
		$(CC) -c $< $(CFLAGS) -o $@
clean:
		rm -f *.o $(BIN)
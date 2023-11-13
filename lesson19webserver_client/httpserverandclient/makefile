src = $(wildcard *.c)
exe = $(patsubst %.c, %, $(src))

ALL:$(exe)

%: %.c
	gcc $< -o $@ -Wall -Werror

.PHONY: ALL clear
clear: 
	-rm -rf $(exe)

MAIN = https-test

CFLAGS =  -Wall -Wextra -Werror -Wfatal-errors -pedantic -std=c99 -D_POSIX_C_SOURCE=201112 -g3
LDFLAGS = -lcyassl
OBJS = $(MAIN).o

.PHONY: clean

%.o : %.c
	$(CC) $(CFLAGS) -c -o $@ $<

$(MAIN) : $(OBJS) Makefile 
	$(CC) $(LDFLAGS) -o $@ $(OBJS)
		
clean:
	rm -f $(MAIN) *.o

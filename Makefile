CC = gcc
CFLAGS = -Wall -Wextra -g

vpath %.c src/
vpath %.h src/

dnsquery : dns.o dnsquery.o
	$(CC) $(CFLAGS) -o $@ $^

%.o : %.c
	$(CC) $(CFLAGS) -c -o $@ $^

.PHONY : clean

clean :
	rm -f *.o

CC = gcc
CFLAGS_RELEASE = -Wall -c
CFLAGS_DEBUG = -Wall -g -c
LIBS = -lpthread -lm
HEADERS = ../lib/tcpwrapper.h ../lib/protocol.h ../router.h

OBJECT_DIR = ../../build/server/

$(OBJECT_DIR)server: $(OBJECT_DIR)main.o $(OBJECT_DIR)tcpwrapper.o $(OBJECT_DIR)router.o $(HEADERS)
	$(CC) $^ -o $(OBJECT_DIR)$@ $(LIBS)

$(OBJECT_DIR)main.o: main.c
	$(CC) $(CFLAGS_DEBUG) $< -o $@

$(OBJECT_DIR)tcpwrapper.o: ../lib/tcpwrapper.c
	$(CC) $(CFLAGS_DEBUG) $< -o $@

$(OBJECT_DIR)router.o: ../router.c
	$(CC) $(CFLAGS_DEBUG) $< -o $@

clean:
	rm $(OBJECT_DIR)*

test:
	echo $(wildcard ../lib/*.c) $(wildcard *.c)

	
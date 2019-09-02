CC = gcc
CFLAGS_RELEASE = -Wall -c
CFLAGS_DEBUG = -Wall -g -c
LIBS = -lpthread
HEADERS = ../lib/tcpwrapper.h ../lib/protocol.h ../router.h ../lib/taskexecutor.h vlnadapter.h starterprotocol.h

OBJECT_DIR = ../../build/client/

$(OBJECT_DIR)client: $(OBJECT_DIR)main.o $(OBJECT_DIR)tcpwrapper.o $(OBJECT_DIR)router.o $(OBJECT_DIR)taskexecutor.o $(OBJECT_DIR)vlnadapter.o $(HEADERS)
	$(CC) $^ -o $(OBJECT_DIR)$@ $(LIBS)

$(OBJECT_DIR)main.o: main.c
	$(CC) $(CFLAGS_DEBUG) $< -o $@

$(OBJECT_DIR)vlnadapter.o: vlnadapter.c
	$(CC) $(CFLAGS_DEBUG) $< -o $@

$(OBJECT_DIR)tcpwrapper.o: ../lib/tcpwrapper.c
	$(CC) $(CFLAGS_DEBUG) $< -o $@

$(OBJECT_DIR)router.o: ../router.c
	$(CC) $(CFLAGS_DEBUG) $< -o $@

$(OBJECT_DIR)taskexecutor.o: ../lib/taskexecutor.c
	$(CC) $(CFLAGS_DEBUG) $< -o $@

clean:
	rm $(OBJECT_DIR)*

test:
	echo $(wildcard ../lib/*.c) $(wildcard *.c)

	
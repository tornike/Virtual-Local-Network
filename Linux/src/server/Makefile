CC = gcc
CFLAGS_RELEASE = -Wall -c
CFLAGS_DEBUG = -Wall -g -c
LIBS = -lpthread -lm -l sqlite3 -ljson-c
HEADERS = ../lib/tcpwrapper.h ../lib/protocol.h ../router.h ../lib/taskexecutor.h db.h

OBJECT_DIR = ../../build/server/

$(OBJECT_DIR)server: $(OBJECT_DIR)main.o $(OBJECT_DIR)tcpwrapper.o $(OBJECT_DIR)router.o $(OBJECT_DIR)taskexecutor.o $(OBJECT_DIR)db.o $(HEADERS)
	$(CC) $^ -o $(OBJECT_DIR)$@ $(LIBS)

$(OBJECT_DIR)main.o: main.c
	$(CC) $(CFLAGS_RELEASE) $< -o $@

$(OBJECT_DIR)db.o: db.c
	$(CC) $(CFLAGS_RELEASE) $< -o $@

$(OBJECT_DIR)tcpwrapper.o: ../lib/tcpwrapper.c
	$(CC) $(CFLAGS_RELEASE) $< -o $@

$(OBJECT_DIR)router.o: ../router.c
	$(CC) $(CFLAGS_RELEASE) $< -o $@

$(OBJECT_DIR)taskexecutor.o: ../lib/taskexecutor.c
	$(CC) $(CFLAGS_RELEASE) $< -o $@

clean:
	rm $(OBJECT_DIR)*

test:
	echo $(wildcard ../lib/*.c) $(wildcard *.c)

	
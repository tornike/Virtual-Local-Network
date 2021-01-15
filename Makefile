
INCLUDE_PATH = include
LIBS = -lpthread -lconfig -lm -lcap
VPATH = build:src:src/vlnd:lib

CC = gcc
CFLAGS_RELEASE = -Wall -c -D _GNU_SOURCE -I $(INCLUDE_PATH)
CFLAGS_DEBUG = -Wall -c -g -D DEVELOP -D _GNU_SOURCE -I $(INCLUDE_PATH)
CFLAGS = $(CFLAGS_DEBUG)

.PHONY: develop
develop: vlnd

.PHONY: release
release: CFLAGS=$(CFLAGS_RELEASE)
release: clean vlnd 

vlnd: main.o server.o client.o rxi_log.o npb_manager.o router.o adapter.o
	$(CC) build/main.o build/server.o build/adapter.o build/client.o build/npb_manager.o build/router.o build/rxi_log.o $(LIBS) -o build/vlnd

main.o: main.c
	$(CC) $(CFLAGS) src/vlnd/main.c -o build/main.o

router.o: router.c
	$(CC) $(CFLAGS) src/router.c -o build/router.o

adapter.o: vln_adapter.c
	$(CC) $(CFLAGS) src/vln_adapter.c -o build/adapter.o

npb_manager.o: npb_manager.c
	$(CC) $(CFLAGS) src/vlnd/npb_manager.c -o build/npb_manager.o

server.o: server.c
	$(CC) $(CFLAGS) src/vlnd/server.c -o build/server.o

client.o: client.c
	$(CC) $(CFLAGS) src/vlnd/client.c -o build/client.o

rxi_log.o: rxi_log.c
	$(CC) $(CFLAGS) lib/rxi_log.c -D LOG_USE_COLOR -o build/rxi_log.o

.PHONY: clean
clean:
	rm -rf build/*

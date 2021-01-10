
export C_INCLUDE_PATH = $(shell pwd)/include

CC = gcc
CFLAGS_RELEASE = -Wall -c
CFLAGS_DEBUG = -Wall -c -g -D DEVELOP

INCLUDE_PATH = include
VPATH = src:src/vlnd:lib:build

all: vlnd
	

vlnd: main.o server.o client.o rxi_log.o npb_manager.o taskexecutor.o router.o adapter.o
	$(CC) build/main.o build/server.o build/adapter.o build/client.o build/npb_manager.o build/taskexecutor.o build/router.o build/rxi_log.o -o build/vlnd -lpthread

main.o: main.c
	$(CC) $(CFLAGS_DEBUG) -I $(INCLUDE_PATH) src/vlnd/main.c -o build/main.o

router.o: router.c
	$(CC) $(CFLAGS_DEBUG) -I $(INCLUDE_PATH) src/router.c -o build/router.o

adapter.o: vln_adapter.c
	$(CC) $(CFLAGS_DEBUG) -I $(INCLUDE_PATH) src/vln_adapter.c -o build/adapter.o

npb_manager.o: npb_manager.c
	$(CC) $(CFLAGS_DEBUG) -I $(INCLUDE_PATH) src/vlnd/npb_manager.c -o build/npb_manager.o

taskexecutor.o: taskexecutor.c
	$(CC) $(CFLAGS_DEBUG) -I $(INCLUDE_PATH) lib/taskexecutor.c -o build/taskexecutor.o

server.o: server.c
	$(CC) $(CFLAGS_DEBUG) -I $(INCLUDE_PATH) src/vlnd/server.c -o build/server.o

client.o: client.c
	$(CC) $(CFLAGS_DEBUG) -I $(INCLUDE_PATH) src/vlnd/client.c -o build/client.o

rxi_log.o: rxi_log.c
	$(CC) $(CFLAGS_DEBUG) -I $(INCLUDE_PATH) lib/rxi_log.c -D LOG_USE_COLOR -o build/rxi_log.o

clean:
	rm -r build/*

	
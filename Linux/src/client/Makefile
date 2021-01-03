CC = gcc
CFLAGS_RELEASE = -Wall -c
CFLAGS_DEBUG = -Wall -g -c
LIBS = -lpthread -ljson-c
HEADERS = ../../lib/tcpwrapper.h ../../lib/protocol.h ../router.h ../../lib/taskexecutor.h vlnadapter.h starterprotocol.h

OBJECT_DIR = ../../build/client/

all: check $(OBJECT_DIR)client $(OBJECT_DIR)starter

check:
ifeq ("$(wildcard $(OBJECT_DIR))", "")
	mkdir $(OBJECT_DIR)
endif

$(OBJECT_DIR)client: $(OBJECT_DIR)main.o $(OBJECT_DIR)tcpwrapper.o $(OBJECT_DIR)router.o $(OBJECT_DIR)taskexecutor.o $(OBJECT_DIR)vlnadapter.o $(HEADERS)
	$(CC) $^ -o $@ ../../build/rxi_log.o $(LIBS)

$(OBJECT_DIR)main.o: main.c
	$(CC) $(CFLAGS_RELEASE) $< -o $@

$(OBJECT_DIR)vlnadapter.o: vlnadapter.c
	$(CC) $(CFLAGS_RELEASE) $< -o $@

$(OBJECT_DIR)tcpwrapper.o: ../../lib/tcpwrapper.c
	$(CC) $(CFLAGS_RELEASE) $< -o $@

$(OBJECT_DIR)router.o: ../router.c
	$(CC) $(CFLAGS_RELEASE) $< -o $@

$(OBJECT_DIR)taskexecutor.o: ../../lib/taskexecutor.c
	$(CC) $(CFLAGS_RELEASE) $< -o $@

$(OBJECT_DIR)starter: starterclient.c $(OBJECT_DIR)tcpwrapper.o
	$(CC) $^ -o $(OBJECT_DIR)$@ $(LIBS)

clean:
	rm -r $(OBJECT_DIR)

	
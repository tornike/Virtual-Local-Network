CC = gcc
CFLAGS_RELEASE = -Wall -c
CFLAGS_DEBUG = -Wall -g -c
LIBS = -lpthread

OBJECT_DIR = ../../build/client/
SRC_DIR = ./ ../ ../lib/
SRC = $(wildcard *.c)
OBJ = $(patsubst %.c, $(OBJECT_DIR)%.o, $(SRC))
OBJ1 = main.o tcpwrapper.o

all: $(OBJECT_DIR)client

$(OBJECT_DIR)main.o: main.c
	$(CC) $(CFLAGS_DEBUG) $< -o $@

$(OBJECT_DIR)tcpwrapper.o: ../lib/tcpwrapper.c
	$(CC) $(CFLAGS_DEBUG) $< -o $@

$(OBJECT_DIR)client: $(OBJECT_DIR)main.o $(OBJECT_DIR)tcpwrapper.o
	$(CC) $^ -o $(OBJECT_DIR)$@ $(LIBS)

clean:
	rm $(OBJECT_DIR)*

test:
	echo $(wildcard ../lib/*.c) $(wildcard *.c)

	
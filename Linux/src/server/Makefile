CC = gcc
CFLAGS_RELEASE = -Wall -c
CFLAGS_DEBUG = -Wall -g -c
LIBS = -lpthread

OBJECT_DIR = ../../build/server/
SRC = $(wildcard *.c)
OBJ = $(patsubst %.c, $(OBJECT_DIR)%.o, $(SRC))

$(OBJECT_DIR)%.o: %.c
	$(CC) $(CFLAGS_DEBUG) $< -o $@

all: $(OBJECT_DIR)server

$(OBJECT_DIR)server: $(OBJ)
	$(CC) $^ -o $(OBJECT_DIR)$@ $(LIBS)

clean:
	rm $(OBJECT_DIR)*

test:
	echo $(OBJ)

	
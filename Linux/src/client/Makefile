CC = gcc
CFLAGS_RELEASE = -Wall -c
CFLAGS_DEBUG = -Wall -g -c
LIBS = -lpthread

OBJECT_DIR = ../../build/client/
SRC = $(wildcard *.c)
OBJ = $(patsubst %.c, $(OBJECT_DIR)%.o, $(SRC))

$(OBJECT_DIR)%.o: %.c
	$(CC) $(CFLAGS_RELEASE) $< -o $@

all: $(OBJECT_DIR)client

$(OBJECT_DIR)client: $(OBJ)
	$(CC) $^ -o $(OBJECT_DIR)$@ $(LIBS)

clean:
	rm $(OBJECT_DIR)*

test:
	echo $(OBJ)

	
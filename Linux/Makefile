
export C_INCLUDE_PATH = $(shell pwd)/include

all:
	cd src/server && $(MAKE)
	cd src/client && $(MAKE)

clean:
	rm -r build/*

	
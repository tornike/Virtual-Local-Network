all:
	cd src/server && $(MAKE)
	cd src/client && $(MAKE) && $(MAKE) starter
	cp build/client/starter build/client/client src/client/vln.config install/

clean:
	rm build/client/*
	rm build/server/*
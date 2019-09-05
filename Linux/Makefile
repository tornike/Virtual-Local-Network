all:
	cd src/server && $(MAKE)
	cd src/client && $(MAKE) && $(MAKE) starter
	cp build/client/starter build/client/client src/client/vln.config install/
	mv install/starter install/vlnstarter
	mv install/client install/vlnclient

clean:
	rm build/client/*
	rm build/server/*
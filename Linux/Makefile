all:
	cd src/server && $(MAKE)
	cd src/client && $(MAKE) && $(MAKE) starter
	cp build/client/starter build/client/client build/server/server src/client/vln.config install/
	mv install/starter install/vlnstarter
	mv install/client install/vlnclient
	mv install/server install/vlnserver

clean:
	rm build/client/*
	rm build/server/*
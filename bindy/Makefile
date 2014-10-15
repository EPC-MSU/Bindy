CC = g++
LIBPATH = ../crypto++/
OUTFILE = main
CFLAGS = -std=c++0x -lpthread -I$(LIBPATH) -L$(LIBPATH) -lcryptopp

main: client-server.o tinythread.o bindy.o
	$(CC) $(CFLAGS) -o $(OUTFILE) client-server.o tinythread.o bindy.o $(LIBPATH)/libcryptopp.a

client-server.o: client-server.cpp
	$(CC) $(CFLAGS) -c client-server.cpp

tinythread.o: tinythread.cpp tinythread.h
	$(CC) $(CFLAGS) -c tinythread.cpp

bindy.o: bindy.cpp bindy.h
	$(CC) $(CFLAGS) -c bindy.cpp


clean:
	rm -f *.o $(OUTFILE)

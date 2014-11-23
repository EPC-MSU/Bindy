CRYPTOPATH = ../crypto++/
CXXFLAGS = -std=c++0x -lpthread -I$(CRYPTOPATH)
LDFLAGS = -L$(CRYPTOPATH)

all: main libbindy.a

main: client-server.o tinythread.o bindy.o $(CRYPTOPATH)/libcryptopp.a
	$(CXX) $(CXXFLAGS) $(LDFLAGS) $^ -o $@

libbindy.a: bindy.o wrapper.o
	$(AR) $(ARFLAGS) $@ $^

clean:
	rm -f *.o *.a main

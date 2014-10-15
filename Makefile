all: cryptopp-build bindy-build
clean: cryptopp-clean bindy-clean

cryptopp-build:
	cd crypto++ && $(MAKE) static

bindy-build:
	cd bindy && $(MAKE)

cryptopp-clean:
	cd crypto++ && $(MAKE) clean

bindy-clean:
	cd bindy && $(MAKE) clean
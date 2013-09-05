# Using g++
CC = g++
# Flags to pass to the compiler
CFLAGS = -Wall
# Library flages - we want cryptopp
CRYPTOPP = -L/cryptopp/
CLIBS = -lcryptopp

all:
	g++  -g3 -ggdb -O0 -Wall -Wextra -Wno-unused -o conversion conversion.cpp $(CRYPTOPP) $(CLIBS)
	# g++ -g3 -ggdb -O0 -Wall -Wextra -Wno-unused -o winternitz winternitz.cpp $(CRYPTOPP) $(CLIBS)


clean:
	rm -rf *o winternitz

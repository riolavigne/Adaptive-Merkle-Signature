#This compiler only works if cryptopp is compiled using clang and -stdlib=libc++
#CC=clang++
#CFLAGS=-g3 -O0 -Wall -Wextra -Wno-unused -std=c++11 -stdlib=libc++

# This compiler only works if cryptopp is compiled without clang
CC=/usr/local/Cellar/gcc47/4.7.2/bin/g++-4.7
CFLAGS=-g3 -ggdb -O0 -Wall -Wextra -Wno-unused -std=c++11 -I/usr/local/ssl/include
LDFLAGS=-L/cryptopp/ -lcryptopp -L/usr/local/ssl/lib -lssl -lcrypto
SOURCES= data.cpp winternitz.cpp merkle.cpp adaptiveMerkle.cpp test.cc
#SOURCES= test.cc
OBJECTS=$(SOURCES:.cpp=.cpp)
EXECUTABLE=test

all: $(SOURCES) $(EXECUTABLE)

$(EXECUTABLE): $(OBJECTS)
	$(CC) $(CFLAGS) $(LDFLAGS) $(OBJECTS) -o $@

.cc.cpp.o:
	$(CC) $(CFLAGS) $< -o $@

rsa:
	g++ -I/usr/local/ssl/include data.cpp rsaTest.cc -o rsaTest

rsa-cryptopp:
	$(CC) $(CFLAGS) $(LDFLAGS) data.cpp rsaCryptopp.cc -o rsaCryptopp

clean:
	rm -rf *o main test rsaTest foo

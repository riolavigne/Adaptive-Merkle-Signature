CC=g++
CFLAGS=-g3 -ggdb -O0 -Wall -Wextra -Wno-unused
LDFLAGS=-L/cryptopp/ -lcryptopp
SOURCES=data.cpp winternitz.cpp merkle.cpp main.cpp
OBJECTS=$(SOURCES:.cpp=.cpp)
EXECUTABLE=main

all: $(SOURCES) $(EXECUTABLE)

$(EXECUTABLE): $(OBJECTS)
	$(CC) $(LDFLAGS) $(OBJECTS) -o $@

.cpp.o:
	$(CC) $(CFLAGS) $< -o $@

clean:
	rm -rf *o main

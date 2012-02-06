CC=g++
CFLAGS=-Wall -pedantic
TESTS=python tests.py compile

SRCS = $(wildcard testing/*.cpp)
PROGS = $(patsubst %.cpp, %.exe, $(SRCS))

testing/%.exe: testing/%.cpp
	$(CC) $(CFLAGS) -o $@ $^

xor:
	$(TESTS) xor

mov:
	$(TESTS) mov

test: $(PROGS)
	
clean:
	rm -rf testing
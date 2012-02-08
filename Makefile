CC=g++
CFLAGS=-Wall -pedantic
TESTS=python tests.py compile

SRCS = $(wildcard testing/*.cpp)
PROGS = $(patsubst %.cpp, %.exe, $(SRCS))

testing/%.exe: testing/%.cpp
	$(CC) $(CFLAGS) -o $@ $^

# each instruction..
%:
	$(TESTS) $@
	
test: $(PROGS)
	
clean:
	rm -rf testing
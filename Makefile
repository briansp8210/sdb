CXX = g++
CXXFLAGS = -g -std=c++11 -Wall -Wextra -pedantic
LDLIBS = -lelf -lcapstone

.PHONY: all clean
all: sdb

sdb: sdb.cc sdb.h
	$(CXX) $(CXXFLAGS) -o $@ $< $(LDLIBS)

clean:
	@rm sdb

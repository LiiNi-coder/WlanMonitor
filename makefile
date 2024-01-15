# Compiler to use
CC = g++

# Compiler flags
CFLAGS = -c -Wall

# Google Test library
GTEST_LIB = -lgtest -pthread -lgtest_main

# Source files
SOURCES = $(wildcard *.cpp)
OBJECTS = $(addprefix build/, $(SOURCES:.cpp=.o))

# Test files
TEST_SOURCES = $(filter-out main.cpp, $(SOURCES))
TEST_OBJECTS = $(addprefix build/, $(TEST_SOURCES:.cpp=_test.o))
TEST_EXECUTABLES = $(addprefix build/, $(TEST_SOURCES:.cpp=_test))

# Executable
EXECUTABLE = build/my_project

.PHONY: all clean test

all: build $(EXECUTABLE)

$(EXECUTABLE): $(OBJECTS)
	$(CC) $^ -o $@ -lpcap

build/%.o: %.cpp
	$(CC) $(CFLAGS) $< -o $@

build/%_test.o: %.cpp
	$(CC) $(CFLAGS) -DUNIT_TEST $< -o $@

build/%_test: build/%_test.o
	$(CC) $^ -o $@ $(GTEST_LIB)

test: $(TEST_EXECUTABLES)

build:
	mkdir -p build

clean:
	$(RM) $(OBJECTS) $(EXECUTABLE) $(TEST_OBJECTS) $(TEST_EXECUTABLES)
	rmdir build

# Compiler to use
CC = g++

# Compiler flags
CFLAGS = -c -Wall

# Source files
SOURCES = $(wildcard *.cpp)
OBJECTS = $(addprefix build/, $(SOURCES:.cpp=.o))

# Executable
EXECUTABLE = build/my_project

.PHONY: all clean

all: build $(EXECUTABLE)

$(EXECUTABLE): $(OBJECTS)
	$(CC) $^ -o $@ -lpcap

build/%.o: %.cpp
	$(CC) $(CFLAGS) $< -o $@

build:
	mkdir -p build

clean:
	$(RM) $(OBJECTS) $(EXECUTABLE)
	rmdir build

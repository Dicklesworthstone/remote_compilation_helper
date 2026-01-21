# RCH E2E Test Fixture - C Hello World Makefile
#
# This Makefile builds the hello_c fixture project.
# Supports both gcc and clang via the CC variable.

CC ?= gcc
CFLAGS ?= -Wall -Wextra -Werror -pedantic -std=c11
LDFLAGS ?=

SRCS = main.c hello.c
OBJS = $(SRCS:.c=.o)
TARGET = hello

.PHONY: all clean test

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $^

%.o: %.c hello.h
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f $(TARGET) $(OBJS)

# Simple test - run the binary and check output
test: $(TARGET)
	./$(TARGET) | grep -q "Hello from rch test fixture!"
	./$(TARGET) | grep -q "2 + 2 = 4"
	@echo "All tests passed!"

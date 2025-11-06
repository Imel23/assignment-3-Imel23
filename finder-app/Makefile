# Compiler and flags
ifeq ($(CROSS_COMPILE),)
    CC = gcc
else
    CC = $(CROSS_COMPILE)gcc
endif

CFLAGS = -Wall -Wextra -g

# Target name
TARGET = writer

# Source files
SRCS = writer.c
OBJS = $(SRCS:.c=.o)

# Default target
$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $(TARGET) $(OBJS)

# How to build .o files from .c
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

# Clean rule
clean:
	rm -f $(OBJS) $(TARGET)

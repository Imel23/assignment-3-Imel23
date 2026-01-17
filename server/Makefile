# If CC is already set (by Yocto), use it. 
# If not, try CROSS_COMPILE prefix. 
# If that is also empty, it defaults to standard gcc.
CC ?= $(CROSS_COMPILE)gcc

# Default to using the char device (1), can be overridden by "make USE_AESD_CHAR_DEVICE=0"
USE_AESD_CHAR_DEVICE ?= 1

# Append your required flags to whatever flags the environment provides
# We add the -D flag to define the macro for the C code
CFLAGS += -Wall -Wextra -g -pthread -DUSE_AESD_CHAR_DEVICE=$(USE_AESD_CHAR_DEVICE)
LDFLAGS += -pthread

TARGET := aesdsocket
SRCS := aesdsocket.c
OBJS := $(SRCS:.c=.o)

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) $(TARGET)

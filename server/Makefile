# If CC is already set (by Yocto), use it. 
# If not, try CROSS_COMPILE prefix. 
# If that is also empty, it defaults to standard gcc.
CC ?= $(CROSS_COMPILE)gcc

# Append your required flags to whatever flags the environment provides
CFLAGS += -Wall -Wextra -g -pthread
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
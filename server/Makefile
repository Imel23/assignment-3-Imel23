# Resolve compiler based on optional CROSS_COMPILE prefix
ifeq ($(strip $(CROSS_COMPILE)),)
CC := gcc
else
CC := $(CROSS_COMPILE)gcc
endif

CFLAGS ?= -Wall -Wextra -g -pthread
LDFLAGS ?= -pthread

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

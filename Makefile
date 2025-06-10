CC = gcc
CFLAGS = -Wall -Wextra -O2 -g -I./brocm_header -D_FILE_OFFSET_BITS=64 -Wno-nonnull
LDFLAGS = -L. -lbrocm -Wl,-rpath,.

TARGET = encdec
SRCS = encdec.c
OBJS = $(SRCS:.c=.o)

HEADERS = $(wildcard brocm_header/*.h)

PREFIX = /usr/local
INSTALL_PATH = $(PREFIX)/bin

.PHONY: all clean install clean-obj

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(OBJS) -o $(TARGET) $(LDFLAGS)
	@$(MAKE) clean-obj

%.o: %.c $(HEADERS)
	$(CC) $(CFLAGS) -c $< -o $@

install: $(TARGET)
	install -d $(DESTDIR)$(INSTALL_PATH)
	install -m 755 $(TARGET) $(DESTDIR)$(INSTALL_PATH)

clean-obj:
	@rm -f $(OBJS)

clean: clean-obj
	@rm -f $(TARGET)

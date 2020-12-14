LDFLAGS += $(shell pkg-config --libs glib-2.0) -lpthread -lm -lunicorn -lcapstone -g -I/usr/include/glib-2.0 -I/usr/lib/glib-2.0/include -Wno-pointer-to-int-cast -Wno-int-conversion -Wno-incompatible-pointer-types

all: elf32 elf64
%: %.c 
	$(CC) $(CFLAGS) $^ $(LDFLAGS) -o $@

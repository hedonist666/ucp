LDFLAGS += $(shell pkg-config --libs glib-2.0) -lpthread -lm -lunicorn -g

all: emu
%: %.c 
	$(CC) $(CFLAGS) $^ $(LDFLAGS) -o $@

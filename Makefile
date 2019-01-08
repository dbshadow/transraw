
TARGET = transraw

all: $(TARGET)

sendraw: transraw.o
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^

.c.o:
	$(CC) $(CFLAGS) $(INCLUDE) -c $<

.PHONY: clean

clean:
	rm  -rf *.o  $(TARGET)

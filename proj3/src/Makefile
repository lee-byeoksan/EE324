CC=gcc
CFLAGS=
LDFLAGS=-levent
TARGET=proxy
SRC=proj3
OBJS=proxy.o

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(patsubst %.o, $(SRC)/%.o, $(OBJS))
	$(CC) -o $@ $^ $(LDFLAGS)

$(SRC)/%.o: $(SRC)/%.c
	$(CC) $(CFLAGS) -o $@ -c $^

clean: FORCE
	rm -rf $(TARGET) $(patsubst %.o, $(SRC)/%.o, $(OBJS))

FORCE:

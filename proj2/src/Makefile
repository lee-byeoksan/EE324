CC=gcc
CFLAGS=
LDFLAGS=-pthread
SRC=proj2
TARGET=proxy
OBJS=proxy.o connection.o listener.o httpuri.o logger.o thread_pool.o

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(patsubst %.o, $(SRC)/%.o, $(OBJS))
	$(CC) $(LDFLAGS) -o $@ $^

$(SRC)/%.o: $(SRC)/%.c
	$(CC) $(CFLAGS) -o $@ -c $^

clean: FORCE
	rm -rf $(TARGET) $(patsubst %.o, $(SRC)/%.o, $(OBJS)) proxy.log

FORCE:

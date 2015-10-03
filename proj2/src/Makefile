CC=gcc
CFLAGS=
LDFLAGS=
SRC=proj2
TARGET=proxy
OBJS=proxy.o

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(patsubst %.o, $(SRC)/%.o, $(OBJS))
	$(CC) $(LDFLAGS) -o $@ $^

$(SRC)/%.o: $(SRC)/%.c
	$(CC) $(CFLAGS) -o $@ -c $^

clean: FORCE
	rm -rf $(TARGET) $(patsubst %.o, $(SRC)/%.o, $(OBJS))

FORCE:

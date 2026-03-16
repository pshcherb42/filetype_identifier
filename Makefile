CC      = gcc
CFLAGS  = -Wall -Wextra -Wpedantic -std=c11 -O2
SRC     = src/main.c src/filetype.c
TARGET  = filetype

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $@ $^

clean:
	rm -f $(TARGET)

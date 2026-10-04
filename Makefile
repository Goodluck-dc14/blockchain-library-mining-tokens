CC      = gcc
CFLAGS  = -std=c11 -Wall -Wextra -pedantic -O2
CPPFLAGS = -D_POSIX_C_SOURCE=200809L
LDLIBS  = -lcrypto

SRC    := $(wildcard src/*.c)
OBJ    := $(SRC:src/%.c=build/%.o)
HDR    := $(wildcard src/*.h)
TARGET := library_chain

all: $(TARGET)

$(TARGET): $(OBJ)
	$(CC) $(CFLAGS) -o $@ $^ $(LDLIBS)

build/%.o: src/%.c $(HDR) | build
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

build:
	mkdir -p build

# Runs the automated test suite in a throwaway folder
test: $(TARGET)
	bash tests/run_tests.sh

# Deletes the chain, pending pool, transfers, keys and librarian account
reset:
	rm -f chain.dat chain.dat.tmp pending.dat pending.dat.tmp transactions.dat librarian.dat private_key.pem public_key.pem

clean:
	rm -rf build $(TARGET)

.PHONY: all test reset clean

CC = cc
CFLAGS = -Wall -Wextra -std=gnu11 -Iinclude -Ihxcrypt/include -DKBV_TEST

HXCRYPT_SRC = hxcrypt/src/blake2s.c hxcrypt/src/chacha20.c \
              hxcrypt/src/csprng.c hxcrypt/src/pbkdf2.c \
              hxcrypt/src/hkdf.c hxcrypt/src/utils.c

KBV_SRC = src/kbv.c platform/kbv_platform_posix.c

.PHONY: test clean

test: test/test_vault.c $(KBV_SRC) $(HXCRYPT_SRC)
	$(CC) $(CFLAGS) -o test_vault $^
	./test_vault
	rm -f test_vault vault.bin

clean:
	rm -f test_vault vault.bin
